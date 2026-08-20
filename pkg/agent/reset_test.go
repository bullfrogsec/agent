package agent

import (
	"errors"
	"fmt"
	"net"
	"strings"
	"testing"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// blockingAgent is an agent in block mode with a recording sender, allowing
// only the loopback default. Anything else is denied.
func blockingAgent(t *testing.T) (*Agent, *mockPacketSender) {
	t.Helper()
	sender := &mockPacketSender{}
	a := NewAgent(AgentConfig{
		EgressPolicy:    EGRESS_POLICY_BLOCK,
		DNSPolicy:       DNS_POLICY_ANY,
		AllowedDomains:  []string{"allowed.example.com"},
		AllowedIPs:      []string{"10.9.9.9"},
		EnableSudo:      true,
		NetInfoProvider: &mockNetInfoProvider{},
		FileSystem:      newMockFileSystem(),
		ProcProvider:    newMockProcProvider(),
		DockerProvider:  newMockDockerProvider(),
		PacketSender:    sender,
	})
	return a, sender
}

var (
	clientIP = net.IP{10, 0, 0, 5}
	serverIP = net.IP{93, 184, 216, 34}
)

// A denied SYN must be answered the way a closed port answers: RST+ACK,
// sequence zero, acknowledging the client's ISN, sourced from the address the
// client was trying to reach.
func TestDeniedSYNIsAnsweredWithConnectionRefused(t *testing.T) {
	a, sender := blockingAgent(t)

	const isn = 4242
	pkt := GenerateTCPPacketWithFlags(clientIP, serverIP, 51000, 443, isn, 0, true, false, false)

	if v := a.ProcessPacket(pkt); v != DROP_REQUEST {
		t.Fatalf("verdict = %d, want DROP_REQUEST", v)
	}
	if sender.count() != 1 {
		t.Fatalf("injected %d packets, want 1", sender.count())
	}

	ip, tcp := sender.lastTCP(t)
	if !ip.SrcIP.Equal(serverIP) || !ip.DstIP.Equal(clientIP) {
		t.Errorf("reset addressed %s -> %s, want %s -> %s", ip.SrcIP, ip.DstIP, serverIP, clientIP)
	}
	if !sender.dsts[0].Equal(clientIP) {
		t.Errorf("reset sent to %s, want the client %s", sender.dsts[0], clientIP)
	}
	if tcp.SrcPort != 443 || tcp.DstPort != 51000 {
		t.Errorf("reset ports %d -> %d, want 443 -> 51000", tcp.SrcPort, tcp.DstPort)
	}
	if !tcp.RST || !tcp.ACK {
		t.Errorf("flags RST=%v ACK=%v, want both set", tcp.RST, tcp.ACK)
	}
	if tcp.SYN || tcp.FIN || tcp.PSH {
		t.Errorf("unexpected extra flags on the reset: %+v", tcp)
	}
	// The whole point of the two constructions: a SYN's own (absent)
	// acknowledgement number must not become the reset's sequence.
	if tcp.Seq != 0 {
		t.Errorf("seq = %d, want 0", tcp.Seq)
	}
	if tcp.Ack != isn+1 {
		t.Errorf("ack = %d, want the client's ISN + 1 (%d)", tcp.Ack, isn+1)
	}
}

// A denied packet on an established connection needs the other construction:
// its sequence must be what the client is expecting next, or RFC 5961 window
// checking discards the reset and it achieves nothing.
func TestDeniedMidConnectionPacketResetsInWindow(t *testing.T) {
	a, sender := blockingAgent(t)

	const clientAck = 987654
	pkt := GenerateTCPPacketWithFlags(clientIP, serverIP, 51000, 443, 100, clientAck, false, true, false)

	if v := a.ProcessPacket(pkt); v != DROP_REQUEST {
		t.Fatalf("verdict = %d, want DROP_REQUEST", v)
	}
	_, tcp := sender.lastTCP(t)
	if tcp.Seq != clientAck {
		t.Errorf("seq = %d, want the denied packet's ack (%d)", tcp.Seq, clientAck)
	}
	if !tcp.RST {
		t.Error("RST flag not set")
	}
	if tcp.ACK {
		t.Error("ACK set on a mid-connection reset; nothing is being acknowledged")
	}
}

// Suppression cases: a packet with no usable sequence number would produce a
// reset the client discards, and a reset must never beget a reset.
func TestNoResetWhenThereIsNothingUsableToBuildOne(t *testing.T) {
	tests := []struct {
		name   string
		packet gopacket.Packet
	}{
		{
			// No SYN, no ACK — R5.19: a placeholder sequence is pure noise.
			name:   "no flags",
			packet: GenerateTCPPacketWithFlags(clientIP, serverIP, 51000, 443, 100, 0, false, false, false),
		},
		{
			// The loop stop. Answering a reset with a reset is how an
			// injected packet fed back through the queue becomes a storm.
			name:   "already a reset",
			packet: GenerateTCPPacketWithFlags(clientIP, serverIP, 51000, 443, 100, 7, false, true, true),
		},
		{
			// UDP is dropped as before; there is no reset to speak of.
			name:   "udp",
			packet: GenerateUDPPacket(clientIP, serverIP, 51000, 4433),
		},
		{
			// IPv6 is dropped like any other denied traffic, but resets
			// are IPv4 only, so nothing is injected.
			name: "ipv6",
			packet: GenerateIPv6TCPPacket(
				net.ParseIP("2001:db8::5"), net.ParseIP("2001:db8::1"), 51000, 443),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a, sender := blockingAgent(t)
			if v := a.ProcessPacket(tt.packet); v != DROP_REQUEST {
				t.Fatalf("verdict = %d, want DROP_REQUEST", v)
			}
			if sender.count() != 0 {
				_, tcp := sender.lastTCP(t)
				t.Fatalf("injected %d packets, want none: %+v", sender.count(), tcp)
			}
		})
	}
}

// Audit mode permits what it logs. Resetting there would convert a warning
// into an outage.
func TestAuditModeNeverResets(t *testing.T) {
	sender := &mockPacketSender{}
	a := NewAgent(AgentConfig{
		EgressPolicy:    EGRESS_POLICY_AUDIT,
		DNSPolicy:       DNS_POLICY_ANY,
		AllowedDomains:  []string{"allowed.example.com"},
		EnableSudo:      true,
		NetInfoProvider: &mockNetInfoProvider{},
		FileSystem:      newMockFileSystem(),
		ProcProvider:    newMockProcProvider(),
		DockerProvider:  newMockDockerProvider(),
		PacketSender:    sender,
	})

	pkt := GenerateTCPPacketWithFlags(clientIP, serverIP, 51000, 443, 1, 0, true, false, false)
	if v := a.ProcessPacket(pkt); v != ACCEPT_REQUEST {
		t.Fatalf("verdict = %d, want ACCEPT_REQUEST", v)
	}
	if sender.count() != 0 {
		t.Fatalf("audit mode injected %d packets, want none", sender.count())
	}
}

// An allowed connection is not a denial and gets no reset.
func TestAllowedConnectionIsNotReset(t *testing.T) {
	a, sender := blockingAgent(t)

	allowed := net.IP{10, 9, 9, 9}
	pkt := GenerateTCPPacketWithFlags(clientIP, allowed, 51000, 443, 1, 0, true, false, false)
	if v := a.ProcessPacket(pkt); v != ACCEPT_REQUEST {
		t.Fatalf("verdict = %d, want ACCEPT_REQUEST", v)
	}
	if sender.count() != 0 {
		t.Fatalf("injected %d packets for an allowed connection, want none", sender.count())
	}
}

// Enforcement must not depend on the feedback succeeding: a send that fails
// still leaves the packet dropped.
func TestDropStandsWhenTheResetCannotBeSent(t *testing.T) {
	a, sender := blockingAgent(t)
	sender.sendErr = errors.New("network is unreachable")

	pkt := GenerateTCPPacketWithFlags(clientIP, serverIP, 51000, 443, 1, 0, true, false, false)
	if v := a.ProcessPacket(pkt); v != DROP_REQUEST {
		t.Fatalf("verdict = %d, want DROP_REQUEST", v)
	}
}

// Likewise when no sender could be opened at all — the agent enforces exactly
// as it did before reset injection existed.
func TestDropStandsWithoutASender(t *testing.T) {
	a, _ := blockingAgent(t)
	a.packetSender = nil

	pkt := GenerateTCPPacketWithFlags(clientIP, serverIP, 51000, 443, 1, 0, true, false, false)
	if v := a.ProcessPacket(pkt); v != DROP_REQUEST {
		t.Fatalf("verdict = %d, want DROP_REQUEST", v)
	}
}

// The injected bytes must be a well-formed IPv4 packet in their own right:
// a raw socket sends what it is given, and a bad checksum or length is
// dropped in silence somewhere far from here.
func TestInjectedResetIsAWellFormedPacket(t *testing.T) {
	rst := &tcpReset{
		SrcIP: serverIP, DstIP: clientIP,
		SrcPort: 443, DstPort: 51000,
		Seq: 0, Ack: 1235, ACK: true,
	}
	b, err := rst.serialize()
	if err != nil {
		t.Fatalf("serialize: %v", err)
	}

	pkt := gopacket.NewPacket(b, layers.LayerTypeIPv4, gopacket.Default)
	if err := pkt.ErrorLayer(); err != nil {
		t.Fatalf("decoding the injected packet: %v", err.Error())
	}
	ip := pkt.NetworkLayer().(*layers.IPv4)
	if int(ip.Length) != len(b) {
		t.Errorf("IP length field %d, packet is %d bytes", ip.Length, len(b))
	}
	if ip.TTL == 0 {
		t.Error("TTL 0: the packet dies at the first hop")
	}

	// Re-verify the TCP checksum by recomputing it over the decoded packet.
	tcp := pkt.Layer(layers.LayerTypeTCP).(*layers.TCP)
	got := tcp.Checksum
	if err := tcp.SetNetworkLayerForChecksum(ip); err != nil {
		t.Fatalf("checksum setup: %v", err)
	}
	buf := gopacket.NewSerializeBuffer()
	if err := gopacket.SerializeLayers(buf,
		gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}, tcp); err != nil {
		t.Fatalf("re-serialize: %v", err)
	}
	want := gopacket.NewPacket(buf.Bytes(), layers.LayerTypeTCP, gopacket.Default).
		Layer(layers.LayerTypeTCP).(*layers.TCP).Checksum
	if got != want {
		t.Errorf("TCP checksum 0x%04x, recomputed 0x%04x", got, want)
	}
}

// The Go code and the ruleset have to agree on the mark. If they disagree the
// agent drops its own resets and denied connections hang again.
func TestRulesetAcceptsTheInjectionMark(t *testing.T) {
	rendered := renderRules(EGRESS_POLICY_BLOCK)

	want := fmt.Sprintf("meta mark 0x%08x ", injectedPacketMark)
	if n := strings.Count(rendered, want); n != 2 {
		t.Errorf("rendered ruleset has %d %q rules, want one per chain (2)", n, want)
	}
	// A leftover placeholder is an nft syntax error, so the agent would not
	// start at all.
	if strings.Contains(rendered, injectionMarkPlaceholder) {
		t.Error("the mark placeholder survived rendering")
	}
	// Audit mode injects nothing, so it has no mark to accept.
	if strings.Contains(renderRules(EGRESS_POLICY_AUDIT), "meta mark") {
		t.Error("the audit ruleset references the injection mark; audit mode never injects")
	}
}

// The mark has to stay out of the repository. A mark anyone can read is a mark
// anyone can set, and the rule would then carry their traffic too.
func TestInjectionMarkIsNotCheckedIn(t *testing.T) {
	if !strings.Contains(blockRules, injectionMarkPlaceholder) {
		t.Fatal("queue_block.nft does not carry the mark placeholder")
	}
	for _, line := range strings.Split(blockRules, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "#") {
			continue
		}
		if strings.Contains(trimmed, "meta mark") &&
			!strings.Contains(trimmed, injectionMarkPlaceholder) {
			t.Errorf("queue_block.nft has a literal mark rule: %q", trimmed)
		}
	}
	if injectedPacketMark == 0 {
		t.Error("the injection mark is 0, which every packet carries by default")
	}
}

// The mark is only a guard if it cannot be guessed, so every run must draw a
// different one.
func TestInjectionMarkIsFreshPerRun(t *testing.T) {
	seen := map[uint32]bool{}
	for range 64 {
		m := newInjectionMark()
		if m == 0 {
			t.Fatal("newInjectionMark returned 0")
		}
		if seen[m] {
			t.Fatalf("newInjectionMark repeated %#x within 64 draws", m)
		}
		seen[m] = true
	}
}

// The mark is not the only guard. The rule also has to describe a reset, so
// that guessing the mark buys an empty packet rather than a way out.
func TestExemptionIsPinnedToTheResetItAllows(t *testing.T) {
	for _, clause := range []string{
		"meta l4proto tcp",
		"meta length 40",
		"tcp flags & (fin|syn|rst|psh|urg) == rst",
	} {
		if n := strings.Count(blockRules, clause); n != 2 {
			t.Errorf("the exemption is missing %q in %d of 2 chains", clause, 2-n)
		}
	}
}

// The rule has to describe what serialize() actually produces, or the agent's
// own resets no longer match it. This fails as soon as a reset grows an option
// or a payload, rather than turning up later as a connection that hangs.
func TestInjectedResetMatchesTheExemptedShape(t *testing.T) {
	for _, tt := range []struct {
		name string
		rst  *tcpReset
	}{
		{"refused", &tcpReset{SrcIP: serverIP, DstIP: clientIP, SrcPort: 443, DstPort: 51000, Ack: 1235, ACK: true}},
		{"mid-connection", &tcpReset{SrcIP: serverIP, DstIP: clientIP, SrcPort: 443, DstPort: 51000, Seq: 987654}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			b, err := tt.rst.serialize()
			if err != nil {
				t.Fatalf("serialize: %v", err)
			}
			// meta length 40.
			if len(b) != 40 {
				t.Errorf("reset is %d bytes, but the ruleset exempts only 40", len(b))
			}
			// tcp flags & (fin|syn|rst|psh|urg) == rst.
			tcp := gopacket.NewPacket(b, layers.LayerTypeIPv4, gopacket.Default).
				Layer(layers.LayerTypeTCP).(*layers.TCP)
			if !tcp.RST {
				t.Error("RST clear: the exemption would not match")
			}
			if tcp.FIN || tcp.SYN || tcp.PSH || tcp.URG {
				t.Errorf("a flag the exemption excludes is set: %+v", tcp)
			}
		})
	}
}
