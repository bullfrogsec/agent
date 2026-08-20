package agent

import (
	crand "crypto/rand"
	"encoding/binary"
	"fmt"
	"net"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// injectionMarkPlaceholder is the token queue_block.nft carries where the mark
// belongs. LoadNftRules fills in the real value.
const injectionMarkPlaceholder = "__INJECTED_PACKET_MARK__"

// injectedPacketMark tags every packet the agent injects, so queue_block.nft
// can tell the agent's own resets apart from the traffic it is judging.
//
// The tag is random per run because the ruleset lets through whatever carries
// it, and a fixed value written in this repository would be usable by anything
// that can set a mark on a socket (see SO_MARK in socket(7)). It is not the
// only guard: queue_block.nft also requires the packet to look like a reset.
var injectedPacketMark = newInjectionMark()

// newInjectionMark draws this run's tag from the system random source.
func newInjectionMark() uint32 {
	for {
		var b [4]byte
		// crypto/rand.Read never returns an error. It crashes the program if
		// the system source is unavailable, which is what we want for a value
		// that has to be unguessable.
		crand.Read(b[:])
		// Every packet carries mark 0 by default, so letting 0 through would
		// let everything through.
		if m := binary.BigEndian.Uint32(b[:]); m != 0 {
			return m
		}
	}
}

// Reasons a denied packet gets no reset. reasonNotResettable covers the
// packets resets do not apply to at all — anything that is not IPv4 TCP.
const (
	reasonNotResettable    = "not-ipv4-tcp"
	reasonAlreadyReset     = "already-reset"
	reasonNoUsableSequence = "no-usable-sequence"
)

// tcpReset is the reset the agent sends to tell a client that its connection
// was refused, described in terms of what goes on the wire.
//
// It always travels in the opposite direction to the packet that was denied,
// bearing the address the client was trying to reach: a reset from anywhere
// else is not the server refusing, and the client's TCP will discard it.
type tcpReset struct {
	SrcIP   net.IP
	DstIP   net.IP
	SrcPort layers.TCPPort
	DstPort layers.TCPPort
	Seq     uint32
	Ack     uint32
	ACK     bool
}

// buildTCPReset derives the reset for a packet that policy has just denied.
//
// It returns nil, plus the reason, when no reset should be sent at all.
//
// Two constructions, chosen by what is being denied:
//
//   - A connection-opening SYN (no ACK). This is the case the current
//     ct-state-new ruleset produces: the decision happens at establishment,
//     before the connection carries any data. The correct answer is the
//     ordinary "connection refused" a closed port gives — RST+ACK, seq 0,
//     ack = the client's ISN + 1. A SYN carries no meaningful acknowledgement
//     number, so taking the reset's sequence from it (which is what a
//     mid-connection reset does) would produce a packet the client discards.
//
//   - A packet on an already-established connection. Here the acknowledgement
//     number IS meaningful: it is exactly the next byte the client expects
//     from the server, so a reset bearing it lands inside the client's receive
//     window. RFC 5961 makes out-of-window reset handling strict — a reset
//     with an arbitrary or zero sequence is silently discarded — which is why
//     the sequence cannot simply be zero here.
//
// A packet that is neither (no SYN, no ACK) carries no number this can be
// derived from, and a reset with a placeholder sequence would be discarded by
// the client anyway, so none is sent. A RST is never answered with a RST.
//
// Resets are IPv4 only, because the packet this builds and the socket that
// sends it are both IPv4 (see rawSocketSender). IPv6 is still enforced: a
// denied v6 connection is dropped like any other. It is just dropped in
// silence, so it hangs until the client gives up rather than failing fast.
func buildTCPReset(packet gopacket.Packet) (*tcpReset, string) {
	ip4, ok := packet.NetworkLayer().(*layers.IPv4)
	if !ok {
		return nil, reasonNotResettable
	}
	tcpLayer := packet.Layer(layers.LayerTypeTCP)
	if tcpLayer == nil {
		return nil, reasonNotResettable
	}
	tcp := tcpLayer.(*layers.TCP)

	// Never answer a reset with a reset. Besides being pointless, this is the
	// loop stop: the agent's own injected packets must not be able to provoke
	// another injection if they are ever fed back through the queue.
	if tcp.RST {
		return nil, reasonAlreadyReset
	}

	rst := &tcpReset{
		SrcIP:   ip4.DstIP,
		DstIP:   ip4.SrcIP,
		SrcPort: tcp.DstPort,
		DstPort: tcp.SrcPort,
	}

	switch {
	case tcp.SYN && !tcp.ACK:
		// Connection refused.
		rst.Seq = 0
		rst.Ack = tcp.Seq + 1
		rst.ACK = true
	case tcp.ACK:
		// Mid-connection: the denied packet tells us what the client expects.
		rst.Seq = tcp.Ack
		rst.Ack = 0
		rst.ACK = false
	default:
		return nil, reasonNoUsableSequence
	}

	return rst, ""
}

// serialize renders the reset as a complete IPv4 packet, header included,
// ready for a raw socket.
func (r *tcpReset) serialize() ([]byte, error) {
	ip := layers.IPv4{
		Version:  4,
		TTL:      64,
		Protocol: layers.IPProtocolTCP,
		SrcIP:    r.SrcIP,
		DstIP:    r.DstIP,
	}
	tcp := layers.TCP{
		SrcPort: r.SrcPort,
		DstPort: r.DstPort,
		Seq:     r.Seq,
		Ack:     r.Ack,
		RST:     true,
		ACK:     r.ACK,
		// No payload and nothing to offer: a reset advertises no window.
		Window: 0,
	}
	if err := tcp.SetNetworkLayerForChecksum(&ip); err != nil {
		return nil, fmt.Errorf("reset checksum setup: %w", err)
	}

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	if err := gopacket.SerializeLayers(buf, opts, &ip, &tcp); err != nil {
		return nil, fmt.Errorf("serializing reset: %w", err)
	}
	return buf.Bytes(), nil
}

func (r *tcpReset) String() string {
	flags := "RST"
	if r.ACK {
		flags = "RST+ACK"
	}
	return fmt.Sprintf("%s %s:%d -> %s:%d seq=%d ack=%d",
		flags, r.SrcIP, r.SrcPort, r.DstIP, r.DstPort, r.Seq, r.Ack)
}

// sendResetForDeniedPacket tells the client its connection was refused, so a
// denial is reported as a denial instead of stalling until the client's own
// timeout — the symptom users report as "the tool hangs".
//
// Deliberately best-effort. The DROP verdict has already been decided by the
// caller and is returned regardless: feedback must never be able to gate
// enforcement, so every failure here is logged and swallowed.
func (a *Agent) sendResetForDeniedPacket(packet gopacket.Packet) {
	// Audit mode permits the traffic it logs. It must never reset anything,
	// and it does not even own a sender — this is the second of the two
	// guards on purpose.
	if !a.blocking || a.packetSender == nil {
		return
	}

	rst, skipped := buildTCPReset(packet)
	if rst == nil {
		// A denied UDP datagram or IPv6 packet is the ordinary case and says
		// nothing an operator needs; it is the TCP connection that went
		// unanswered that is worth a line, because "why did this one hang
		// when the others were refused" is the question being answered.
		if skipped != reasonNotResettable {
			fmt.Printf("RESET: not sent (%s)\n", skipped)
		}
		return
	}

	b, err := rst.serialize()
	if err != nil {
		fmt.Printf("RESET: not sent: %v\n", err)
		return
	}
	if err := a.packetSender.SendIPv4(rst.DstIP, b); err != nil {
		fmt.Printf("RESET: send failed: %v\n", err)
		return
	}
	fmt.Printf("RESET: %s\n", rst)
}
