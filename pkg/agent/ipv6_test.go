package agent

import (
	"net"
	"strings"
	"testing"
)

var nameserver = net.IP{127, 0, 0, 53}

// ipv6Agent allows one domain and nothing else, so the only way an IPv6
// address reaches the allow-list is through the domain's AAAA record.
func ipv6Agent(t *testing.T) *Agent {
	t.Helper()
	return NewAgent(AgentConfig{
		EgressPolicy:    EGRESS_POLICY_BLOCK,
		DNSPolicy:       DNS_POLICY_ANY,
		AllowedDomains:  []string{"allowed.example.com"},
		EnableSudo:      true,
		NetInfoProvider: &mockNetInfoProvider{},
		FileSystem:      newMockFileSystem(),
		ProcProvider:    newMockProcProvider(),
		DockerProvider:  newMockDockerProvider(),
		PacketSender:    &mockPacketSender{},
	})
}

var (
	client6  = net.ParseIP("2001:db8::5")
	allowed6 = net.ParseIP("2001:db8::10")
	denied6  = net.ParseIP("2001:db8::99")
)

// An allowed domain must be reachable over IPv6. Its address arrives in a AAAA
// record, so the agent has to learn AAAA answers the same way it learns A.
func TestAAAAResponseForAnAllowedDomainIsLearned(t *testing.T) {
	a := ipv6Agent(t)

	dns := GenerateDNSTypeAAAAResponsePacket("allowed.example.com", allowed6, nameserver)
	if v := a.ProcessPacket(dns); v != ACCEPT_REQUEST {
		t.Fatalf("DNS response verdict = %d, want ACCEPT_REQUEST", v)
	}

	if !a.allowedIps[allowed6.String()] {
		t.Errorf("%s was not added to the allow-list", allowed6)
	}
	// The connection log needs the name too, or a v6 decision is reported
	// against a bare address.
	if got := a.ipToDomain[allowed6.String()]; got != "allowed.example.com" {
		t.Errorf("ipToDomain[%s] = %q, want the domain that resolved it", allowed6, got)
	}

	conn := GenerateIPv6TCPPacket(client6, allowed6, 51000, 443)
	if v := a.ProcessPacket(conn); v != ACCEPT_REQUEST {
		t.Errorf("connection to the allowed domain's IPv6 address = %d, want ACCEPT_REQUEST", v)
	}
}

// The other direction: learning AAAA must not turn into learning every AAAA.
func TestAAAAResponseForADeniedDomainIsNotLearned(t *testing.T) {
	a := ipv6Agent(t)

	dns := GenerateDNSTypeAAAAResponsePacket("denied.example.com", denied6, nameserver)
	a.ProcessPacket(dns)

	if a.allowedIps[denied6.String()] {
		t.Errorf("%s reached the allow-list from a domain that is not allowed", denied6)
	}

	conn := GenerateIPv6TCPPacket(client6, denied6, 51000, 443)
	if v := a.ProcessPacket(conn); v != DROP_REQUEST {
		t.Errorf("connection to a denied IPv6 address = %d, want DROP_REQUEST", v)
	}
}

// Forwarded traffic is a container's traffic. The DOCKER-USER rules are in the
// `ip` family, which is IPv4 only, so IPv6 needs a forward chain of its own or
// a container's IPv6 egress is never judged at all.
func TestForwardedIPv6IsFiltered(t *testing.T) {
	for _, tt := range []struct {
		name  string
		rules string
	}{
		{"block", blockRules},
		{"audit", auditRules},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if !strings.Contains(tt.rules, "hook forward") {
				t.Fatal("no forward chain: forwarded traffic is never seen")
			}
			forward := tt.rules[strings.Index(tt.rules, "hook forward"):]
			if end := strings.Index(forward, "\n    }"); end > 0 {
				forward = forward[:end]
			}
			// New IPv6 connections must reach the agent for a decision.
			if !strings.Contains(forward, "meta nfproto ipv6 ct state new counter queue num 0") {
				t.Error("new IPv6 connections are not queued for a decision")
			}
			// And DNS over IPv6 must be inspected, or AAAA answers are never
			// seen and an allowed domain stays unreachable.
			for _, dns := range []string{
				"meta nfproto ipv6 udp dport 53 counter queue num 0",
				"meta nfproto ipv6 tcp dport 53 counter queue num 0",
			} {
				if !strings.Contains(forward, dns) {
					t.Errorf("IPv6 DNS is not inspected: missing %q", dns)
				}
			}
		})
	}
}
