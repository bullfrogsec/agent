package agent

import "testing"

func TestParseResolvectlDNSServer(t *testing.T) {
	cases := map[string]struct{ in, want string }{
		"per-link list": {"Link 2 (eth0)\n    Current Scopes: DNS\n       DNS Servers: 168.63.129.16 10.0.0.2\n", "168.63.129.16"},
		"current wins":  {"Global\n Current DNS Server: 10.0.0.2\n        DNS Servers: 8.8.8.8 10.0.0.2\n", "10.0.0.2"},
		// Depot: the default interface has no DNS server at all (previously a panic).
		"no server":    {"Link 2 (enp0s6)\n    Current Scopes: none\n", ""},
		"empty output": {"", ""},
		"empty value":  {"       DNS Servers:\n", ""},
	}
	for name, c := range cases {
		if got := parseResolvectlDNSServer(c.in); got != c.want {
			t.Errorf("%s: got %q, want %q", name, got, c.want)
		}
	}
}

func TestParseResolvConfNameserver(t *testing.T) {
	cases := map[string]struct{ in, want string }{
		"stub skipped": {"# managed\nnameserver 127.0.0.53\nnameserver 10.1.2.3\nsearch x\n", "10.1.2.3"},
		"stub only":    {"nameserver 127.0.0.53\noptions edns0\n", ""},
		"direct":       {"nameserver 169.254.169.253\n", "169.254.169.253"},
		"empty":        {"", ""},
	}
	for name, c := range cases {
		if got := parseResolvConfNameserver(c.in); got != c.want {
			t.Errorf("%s: got %q, want %q", name, got, c.want)
		}
	}
}
