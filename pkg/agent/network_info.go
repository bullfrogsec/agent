package agent

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
)

type INetInfoProvider interface {
	GetDNSServer() (string, error)
	FlushDNSCache() error
}

type LinuxNetInfoProvider struct {
}

// resolvConfPaths are read, in order, when resolvectl reports no DNS server.
// /run/systemd/resolve/resolv.conf lists systemd-resolved's upstream servers;
// /etc/resolv.conf covers hosts where resolv.conf points at a resolver directly.
var resolvConfPaths = []string{"/run/systemd/resolve/resolv.conf", "/etc/resolv.conf"}

// GetDNSServer returns the upstream DNS server the host resolves through, or ""
// when none can be determined. It never fails on empty command output: some
// runners (e.g. Depot) report no per-link DNS server for the default interface.
func (l *LinuxNetInfoProvider) GetDNSServer() (string, error) {
	networkInterface := ""
	out, err := exec.Command("sh", "-c", "ip route | grep default | awk '{print $5}'").Output()
	if err != nil {
		fmt.Printf("Error getting default network interface: %s\n", err)
	} else {
		networkInterface = firstLine(string(out))
	}
	fmt.Printf("Network interface: %s\n", networkInterface)

	if networkInterface != "" {
		if out, err := exec.Command("resolvectl", "status", networkInterface).CombinedOutput(); err == nil {
			if dnsServer := parseResolvectlDNSServer(string(out)); dnsServer != "" {
				fmt.Printf("DNS server: %s\n", dnsServer)
				return dnsServer, nil
			}
		}
	}

	if out, err := exec.Command("resolvectl", "status").CombinedOutput(); err == nil {
		if dnsServer := parseResolvectlDNSServer(string(out)); dnsServer != "" {
			fmt.Printf("DNS server (global): %s\n", dnsServer)
			return dnsServer, nil
		}
	}

	for _, path := range resolvConfPaths {
		content, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		if dnsServer := parseResolvConfNameserver(string(content)); dnsServer != "" {
			fmt.Printf("DNS server (%s): %s\n", path, dnsServer)
			return dnsServer, nil
		}
	}

	fmt.Println("No upstream DNS server found; allowing only the default DNS servers")
	return "", nil
}

// parseResolvectlDNSServer extracts the first DNS server from `resolvectl status`
// output, preferring "Current DNS Server" over the "DNS Servers" list.
func parseResolvectlDNSServer(output string) string {
	for _, key := range []string{"Current DNS Server:", "DNS Servers:"} {
		for _, line := range strings.Split(output, "\n") {
			line = strings.TrimSpace(line)
			if !strings.HasPrefix(line, key) {
				continue
			}
			if fields := strings.Fields(strings.TrimPrefix(line, key)); len(fields) > 0 {
				return fields[0]
			}
		}
	}
	return ""
}

// parseResolvConfNameserver returns the first nameserver in resolv.conf content
// that is not already one of the default DNS servers (the systemd-resolved stub).
func parseResolvConfNameserver(content string) string {
	for _, line := range strings.Split(content, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 || fields[0] != "nameserver" {
			continue
		}
		if !isDefaultDNSServer(fields[1]) {
			return fields[1]
		}
	}
	return ""
}

func isDefaultDNSServer(server string) bool {
	for _, d := range defaultDNSServers {
		if d == server {
			return true
		}
	}
	return false
}

func firstLine(s string) string {
	return strings.TrimSpace(strings.SplitN(s, "\n", 2)[0])
}

func (l *LinuxNetInfoProvider) FlushDNSCache() error {
	_, err := exec.Command("sh", "-c", "resolvectl flush-caches").Output()
	if err != nil {
		fmt.Println("Error flushing DNS cache: ", err)
		return err
	}
	return nil
}
