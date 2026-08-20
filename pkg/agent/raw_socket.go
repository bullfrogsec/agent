package agent

import (
	"fmt"
	"net"
	"sync"

	"golang.org/x/sys/unix"
)

// IPacketSender injects a fully-formed IPv4 packet, header included.
//
// An interface because the real implementation needs CAP_NET_RAW and a live
// network stack, and the packet construction it carries must be testable
// without either.
type IPacketSender interface {
	SendIPv4(dst net.IP, packet []byte) error
	Close() error
}

// rawSocketSender writes packets the agent builds itself onto the wire.
//
// The socket carries injectedPacketMark so the ruleset can tell the agent's
// own packets apart from the traffic it is judging; without that, a reset
// addressed to a blocked destination is a new connection as far as conntrack
// is concerned, and the agent's own policy would drop the packet that exists
// to report that policy's decision.
type rawSocketSender struct {
	mu sync.Mutex
	fd int
}

// NewRawSocketSender opens the injection socket. Requires CAP_NET_RAW.
func NewRawSocketSender() (*rawSocketSender, error) {
	// SOCK_CLOEXEC keeps this socket out of the processes the agent starts.
	// It carries the injection mark, so whoever holds it can send packets the
	// ruleset lets through. Go only closes descriptors on exec if they were
	// opened with this flag (see socket(2)), and syscall.Socket does not set
	// it, so open the socket through x/sys/unix and set it here.
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_RAW|unix.SOCK_CLOEXEC, unix.IPPROTO_RAW)
	if err != nil {
		return nil, fmt.Errorf("opening raw socket: %w", err)
	}
	// IPPROTO_RAW implies IP_HDRINCL, but say so explicitly: the agent builds
	// the IP header, and a kernel-built one would carry the agent's own source
	// address rather than the address the client tried to reach.
	if err := unix.SetsockoptInt(fd, unix.IPPROTO_IP, unix.IP_HDRINCL, 1); err != nil {
		unix.Close(fd)
		return nil, fmt.Errorf("setting IP_HDRINCL: %w", err)
	}
	if err := unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_MARK, int(injectedPacketMark)); err != nil {
		unix.Close(fd)
		return nil, fmt.Errorf("setting fwmark: %w", err)
	}
	return &rawSocketSender{fd: fd}, nil
}

func (s *rawSocketSender) SendIPv4(dst net.IP, packet []byte) error {
	v4 := dst.To4()
	if v4 == nil {
		return fmt.Errorf("not an IPv4 destination: %s", dst)
	}
	addr := &unix.SockaddrInet4{}
	copy(addr.Addr[:], v4)

	// One socket, and ProcessPacket may one day be called concurrently.
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.fd < 0 {
		return fmt.Errorf("sender is closed")
	}
	return unix.Sendto(s.fd, packet, 0, addr)
}

func (s *rawSocketSender) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.fd < 0 {
		return nil
	}
	fd := s.fd
	s.fd = -1
	return unix.Close(fd)
}
