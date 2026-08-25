// dnspipeline sends two DNS queries pipelined into a single TCP segment: one
// for an allowed domain, one for a blocked domain.
//
// DNS over TCP frames each message with a 2-byte length prefix, and nothing
// stops a client from putting several messages in one segment. An agent that
// only inspects the first message would let the second one through, which is
// an exfiltration channel (GHSA-236v-v2rq-6pq2).
//
// It exits non-zero if the blocked domain was answered.
package main

import (
	"encoding/binary"
	"flag"
	"fmt"
	"io"
	"math/rand"
	"net"
	"os"
	"strings"
	"time"
)

func main() {
	server := flag.String("server", "", "DNS server, host:port")
	allowed := flag.String("allowed", "", "domain the policy allows")
	blocked := flag.String("blocked", "", "domain the policy blocks")
	timeout := flag.Duration("timeout", 5*time.Second, "how long to wait for responses")
	flag.Parse()

	if *server == "" || *allowed == "" || *blocked == "" {
		fatal("-server, -allowed and -blocked are all required")
	}

	idAllowed := uint16(rand.Intn(0xffff))
	idBlocked := idAllowed ^ 0x5a5a

	payload := append(
		frame(query(idAllowed, *allowed)),
		frame(query(idBlocked, *blocked))...,
	)

	conn, err := net.DialTimeout("tcp", *server, *timeout)
	if err != nil {
		// A blocked connection is a pass: nothing was exfiltrated.
		fmt.Printf("could not connect to %s: %v\n", *server, err)
		return
	}
	defer conn.Close()

	if _, err := conn.Write(payload); err != nil {
		fmt.Printf("could not send the pipelined queries: %v\n", err)
		return
	}

	_ = conn.SetReadDeadline(time.Now().Add(*timeout))
	answered := map[uint16]bool{}
	for {
		var length uint16
		if err := binary.Read(conn, binary.BigEndian, &length); err != nil {
			if err != io.EOF && !os.IsTimeout(err) {
				fmt.Printf("read: %v\n", err)
			}
			break
		}
		msg := make([]byte, length)
		if _, err := io.ReadFull(conn, msg); err != nil {
			break
		}
		if len(msg) >= 2 {
			answered[binary.BigEndian.Uint16(msg[:2])] = true
		}
	}

	fmt.Printf("%s answered: %t\n", *allowed, answered[idAllowed])
	fmt.Printf("%s answered: %t\n", *blocked, answered[idBlocked])

	if answered[idBlocked] {
		fmt.Printf("EXFILTRATION: the query for %s reached the DNS server\n", *blocked)
		os.Exit(1)
	}
}

// query builds a minimal A-record query.
func query(id uint16, domain string) []byte {
	msg := make([]byte, 0, len(domain)+32)
	msg = binary.BigEndian.AppendUint16(msg, id)
	msg = binary.BigEndian.AppendUint16(msg, 0x0100) // recursion desired
	msg = binary.BigEndian.AppendUint16(msg, 1)      // QDCOUNT
	msg = binary.BigEndian.AppendUint16(msg, 0)      // ANCOUNT
	msg = binary.BigEndian.AppendUint16(msg, 0)      // NSCOUNT
	msg = binary.BigEndian.AppendUint16(msg, 0)      // ARCOUNT
	for _, label := range strings.Split(strings.TrimSuffix(domain, "."), ".") {
		msg = append(msg, byte(len(label)))
		msg = append(msg, label...)
	}
	msg = append(msg, 0)
	msg = binary.BigEndian.AppendUint16(msg, 1) // A
	msg = binary.BigEndian.AppendUint16(msg, 1) // IN
	return msg
}

// frame prefixes a message with its length, as DNS over TCP requires.
func frame(msg []byte) []byte {
	return append(binary.BigEndian.AppendUint16(nil, uint16(len(msg))), msg...)
}

func fatal(f string, a ...any) {
	fmt.Fprintf(os.Stderr, "dnspipeline: "+f+"\n", a...)
	os.Exit(2)
}
