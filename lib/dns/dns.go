package dns

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"time"

	"github.com/R0X4R/vaasuki/pkg/model"
	"github.com/R0X4R/vaasuki/pkg/network"
)

// dnsChaosVersionQuery is a DNS query over TCP for version.bind TXT CH (CHAOS class).
var dnsChaosVersionQuery = []byte{
	// TCP length prefix: 30 bytes
	0x00, 0x1e,
	// Transaction ID
	0x13, 0x37,
	// Flags: Standard query (0x0100 with RD)
	0x01, 0x00,
	// Questions: 1, Answer RRs: 0, Authority RRs: 0, Additional RRs: 0
	0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	// Query: "\x07version\x04bind\x00"
	0x07, 'v', 'e', 'r', 's', 'i', 'o', 'n',
	0x04, 'b', 'i', 'n', 'd', 0x00,
	// Type: TXT (16 = 0x0010)
	0x00, 0x10,
	// Class: CH / Chaos (3 = 0x0003)
	0x00, 0x03,
}

// Verify tests whether a DNS server responds to CHAOS version.bind or recursion queries over TCP.
func Verify(host string, port int, timeout time.Duration) (*model.Finding, error) {
	conn, err := network.DialTimeout("tcp", fmt.Sprintf("%s:%d", host, port), timeout)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	_ = conn.SetDeadline(time.Now().Add(timeout))

	if _, err := conn.Write(dnsChaosVersionQuery); err != nil {
		return nil, err
	}

	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	if err != nil || n < 14 {
		return nil, err
	}

	// First 2 bytes are TCP length prefix
	tcpLen := binary.BigEndian.Uint16(buf[:2])
	if int(tcpLen) > n-2 {
		return nil, nil
	}

	// Transaction ID must match 0x1337
	if buf[2] == 0x13 && buf[3] == 0x37 {
		flags := binary.BigEndian.Uint16(buf[4:6])
		isResponse := (flags & 0x8000) != 0

		if isResponse {
			evidence := []string{fmt.Sprintf("DNS TCP CHAOS response received (%d bytes)", n)}
			if bytes.Contains(buf[:n], []byte("Vaasuki")) || bytes.Contains(buf[:n], []byte("CoreDNS")) {
				evidence = append(evidence, "CHAOS version banner leaked")
			}

			return &model.Finding{
				Target:     host,
				Port:       port,
				Protocol:   "dns",
				Service:    "dns",
				Title:      "Exposed DNS Nameserver Responding to CHAOS Version Queries",
				Severity:   "medium",
				Confidence: model.Confirmed,
				Auth: model.AuthResult{
					Attempted: false,
					Method:    "none",
					Status:    "unauthenticated",
				},
				Evidence:  evidence,
				Timestamp: time.Now().UTC(),
			}, nil
		}
	}

	return nil, nil
}
