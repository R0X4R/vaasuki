package tftp

import (
	"fmt"
	"net"
	"time"

	"github.com/R0X4R/vaasuki/pkg/model"
)

// Verify tests whether a TFTP service is accessible over UDP.
func Verify(host string, port int, timeout time.Duration) (*model.Finding, error) {
	addr, err := net.ResolveUDPAddr("udp", fmt.Sprintf("%s:%d", host, port))
	if err != nil {
		return nil, err
	}

	conn, err := net.DialUDP("udp", nil, addr)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	_ = conn.SetDeadline(time.Now().Add(timeout))

	// TFTP Read Request (RRQ) for test file
	rrq := []byte{
		0x00, 0x01,
		'v', 'e', 'r', 's', 'i', 'o', 'n', 0x00,
		'n', 'e', 't', 'a', 's', 'c', 'i', 'i', 0x00,
	}

	if _, err := conn.Write(rrq); err != nil {
		return nil, err
	}

	buf := make([]byte, 512)
	n, err := conn.Read(buf)
	if err != nil || n < 4 {
		return nil, nil
	}

	// Opcode 3 = DATA, Opcode 5 = ERROR (file not found / access violation) -> TFTP active
	opcode := (int(buf[0]) << 8) | int(buf[1])
	if opcode == 3 || opcode == 5 {
		return &model.Finding{
			Target:     host,
			Port:       port,
			Protocol:   "tftp",
			Service:    "tftp",
			Title:      "Exposed Unauthenticated TFTP Service",
			Severity:   "medium",
			Confidence: model.Confirmed,
			Auth: model.AuthResult{
				Attempted: true,
				Method:    "none",
				Status:    "successful",
			},
			Evidence:  []string{fmt.Sprintf("TFTP packet response opcode %d received", opcode)},
			Timestamp: time.Now().UTC(),
		}, nil
	}

	return nil, nil
}
