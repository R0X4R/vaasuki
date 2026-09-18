package rmi

import (
	"fmt"
	"time"

	"github.com/R0X4R/vaasuki/pkg/model"
	"github.com/R0X4R/vaasuki/pkg/network"
)

// Verify tests whether an unauthenticated Java RMI / JMX registry port is exposed.
func Verify(host string, port int, timeout time.Duration) (*model.Finding, error) {
	conn, err := network.DialTimeout("tcp", fmt.Sprintf("%s:%d", host, port), timeout)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	_ = conn.SetDeadline(time.Now().Add(timeout))

	// JRMI handshake: 'JRMI', version 2, StreamProtocol (0x4b)
	jrmiHandshake := []byte{0x4a, 0x52, 0x4d, 0x49, 0x00, 0x02, 0x4b}
	if _, err := conn.Write(jrmiHandshake); err != nil {
		return nil, err
	}

	buf := make([]byte, 32)
	n, err := conn.Read(buf)
	if err != nil || n < 1 {
		return nil, nil
	}

	// 0x4e = ProtocolAck from RMI server
	if buf[0] == 0x4e {
		return &model.Finding{
			Target:     host,
			Port:       port,
			Protocol:   "rmi",
			Service:    "rmi",
			Title:      "Exposed Java RMI / JMX Registry Without Authentication",
			Severity:   "critical",
			Confidence: model.Confirmed,
			Auth: model.AuthResult{
				Attempted: true,
				Method:    "none",
				Status:    "successful",
			},
			Evidence:  []string{"JRMI ProtocolAck (0x4E) handshake accepted"},
			Timestamp: time.Now().UTC(),
		}, nil
	}

	return nil, nil
}
