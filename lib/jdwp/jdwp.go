package jdwp

import (
	"bytes"
	"fmt"
	"time"

	"github.com/R0X4R/vaasuki/pkg/model"
	"github.com/R0X4R/vaasuki/pkg/network"
)

func Verify(host string, port int, timeout time.Duration) (*model.Finding, error) {
	conn, err := network.DialTimeout("tcp", fmt.Sprintf("%s:%d", host, port), timeout)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	_ = conn.SetDeadline(time.Now().Add(timeout))
	handshake := []byte("JDWP-Handshake")
	if _, err := conn.Write(handshake); err != nil {
		return nil, err
	}

	buf := make([]byte, 14)
	n, err := conn.Read(buf)
	if err != nil || n != 14 {
		return nil, nil
	}

	if bytes.Equal(buf, handshake) {
		return &model.Finding{
			Target:     host,
			Port:       port,
			Protocol:   "jdwp",
			Service:    "jdwp",
			Title:      "Exposed Java Debug Wire Protocol (JDWP) Without Authentication",
			Severity:   "critical",
			Confidence: model.Confirmed,
			Auth: model.AuthResult{
				Attempted: true,
				Method:    "none",
				Status:    "successful",
			},
			Evidence:  []string{"JDWP-Handshake verified"},
			Timestamp: time.Now().UTC(),
		}, nil
	}

	return nil, nil
}
