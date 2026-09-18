package snmp

import (
	"bytes"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/R0X4R/vaasuki/v2/pkg/model"
)

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

	snmpPkt := []byte{
		0x30, 0x29, 0x02, 0x01, 0x00, 0x04, 0x06, 'p', 'u', 'b', 'l', 'i', 'c',
		0xa0, 0x1c, 0x02, 0x04, 0x01, 0x02, 0x03, 0x04, 0x02, 0x01, 0x00, 0x02,
		0x01, 0x00, 0x30, 0x0e, 0x30, 0x0c, 0x06, 0x08, 0x2b, 0x06, 0x01, 0x02,
		0x01, 0x01, 0x01, 0x00, 0x05, 0x00,
	}

	if _, err := conn.Write(snmpPkt); err != nil {
		return nil, err
	}

	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	if err != nil || n < 10 {
		return nil, nil
	}

	// Validate SNMP response: ASN.1 SEQUENCE (0x30), GetResponse PDU (0xa2), matching Request ID, and community 'public'
	reqID := []byte{0x01, 0x02, 0x03, 0x04}
	if buf[0] != 0x30 || !bytes.Contains(buf[:n], []byte{0xa2}) || !bytes.Contains(buf[:n], reqID) || !bytes.Contains(buf[:n], []byte("public")) {
		return nil, nil
	}

	respStr := string(buf[:n])
	return &model.Finding{
		Target:     host,
		Port:       port,
		Protocol:   "snmp",
		Service:    "snmp",
		Title:      "SNMP Service Accepts Default Community String 'public'",
		Severity:   "medium",
		Confidence: model.Confirmed,
		Auth: model.AuthResult{
			Attempted: true,
			Method:    "public",
			Status:    "successful",
		},
		Evidence:  []string{fmt.Sprintf("SNMP response length: %d bytes (contains: %s)", n, strings.ReplaceAll(respStr, "\n", " "))},
		Timestamp: time.Now().UTC(),
	}, nil
}
