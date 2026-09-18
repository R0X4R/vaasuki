package zabbix

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"strings"
	"time"

	"github.com/R0X4R/vaasuki/pkg/model"
	"github.com/R0X4R/vaasuki/pkg/network"
)

// Verify tests whether an exposed Zabbix trapper port accepts unauthenticated metrics.
func Verify(host string, port int, timeout time.Duration) (*model.Finding, error) {
	conn, err := network.DialTimeout("tcp", fmt.Sprintf("%s:%d", host, port), timeout)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	_ = conn.SetDeadline(time.Now().Add(timeout))

	payload := []byte(`{"request":"sender data","data":[]}`)
	header := []byte("ZBXD\x01")
	lenBytes := make([]byte, 8)
	binary.LittleEndian.PutUint64(lenBytes, uint64(len(payload)))

	req := append(header, lenBytes...)
	req = append(req, payload...)

	if _, err := conn.Write(req); err != nil {
		return nil, err
	}

	buf := make([]byte, 256)
	n, err := conn.Read(buf)
	if err != nil || n < 13 {
		return nil, nil
	}

	if bytes.HasPrefix(buf[:n], []byte("ZBXD\x01")) {
		body := string(buf[13:n])
		if strings.Contains(body, "response") {
			return &model.Finding{
				Target:     host,
				Port:       port,
				Protocol:   "zabbix",
				Service:    "zabbix",
				Title:      "Unauthenticated Zabbix Server Trapper Port",
				Severity:   "medium",
				Confidence: model.Confirmed,
				Auth: model.AuthResult{
					Attempted: true,
					Method:    "none",
					Status:    "successful",
				},
				Evidence:  []string{fmt.Sprintf("Zabbix trapper response: %s", body)},
				Timestamp: time.Now().UTC(),
			}, nil
		}
	}

	return nil, nil
}
