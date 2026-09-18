package zabbix

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
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

	hdr := make([]byte, 13)
	if _, err := io.ReadFull(conn, hdr); err != nil {
		return nil, nil
	}

	if !bytes.HasPrefix(hdr, []byte("ZBXD\x01")) {
		return nil, nil
	}

	dataLen := binary.LittleEndian.Uint64(hdr[5:13])
	if dataLen == 0 || dataLen > 65536 {
		return nil, nil
	}

	bodyBuf := make([]byte, dataLen)
	if _, err := io.ReadFull(conn, bodyBuf); err != nil {
		return nil, nil
	}

	body := string(bodyBuf)
	if strings.Contains(body, `"response"`) && (strings.Contains(body, `"success"`) || strings.Contains(body, `"info"`)) {
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

	return nil, nil
}
