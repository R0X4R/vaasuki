package memcached

import (
	"bufio"
	"fmt"
	"strings"
	"time"

	"github.com/R0X4R/vaasuki/v2/pkg/model"
	"github.com/R0X4R/vaasuki/v2/pkg/network"
)

// Verify tests whether a Memcached instance allows unauthenticated commands and returns server info.
func Verify(host string, port int, timeout time.Duration) (*model.Finding, error) {
	conn, err := network.DialTimeout("tcp", fmt.Sprintf("%s:%d", host, port), timeout)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	_ = conn.SetDeadline(time.Now().Add(timeout))
	writer := bufio.NewWriter(conn)
	reader := bufio.NewReader(conn)

	if _, err := writer.WriteString("version\r\n"); err != nil {
		return nil, err
	}
	_ = writer.Flush()

	resp, err := reader.ReadString('\n')
	if err != nil {
		return nil, err
	}

	cleanResp := strings.TrimSpace(resp)
	if !strings.HasPrefix(cleanResp, "VERSION") {
		return nil, nil
	}

	// Send stats to verify operational access
	if _, err := writer.WriteString("stats\r\n"); err == nil {
		_ = writer.Flush()
	}

	return &model.Finding{
		Target:     host,
		Port:       port,
		Protocol:   "memcached",
		Service:    "memcached",
		Title:      "Unauthenticated Memcached Server Access",
		Severity:   "high",
		Confidence: model.Confirmed,
		Auth: model.AuthResult{
			Attempted: true,
			Method:    "none",
			Status:    "successful",
		},
		Evidence:  []string{cleanResp},
		Timestamp: time.Now().UTC(),
	}, nil
}
