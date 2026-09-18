package redis

import (
	"bufio"
	"fmt"
	"strings"
	"time"

	"github.com/R0X4R/vaasuki/v2/pkg/model"
	"github.com/R0X4R/vaasuki/v2/pkg/network"
)

// Verify tests whether a Redis instance accepts unauthenticated commands.
func Verify(host string, port int, timeout time.Duration) (*model.Finding, error) {
	conn, err := network.DialTimeout("tcp", fmt.Sprintf("%s:%d", host, port), timeout)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	_ = conn.SetDeadline(time.Now().Add(timeout))
	reader := bufio.NewReader(conn)
	writer := bufio.NewWriter(conn)

	if _, err := writer.WriteString("PING\r\n"); err != nil {
		return nil, err
	}
	_ = writer.Flush()

	resp, err := reader.ReadString('\n')
	if err != nil {
		return nil, err
	}

	cleanResp := strings.TrimSpace(resp)
	if cleanResp != "+PONG" {
		return nil, nil
	}

	return &model.Finding{
		Target:     host,
		Port:       port,
		Protocol:   "redis",
		Service:    "redis",
		Title:      "Unauthenticated Redis Database Access",
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
