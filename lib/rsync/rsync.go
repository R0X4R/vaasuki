package rsync

import (
	"bufio"
	"fmt"
	"strings"
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

	reader := bufio.NewReader(conn)
	banner, err := reader.ReadString('\n')
	if err != nil || !strings.HasPrefix(banner, "@RSYNCD") {
		return nil, nil
	}

	if _, err := conn.Write([]byte("@RSYNCD: 31.0\n")); err != nil {
		return nil, err
	}

	if _, err := conn.Write([]byte("\n")); err != nil {
		return nil, err
	}

	var modules []string
	for i := 0; i < 20; i++ {
		line, err := reader.ReadString('\n')
		if err != nil || strings.HasPrefix(line, "@RSYNCD: EXIT") {
			break
		}
		trimmed := strings.TrimSpace(line)
		if trimmed != "" && !strings.HasPrefix(trimmed, "@RSYNCD") {
			modules = append(modules, trimmed)
		}
	}

	if len(modules) == 0 {
		return nil, nil
	}

	return &model.Finding{
		Target:     host,
		Port:       port,
		Protocol:   "rsync",
		Service:    "rsync",
		Version:    strings.TrimSpace(banner),
		Title:      fmt.Sprintf("Exposed rsync Daemon (%d Anonymous Modules Found)", len(modules)),
		Severity:   "high",
		Confidence: model.Confirmed,
		Auth: model.AuthResult{
			Attempted: true,
			Method:    "none",
			Status:    "successful",
		},
		Evidence:  []string{fmt.Sprintf("Banner: %s", strings.TrimSpace(banner)), fmt.Sprintf("Modules: %s", strings.Join(modules, ", "))},
		Timestamp: time.Now().UTC(),
	}, nil
}
