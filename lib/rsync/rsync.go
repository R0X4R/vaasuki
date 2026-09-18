package rsync

import (
	"bufio"
	"fmt"
	"strings"
	"time"

	"github.com/R0X4R/vaasuki/v2/pkg/model"
	"github.com/R0X4R/vaasuki/v2/pkg/network"
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

	anonymousAccess := false
	firstMod := strings.Fields(modules[0])[0]
	if conn2, err := network.DialTimeout("tcp", fmt.Sprintf("%s:%d", host, port), timeout); err == nil {
		_ = conn2.SetDeadline(time.Now().Add(timeout))
		r2 := bufio.NewReader(conn2)
		if b, err := r2.ReadString('\n'); err == nil && strings.HasPrefix(b, "@RSYNCD") {
			_, _ = conn2.Write([]byte("@RSYNCD: 31.0\n"))
			_, _ = conn2.Write([]byte(firstMod + "\n"))
			if resp, err := r2.ReadString('\n'); err == nil {
				if strings.HasPrefix(resp, "@RSYNCD: OK") {
					anonymousAccess = true
				}
			}
		}
		conn2.Close()
	}

	title := fmt.Sprintf("Exposed rsync Daemon (%d Modules Listed, Authentication Required)", len(modules))
	severity := "medium"
	status := "failed"
	if anonymousAccess {
		title = fmt.Sprintf("Unauthenticated rsync Module Access (%d Modules Available)", len(modules))
		severity = "high"
		status = "successful"
	}

	return &model.Finding{
		Target:     host,
		Port:       port,
		Protocol:   "rsync",
		Service:    "rsync",
		Version:    strings.TrimSpace(banner),
		Title:      title,
		Severity:   severity,
		Confidence: model.Confirmed,
		Auth: model.AuthResult{
			Attempted: true,
			Method:    "none",
			Status:    status,
		},
		Evidence:  []string{fmt.Sprintf("Banner: %s", strings.TrimSpace(banner)), fmt.Sprintf("Modules: %s", strings.Join(modules, ", "))},
		Timestamp: time.Now().UTC(),
	}, nil
}
