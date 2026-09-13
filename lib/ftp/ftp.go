package ftp

import (
	"bufio"
	"fmt"
	"strings"
	"time"

	"github.com/R0X4R/vaasuki/pkg/model"
	"github.com/R0X4R/vaasuki/pkg/network"
)

// Verify performs active protocol handshake and anonymous authentication against an FTP service.
func Verify(host string, port int, timeout time.Duration) (*model.Finding, error) {
	conn, err := network.DialTimeout("tcp", fmt.Sprintf("%s:%d", host, port), timeout)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	_ = conn.SetDeadline(time.Now().Add(timeout))
	reader := bufio.NewReader(conn)
	writer := bufio.NewWriter(conn)

	banner, err := reader.ReadString('\n')
	if err != nil || !strings.HasPrefix(banner, "220") {
		return nil, fmt.Errorf("unexpected ftp banner: %s", strings.TrimSpace(banner))
	}

	if _, err := writer.WriteString("USER anonymous\r\n"); err != nil {
		return nil, err
	}
	_ = writer.Flush()

	userResp, err := reader.ReadString('\n')
	if err != nil {
		return nil, err
	}

	var authSuccess bool
	var evidence []string
	evidence = append(evidence, strings.TrimSpace(banner))

	if strings.HasPrefix(userResp, "230") {
		authSuccess = true
		evidence = append(evidence, strings.TrimSpace(userResp))
	} else if strings.HasPrefix(userResp, "331") {
		if _, err := writer.WriteString("PASS anonymous@\r\n"); err != nil {
			return nil, err
		}
		_ = writer.Flush()

		passResp, err := reader.ReadString('\n')
		if err != nil {
			return nil, err
		}
		evidence = append(evidence, strings.TrimSpace(passResp))
		if strings.HasPrefix(passResp, "230") {
			authSuccess = true
		}
	}

	if !authSuccess {
		return nil, nil
	}

	return &model.Finding{
		Target:     host,
		Port:       port,
		Protocol:   "ftp",
		Service:    "ftp",
		Title:      "FTP Anonymous Authentication Enabled",
		Severity:   "medium",
		Confidence: model.Confirmed,
		Auth: model.AuthResult{
			Attempted: true,
			Method:    "anonymous",
			Status:    "successful",
		},
		Evidence:  evidence,
		Timestamp: time.Now().UTC(),
	}, nil
}
