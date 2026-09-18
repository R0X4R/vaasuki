package ftp

import (
	"bufio"
	"fmt"
	"strings"
	"time"

	"github.com/R0X4R/vaasuki/v2/pkg/model"
	"github.com/R0X4R/vaasuki/v2/pkg/network"
)

// readFTPReply reads an RFC 959 compliant response, correctly consuming multi-line replies.
func readFTPReply(reader *bufio.Reader) (string, []string, error) {
	var lines []string
	var code string

	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			return code, lines, err
		}
		trimmed := strings.TrimRight(line, "\r\n")
		lines = append(lines, trimmed)

		if len(trimmed) >= 3 {
			c := trimmed[:3]
			if code == "" {
				code = c
			}
			// RFC 959: Continuation lines have '-' as 4th char (e.g. "220-").
			// Terminating line has a space ' ' as 4th char (e.g. "220 ") or ends right after 3 digits.
			if len(trimmed) == 3 || (len(trimmed) > 3 && trimmed[3] == ' ' && c == code) {
				return code, lines, nil
			}
		}
	}
}

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

	bannerCode, bannerLines, err := readFTPReply(reader)
	if err != nil || bannerCode != "220" {
		bannerSummary := bannerCode
		if len(bannerLines) > 0 {
			bannerSummary = bannerLines[0]
		}
		return nil, fmt.Errorf("unexpected ftp banner: %s", bannerSummary)
	}

	if _, err := writer.WriteString("USER anonymous\r\n"); err != nil {
		return nil, err
	}
	_ = writer.Flush()

	userCode, userLines, err := readFTPReply(reader)
	if err != nil {
		return nil, err
	}

	var authSuccess bool
	var evidence []string
	if len(bannerLines) > 0 {
		evidence = append(evidence, bannerLines[0])
	}

	if userCode == "230" {
		authSuccess = true
		if len(userLines) > 0 {
			evidence = append(evidence, userLines[len(userLines)-1])
		}
	} else if userCode == "331" {
		if _, err := writer.WriteString("PASS anonymous@\r\n"); err != nil {
			return nil, err
		}
		_ = writer.Flush()

		passCode, passLines, err := readFTPReply(reader)
		if err != nil {
			return nil, err
		}
		if len(passLines) > 0 {
			evidence = append(evidence, passLines[len(passLines)-1])
		}
		if passCode == "230" {
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
