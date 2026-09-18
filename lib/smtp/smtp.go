package smtp

import (
	"bufio"
	"fmt"
	"strings"
	"time"

	"github.com/R0X4R/vaasuki/v2/pkg/model"
	"github.com/R0X4R/vaasuki/v2/pkg/network"
)

// readSMTPReply reads an RFC 5321 compliant response, correctly consuming multi-line replies.
func readSMTPReply(reader *bufio.Reader) (string, []string, error) {
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
			// RFC 5321: Continuation lines have '-' as 4th char (e.g. "250-").
			// Terminating line has a space ' ' as 4th char (e.g. "250 ") or ends right after 3 digits.
			if len(trimmed) == 3 || (len(trimmed) > 3 && trimmed[3] == ' ' && c == code) {
				return code, lines, nil
			}
		}
	}
}

// Verify tests whether an SMTP server allows unauthenticated relaying or anonymous message submission.
func Verify(host string, port int, timeout time.Duration) (*model.Finding, error) {
	conn, err := network.DialTimeout("tcp", fmt.Sprintf("%s:%d", host, port), timeout)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	_ = conn.SetDeadline(time.Now().Add(timeout))
	reader := bufio.NewReader(conn)
	writer := bufio.NewWriter(conn)

	bannerCode, bannerLines, err := readSMTPReply(reader)
	if err != nil || bannerCode != "220" {
		bannerSummary := bannerCode
		if len(bannerLines) > 0 {
			bannerSummary = bannerLines[0]
		}
		return nil, fmt.Errorf("invalid smtp banner: %s", bannerSummary)
	}

	if _, err := writer.WriteString("HELO vaasuki.local\r\n"); err != nil {
		return nil, err
	}
	_ = writer.Flush()

	heloCode, _, err := readSMTPReply(reader)
	if err != nil || heloCode != "250" {
		return nil, nil
	}

	if _, err := writer.WriteString("MAIL FROM:<recon@vaasuki.local>\r\n"); err != nil {
		return nil, err
	}
	_ = writer.Flush()

	mailCode, _, err := readSMTPReply(reader)
	if err != nil || mailCode != "250" {
		return nil, nil
	}

	if _, err := writer.WriteString("RCPT TO:<victim@vaasuki.local>\r\n"); err != nil {
		return nil, err
	}
	_ = writer.Flush()

	rcptCode, rcptLines, err := readSMTPReply(reader)
	if err != nil {
		return nil, nil
	}

	if rcptCode == "250" {
		// Send RSET and QUIT gracefully
		_, _ = writer.WriteString("RSET\r\nQUIT\r\n")
		_ = writer.Flush()

		evidence := []string{}
		if len(bannerLines) > 0 {
			evidence = append(evidence, fmt.Sprintf("Banner: %s", bannerLines[0]))
		}
		if len(rcptLines) > 0 {
			evidence = append(evidence, fmt.Sprintf("RCPT TO: %s", rcptLines[len(rcptLines)-1]))
		}

		return &model.Finding{
			Target:     host,
			Port:       port,
			Protocol:   "smtp",
			Service:    "smtp",
			Title:      "SMTP Insecure Open Mail Relay Submission Allowed",
			Severity:   "high",
			Confidence: model.Confirmed,
			Auth: model.AuthResult{
				Attempted: true,
				Method:    "none",
				Status:    "successful",
			},
			Evidence:  evidence,
			Timestamp: time.Now().UTC(),
		}, nil
	}

	return nil, nil
}
