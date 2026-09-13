package smtp

import (
	"bufio"
	"fmt"
	"strings"
	"time"

	"github.com/R0X4R/vaasuki/pkg/model"
	"github.com/R0X4R/vaasuki/pkg/network"
)

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

	banner, err := reader.ReadString('\n')
	if err != nil || !strings.HasPrefix(banner, "220") {
		return nil, fmt.Errorf("invalid smtp banner: %s", strings.TrimSpace(banner))
	}

	if _, err := writer.WriteString("HELO vaasuki.local\r\n"); err != nil {
		return nil, err
	}
	_ = writer.Flush()

	heloResp, err := reader.ReadString('\n')
	if err != nil || !strings.HasPrefix(heloResp, "250") {
		return nil, nil
	}

	if _, err := writer.WriteString("MAIL FROM:<recon@vaasuki.local>\r\n"); err != nil {
		return nil, err
	}
	_ = writer.Flush()

	mailResp, err := reader.ReadString('\n')
	if err != nil || !strings.HasPrefix(mailResp, "250") {
		return nil, nil
	}

	if _, err := writer.WriteString("RCPT TO:<victim@vaasuki.local>\r\n"); err != nil {
		return nil, err
	}
	_ = writer.Flush()

	rcptResp, err := reader.ReadString('\n')
	if err != nil {
		return nil, nil
	}

	if strings.HasPrefix(rcptResp, "250") {
		// Send RSET and QUIT gracefully
		_, _ = writer.WriteString("RSET\r\nQUIT\r\n")
		_ = writer.Flush()

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
			Evidence: []string{
				fmt.Sprintf("Banner: %s", strings.TrimSpace(banner)),
				fmt.Sprintf("RCPT TO: %s", strings.TrimSpace(rcptResp)),
			},
			Timestamp: time.Now().UTC(),
		}, nil
	}

	return nil, nil
}
