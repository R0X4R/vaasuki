package telnet

import (
	"bytes"
	"fmt"
	"strings"
	"time"

	"github.com/R0X4R/vaasuki/v2/pkg/model"
	"github.com/R0X4R/vaasuki/v2/pkg/network"
)

// Verify tests whether a Telnet service is active and vulnerable to default credentials (root:toor or testuser:testpass).
func Verify(host string, port int, timeout time.Duration) (*model.Finding, error) {
	conn, err := network.DialTimeout("tcp", fmt.Sprintf("%s:%d", host, port), timeout)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	_ = conn.SetDeadline(time.Now().Add(timeout))

	buf := make([]byte, 1024)
	n, _ := conn.Read(buf)

	isTelnet := bytes.Contains(buf[:n], []byte{0xff, 0xfd}) ||
		bytes.Contains(buf[:n], []byte{0xff, 0xfb}) ||
		strings.Contains(strings.ToLower(string(buf[:n])), "login")

	// Try default credentials (root:toor)
	_, _ = conn.Write([]byte("root\r\n"))
	time.Sleep(200 * time.Millisecond)
	_, _ = conn.Write([]byte("toor\r\n"))
	time.Sleep(300 * time.Millisecond)

	readBuf := make([]byte, 2048)
	rn, _ := conn.Read(readBuf)
	resp := string(readBuf[:rn])

	lowerResp := strings.ToLower(resp)
	loginFailed := strings.Contains(lowerResp, "login incorrect") ||
		strings.Contains(lowerResp, "login failed") ||
		strings.Contains(lowerResp, "authentication failure") ||
		strings.Contains(lowerResp, "invalid password") ||
		strings.Contains(lowerResp, "login:") ||
		strings.Contains(lowerResp, "password:")

	// Authentic root prompt indicators (e.g. "root@", "# ", "~#", "/#")
	hasRootShell := !loginFailed && (strings.Contains(resp, "root@") ||
		strings.Contains(resp, "# ") ||
		strings.HasSuffix(strings.TrimSpace(resp), "#") ||
		strings.Contains(resp, "~#") ||
		strings.Contains(resp, "/#"))

	if hasRootShell {
		return &model.Finding{
			Target:     host,
			Port:       port,
			Protocol:   "telnet",
			Service:    "telnet",
			Title:      "Telnet Cleartext Service with Default Root Credentials (root:toor)",
			Severity:   "critical",
			Confidence: model.Confirmed,
			Auth: model.AuthResult{
				Attempted: true,
				Method:    "password",
				Status:    "successful",
			},
			Evidence:  []string{"Telnet root shell prompt confirmed"},
			Timestamp: time.Now().UTC(),
		}, nil
	}

	if isTelnet {
		return &model.Finding{
			Target:     host,
			Port:       port,
			Protocol:   "telnet",
			Service:    "telnet",
			Title:      "Exposed Insecure Telnet Cleartext Protocol Service",
			Severity:   "medium",
			Confidence: model.Confirmed,
			Auth: model.AuthResult{
				Attempted: false,
				Method:    "none",
				Status:    "unauthenticated",
			},
			Evidence:  []string{fmt.Sprintf("Telnet IAC negotiation confirmed (%d bytes)", n)},
			Timestamp: time.Now().UTC(),
		}, nil
	}

	return nil, nil
}
