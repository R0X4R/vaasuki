package consul

import (
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/R0X4R/vaasuki/pkg/model"
	"github.com/R0X4R/vaasuki/pkg/network"
)

// Verify tests whether an exposed unauthenticated Consul agent API is accessible.
func Verify(host string, port int, timeout time.Duration) (*model.Finding, error) {
	client := &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}

	schemes := []string{"http", "https"}
	for _, scheme := range schemes {
		url := fmt.Sprintf("%s://%s:%d/v1/status/leader", scheme, host, port)
		req, err := http.NewRequest("GET", url, nil)
		if err != nil {
			continue
		}
		network.ApplyCustomHeaders(req)

		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
		resp.Body.Close()

		if resp.StatusCode == http.StatusOK {
			bodyStr := strings.TrimSpace(string(body))
			// Consul /v1/status/leader returns e.g. "127.0.0.1:8300"
			if strings.HasPrefix(bodyStr, "\"") && strings.HasSuffix(bodyStr, "\"") && strings.Contains(bodyStr, ":") && !strings.Contains(bodyStr, "MongoDB") {
				return &model.Finding{
					Target:     host,
					Port:       port,
					Protocol:   scheme,
					Service:    "consul",
					Title:      fmt.Sprintf("Unauthenticated HashiCorp Consul Agent API Access (Leader: %s)", bodyStr),
					Severity:   "high",
					Confidence: model.Confirmed,
					Auth: model.AuthResult{
						Attempted: true,
						Method:    "none",
						Status:    "successful",
					},
					Evidence:  []string{fmt.Sprintf("HTTP 200 OK: %s", bodyStr)},
					Timestamp: time.Now().UTC(),
				}, nil
			}
		}
	}

	return nil, nil
}
