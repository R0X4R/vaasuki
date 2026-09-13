package dockerapi

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/R0X4R/vaasuki/pkg/model"
)

// Verify tests whether an exposed unauthenticated Docker Remote API is accessible.
func Verify(host string, port int, timeout time.Duration) (*model.Finding, error) {
	client := &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}

	schemes := []string{"http", "https"}
	for _, scheme := range schemes {
		url := fmt.Sprintf("%s://%s:%d/version", scheme, host, port)
		req, err := http.NewRequest("GET", url, nil)
		if err != nil {
			continue
		}
		req.Header.Set("User-Agent", "Mozilla/5.0 (Vaasuki-Recon)")

		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 8192))
		resp.Body.Close()

		if resp.StatusCode == http.StatusOK {
			bodyStr := string(body)
			if strings.Contains(bodyStr, "ApiVersion") || strings.Contains(bodyStr, "Docker") || strings.Contains(bodyStr, "Components") {
				var data map[string]any
				_ = json.Unmarshal(body, &data)

				apiVersion := "unknown"
				if av, ok := data["ApiVersion"].(string); ok {
					apiVersion = av
				}

				return &model.Finding{
					Target:     host,
					Port:       port,
					Protocol:   scheme,
					Service:    "docker",
					Title:      fmt.Sprintf("Exposed Docker Daemon API Without Authentication (API: %s)", apiVersion),
					Severity:   "critical",
					Confidence: model.Confirmed,
					Auth: model.AuthResult{
						Attempted: true,
						Method:    "none",
						Status:    "successful",
					},
					Evidence:  []string{fmt.Sprintf("HTTP 200 OK: %s", bodyStr[:min(len(bodyStr), 200)])},
					Timestamp: time.Now().UTC(),
				}, nil
			}
		}
	}

	return nil, nil
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
