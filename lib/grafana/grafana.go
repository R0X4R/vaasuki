package grafana

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

// Verify tests whether Grafana anonymous access or unauthenticated API is exposed.
func Verify(host string, port int, timeout time.Duration) (*model.Finding, error) {
	client := &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}

	schemes := []string{"http", "https"}
	for _, scheme := range schemes {
		// Check /api/org first for anonymous organization permissions
		url := fmt.Sprintf("%s://%s:%d/api/org", scheme, host, port)
		req, err := http.NewRequest("GET", url, nil)
		if err != nil {
			continue
		}
		req.Header.Set("User-Agent", "Mozilla/5.0 (Vaasuki-Recon)")

		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		resp.Body.Close()

		if resp.StatusCode == http.StatusOK {
			var data map[string]any
			if err := json.Unmarshal(body, &data); err == nil {
				role := "Viewer"
				if r, ok := data["role"].(string); ok {
					role = r
				}
				orgName := "Default"
				if n, ok := data["name"].(string); ok {
					orgName = n
				}

				return &model.Finding{
					Target:     host,
					Port:       port,
					Protocol:   scheme,
					Service:    "grafana",
					Title:      fmt.Sprintf("Grafana Anonymous Access Enabled (Org: %s, Role: %s)", orgName, role),
					Severity:   "high",
					Confidence: model.Confirmed,
					Auth: model.AuthResult{
						Attempted: true,
						Method:    "anonymous",
						Status:    "successful",
					},
					Evidence:  []string{fmt.Sprintf("HTTP 200 OK: %s", string(body))},
					Timestamp: time.Now().UTC(),
				}, nil
			}
		}

		// Fallback to /api/health
		healthURL := fmt.Sprintf("%s://%s:%d/api/health", scheme, host, port)
		reqHealth, err := http.NewRequest("GET", healthURL, nil)
		if err != nil {
			continue
		}
		reqHealth.Header.Set("User-Agent", "Mozilla/5.0 (Vaasuki-Recon)")
		respHealth, err := client.Do(reqHealth)
		if err != nil {
			continue
		}
		healthBody, _ := io.ReadAll(io.LimitReader(respHealth.Body, 2048))
		respHealth.Body.Close()

		if respHealth.StatusCode == http.StatusOK && strings.Contains(string(healthBody), "database") {
			return &model.Finding{
				Target:     host,
				Port:       port,
				Protocol:   scheme,
				Service:    "grafana",
				Title:      "Exposed Grafana Dashboard Health API",
				Severity:   "medium",
				Confidence: model.Confirmed,
				Auth: model.AuthResult{
					Attempted: true,
					Method:    "none",
					Status:    "successful",
				},
				Evidence:  []string{fmt.Sprintf("HTTP 200 OK: %s", string(healthBody))},
				Timestamp: time.Now().UTC(),
			}, nil
		}
	}

	return nil, nil
}
