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
	"github.com/R0X4R/vaasuki/pkg/network"
)

// Verify tests whether Grafana anonymous access or unauthenticated API is exposed.
func Verify(host string, port int, timeout time.Duration) (*model.Finding, error) {
	client := &http.Client{
		Timeout: timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
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
		network.ApplyCustomHeaders(req)

		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		resp.Body.Close()

		cType := strings.ToLower(resp.Header.Get("Content-Type"))
		if resp.StatusCode == http.StatusOK && strings.Contains(cType, "application/json") {
			var data map[string]any
			if err := json.Unmarshal(body, &data); err == nil {
				_, hasID := data["id"]
				_, hasName := data["name"]
				if hasID || hasName {
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
						Evidence:  []string{fmt.Sprintf("HTTP 200 OK (application/json): %s", string(body))},
						Timestamp: time.Now().UTC(),
					}, nil
				}
			}
		}

		// Fallback to /api/health
		healthURL := fmt.Sprintf("%s://%s:%d/api/health", scheme, host, port)
		reqHealth, err := http.NewRequest("GET", healthURL, nil)
		if err != nil {
			continue
		}
		network.ApplyCustomHeaders(reqHealth)
		respHealth, err := client.Do(reqHealth)
		if err != nil {
			continue
		}
		healthBody, _ := io.ReadAll(io.LimitReader(respHealth.Body, 2048))
		respHealth.Body.Close()

		healthCType := strings.ToLower(respHealth.Header.Get("Content-Type"))
		if respHealth.StatusCode == http.StatusOK && strings.Contains(healthCType, "application/json") {
			var healthData map[string]any
			if err := json.Unmarshal(healthBody, &healthData); err == nil {
				if db, ok := healthData["database"].(string); ok && (db == "ok" || strings.EqualFold(db, "ok")) {
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
						Evidence:  []string{fmt.Sprintf("HTTP 200 OK (application/json): %s", string(healthBody))},
						Timestamp: time.Now().UTC(),
					}, nil
				}
			}
		}
	}

	return nil, nil
}
