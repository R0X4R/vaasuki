package prometheus

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

// Verify tests whether an unauthenticated Prometheus metrics server is exposed.
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
		url := fmt.Sprintf("%s://%s:%d/-/healthy", scheme, host, port)
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

		bodyStr := strings.TrimSpace(string(body))
		isHealthy := strings.Contains(bodyStr, "Prometheus Server is Healthy.") ||
			strings.Contains(bodyStr, "Prometheus is Healthy.") ||
			strings.HasPrefix(bodyStr, "Prometheus Server is Healthy")

		if resp.StatusCode == http.StatusOK && isHealthy {
			return &model.Finding{
				Target:     host,
				Port:       port,
				Protocol:   scheme,
				Service:    "prometheus",
				Title:      "Unauthenticated Prometheus Metrics API Exposed",
				Severity:   "medium",
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

	return nil, nil
}
