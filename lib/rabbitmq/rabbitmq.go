package rabbitmq

import (
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/R0X4R/vaasuki/pkg/model"
)

// Verify tests whether RabbitMQ Management API is accessible with default credentials (guest:guest).
func Verify(host string, port int, timeout time.Duration) (*model.Finding, error) {
	client := &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}

	schemes := []string{"http", "https"}
	for _, scheme := range schemes {
		url := fmt.Sprintf("%s://%s:%d/api/whoami", scheme, host, port)
		req, err := http.NewRequest("GET", url, nil)
		if err != nil {
			continue
		}
		req.Header.Set("User-Agent", "Mozilla/5.0 (Vaasuki-Recon)")
		auth := base64.StdEncoding.EncodeToString([]byte("guest:guest"))
		req.Header.Set("Authorization", "Basic "+auth)

		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
		resp.Body.Close()

		if resp.StatusCode == http.StatusOK && strings.Contains(string(body), "administrator") {
			return &model.Finding{
				Target:     host,
				Port:       port,
				Protocol:   scheme,
				Service:    "rabbitmq",
				Title:      "RabbitMQ Default Administrative Credentials (guest:guest)",
				Severity:   "high",
				Confidence: model.Confirmed,
				Auth: model.AuthResult{
					Attempted: true,
					Method:    "basic",
					Status:    "successful",
				},
				Evidence:  []string{fmt.Sprintf("HTTP 200 OK: %s", strings.TrimSpace(string(body)))},
				Timestamp: time.Now().UTC(),
			}, nil
		}
	}

	return nil, nil
}
