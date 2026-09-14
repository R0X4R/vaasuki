package rabbitmq

import (
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/R0X4R/vaasuki/pkg/model"
	"github.com/R0X4R/vaasuki/pkg/network"
)

// Verify tests whether RabbitMQ Management API is accessible with default credentials (guest:guest).
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
		url := fmt.Sprintf("%s://%s:%d/api/whoami", scheme, host, port)
		req, err := http.NewRequest("GET", url, nil)
		if err != nil {
			continue
		}
		network.ApplyCustomHeaders(req)
		auth := base64.StdEncoding.EncodeToString([]byte("guest:guest"))
		req.Header.Set("Authorization", "Basic "+auth)

		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
		resp.Body.Close()

		cType := strings.ToLower(resp.Header.Get("Content-Type"))
		if resp.StatusCode != http.StatusOK || !strings.Contains(cType, "application/json") {
			continue
		}

		var whoami struct {
			Name string `json:"name"`
			Tags any    `json:"tags"`
		}
		if err := json.Unmarshal(body, &whoami); err != nil {
			continue
		}
		if whoami.Name != "guest" {
			continue
		}

		hasAdminTag := false
		switch tags := whoami.Tags.(type) {
		case []any:
			for _, t := range tags {
				if str, ok := t.(string); ok && str == "administrator" {
					hasAdminTag = true
					break
				}
			}
		case string:
			for _, str := range strings.Split(tags, ",") {
				if strings.TrimSpace(str) == "administrator" {
					hasAdminTag = true
					break
				}
			}
		}

		if hasAdminTag {
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
				Evidence:  []string{fmt.Sprintf("HTTP 200 OK (application/json): %s", strings.TrimSpace(string(body)))},
				Timestamp: time.Now().UTC(),
			}, nil
		}
	}

	return nil, nil
}

