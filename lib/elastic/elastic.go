package elastic

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

// Verify tests whether an Elasticsearch instance allows unauthenticated access.
func Verify(host string, port int, timeout time.Duration) (*model.Finding, error) {
	client := &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}

	schemes := []string{"http", "https"}
	for _, scheme := range schemes {
		url := fmt.Sprintf("%s://%s:%d/", scheme, host, port)
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
			if strings.Contains(bodyStr, "cluster_name") || strings.Contains(bodyStr, "tagline") {
				var data map[string]any
				_ = json.Unmarshal(body, &data)

				clusterName := "unknown"
				if cn, ok := data["cluster_name"].(string); ok {
					clusterName = cn
				}

				return &model.Finding{
					Target:     host,
					Port:       port,
					Protocol:   scheme,
					Service:    "elasticsearch",
					Title:      fmt.Sprintf("Unauthenticated Elasticsearch Cluster Access (Cluster: %s)", clusterName),
					Severity:   "high",
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
