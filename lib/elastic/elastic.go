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
	"github.com/R0X4R/vaasuki/pkg/network"
)

// Verify tests whether an Elasticsearch instance allows unauthenticated access.
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
		url := fmt.Sprintf("%s://%s:%d/", scheme, host, port)
		req, err := http.NewRequest("GET", url, nil)
		if err != nil {
			continue
		}
		network.ApplyCustomHeaders(req)

		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 8192))
		resp.Body.Close()

		cType := strings.ToLower(resp.Header.Get("Content-Type"))
		if resp.StatusCode != http.StatusOK || !strings.Contains(cType, "application/json") {
			continue
		}

		var data map[string]any
		if err := json.Unmarshal(body, &data); err != nil {
			continue
		}

		clusterName, hasCluster := data["cluster_name"].(string)
		_, hasVersion := data["version"]
		tagline, _ := data["tagline"].(string)

		if !hasCluster && !hasVersion && !strings.Contains(tagline, "You Know, for Search") {
			continue
		}

		if clusterName == "" {
			clusterName = "unknown"
		}

		bodyStr := string(body)
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
			Evidence:  []string{fmt.Sprintf("HTTP 200 OK (application/json): %s", bodyStr[:min(len(bodyStr), 200)])},
			Timestamp: time.Now().UTC(),
		}, nil
	}

	return nil, nil
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
