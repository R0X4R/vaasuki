package influxdb

import (
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/R0X4R/vaasuki/v2/pkg/model"
	"github.com/R0X4R/vaasuki/v2/pkg/network"
)

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
		url := fmt.Sprintf("%s://%s:%d/query?q=SHOW+DATABASES", scheme, host, port)
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

		isInflux := resp.Header.Get("X-Influxdb-Version") != "" ||
			resp.Header.Get("X-Influxdb-Build") != "" ||
			strings.Contains(string(body), "statement_id") ||
			strings.Contains(string(body), "databases")

		if resp.StatusCode == http.StatusOK && isInflux && strings.Contains(string(body), "results") {
			return &model.Finding{
				Target:     host,
				Port:       port,
				Protocol:   scheme,
				Service:    "influxdb",
				Title:      "Unauthenticated InfluxDB Query Access",
				Severity:   "high",
				Confidence: model.Confirmed,
				Auth: model.AuthResult{
					Attempted: true,
					Method:    "none",
					Status:    "successful",
				},
				Evidence:  []string{"SHOW DATABASES executed with 200 OK on InfluxDB"},
				Timestamp: time.Now().UTC(),
			}, nil
		}
	}
	return nil, nil
}
