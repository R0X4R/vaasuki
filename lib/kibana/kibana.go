package kibana

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
		url := fmt.Sprintf("%s://%s:%d/api/status", scheme, host, port)
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
		kbnHeader := resp.Header.Get("kbn-name")
		resp.Body.Close()

		if resp.StatusCode == http.StatusOK {
			bodyStr := string(body)
			isKibana := kbnHeader != "" ||
				resp.Header.Get("kbn-version") != "" ||
				strings.Contains(strings.ToLower(bodyStr), "kibana")

			if isKibana && strings.Contains(bodyStr, "status") {
				evidence := []string{"HTTP 200 OK on /api/status"}

				// Cross-check whether underlying Elasticsearch on port 9200 is also unauthenticated
				esURL := fmt.Sprintf("%s://%s:9200/", scheme, host)
				if esReq, err := http.NewRequest("GET", esURL, nil); err == nil {
					network.ApplyCustomHeaders(esReq)
					if esResp, err := client.Do(esReq); err == nil {
						esBody, _ := io.ReadAll(io.LimitReader(esResp.Body, 1024))
						esResp.Body.Close()
						if esResp.StatusCode == http.StatusOK && strings.Contains(string(esBody), "cluster_name") {
							evidence = append(evidence, "Underlying Elasticsearch instance (port 9200) is also unauthenticated")
						}
					}
				}

				return &model.Finding{
					Target:     host,
					Port:       port,
					Protocol:   scheme,
					Service:    "kibana",
					Title:      "Exposed Unauthenticated Kibana Dashboard",
					Severity:   "high",
					Confidence: model.Confirmed,
					Auth: model.AuthResult{
						Attempted: true,
						Method:    "none",
						Status:    "successful",
					},
					Evidence:  evidence,
					Timestamp: time.Now().UTC(),
				}, nil
			}
		}
	}
	return nil, nil
}
