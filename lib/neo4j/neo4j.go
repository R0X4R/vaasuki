package neo4j

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
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		resp.Body.Close()

		if resp.StatusCode == http.StatusOK {
			bodyStr := string(body)
			if strings.Contains(bodyStr, "neo4j_version") || strings.Contains(bodyStr, "bolt_routing") {
				// If authDisabled is explicitly true in root JSON
				if strings.Contains(bodyStr, `"authDisabled": true`) || strings.Contains(bodyStr, `"authDisabled":true`) {
					return &model.Finding{
						Target:     host,
						Port:       port,
						Protocol:   scheme,
						Service:    "neo4j",
						Title:      "Unauthenticated Neo4j Graph Database Access",
						Severity:   "critical",
						Confidence: model.Confirmed,
						Auth: model.AuthResult{
							Attempted: true,
							Method:    "none",
							Status:    "successful",
						},
						Evidence:  []string{"Neo4j reports authDisabled: true at root endpoint"},
						Timestamp: time.Now().UTC(),
					}, nil
				}

				// Otherwise test unauthenticated Cypher execution via transactional endpoints
				txEndpoints := []string{"/db/neo4j/tx/commit", "/db/data/transaction/commit"}
				for _, txEp := range txEndpoints {
					txURL := fmt.Sprintf("%s://%s:%d%s", scheme, host, port, txEp)
					txReq, err := http.NewRequest("POST", txURL, strings.NewReader(`{"statements":[{"statement":"RETURN 1"}]}`))
					if err != nil {
						continue
					}
					txReq.Header.Set("Content-Type", "application/json")
					network.ApplyCustomHeaders(txReq)

					txResp, err := client.Do(txReq)
					if err != nil {
						continue
					}
					txBody, _ := io.ReadAll(io.LimitReader(txResp.Body, 2048))
					txResp.Body.Close()

					if txResp.StatusCode == http.StatusOK && strings.Contains(string(txBody), "results") {
						return &model.Finding{
							Target:     host,
							Port:       port,
							Protocol:   scheme,
							Service:    "neo4j",
							Title:      "Unauthenticated Neo4j Graph Database Access",
							Severity:   "critical",
							Confidence: model.Confirmed,
							Auth: model.AuthResult{
								Attempted: true,
								Method:    "none",
								Status:    "successful",
							},
							Evidence:  []string{fmt.Sprintf("Cypher 'RETURN 1' executed anonymously on %s (200 OK)", txEp)},
							Timestamp: time.Now().UTC(),
						}, nil
					}
				}
			}
		}
	}
	return nil, nil
}
