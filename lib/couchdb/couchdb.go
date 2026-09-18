package couchdb

import (
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/R0X4R/vaasuki/pkg/model"
	"github.com/R0X4R/vaasuki/pkg/network"
)

func Verify(host string, port int, timeout time.Duration) (*model.Finding, error) {
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	defer tr.CloseIdleConnections()

	client := &http.Client{
		Timeout: timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
		Transport: tr,
	}

	targetHostPort := net.JoinHostPort(host, strconv.Itoa(port))
	schemes := []string{"http", "https"}
	for _, scheme := range schemes {
		url := fmt.Sprintf("%s://%s/_all_dbs", scheme, targetHostPort)
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
			isCouch := strings.Contains(strings.ToLower(resp.Header.Get("Server")), "couchdb") ||
				strings.Contains(bodyStr, "_users") ||
				strings.Contains(bodyStr, "_replicator") ||
				strings.Contains(bodyStr, "_global_changes")

			if strings.HasPrefix(strings.TrimSpace(bodyStr), "[") && isCouch {
				evidence := []string{fmt.Sprintf("Databases listed: %s", bodyStr)}

				// Check /_membership for cluster info leak
				memURL := fmt.Sprintf("%s://%s/_membership", scheme, targetHostPort)
				if memReq, err := http.NewRequest("GET", memURL, nil); err == nil {
					network.ApplyCustomHeaders(memReq)
					if memResp, err := client.Do(memReq); err == nil {
						if memBody, err := io.ReadAll(io.LimitReader(memResp.Body, 1024)); err == nil && memResp.StatusCode == http.StatusOK {
							evidence = append(evidence, fmt.Sprintf("Cluster Membership: %s", strings.TrimSpace(string(memBody))))
						}
						memResp.Body.Close()
					}
				}

				return &model.Finding{
					Target:     host,
					Port:       port,
					Protocol:   scheme,
					Service:    "couchdb",
					Title:      "Unauthenticated Apache CouchDB Access (Admin Party / Open)",
					Severity:   "critical",
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
