package solr

import (
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/R0X4R/vaasuki/v2/pkg/model"
	"github.com/R0X4R/vaasuki/v2/pkg/network"
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
		url := fmt.Sprintf("%s://%s/solr/admin/cores?action=STATUS&wt=json", scheme, targetHostPort)
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
			if strings.Contains(bodyStr, "responseHeader") && strings.Contains(bodyStr, "status") {
				evidence := []string{
					"HTTP 200 OK on /solr/admin/cores?action=STATUS",
					"Solr core admin API exposed; /solr/<core>/config reachable (RCE-capable if VelocityResponseWriter enabled - manual verification recommended)",
				}
				return &model.Finding{
					Target:     host,
					Port:       port,
					Protocol:   scheme,
					Service:    "solr",
					Title:      "Unauthenticated Apache Solr Admin Core Access",
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
