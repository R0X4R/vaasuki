package clickhouse

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
		url := fmt.Sprintf("%s://%s/?query=SELECT%%201", scheme, targetHostPort)
		req, err := http.NewRequest("GET", url, nil)
		if err != nil {
			continue
		}
		network.ApplyCustomHeaders(req)

		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		resp.Body.Close()

		isClickHouse := resp.Header.Get("X-ClickHouse-Server-Timezone") != "" ||
			resp.Header.Get("X-ClickHouse-Summary") != "" ||
			strings.Contains(strings.ToLower(resp.Header.Get("Server")), "clickhouse")

		if resp.StatusCode == http.StatusOK && strings.TrimSpace(string(body)) == "1" && isClickHouse {
			return &model.Finding{
				Target:     host,
				Port:       port,
				Protocol:   scheme,
				Service:    "clickhouse",
				Title:      "Unauthenticated ClickHouse HTTP Query Access",
				Severity:   "high",
				Confidence: model.Confirmed,
				Auth: model.AuthResult{
					Attempted: true,
					Method:    "none",
					Status:    "successful",
				},
				Evidence:  []string{"Query 'SELECT 1' returned 1 (200 OK) with ClickHouse response headers"},
				Timestamp: time.Now().UTC(),
			}, nil
		}
	}
	return nil, nil
}
