package hadoop

import (
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/R0X4R/vaasuki/pkg/model"
	"github.com/R0X4R/vaasuki/pkg/network"
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
		url := fmt.Sprintf("%s://%s:%d/webhdfs/v1/?op=LISTSTATUS", scheme, host, port)
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

		if resp.StatusCode == http.StatusOK && strings.Contains(string(body), "FileStatuses") {
			evidence := []string{"HTTP 200 OK on /webhdfs/v1/?op=LISTSTATUS"}

			// Test op=CREATE reachability (check 307 redirect vs 401 without executing write)
			createURL := fmt.Sprintf("%s://%s:%d/webhdfs/v1/vaasuki_write_test?op=CREATE&noredirect=true", scheme, host, port)
			if createReq, err := http.NewRequest("PUT", createURL, nil); err == nil {
				network.ApplyCustomHeaders(createReq)
				if createResp, err := client.Do(createReq); err == nil {
					createResp.Body.Close()
					if createResp.StatusCode == http.StatusTemporaryRedirect || createResp.StatusCode == http.StatusOK {
						evidence = append(evidence, "Unauthenticated write test (op=CREATE) reachable (307 redirect to DataNode allowed)")
					}
				}
			}

			return &model.Finding{
				Target:     host,
				Port:       port,
				Protocol:   scheme,
				Service:    "hadoop",
				Title:      "Unauthenticated Hadoop WebHDFS Directory Access",
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
	return nil, nil
}
