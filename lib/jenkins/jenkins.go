package jenkins

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

// Verify tests whether an unauthenticated Jenkins CI/CD instance is exposed.
func Verify(host string, port int, timeout time.Duration) (*model.Finding, error) {
	client := &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}

	schemes := []string{"http", "https"}
	for _, scheme := range schemes {
		url := fmt.Sprintf("%s://%s:%d/api/json", scheme, host, port)
		req, err := http.NewRequest("GET", url, nil)
		if err != nil {
			continue
		}
		network.ApplyCustomHeaders(req)

		resp, err := client.Do(req)
		if err != nil {
			// Try root /
			urlRoot := fmt.Sprintf("%s://%s:%d/", scheme, host, port)
			reqRoot, errRoot := http.NewRequest("GET", urlRoot, nil)
			if errRoot != nil {
				continue
			}
			network.ApplyCustomHeaders(reqRoot)
			respRoot, errRoot := client.Do(reqRoot)
			if errRoot != nil {
				continue
			}
			resp = respRoot
		}

		jenkinsHeader := resp.Header.Get("X-Jenkins")
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		resp.Body.Close()

		if jenkinsHeader != "" || strings.Contains(string(body), "Jenkins") {
			ver := jenkinsHeader
			if ver == "" {
				ver = "unknown"
			}
			return &model.Finding{
				Target:     host,
				Port:       port,
				Protocol:   scheme,
				Service:    "jenkins",
				Title:      fmt.Sprintf("Exposed Jenkins CI/CD Instance (Version: %s)", ver),
				Severity:   "medium",
				Confidence: model.Confirmed,
				Auth: model.AuthResult{
					Attempted: true,
					Method:    "none",
					Status:    "successful",
				},
				Evidence:  []string{fmt.Sprintf("X-Jenkins: %s, Status: %d", jenkinsHeader, resp.StatusCode)},
				Timestamp: time.Now().UTC(),
			}, nil
		}
	}

	return nil, nil
}
