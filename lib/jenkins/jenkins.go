package jenkins

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

// Verify tests whether an unauthenticated Jenkins CI/CD instance is exposed.
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
		if jenkinsHeader == "" {
			jenkinsHeader = resp.Header.Get("X-Hudson")
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		resp.Body.Close()

		bodyStr := string(body)
		isJenkins := false
		if jenkinsHeader != "" {
			isJenkins = true
		} else if strings.Contains(bodyStr, "hudson.model.Hudson") || strings.Contains(bodyStr, "jenkins.model.Jenkins") {
			isJenkins = true
		} else if strings.Contains(bodyStr, "<title>Dashboard [Jenkins]</title>") ||
			strings.Contains(bodyStr, "<title>Sign in [Jenkins]</title>") ||
			strings.Contains(bodyStr, "class=\"jenkins-") ||
			(strings.Contains(bodyStr, "name=\"j_username\"") && (strings.Contains(strings.ToLower(bodyStr), "jenkins") || strings.Contains(strings.ToLower(bodyStr), "hudson"))) {
			isJenkins = true
		}

		if isJenkins {
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
