package kubelet

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

// Verify tests whether an exposed Kubelet API allows unauthenticated pod/stats access.
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

	schemes := []string{"https", "http"}
	for _, scheme := range schemes {
		podsURL := fmt.Sprintf("%s://%s:%d/pods", scheme, host, port)
		req, err := http.NewRequest("GET", podsURL, nil)
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

		if resp.StatusCode == http.StatusOK && strings.Contains(string(body), "PodList") {
			return &model.Finding{
				Target:     host,
				Port:       port,
				Protocol:   scheme,
				Service:    "kubelet",
				Title:      "Unauthenticated Kubelet API Pod Listing Access",
				Severity:   "critical",
				Confidence: model.Confirmed,
				Auth: model.AuthResult{
					Attempted: true,
					Method:    "none",
					Status:    "successful",
				},
				Evidence: []string{
					"Unauthenticated /pods returned PodList (200 OK)",
				},
				Timestamp: time.Now().UTC(),
			}, nil
		}

		// Secondary check: /stats/summary
		statsURL := fmt.Sprintf("%s://%s:%d/stats/summary", scheme, host, port)
		statsReq, err := http.NewRequest("GET", statsURL, nil)
		if err != nil {
			continue
		}
		network.ApplyCustomHeaders(statsReq)

		statsResp, err := client.Do(statsReq)
		if err != nil {
			continue
		}
		statsBody, _ := io.ReadAll(io.LimitReader(statsResp.Body, 4096))
		statsResp.Body.Close()

		if statsResp.StatusCode == http.StatusOK && strings.Contains(string(statsBody), "nodeName") {
			return &model.Finding{
				Target:     host,
				Port:       port,
				Protocol:   scheme,
				Service:    "kubelet",
				Title:      "Unauthenticated Kubelet API Node Stats Access",
				Severity:   "critical",
				Confidence: model.Confirmed,
				Auth: model.AuthResult{
					Attempted: true,
					Method:    "none",
					Status:    "successful",
				},
				Evidence: []string{
					"Unauthenticated /stats/summary returned node metrics (200 OK)",
				},
				Timestamp: time.Now().UTC(),
			}, nil
		}
	}

	return nil, nil
}