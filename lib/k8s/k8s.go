
package k8s

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/R0X4R/vaasuki/v2/pkg/model"
	"github.com/R0X4R/vaasuki/v2/pkg/network"
)

// Verify tests whether an exposed Kubernetes API Server allows unauthenticated resource access.
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
		versionURL := fmt.Sprintf("%s://%s:%d/version", scheme, host, port)
		req, err := http.NewRequest("GET", versionURL, nil)
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

		if resp.StatusCode != http.StatusOK {
			continue
		}

		var versionData struct {
			Major      string `json:"major"`
			Minor      string `json:"minor"`
			GitVersion string `json:"gitVersion"`
		}
		if err := json.Unmarshal(body, &versionData); err != nil || versionData.GitVersion == "" {
			continue
		}

		// False-positive guard: verify whether resources (namespaces / pods) can be listed anonymously
		nsURL := fmt.Sprintf("%s://%s:%d/api/v1/namespaces", scheme, host, port)
		nsReq, err := http.NewRequest("GET", nsURL, nil)
		if err != nil {
			continue
		}
		network.ApplyCustomHeaders(nsReq)

		nsResp, err := client.Do(nsReq)
		if err != nil {
			continue
		}
		nsBody, _ := io.ReadAll(io.LimitReader(nsResp.Body, 8192))
		nsResp.Body.Close()

		if nsResp.StatusCode == http.StatusOK && strings.Contains(string(nsBody), "NamespaceList") {
			return &model.Finding{
				Target:     host,
				Port:       port,
				Protocol:   scheme,
				Service:    "k8s",
				Version:    versionData.GitVersion,
				Title:      fmt.Sprintf("Unauthenticated Kubernetes API Server Access (%s)", versionData.GitVersion),
				Severity:   "critical",
				Confidence: model.Confirmed,
				Auth: model.AuthResult{
					Attempted: true,
					Method:    "none",
					Status:    "successful",
				},
				Evidence: []string{
					fmt.Sprintf("Kubernetes Version: %s", versionData.GitVersion),
					"Anonymous /api/v1/namespaces listing allowed (200 OK)",
				},
				Timestamp: time.Now().UTC(),
			}, nil
		}
	}

	return nil, nil
}