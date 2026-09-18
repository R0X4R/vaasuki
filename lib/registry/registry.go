package registry

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

// Verify tests whether an exposed Docker Registry v2 allows unauthenticated catalog enumeration.
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
		v2URL := fmt.Sprintf("%s://%s:%d/v2/", scheme, host, port)
		req, err := http.NewRequest("GET", v2URL, nil)
		if err != nil {
			continue
		}
		network.ApplyCustomHeaders(req)

		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		resp.Body.Close()

		distHeader := resp.Header.Get("Docker-Distribution-Api-Version")
		if resp.StatusCode != http.StatusOK || !strings.Contains(distHeader, "registry/2.0") {
			continue
		}

		// Check catalog enumeration
		catalogURL := fmt.Sprintf("%s://%s:%d/v2/_catalog", scheme, host, port)
		catReq, err := http.NewRequest("GET", catalogURL, nil)
		if err != nil {
			continue
		}
		network.ApplyCustomHeaders(catReq)

		catResp, err := client.Do(catReq)
		if err != nil {
			continue
		}
		body, _ := io.ReadAll(io.LimitReader(catResp.Body, 8192))
		catResp.Body.Close()

		if catResp.StatusCode == http.StatusOK {
			var catalogData struct {
				Repositories []string `json:"repositories"`
			}
			_ = json.Unmarshal(body, &catalogData)

			return &model.Finding{
				Target:     host,
				Port:       port,
				Protocol:   scheme,
				Service:    "registry",
				Title:      "Unauthenticated Docker Registry v2 Access",
				Severity:   "high",
				Confidence: model.Confirmed,
				Auth: model.AuthResult{
					Attempted: true,
					Method:    "none",
					Status:    "successful",
				},
				Evidence: []string{
					fmt.Sprintf("Docker-Distribution-Api-Version: %s", distHeader),
					fmt.Sprintf("Catalog Repositories: %d found", len(catalogData.Repositories)),
				},
				Timestamp: time.Now().UTC(),
			}, nil
		}
	}

	return nil, nil
}