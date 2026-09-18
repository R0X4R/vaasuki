package actuator

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

	endpoints := []string{"/actuator/env", "/actuator/mappings"}
	schemes := []string{"http", "https"}
	targetHostPort := net.JoinHostPort(host, strconv.Itoa(port))

	for _, scheme := range schemes {
		for _, ep := range endpoints {
			url := fmt.Sprintf("%s://%s%s", scheme, targetHostPort, ep)
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
				if strings.Contains(bodyStr, "propertySources") || strings.Contains(bodyStr, "contexts") || strings.Contains(bodyStr, "JAVA PROFILE") {
					sev := "high"
					if ep == "/actuator/heapdump" || ep == "/actuator/env" {
						sev = "critical"
					}
					return &model.Finding{
						Target:     host,
						Port:       port,
						Protocol:   scheme,
						Service:    "actuator",
						Title:      fmt.Sprintf("Exposed Spring Boot Actuator (%s)", ep),
						Severity:   sev,
						Confidence: model.Confirmed,
						Auth: model.AuthResult{
							Attempted: true,
							Method:    "none",
							Status:    "successful",
						},
						Evidence:  []string{fmt.Sprintf("HTTP 200 OK at %s", ep)},
						Timestamp: time.Now().UTC(),
					}, nil
				}
			}
		}
	}
	return nil, nil
}
