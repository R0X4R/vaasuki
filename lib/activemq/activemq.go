package activemq

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
	for _, scheme := range []string{"http", "https"} {
		url := fmt.Sprintf("%s://%s/admin/", scheme, targetHostPort)
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

		bodyStr := string(body)
		if resp.StatusCode == http.StatusOK && strings.Contains(bodyStr, "ActiveMQ") &&
			(strings.Contains(bodyStr, "queues.jsp") || strings.Contains(bodyStr, "topics.jsp") || strings.Contains(bodyStr, "Broker") || strings.Contains(bodyStr, "subscribers.jsp")) {
			return &model.Finding{
				Target:     host,
				Port:       port,
				Protocol:   scheme,
				Service:    "activemq",
				Title:      "Unauthenticated ActiveMQ Web Console Access",
				Severity:   "high",
				Confidence: model.Confirmed,
				Auth: model.AuthResult{
					Attempted: true,
					Method:    "none",
					Status:    "successful",
				},
				Evidence:  []string{"HTTP 200 OK on /admin/ console with active broker links"},
				Timestamp: time.Now().UTC(),
			}, nil
		}

		// If 401 Unauthorized, test default credentials admin:admin
		if resp.StatusCode == http.StatusUnauthorized {
			authReq, err := http.NewRequest("GET", url, nil)
			if err == nil {
				authReq.SetBasicAuth("admin", "admin")
				network.ApplyCustomHeaders(authReq)
				authResp, err := client.Do(authReq)
				if err == nil {
					authBody, _ := io.ReadAll(io.LimitReader(authResp.Body, 4096))
					authResp.Body.Close()
					if authResp.StatusCode == http.StatusOK && strings.Contains(string(authBody), "ActiveMQ") {
						return &model.Finding{
							Target:     host,
							Port:       port,
							Protocol:   scheme,
							Service:    "activemq",
							Title:      "ActiveMQ Web Console Default Credentials (admin:admin)",
							Severity:   "high",
							Confidence: model.Confirmed,
							Auth: model.AuthResult{
								Attempted: true,
								Method:    "admin:admin",
								Status:    "successful",
							},
							Evidence:  []string{"Default credentials admin:admin accepted on /admin/ console"},
							Timestamp: time.Now().UTC(),
						}, nil
					}
				}
			}
		}
	}

	if conn, err := network.DialTimeout("tcp", fmt.Sprintf("%s:%d", host, port), timeout); err == nil {
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(timeout))
		buf := make([]byte, 512)
		n, _ := conn.Read(buf)
		if n > 0 && strings.Contains(string(buf[:n]), "ActiveMQ") {
			banner := string(buf[:n])
			version := extractVersion(banner)

			title := "Exposed ActiveMQ OpenWire Broker Port"
			severity := "high"
			evidence := []string{"ActiveMQ OpenWire banner detected"}

			if version != "" {
				evidence = append(evidence, fmt.Sprintf("Extracted Broker Version: %s", version))
				if isCVE2023_46604Vulnerable(version) {
					title = fmt.Sprintf("Vulnerable ActiveMQ OpenWire (CVE-2023-46604, %s)", version)
					severity = "critical"
					evidence = append(evidence, "Vulnerable version (< 5.15.16, < 5.16.7, < 5.17.6, < 5.18.3) reachable without authentication")
				}
			}

			return &model.Finding{
				Target:     host,
				Port:       port,
				Protocol:   "openwire",
				Service:    "activemq",
				Version:    version,
				Title:      title,
				Severity:   severity,
				Confidence: model.Confirmed,
				Auth: model.AuthResult{
					Attempted: false,
					Method:    "none",
					Status:    "untested",
				},
				Evidence:  evidence,
				Timestamp: time.Now().UTC(),
			}, nil
		}
	}

	return nil, nil
}

func extractVersion(banner string) string {
	for i := 0; i < len(banner)-4; i++ {
		if banner[i] >= '0' && banner[i] <= '9' && banner[i+1] == '.' {
			end := i + 2
			for end < len(banner) && ((banner[end] >= '0' && banner[end] <= '9') || banner[end] == '.') {
				end++
			}
			candidate := banner[i:end]
			var maj, min, pat int
			if n, _ := fmt.Sscanf(candidate, "%d.%d.%d", &maj, &min, &pat); n >= 2 {
				return candidate
			}
		}
	}
	return ""
}

func isCVE2023_46604Vulnerable(ver string) bool {
	var maj, min, pat int
	n, _ := fmt.Sscanf(ver, "%d.%d.%d", &maj, &min, &pat)
	if n < 2 {
		return false
	}
	if maj < 5 {
		return true
	}
	if maj == 5 {
		if min < 15 {
			return true
		}
		if min == 15 && pat < 16 {
			return true
		}
		if min == 16 && pat < 7 {
			return true
		}
		if min == 17 && pat < 6 {
			return true
		}
		if min == 18 && pat < 3 {
			return true
		}
	}
	return false
}
