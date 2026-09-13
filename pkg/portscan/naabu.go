package portscan

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/projectdiscovery/naabu/v2/pkg/result"
	"github.com/projectdiscovery/naabu/v2/pkg/runner"
)

// ScanWithNaabu invokes Naabu programmatically to scan ports for the specified host.
func ScanWithNaabu(host string, portsStr string, topPorts string, rate int, timeoutSec int) ([]int, error) {
	var discovered []int

	if rate <= 0 {
		rate = 1000
	}
	timeout := time.Second
	if timeoutSec > 0 {
		timeout = time.Duration(timeoutSec) * time.Second
	}

	options := runner.Options{
		Host:          []string{host},
		ScanType:      runner.ConnectScan,
		Rate:          rate,
		Timeout:       timeout,
		Silent:        true,
		DisableStdout: true,
		OnResult: func(hr *result.HostResult) {
			for _, port := range hr.Ports {
				discovered = append(discovered, port.Port)
			}
		},
	}

	trimmedPorts := strings.TrimSpace(portsStr)
	if trimmedPorts == "-" || trimmedPorts == "all" || trimmedPorts == "full" {
		options.Ports = "1-65535"
	} else if trimmedPorts != "" {
		options.Ports = trimmedPorts
	} else if topPorts != "" {
		options.TopPorts = topPorts
	} else {
		// Default to scanning all ports 1-65535
		options.Ports = "1-65535"
	}

	naabuRunner, err := runner.NewRunner(&options)
	if err != nil {
		return nil, fmt.Errorf("failed to create naabu runner: %w", err)
	}
	defer naabuRunner.Close()

	if err := naabuRunner.RunEnumeration(context.Background()); err != nil {
		return nil, fmt.Errorf("naabu scan failed: %w", err)
	}

	return discovered, nil
}

// ParsePortOrRange converts a single string token to integer port.
func ParsePortOrRange(val string) (int, error) {
	return strconv.Atoi(strings.TrimSpace(val))
}
