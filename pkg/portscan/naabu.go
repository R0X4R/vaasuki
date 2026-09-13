package portscan

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"github.com/projectdiscovery/naabu/v2/pkg/result"
	"github.com/projectdiscovery/naabu/v2/pkg/runner"
)

// ScanWithNaabu invokes Naabu programmatically to scan ports for the specified host.
func ScanWithNaabu(host string, portsStr string, rate int) ([]int, error) {
	var discovered []int

	options := runner.Options{
		Host:     []string{host},
		ScanType: runner.ConnectScan,
		Rate:     rate,
		Silent:   true,
		OnResult: func(hr *result.HostResult) {
			for _, port := range hr.Ports {
				discovered = append(discovered, port.Port)
			}
		},
	}

	if portsStr != "" {
		options.Ports = portsStr
	} else {
		options.TopPorts = "100"
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
