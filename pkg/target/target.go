package target

import (
	"fmt"
	"net"
	"strconv"
	"strings"
)

// Target represents a validated target endpoint.
type Target struct {
	Host string
	Port int
}

// ParsePortList parses port specifications like "21,22,80" or "80-85".
func ParsePortList(raw string) ([]int, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" || trimmed == "-" || trimmed == "all" || trimmed == "full" {
		return nil, nil
	}
	var ports []int
	parts := strings.Split(trimmed, ",")
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if strings.Contains(p, "-") {
			rangeParts := strings.Split(p, "-")
			if len(rangeParts) != 2 {
				return nil, fmt.Errorf("invalid port range: %s", p)
			}
			start, err1 := strconv.Atoi(strings.TrimSpace(rangeParts[0]))
			end, err2 := strconv.Atoi(strings.TrimSpace(rangeParts[1]))
			if err1 != nil || err2 != nil || start > end || start < 1 || end > 65535 {
				return nil, fmt.Errorf("invalid port range values: %s", p)
			}
			for i := start; i <= end; i++ {
				ports = append(ports, i)
			}
		} else {
			val, err := strconv.Atoi(p)
			if err != nil || val < 1 || val > 65535 {
				return nil, fmt.Errorf("invalid port number: %s", p)
			}
			ports = append(ports, val)
		}
	}
	return ports, nil
}

// ParseTargetLine parses an input line which may be "host", "host:port", or URL format.
// Returns Target, a boolean indicating if an explicit port was present, and error.
func ParseTargetLine(raw string) (Target, bool, error) {
	line := strings.TrimSpace(raw)
	if line == "" {
		return Target{}, false, fmt.Errorf("empty target line")
	}

	// Strip URL schemes
	if strings.Contains(line, "://") {
		parts := strings.SplitN(line, "://", 2)
		line = parts[1]
	}

	// Strip trailing path
	if idx := strings.Index(line, "/"); idx != -1 {
		line = line[:idx]
	}

	if strings.Contains(line, ":") {
		host, portStr, err := net.SplitHostPort(line)
		if err != nil {
			parts := strings.Split(line, ":")
			if len(parts) == 2 {
				host = parts[0]
				portStr = parts[1]
			} else {
				return Target{}, false, err
			}
		}
		port, err := strconv.Atoi(portStr)
		if err != nil || port < 1 || port > 65535 {
			return Target{}, false, fmt.Errorf("invalid port in line %s: %w", raw, err)
		}
		return Target{Host: host, Port: port}, true, nil
	}

	return Target{Host: line, Port: 0}, false, nil
}
