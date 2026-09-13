package target

import (
	"fmt"
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
	if strings.TrimSpace(raw) == "" {
		return nil, nil
	}
	var ports []int
	parts := strings.Split(raw, ",")
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
