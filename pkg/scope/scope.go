package scope

import (
	"net"
	"os"
	"strings"
)

// Policy defines authorized and restricted targets.
type Policy struct {
	Allow []string
	Deny  []string

	allowNets []*net.IPNet
	denyNets  []*net.IPNet
	allowIPs  []net.IP
	denyIPs   []net.IP
}

// LoadPolicyFromFile loads scope rules from a file. Lines prefixed with '!' or 'deny:' are deny rules.
func LoadPolicyFromFile(path string) (*Policy, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	p := &Policy{}
	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
		line = strings.TrimPrefix(line, "\ufeff")
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasPrefix(line, "!") {
			p.Deny = append(p.Deny, strings.TrimSpace(line[1:]))
		} else if strings.HasPrefix(strings.ToLower(line), "deny:") {
			p.Deny = append(p.Deny, strings.TrimSpace(line[5:]))
		} else if strings.HasPrefix(strings.ToLower(line), "allow:") {
			p.Allow = append(p.Allow, strings.TrimSpace(line[6:]))
		} else {
			p.Allow = append(p.Allow, line)
		}
	}
	if err := p.Compile(); err != nil {
		return nil, err
	}
	return p, nil
}

// Compile compiles the allow and deny rules into lookup structures.
func (p *Policy) Compile() error {
	for _, a := range p.Allow {
		if strings.Contains(a, "/") {
			_, ipnet, err := net.ParseCIDR(a)
			if err == nil {
				p.allowNets = append(p.allowNets, ipnet)
				continue
			}
		}
		ip := net.ParseIP(a)
		if ip != nil {
			p.allowIPs = append(p.allowIPs, ip)
		}
	}

	for _, d := range p.Deny {
		if strings.Contains(d, "/") {
			_, ipnet, err := net.ParseCIDR(d)
			if err == nil {
				p.denyNets = append(p.denyNets, ipnet)
				continue
			}
		}
		ip := net.ParseIP(d)
		if ip != nil {
			p.denyIPs = append(p.denyIPs, ip)
		}
	}
	return nil
}

// IsAllowed evaluates whether a host or IP is permitted by the policy.
func (p *Policy) IsAllowed(hostOrIP string) bool {
	ip := net.ParseIP(hostOrIP)
	if ip != nil {
		for _, dip := range p.denyIPs {
			if dip.Equal(ip) {
				return false
			}
		}
		for _, dnet := range p.denyNets {
			if dnet.Contains(ip) {
				return false
			}
		}
		if len(p.allowIPs) == 0 && len(p.allowNets) == 0 {
			return true
		}
		for _, aip := range p.allowIPs {
			if aip.Equal(ip) {
				return true
			}
		}
		for _, anet := range p.allowNets {
			if anet.Contains(ip) {
				return true
			}
		}
		return false
	}

	for _, d := range p.Deny {
		if matchDomain(d, hostOrIP) {
			return false
		}
	}
	if len(p.Allow) == 0 {
		return true
	}
	for _, a := range p.Allow {
		if matchDomain(a, hostOrIP) {
			return true
		}
	}
	return false
}

func matchDomain(pattern, host string) bool {
	pattern = strings.ToLower(pattern)
	host = strings.ToLower(host)
	if pattern == host {
		return true
	}
	if strings.HasPrefix(pattern, "*.") {
		suffix := pattern[1:]
		return strings.HasSuffix(host, suffix)
	}
	return false
}
