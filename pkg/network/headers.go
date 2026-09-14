package network

import (
	"net/http"
	"strings"
	"sync"
)

// DefaultUserAgent used across HTTP discovery and verification requests.
const DefaultUserAgent = "Mozilla/5.0 (Vaasuki-Recon)"

var (
	customHeaders   http.Header
	customHeadersMu sync.RWMutex
)

// SetCustomHeaders parses a list of "Header: Value" strings and stores them.
func SetCustomHeaders(rawHeaders []string) {
	customHeadersMu.Lock()
	defer customHeadersMu.Unlock()
	customHeaders = make(http.Header)
	for _, h := range rawHeaders {
		h = strings.TrimSpace(h)
		if h == "" {
			continue
		}
		parts := strings.SplitN(h, ":", 2)
		if len(parts) == 2 {
			key := strings.TrimSpace(parts[0])
			val := strings.TrimSpace(parts[1])
			if key != "" {
				customHeaders.Add(key, val)
			}
		}
	}
}

// ApplyCustomHeaders attaches the default User-Agent and any user-configured custom headers to an HTTP request.
func ApplyCustomHeaders(req *http.Request) {
	if req == nil {
		return
	}
	if req.Header.Get("User-Agent") == "" {
		req.Header.Set("User-Agent", DefaultUserAgent)
	}

	customHeadersMu.RLock()
	defer customHeadersMu.RUnlock()
	for k, vals := range customHeaders {
		for i, v := range vals {
			if i == 0 {
				req.Header.Set(k, v)
			} else {
				req.Header.Add(k, v)
			}
		}
	}
}
