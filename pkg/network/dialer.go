package network

import (
	"context"
	"fmt"
	"net"
	"time"
)

// DialTimeout establishes a connection within the specified duration using net.Dialer.
func DialTimeout(networkType, address string, timeout time.Duration) (net.Conn, error) {
	d := net.Dialer{
		Timeout: timeout,
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	return d.DialContext(ctx, networkType, address)
}

// IsPortOpen checks whether a specific host and TCP port is accepting connections.
func IsPortOpen(host string, port int, timeout time.Duration) bool {
	addr := fmt.Sprintf("%s:%d", host, port)
	conn, err := DialTimeout("tcp", addr, timeout)
	if err != nil {
		return false
	}
	_ = conn.Close()
	return true
}
