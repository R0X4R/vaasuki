package target

import (
	"context"
	"fmt"
	"net"
	"os/exec"
	"runtime"
	"strings"
	"sync"
	"time"
)

// CommonAlivePorts are universal high-visibility TCP ports used for fast liveness detection.
var CommonAlivePorts = []int{80, 443, 22, 21, 53, 445, 8080, 8443, 3389, 25}

// CheckHostLiveness performs fast pre-flight host discovery to avoid wasting time
// on unreachable, invalid, or dead target addresses before triggering full port discovery.
func CheckHostLiveness(ctx context.Context, targetHost string, timeout time.Duration) (bool, string) {
	host := strings.TrimSpace(targetHost)
	if host == "" {
		return false, "empty host specification"
	}

	// 1. Loopback addresses are always considered alive.
	if host == "127.0.0.1" || host == "localhost" || host == "::1" {
		return true, "loopback address"
	}
	ip := net.ParseIP(host)
	if ip != nil && ip.IsLoopback() {
		return true, "loopback address"
	}

	// 2. If it's a hostname or domain, verify DNS resolution first.
	if ip == nil {
		resolver := net.DefaultResolver
		lookupCtx, lookupCancel := context.WithTimeout(ctx, 2*time.Second)
		defer lookupCancel()
		addrs, err := resolver.LookupHost(lookupCtx, host)
		if err != nil || len(addrs) == 0 {
			return false, fmt.Sprintf("unresolved domain (%v)", err)
		}
	}

	// 3. Fast concurrent TCP liveness probes.
	// A port indicates an active host if:
	// - The connection succeeds (SYN-ACK / port open)
	// - The connection is refused (RST received from host operating system)
	probeTimeout := timeout
	if probeTimeout <= 0 || probeTimeout > 2*time.Second {
		probeTimeout = 1500 * time.Millisecond
	}

	aliveChan := make(chan string, len(CommonAlivePorts)+1)
	var wg sync.WaitGroup

	ctxProbe, cancelProbe := context.WithTimeout(ctx, probeTimeout)
	defer cancelProbe()

	for _, port := range CommonAlivePorts {
		wg.Add(1)
		go func(p int) {
			defer wg.Done()
			addr := net.JoinHostPort(host, fmt.Sprintf("%d", p))
			d := net.Dialer{Timeout: probeTimeout}
			conn, err := d.DialContext(ctxProbe, "tcp", addr)
			if err == nil {
				_ = conn.Close()
				select {
				case aliveChan <- fmt.Sprintf("TCP port %d open", p):
				default:
				}
				cancelProbe()
				return
			}
			errStr := strings.ToLower(err.Error())
			if strings.Contains(errStr, "refused") {
				select {
				case aliveChan <- fmt.Sprintf("TCP port %d refused (RST received)", p):
				default:
				}
				cancelProbe()
				return
			}
		}(port)
	}

	// 4. Concurrently run ICMP / system ping
	wg.Add(1)
	go func() {
		defer wg.Done()
		if pingHost(ctxProbe, host) {
			select {
			case aliveChan <- "ICMP ping response received":
			default:
			}
			cancelProbe()
		}
	}()

	go func() {
		wg.Wait()
		close(aliveChan)
	}()

	select {
	case reason, ok := <-aliveChan:
		if ok && reason != "" {
			return true, reason
		}
	case <-ctxProbe.Done():
	}

	select {
	case reason, ok := <-aliveChan:
		if ok && reason != "" {
			return true, reason
		}
	default:
	}

	return false, "host unresponsive to TCP probes and ping (offline or dropping packets)"
}

func pingHost(ctx context.Context, host string) bool {
	var cmd *exec.Cmd
	if runtime.GOOS == "windows" {
		cmd = exec.CommandContext(ctx, "ping", "-n", "1", "-w", "1000", host)
	} else {
		cmd = exec.CommandContext(ctx, "ping", "-c", "1", "-W", "1", host)
	}
	return cmd.Run() == nil
}
