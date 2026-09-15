package main

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/R0X4R/vaasuki/pkg/config"
	"github.com/R0X4R/vaasuki/pkg/console"
	"github.com/R0X4R/vaasuki/pkg/dispatcher"
	"github.com/R0X4R/vaasuki/pkg/fingerprint"
	"github.com/R0X4R/vaasuki/pkg/model"
	"github.com/R0X4R/vaasuki/pkg/network"
	"github.com/R0X4R/vaasuki/pkg/portscan"
	"github.com/R0X4R/vaasuki/pkg/scope"
	"github.com/R0X4R/vaasuki/pkg/target"
)

const Version = "2.6.0"

func main() {
	if err := run(); err != nil {
		console.Errorf("%v", err)
		os.Exit(1)
	}
}

type scanCoordinator struct {
	opts           *config.Options
	scopePolicy    *scope.Policy
	timeout        time.Duration
	openPortsCount int64
	confirmedCount int64
	seenMu         sync.Mutex
	seenTargets    map[string]bool
	fileMu         sync.Mutex
}

func run() error {
	opts, err := config.ParseOptions()
	if err != nil {
		return err
	}

	if len(opts.Headers) > 0 {
		network.SetCustomHeaders(opts.Headers)
	}

	if opts.Version {
		console.Version(Version)
		return nil
	}

	if opts.ColorBlind {
		console.SetColorBlind(true)
	}
	if opts.Silent {
		console.SetSilent(true)
	}
	if opts.Verbose {
		console.SetVerbose(true)
	}

	console.Banner(Version)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigChan
		console.Warnf("Scan interrupted by user, shutting down gracefully...")
		cancel()
		// If user presses Ctrl+C again, force exit immediately
		<-sigChan
		console.Warnf("Forced exit requested.")
		os.Exit(130)
	}()

	var directEndpoints []target.Target
	var hostTargets []string

	// Check if piped from stdin (e.g. naabu -host domain.com | vaasuki)
	if opts.Target == "" && opts.TargetsList == "" {
		stat, statErr := os.Stdin.Stat()
		if statErr == nil && (stat.Mode()&os.ModeCharDevice) == 0 {
			scanner := bufio.NewScanner(os.Stdin)
			for scanner.Scan() {
				line := strings.TrimSpace(scanner.Text())
				if line == "" {
					continue
				}
				t, hasPort, parseErr := target.ParseTargetLine(line)
				if parseErr != nil {
					continue
				}
				if hasPort {
					directEndpoints = append(directEndpoints, t)
				} else {
					hostTargets = append(hostTargets, t.Host)
				}
			}
			if scanErr := scanner.Err(); scanErr != nil {
				return fmt.Errorf("error reading stdin: %w", scanErr)
			}
		}
	}

	// Read from target file (-l)
	if opts.TargetsList != "" {
		file, err := os.Open(opts.TargetsList)
		if err != nil {
			return fmt.Errorf("failed to open target file: %w", err)
		}
		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line == "" {
				continue
			}
			t, hasPort, parseErr := target.ParseTargetLine(line)
			if parseErr != nil {
				continue
			}
			if hasPort {
				directEndpoints = append(directEndpoints, t)
			} else {
				hostTargets = append(hostTargets, t.Host)
			}
		}
		if scanErr := scanner.Err(); scanErr != nil {
			_ = file.Close()
			return fmt.Errorf("error reading target file: %w", scanErr)
		}
		_ = file.Close()
	}

	// Read single target (-u)
	if opts.Target != "" {
		t, hasPort, parseErr := target.ParseTargetLine(opts.Target)
		if parseErr == nil {
			if hasPort {
				directEndpoints = append(directEndpoints, t)
			} else {
				hostTargets = append(hostTargets, t.Host)
			}
		} else {
			hostTargets = append(hostTargets, opts.Target)
		}
	}

	if len(directEndpoints) == 0 && len(hostTargets) == 0 {
		return fmt.Errorf("no target specified; use -u <target>, -l <file>, or pipe from naabu")
	}

	var scopePolicy *scope.Policy
	if opts.ScopeFile != "" {
		var scopeErr error
		scopePolicy, scopeErr = scope.LoadPolicyFromFile(opts.ScopeFile)
		if scopeErr != nil {
			return fmt.Errorf("failed to load scope policy file: %w", scopeErr)
		}
	}

	sc := &scanCoordinator{
		opts:        opts,
		scopePolicy: scopePolicy,
		timeout:     time.Duration(opts.Timeout) * time.Second,
		seenTargets: make(map[string]bool),
	}

	// 1. Process Direct Endpoints concurrently using worker pool
	if len(directEndpoints) > 0 {
		sc.runEndpointWorkers(ctx, directEndpoints)
		if atomic.LoadInt64(&sc.openPortsCount) == 0 {
			console.Errorf("No responsive open ports found across %d endpoints (connection refused or host unreachable)", len(directEndpoints))
		}
	}

	// 2. Process Host Targets (perform port scan then fingerprint & verify concurrently)
	for _, host := range hostTargets {
		if ctx.Err() != nil {
			break
		}
		if scopePolicy != nil && !scopePolicy.IsAllowed(host) {
			console.Warnf("Target %s is outside scope policy, skipping", host)
			continue
		}

		// Host discovery pre-flight check
		if !opts.SkipHostDiscovery {
			alive, reason := target.CheckHostLiveness(ctx, host, time.Duration(opts.Timeout)*time.Second)
			if !alive {
				console.Errorf("Host discovery failed for %s: %s (skipping port scan)", host, reason)
				continue
			}
			console.Verbosef("Host %s confirmed alive (%s)", host, reason)
		}

		var ports []int
		trimmedPorts := strings.TrimSpace(opts.Ports)
		if trimmedPorts != "" && trimmedPorts != "-" && trimmedPorts != "all" && trimmedPorts != "full" && opts.TopPorts == "" {
			// User specified explicit ports (e.g. -p 80,443 or -p 80-90)
			var pErr error
			ports, pErr = target.ParsePortList(trimmedPorts)
			if pErr != nil {
				return pErr
			}
		} else {
			console.Infof("Running automated Naabu port discovery on: %s", host)
			var scanErr error
			ports, scanErr = portscan.ScanWithNaabu(ctx, host, opts.Ports, opts.TopPorts, opts.RateLimit, opts.Timeout)
			if scanErr != nil {
				if ctx.Err() != nil {
					return nil
				}
				console.Warnf("Naabu port scan error (%s): %v, falling back to top ports", host, scanErr)
				ports = []int{21, 2121, 23, 2323, 80, 443, 4445, 6379, 6380, 8080, 8088, 9200, 11211}
			}
		}

		if len(ports) == 0 {
			console.Warnf("No open ports discovered on target %s", host)
			continue
		}

		console.Infof("Scanning target: %s (%d ports)", host, len(ports))
		var hostEndpoints []target.Target
		for _, port := range ports {
			hostEndpoints = append(hostEndpoints, target.Target{Host: host, Port: port})
		}
		sc.runEndpointWorkers(ctx, hostEndpoints)
	}

	if atomic.LoadInt64(&sc.openPortsCount) > 0 && atomic.LoadInt64(&sc.confirmedCount) == 0 {
		console.Verbosef("Verification complete: %d open ports analyzed, no vulnerabilities confirmed", atomic.LoadInt64(&sc.openPortsCount))
	}

	return nil
}

func (sc *scanCoordinator) runEndpointWorkers(ctx context.Context, endpoints []target.Target) {
	var queue []target.Target
	sc.seenMu.Lock()
	for _, ep := range endpoints {
		key := fmt.Sprintf("%s:%d", ep.Host, ep.Port)
		if sc.seenTargets[key] {
			continue
		}
		sc.seenTargets[key] = true
		queue = append(queue, ep)
	}
	sc.seenMu.Unlock()

	if len(queue) == 0 {
		return
	}

	workers := sc.opts.Threads
	if workers > len(queue) {
		workers = len(queue)
	}
	if workers <= 0 {
		workers = 1
	}

	jobs := make(chan target.Target, len(queue))
	for _, ep := range queue {
		jobs <- ep
	}
	close(jobs)

	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-ctx.Done():
					return
				case ep, ok := <-jobs:
					if !ok {
						return
					}
					sc.verifyEndpoint(ctx, ep)
				}
			}
		}()
	}
	wg.Wait()
}

func (sc *scanCoordinator) verifyEndpoint(ctx context.Context, ep target.Target) {
	if ctx.Err() != nil {
		return
	}

	if sc.scopePolicy != nil && !sc.scopePolicy.IsAllowed(ep.Host) {
		console.Warnf("Target %s is outside scope policy, skipping", ep.Host)
		return
	}

	if !network.IsPortOpen(ep.Host, ep.Port, sc.timeout) {
		console.Verbosef("Connection failed: %s:%d (closed or dropped)", ep.Host, ep.Port)
		return
	}

	atomic.AddInt64(&sc.openPortsCount, 1)
	console.Verbosef("Open port verified: %s:%d", ep.Host, ep.Port)

	if !sc.opts.Verify {
		return
	}

	svc := fingerprint.Identify(ep.Host, ep.Port, sc.timeout)
	if svc == fingerprint.ServiceUnknown {
		svc = fingerprint.Guess(ep.Port)
	}

	finding, _ := dispatcher.VerifyTarget(svc, ep.Host, ep.Port, sc.timeout)
	if finding != nil && finding.Confidence == model.Confirmed {
		atomic.AddInt64(&sc.confirmedCount, 1)

		targetURL := fmt.Sprintf("%s:%d", ep.Host, ep.Port)
		protoLower := strings.ToLower(finding.Protocol)
		if protoLower == "http" || protoLower == "https" {
			if (protoLower == "http" && ep.Port == 80) || (protoLower == "https" && ep.Port == 443) {
				targetURL = fmt.Sprintf("%s://%s", protoLower, ep.Host)
			} else {
				targetURL = fmt.Sprintf("%s://%s:%d", protoLower, ep.Host, ep.Port)
			}
		}

		serviceName := finding.Service
		if serviceName == "" {
			serviceName = finding.Protocol
		}

		console.Findingf(finding.Severity, serviceName, targetURL, finding.Title)
		sc.recordFinding(finding)
	}
}

func (sc *scanCoordinator) recordFinding(finding *model.Finding) {
	if sc.opts.OutputFile == "" {
		return
	}
	sc.fileMu.Lock()
	defer sc.fileMu.Unlock()

	f, err := os.OpenFile(sc.opts.OutputFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err == nil {
		_ = model.WriteFinding(f, *finding)
		_ = f.Close()
	}
}
