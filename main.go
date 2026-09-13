package main

import (
	"bufio"
	"fmt"
	"os"
	"os/signal"
	"strings"
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

const Version = "1.0.0"

func main() {
	if err := run(); err != nil {
		console.Errorf("%v", err)
		os.Exit(1)
	}
}

func run() error {
	opts, err := config.ParseOptions()
	if err != nil {
		return err
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

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigChan
		console.Warnf("Scan interrupted by user, exiting...")
		os.Exit(0)
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

	timeout := time.Duration(opts.Timeout) * time.Second

	// 1. Process Direct Endpoints (e.g. from naabu pipe or host:port inputs)
	for _, ep := range directEndpoints {
		if scopePolicy != nil && !scopePolicy.IsAllowed(ep.Host) {
			console.Warnf("Target %s is outside scope policy, skipping", ep.Host)
			continue
		}

		if !network.IsPortOpen(ep.Host, ep.Port, timeout) {
			continue
		}
		console.Verbosef("Open port verified: %s:%d", ep.Host, ep.Port)

		if !opts.Verify {
			continue
		}

		// Dynamically detect service; fallback to port-based guessing
		svc := fingerprint.Identify(ep.Host, ep.Port, timeout)
		if svc == fingerprint.ServiceUnknown {
			svc = fingerprint.Guess(ep.Port)
		}

		finding, _ := dispatcher.VerifyTarget(svc, ep.Host, ep.Port, timeout)
		if finding != nil && finding.Confidence == model.Confirmed {
			console.Confirmedf("%s %s:%d - %s", console.ProtocolTag(finding.Protocol), ep.Host, ep.Port, finding.Title)
			recordFinding(opts, finding)
		}
	}

	// 2. Process Host Targets (perform port scan then fingerprint & verify)
	for _, host := range hostTargets {
		if scopePolicy != nil && !scopePolicy.IsAllowed(host) {
			console.Warnf("Target %s is outside scope policy, skipping", host)
			continue
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
			ports, scanErr = portscan.ScanWithNaabu(host, opts.Ports, opts.TopPorts, opts.RateLimit, opts.Timeout)
			if scanErr != nil {
				console.Warnf("Naabu port scan error (%s): %v, falling back to top ports", host, scanErr)
				ports = []int{21, 2121, 23, 2323, 80, 443, 4445, 6379, 6380, 8080, 8088, 9200, 11211}
			}
		}

		console.Infof("Scanning target: %s (%d ports)", host, len(ports))
		for _, port := range ports {
			if !network.IsPortOpen(host, port, timeout) {
				continue
			}

			console.Verbosef("Open port detected: %s:%d", host, port)

			if !opts.Verify {
				continue
			}

			// Dynamically detect service; fallback to port-based guessing
			svc := fingerprint.Identify(host, port, timeout)
			if svc == fingerprint.ServiceUnknown {
				svc = fingerprint.Guess(port)
			}

			finding, _ := dispatcher.VerifyTarget(svc, host, port, timeout)
			if finding != nil && finding.Confidence == model.Confirmed {
				console.Confirmedf("%s %s:%d - %s", console.ProtocolTag(finding.Protocol), host, port, finding.Title)
				recordFinding(opts, finding)
			}
		}
	}

	return nil
}

func recordFinding(opts *config.Options, finding *model.Finding) {
	if opts.OutputFile == "" {
		return
	}
	f, err := os.OpenFile(opts.OutputFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err == nil {
		_ = model.WriteFinding(f, *finding)
		_ = f.Close()
	}
}
