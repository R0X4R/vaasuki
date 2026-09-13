package main

import (
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/R0X4R/vaasuki/lib/ftp"
	"github.com/R0X4R/vaasuki/lib/redis"
	"github.com/R0X4R/vaasuki/pkg/config"
	"github.com/R0X4R/vaasuki/pkg/console"
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

	if opts.Target == "" && opts.TargetsList == "" {
		return fmt.Errorf("no target specified; use -u <target> or -l <file>")
	}

	var targets []string
	if opts.Target != "" {
		targets = append(targets, opts.Target)
	}

	var scopePolicy *scope.Policy
	if opts.ScopeFile != "" {
		// load scope policy if provided
		scopePolicy = &scope.Policy{}
		_ = scopePolicy.Compile()
	}

	timeout := time.Duration(opts.Timeout) * time.Second

	for _, host := range targets {
		if scopePolicy != nil && !scopePolicy.IsAllowed(host) {
			console.Warnf("Target %s is outside scope policy, skipping", host)
			continue
		}

		var ports []int
		if opts.Ports != "" {
			ports, err = target.ParsePortList(opts.Ports)
			if err != nil {
				return err
			}
		} else {
			console.Infof("Running automated Naabu port discovery on: %s", host)
			ports, err = portscan.ScanWithNaabu(host, "", opts.RateLimit)
			if err != nil {
				console.Warnf("Naabu port scan error (%s): %v, falling back to top ports", host, err)
				ports = []int{21, 2121, 23, 2323, 80, 443, 4445, 6379, 6380, 8080, 8088, 9200, 11211}
			}
		}

		console.Infof("Scanning target: %s (%d ports)", host, len(ports))
		for _, port := range ports {
			if !network.IsPortOpen(host, port, timeout) {
				continue
			}

			console.Infof("Open port detected: %s:%d", host, port)

			if !opts.Verify {
				continue
			}

			var finding *model.Finding
			switch port {
			case 21, 2121:
				finding, _ = ftp.Verify(host, port, timeout)
			case 6379, 6380:
				finding, _ = redis.Verify(host, port, timeout)
			}

			if finding != nil && finding.Confidence == model.Confirmed {
				console.Confirmedf("[%s] %s:%d - %s", finding.Protocol, host, port, finding.Title)
				if opts.OutputFile != "" {
					f, err := os.OpenFile(opts.OutputFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
					if err == nil {
						_ = model.WriteFinding(f, *finding)
						_ = f.Close()
					}
				}
			}
		}
	}

	console.Infof("Scan completed.")
	return nil
}
