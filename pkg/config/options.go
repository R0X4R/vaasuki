package config

import (
	"fmt"
	"os"

	"github.com/projectdiscovery/goflags"
)

// Options holds all user-configurable parameters parsed from flags.
type Options struct {
	Target            string
	TargetsList       string
	Ports             string
	TopPorts          string
	Threads           int
	Timeout           int
	RateLimit         int
	Verify            bool
	ScopeFile         string
	OutputFile        string
	JSONOutput        bool
	Silent            bool
	ColorBlind        bool
	Verbose           bool
	Version           bool
	SkipHostDiscovery bool
	Headers           goflags.StringSlice
}

// ParseOptions parses command-line flags and validates inputs.
func ParseOptions() (*Options, error) {
	opts := &Options{}
	flagSet := goflags.NewFlagSet()
	flagSet.SetDescription("Vaasuki - Hunt Vulnerabilities in Exposed Services")

	flagSet.CreateGroup("input", "Input",
		flagSet.StringVarP(&opts.Target, "target", "u", "", "\tSingle target host, IP, or CIDR block"),
		flagSet.StringVarP(&opts.TargetsList, "list", "l", "", "\tFile containing list of targets"),
		flagSet.StringVarP(&opts.Ports, "ports", "p", "", "\tPorts to scan (defaults to all 0-65535, or e.g. 21,22,80,6379, 1-1000)"),
		flagSet.StringVar(&opts.TopPorts, "top-ports", "", "\tTop ports to scan via naabu (100, 1000, 10000)"),
	)

	flagSet.CreateGroup("verification", "Verification & Safety",
		flagSet.BoolVarP(&opts.Verify, "verify", "vf", true, "\tPerform safe non-destructive authentication verification"),
		flagSet.StringVarP(&opts.ScopeFile, "scope", "sc", "", "\tPath to scope authorization file"),
		flagSet.BoolVar(&opts.SkipHostDiscovery, "Pn", false, "\tTreat all hosts as online skip host discovery"),
		flagSet.StringSliceVarP(&opts.Headers, "header", "H", nil, "\tCustom header to include in HTTP requests (e.g. -H 'Header: Value')", goflags.StringSliceOptions),
	)

	flagSet.CreateGroup("performance", "Performance & Optimization",
		flagSet.IntVarP(&opts.Threads, "threads", "t", 25, "\tNumber of concurrent workers"),
		flagSet.IntVar(&opts.Timeout, "timeout", 3, "\tConnection timeout in seconds"),
		flagSet.IntVarP(&opts.RateLimit, "rate", "r", 1000, "\tMaximum connection attempts per second"),
	)

	flagSet.CreateGroup("output", "Output & Reporting",
		flagSet.StringVarP(&opts.OutputFile, "output", "o", "", "\tOutput findings file path"),
		flagSet.BoolVarP(&opts.JSONOutput, "json", "j", false, "\tWrite output in JSONL format"),
		flagSet.BoolVarP(&opts.Silent, "silent", "s", false, "\tSuppress banner and non-essential status lines"),
		flagSet.BoolVarP(&opts.ColorBlind, "color-blind", "b", false, "\tDisable ANSI colored output"),
		flagSet.BoolVarP(&opts.Verbose, "verbose", "v", false, "\tShow verbose connection diagnostics"),
	)

	flagSet.CreateGroup("debug", "Debug & Information",
		flagSet.BoolVar(&opts.Version, "version", false, "\tShow tool version"),
	)

	if err := flagSet.Parse(); err != nil {
		return nil, err
	}

	if opts.Threads <= 0 {
		opts.Threads = 25
	}
	if opts.Timeout <= 0 {
		opts.Timeout = 3
	}
	if opts.RateLimit <= 0 {
		opts.RateLimit = 1000
	}

	if opts.TargetsList != "" {
		stat, err := os.Stat(opts.TargetsList)
		if err != nil {
			return nil, fmt.Errorf("Target list file not found: %w", err)
		}
		if stat.IsDir() {
			return nil, fmt.Errorf("Target list path is a directory: %s", opts.TargetsList)
		}
	}

	return opts, nil
}
