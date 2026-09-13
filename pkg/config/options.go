package config

import (
	"fmt"
	"os"

	"github.com/projectdiscovery/goflags"
)

// Options holds all user-configurable parameters parsed from flags.
type Options struct {
	Target       string
	TargetsList  string
	Ports        string
	TopPorts     string
	Threads      int
	Timeout      int
	RateLimit    int
	Verify       bool
	ScopeFile    string
	OutputFile   string
	JSONOutput   bool
	Silent       bool
	ColorBlind   bool
	Verbose      bool
}

// ParseOptions parses command-line flags and validates inputs.
func ParseOptions() (*Options, error) {
	opts := &Options{}
	flagSet := goflags.NewFlagSet()
	flagSet.SetDescription("Vaasuki - High-Performance Network Service Reconnaissance & Verification Scanner")

	flagSet.CreateGroup("input", "Input Target Options",
		flagSet.StringVarP(&opts.Target, "target", "u", "", "\tSingle target host, IP, or CIDR block"),
		flagSet.StringVarP(&opts.TargetsList, "list", "l", "", "\tFile containing list of targets"),
		flagSet.StringVarP(&opts.Ports, "ports", "p", "", "\tPorts to scan (e.g. 21,22,80,6379 or 1-1000)"),
		flagSet.StringVarP(&opts.TopPorts, "top-ports", "tp", "", "\tTop ports to scan via naabu (100, 1000)"),
	)

	flagSet.CreateGroup("verification", "Verification & Safety",
		flagSet.BoolVarP(&opts.Verify, "verify", "vf", true, "\tPerform safe non-destructive authentication verification"),
		flagSet.StringVarP(&opts.ScopeFile, "scope", "sc", "", "\tPath to scope authorization file"),
	)

	flagSet.CreateGroup("performance", "Performance & Optimization",
		flagSet.IntVarP(&opts.Threads, "threads", "t", 25, "\tNumber of concurrent workers"),
		flagSet.IntVarP(&opts.Timeout, "timeout", "to", 5, "\tConnection timeout in seconds"),
		flagSet.IntVarP(&opts.RateLimit, "rate", "r", 50, "\tMaximum connection attempts per second"),
	)

	flagSet.CreateGroup("output", "Output & Reporting",
		flagSet.StringVarP(&opts.OutputFile, "output", "o", "", "\tOutput findings file path"),
		flagSet.BoolVarP(&opts.JSONOutput, "json", "j", false, "\tWrite output in JSONL format"),
		flagSet.BoolVarP(&opts.Silent, "silent", "s", false, "\tSuppress banner and non-essential status lines"),
		flagSet.BoolVarP(&opts.ColorBlind, "color-blind", "b", false, "\tDisable ANSI colored output"),
		flagSet.BoolVarP(&opts.Verbose, "verbose", "v", false, "\tShow verbose connection diagnostics"),
	)

	if err := flagSet.Parse(); err != nil {
		return nil, err
	}

	if opts.TargetsList != "" {
		stat, err := os.Stat(opts.TargetsList)
		if err != nil {
			return nil, fmt.Errorf("target list file not found: %w", err)
		}
		if stat.IsDir() {
			return nil, fmt.Errorf("target list path is a directory: %s", opts.TargetsList)
		}
	}

	return opts, nil
}
