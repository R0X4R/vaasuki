package config

import (
	"os"
	"testing"
)

func TestParseOptionsDefaults(t *testing.T) {
	oldArgs := os.Args
	defer func() { os.Args = oldArgs }()

	os.Args = []string{"vaasuki"}
	opts, err := ParseOptions()
	if err != nil {
		t.Fatalf("unexpected error parsing options: %v", err)
	}

	if opts.Threads != 25 {
		t.Errorf("expected default threads 25, got %d", opts.Threads)
	}
	if opts.Timeout != 5 {
		t.Errorf("expected default timeout 5s, got %d", opts.Timeout)
	}
	if opts.RateLimit != 50 {
		t.Errorf("expected default rate limit 50, got %d", opts.RateLimit)
	}
}
