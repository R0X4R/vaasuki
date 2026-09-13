package console

import (
	"bytes"
	"strings"
	"testing"

	"github.com/fatih/color"
)

func TestConsoleTags(t *testing.T) {
	color.NoColor = true
	var buf bytes.Buffer
	SetOutput(&buf)

	Infof("Scanning target: %s", "127.0.0.1")
	if !strings.Contains(buf.String(), "[INF] Scanning target: 127.0.0.1") {
		t.Fatalf("expected [INF] tag, got: %s", buf.String())
	}
	buf.Reset()

	Confirmedf("Verified login on port %d", 21)
	if !strings.Contains(buf.String(), "[CNF] Verified login on port 21") {
		t.Fatalf("expected [CNF] tag, got: %s", buf.String())
	}
	buf.Reset()

	Warnf("Rate limit reached")
	if !strings.Contains(buf.String(), "[WRN] Rate limit reached") {
		t.Fatalf("expected [WRN] tag, got: %s", buf.String())
	}
	buf.Reset()

	Errorf("Connection dropped")
	if !strings.Contains(buf.String(), "[ERR] Connection dropped") {
		t.Fatalf("expected [ERR] tag, got: %s", buf.String())
	}
	buf.Reset()

	Hitf("Potential vulnerability detected")
	if !strings.Contains(buf.String(), "[HIT] Potential vulnerability detected") {
		t.Fatalf("expected [HIT] tag, got: %s", buf.String())
	}
}
