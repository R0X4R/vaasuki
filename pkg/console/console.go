package console

import (
	"fmt"
	"io"
	"os"
	"sync"

	"github.com/fatih/color"
)

var (
	outMu   sync.Mutex
	outDest io.Writer = os.Stdout
	silent  bool
	verbose bool
)

// SetOutput redirects console output, primarily for testing.
func SetOutput(w io.Writer) {
	outMu.Lock()
	defer outMu.Unlock()
	outDest = w
}

// SetColorBlind toggles color stripping across the entire terminal session.
func SetColorBlind(disabled bool) {
	color.NoColor = disabled
}

// SetSilent configures silence mode.
func SetSilent(s bool) {
	silent = s
}

// SetVerbose configures verbosity mode.
func SetVerbose(v bool) {
	verbose = v
}

// Infof prints an informational message with a blue [INF] prefix.
func Infof(format string, args ...any) {
	if silent {
		return
	}
	outMu.Lock()
	defer outMu.Unlock()
	tag := color.BlueString("[INF]")
	fmt.Fprintf(outDest, "%s "+format+"\n", append([]any{tag}, args...)...)
}

// Warnf prints a warning message with a yellow [WRN] prefix.
func Warnf(format string, args ...any) {
	if silent {
		return
	}
	outMu.Lock()
	defer outMu.Unlock()
	tag := color.YellowString("[WRN]")
	fmt.Fprintf(outDest, "%s "+format+"\n", append([]any{tag}, args...)...)
}

// Errorf prints an error message with a red [ERR] prefix.
func Errorf(format string, args ...any) {
	outMu.Lock()
	defer outMu.Unlock()
	tag := color.RedString("[ERR]")
	fmt.Fprintf(outDest, "%s "+format+"\n", append([]any{tag}, args...)...)
}

// Hitf prints a potential hit message with a magenta [HIT] prefix.
func Hitf(format string, args ...any) {
	outMu.Lock()
	defer outMu.Unlock()
	tag := color.HiMagentaString("[HIT]")
	fmt.Fprintf(outDest, "%s "+format+"\n", append([]any{tag}, args...)...)
}

// Confirmedf prints a verified finding message with a green [CNF] prefix.
func Confirmedf(format string, args ...any) {
	outMu.Lock()
	defer outMu.Unlock()
	tag := color.HiGreenString("[CNF]")
	fmt.Fprintf(outDest, "%s "+format+"\n", append([]any{tag}, args...)...)
}

// Banner prints the tool startup banner.
func Banner(version string) {
	if silent {
		return
	}
	outMu.Lock()
	defer outMu.Unlock()
	color.New(color.Bold, color.FgCyan).Println("Vaasuki - Network Service Reconnaissance and Active Verification Engine")
	fmt.Fprintf(outDest, "[%s] [%s: %s]\n\n",
		color.HiGreenString("VERSION"),
		color.HiYellowString("RELEASE"),
		version,
	)
}
