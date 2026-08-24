package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/jimbo111/open-quantum-secure/pkg/orchestrator"
)

var version = "0.1.0"

// errFailOn is returned when policy violations are detected, causing exit code 1.
var errFailOn = errors.New("policy violations detected")

// Exit-code contract (stable — CI systems depend on it):
//
//	0 — scan completed, no policy/compliance violations
//	1 — scan completed, but policy or compliance violations were found
//	    (--fail-on threshold hit, blocked algorithm, --compliance FAIL).
//	    The scan result is valid; the findings violate configured policy.
//	2 — the scan could not complete: invalid/missing --path, config errors,
//	    all engines failed, invalid flags, or any other operational error.
//	    The result (if any) is meaningless; do not gate PRs on it.
//
// exitCodeFor maps a root.Execute() error to that contract.
func exitCodeFor(err error) int {
	switch {
	case err == nil:
		return 0
	case errors.Is(err, errFailOn):
		return 1
	default:
		return 2
	}
}

func main() {
	orchestrator.SetScannerVersion(version)

	// Install a SIGINT/SIGTERM handler so Ctrl+C and `kill <pid>` cleanly
	// cancel the scan context. Subprocess engines (astgrep, semgrep,
	// cdxgen, syft, cbomkit, cipherscope, cryptoscan, cryptodeps) all run
	// under exec.CommandContext + WaitDelay=2s and react to ctx
	// cancellation by sending SIGKILL to the child after the wait window.
	// Without this signal hook, Ctrl+C kills oqs-scanner immediately,
	// orphans the subprocess children, and leaks astgrep's temp rule
	// files (oqs-astgrep-rules-*.yml in TMPDIR) on every run.
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	root := rootCmd()
	root.SetContext(ctx)

	if err := root.Execute(); err != nil {
		// errFailOn (exit 1) is a policy verdict, already printed by the
		// evaluators — no extra "Error:" line. Everything else is an
		// operational failure (exit 2) and gets the one-shot stderr print.
		if !errors.Is(err, errFailOn) {
			fmt.Fprintf(os.Stderr, "Error: %s\n", err)
		}
		os.Exit(exitCodeFor(err))
	}
}
