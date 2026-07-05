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
		if !errors.Is(err, errFailOn) {
			fmt.Fprintf(os.Stderr, "Error: %s\n", err)
		}
		os.Exit(1)
	}
}
