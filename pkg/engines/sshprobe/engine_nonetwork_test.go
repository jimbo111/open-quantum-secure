// engine_nonetwork_test.go — invariant tests for the NoNetwork kill-switch.
//
// Purpose: verify that when opts.NoNetwork=true, the Scan method returns
// (nil, nil) immediately without invoking probeFn or opening any network
// connections. This mirrors the tls-probe pattern from Sprint 2 M1.
//
// Seam: probeFn (package-level var in probe.go) is overridden with a
// panicDialer that panics if ever called, proving the no-network gate fires
// before any probe attempt.
package sshprobe

import (
	"context"
	"testing"
	"time"

	"github.com/jimbo111/open-quantum-secure/pkg/engines"
)

// panicProbe is injected as probeFn when NoNetwork=true.
// If it is ever called, the test fails (and panics to make the failure obvious).
func panicProbe(_ context.Context, _ string, _ time.Duration, _ bool) ProbeResult {
	panic("probeFn called with NoNetwork=true — engine must short-circuit before reaching the probe")
}

// TestNoNetwork_ShortCircuits verifies that NoNetwork=true causes Scan to return
// (nil, nil) without calling probeFn.
func TestNoNetwork_ShortCircuits(t *testing.T) {
	original := probeFn
	probeFn = panicProbe
	defer func() { probeFn = original }()

	e := New()
	ff, err := e.Scan(context.Background(), engines.ScanOptions{
		SSHTargets: []string{"example.com:22"},
		NoNetwork:  true,
	})
	if err != nil {
		t.Errorf("expected nil error with NoNetwork=true, got: %v", err)
	}
	if ff != nil {
		t.Errorf("expected nil findings with NoNetwork=true, got %d findings", len(ff))
	}
}

// TestNoNetwork_EmptyTargets_ShortCircuits verifies that an empty target list
// also short-circuits before probeFn (separate early-return path).
func TestNoNetwork_EmptyTargets_ShortCircuits(t *testing.T) {
	original := probeFn
	probeFn = panicProbe
	defer func() { probeFn = original }()

	e := New()
	ff, err := e.Scan(context.Background(), engines.ScanOptions{
		SSHTargets: nil,
		NoNetwork:  false, // not NoNetwork — empty target list triggers a different guard
	})
	if err != nil {
		t.Errorf("expected nil error for empty targets, got: %v", err)
	}
	if ff != nil {
		t.Errorf("expected nil findings for empty targets, got %d findings", len(ff))
	}
}

// TestNoNetwork_WithMultipleTargets verifies that even with many targets set,
// NoNetwork=true blocks all probes.
func TestNoNetwork_WithMultipleTargets(t *testing.T) {
	original := probeFn
	probeFn = panicProbe
	defer func() { probeFn = original }()

	targets := make([]string, maxTargets)
	for i := range targets {
		targets[i] = "198.51.100.1:22"
	}

	e := New()
	ff, err := e.Scan(context.Background(), engines.ScanOptions{
		SSHTargets: targets,
		NoNetwork:  true,
	})
	if err != nil {
		t.Errorf("expected nil error with NoNetwork=true + %d targets, got: %v", len(targets), err)
	}
	if ff != nil {
		t.Errorf("expected nil findings with NoNetwork=true, got %d", len(ff))
	}
}

// TestNoNetwork_NoNetwork_False_DoesCallProbe verifies the inverse: when
// NoNetwork=false, probeFn IS called (so panicProbe would indeed panic).
// This test uses a safe replacement to confirm the call path is active.
func TestNoNetwork_NoNetwork_False_DoesCallProbe(t *testing.T) {
	original := probeFn
	var called bool
	probeFn = func(_ context.Context, target string, _ time.Duration, _ bool) ProbeResult {
		called = true
		return ProbeResult{Target: target, Error: context.Canceled}
	}
	defer func() { probeFn = original }()

	e := New()
	_, _ = e.Scan(context.Background(), engines.ScanOptions{
		SSHTargets: []string{"198.51.100.2:22"},
		NoNetwork:  false,
	})
	if !called {
		t.Error("expected probeFn to be called when NoNetwork=false, but it was not")
	}
}
