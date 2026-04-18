// engine_stress_test.go — concurrency and cancellation stress tests for the SSH probe engine.
//
// Purpose: verify that the engine's bounded-concurrency design holds under load:
//   1. 100 concurrent SSH targets → goroutine count never exceeds baseline + maxConcurrency + slack.
//   2. Context cancellation propagates to all in-flight probes within 100ms.
//   3. No data races under -race (all tests pass with go test -race -count=1).
//
// Seam note: these tests inject probeFn (already injectable via the package-level
// var in probe.go) to avoid real network connections while maintaining control
// over timing and goroutine coordination.
package sshprobe

import (
	"context"
	"fmt"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jimbo111/open-quantum-secure/pkg/engines"
)

// TestEngineStress_GoroutineCapBounded verifies that scanning 100 targets
// never spawns more than baseline + maxConcurrency + slack goroutines
// simultaneously, enforcing the semaphore invariant (Sprint 4 M1 design).
func TestEngineStress_GoroutineCapBounded(t *testing.T) {
	// Record baseline goroutine count before the scan.
	baseline := runtime.NumGoroutine()

	// Semaphore to hold probe goroutines so we can observe peak count.
	gate := make(chan struct{})
	var mu sync.Mutex
	var peakGoroutines int

	original := probeFn
	defer func() { probeFn = original }()
	probeFn = func(ctx context.Context, target string, timeout time.Duration) ProbeResult {
		// Record current goroutine count while blocked — this is when concurrent
		// probes are at their peak.
		current := runtime.NumGoroutine()
		mu.Lock()
		if current > peakGoroutines {
			peakGoroutines = current
		}
		mu.Unlock()

		// Block until the gate is closed (all probes launched before reading).
		select {
		case <-gate:
		case <-ctx.Done():
		}

		return ProbeResult{Target: target, Error: fmt.Errorf("test stub")}
	}

	// Build 100 distinct targets.
	targets := make([]string, 100)
	for i := range targets {
		targets[i] = fmt.Sprintf("192.0.2.%d:22", i+1)
	}

	// Run Scan in a background goroutine so we can close the gate after launch.
	errCh := make(chan error, 1)
	go func() {
		e := New()
		_, err := e.Scan(context.Background(), engines.ScanOptions{
			SSHTargets: targets,
		})
		errCh <- err
	}()

	// Give the engine a moment to fill the semaphore (at most maxConcurrency probes
	// will be in flight simultaneously).
	time.Sleep(50 * time.Millisecond)

	// Release all blocked probes.
	close(gate)

	// Wait for the scan to complete.
	select {
	case <-errCh:
	case <-time.After(10 * time.Second):
		t.Fatal("scan did not complete within 10s")
	}

	// Allow some slack for test framework goroutines, GC, and runtime internals.
	// The strict bound is baseline + maxConcurrency; +10 provides tolerance for
	// goroutines the test binary itself uses (e.g. GC, finalizer, netpoll).
	const slack = 10
	allowed := baseline + maxConcurrency + slack
	if peakGoroutines > allowed {
		t.Errorf("peak goroutines = %d; want ≤ %d (baseline=%d + cap=%d + slack=%d)",
			peakGoroutines, allowed, baseline, maxConcurrency, slack)
	}
	t.Logf("peak goroutines = %d (baseline=%d, cap=%d, slack=%d)",
		peakGoroutines, baseline, maxConcurrency, slack)
}

// TestEngineStress_ContextCancelWithin100ms verifies that cancelling the context
// propagates to all in-flight probes and the Scan call returns within 100ms of
// cancellation.
func TestEngineStress_ContextCancelWithin100ms(t *testing.T) {
	original := probeFn
	defer func() { probeFn = original }()

	var launched atomic.Int64
	probeFn = func(ctx context.Context, target string, timeout time.Duration) ProbeResult {
		launched.Add(1)
		// Block until context is cancelled.
		<-ctx.Done()
		return ProbeResult{Target: target, Error: ctx.Err()}
	}

	targets := make([]string, 100)
	for i := range targets {
		targets[i] = fmt.Sprintf("192.0.2.%d:22", i+1)
	}

	ctx, cancel := context.WithCancel(context.Background())

	scanDone := make(chan struct{})
	go func() {
		e := New()
		_, _ = e.Scan(ctx, engines.ScanOptions{SSHTargets: targets})
		close(scanDone)
	}()

	// Wait until at least some probes are in flight.
	deadline := time.Now().Add(2 * time.Second)
	for launched.Load() == 0 && time.Now().Before(deadline) {
		runtime.Gosched()
	}

	// Cancel and measure response time.
	cancelAt := time.Now()
	cancel()

	select {
	case <-scanDone:
		elapsed := time.Since(cancelAt)
		if elapsed > 100*time.Millisecond {
			t.Errorf("context cancel took %v to propagate; want ≤ 100ms", elapsed)
		}
		t.Logf("cancel propagation latency: %v", elapsed)
	case <-time.After(500 * time.Millisecond):
		t.Fatal("Scan did not return within 500ms after context cancel")
	}
}

// TestEngineStress_ConcurrencyRaceDetector runs a concurrency-sensitive scan
// under -race to expose any shared-state races. Uses real goroutines and
// concurrent access to the results slice.
func TestEngineStress_ConcurrencyRaceDetector(t *testing.T) {
	original := probeFn
	defer func() { probeFn = original }()

	// Minimal delay to ensure goroutines interleave.
	probeFn = func(ctx context.Context, target string, timeout time.Duration) ProbeResult {
		runtime.Gosched()
		if ctx.Err() != nil {
			return ProbeResult{Target: target, Error: ctx.Err()}
		}
		return ProbeResult{
			Target:     target,
			ServerID:   "SSH-2.0-test",
			KEXMethods: []string{"curve25519-sha256", "diffie-hellman-group14-sha256"},
		}
	}

	targets := make([]string, 50)
	for i := range targets {
		targets[i] = fmt.Sprintf("198.51.100.%d:22", i+1)
	}

	e := New()
	ff, err := e.Scan(context.Background(), engines.ScanOptions{SSHTargets: targets})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// 50 targets × 2 methods each = 100 findings.
	if len(ff) != 100 {
		t.Errorf("findings count = %d; want 100 (50 targets × 2 methods)", len(ff))
	}
}

// TestEngineStress_MaxTargetsExact verifies behaviour at exactly maxTargets
// (accepted) and maxTargets+1 (rejected).
func TestEngineStress_MaxTargetsExact(t *testing.T) {
	original := probeFn
	defer func() { probeFn = original }()
	probeFn = func(ctx context.Context, target string, timeout time.Duration) ProbeResult {
		return ProbeResult{Target: target, Error: fmt.Errorf("stub")}
	}

	// Exactly maxTargets → must not error with the count-check error.
	targets := make([]string, maxTargets)
	for i := range targets {
		targets[i] = fmt.Sprintf("192.0.2.1:%d", 1000+i)
	}
	e := New()
	_, err := e.Scan(context.Background(), engines.ScanOptions{SSHTargets: targets})
	// All probes fail (stub returns error), so we expect an "all unreachable" error,
	// NOT a "too many targets" error.
	if err != nil && strings.Contains(err.Error(), "too many targets") {
		t.Errorf("unexpected 'too many targets' error for exactly %d targets", maxTargets)
	}

	// maxTargets+1 → must return "too many targets" error.
	tooMany := make([]string, maxTargets+1)
	for i := range tooMany {
		tooMany[i] = fmt.Sprintf("192.0.2.1:%d", 1000+i)
	}
	_, err2 := e.Scan(context.Background(), engines.ScanOptions{SSHTargets: tooMany})
	if err2 == nil || !strings.Contains(err2.Error(), "too many targets") {
		t.Errorf("expected 'too many targets' error for %d targets, got: %v", len(tooMany), err2)
	}
}
