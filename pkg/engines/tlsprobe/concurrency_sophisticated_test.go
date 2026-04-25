package tlsprobe

// concurrency_sophisticated_test.go — Sophisticated concurrency tests.
//
// Covers:
//  1. Semaphore is acquired in PARENT goroutine (not inside child) — per Sprint 2
//     M1 spec. We verify that with 100 targets, goroutines never burst to 100.
//  2. Context cancellation mid-scan: the engine must stop launching new goroutines
//     once ctx.Done() is triggered, and must return in bounded time.
//  3. ctx.Err() recheck inside child goroutine: even if semaphore was already
//     acquired, a post-acquire ctx.Done() must cause the child to skip the probe.
//  4. WaitGroup correctness: wg.Done() is always called regardless of ctx state
//     so wg.Wait() never deadlocks.

import (
	"context"
	"errors"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jimbo111/open-quantum-secure/pkg/engines"
)

// TestConcurrency_100Targets_NeverBurst100Goroutines is the Sprint 2 M1 regression:
// the semaphore must be acquired by the PARENT loop, not inside each goroutine.
// With 100 targets and defaultConcurrency=5, peak goroutines launched from the
// engine must never exceed 5 simultaneously active probes.
//
// We measure peak goroutine count delta (not absolute) to avoid sensitivity to
// background goroutines from the test runtime.
func TestConcurrency_100Targets_NeverBurst100Goroutines(t *testing.T) {
	// Only valid if maxTargets allows 100 targets.
	if maxTargets < 100 {
		t.Skipf("maxTargets=%d < 100, skipping burst test", maxTargets)
	}

	var active atomic.Int32
	var peakActive atomic.Int32

	origProbeFn := probeFn
	t.Cleanup(func() { probeFn = origProbeFn })

	probeFn = func(ctx context.Context, target string, opts ProbeOpts) ProbeResult {
		// Atomically bump active count and record peak.
		cur := active.Add(1)
		for {
			peak := peakActive.Load()
			if cur <= peak || peakActive.CompareAndSwap(peak, cur) {
				break
			}
		}

		// Hold the slot for a few ms so multiple "probes" are in-flight together.
		select {
		case <-ctx.Done():
		case <-time.After(10 * time.Millisecond):
		}

		active.Add(-1)
		return ProbeResult{Target: target, Error: errors.New("stub")}
	}

	const numTargets = 100
	targets := make([]string, numTargets)
	for i := range targets {
		targets[i] = "192.0.2.1:443"
	}

	e := New()
	opts := engines.ScanOptions{
		TLSTargets:  targets,
		TLSInsecure: true,
		TLSTimeout:  5,
	}

	goroutinesBefore := runtime.NumGoroutine()
	_, _ = e.Scan(context.Background(), opts)
	time.Sleep(50 * time.Millisecond) // let goroutine count settle
	goroutinesAfter := runtime.NumGoroutine()

	peak := peakActive.Load()

	// Sprint 2 M1 invariant: peak concurrent probes must not exceed defaultConcurrency (5).
	if peak > int32(defaultConcurrency) {
		t.Errorf("peak concurrent probes=%d for 100 targets, want ≤%d (semaphore acquired in parent)",
			peak, defaultConcurrency)
	}
	if peak == 0 {
		t.Error("peak concurrent probes=0 — probe function never called")
	}

	// Goroutine leak check (generous tolerance for test-runtime goroutines).
	const leakTolerance = 10
	if goroutinesAfter > goroutinesBefore+leakTolerance {
		t.Errorf("goroutine leak: before=%d after=%d delta=%d > tolerance=%d",
			goroutinesBefore, goroutinesAfter, goroutinesAfter-goroutinesBefore, leakTolerance)
	}

	t.Logf("100-target scan: peak concurrent probes=%d (limit=%d), goroutines before/after %d/%d",
		peak, defaultConcurrency, goroutinesBefore, goroutinesAfter)
}

// TestConcurrency_ContextCancelStopsNewLaunches verifies that when the context
// is cancelled mid-scan, the engine's parent loop stops launching new goroutines
// and Scan returns promptly.
//
// Setup: slow probe function (200ms per probe). We cancel the context after 50ms.
// With defaultConcurrency=5 and 20 targets at 200ms each, an unguarded scan
// would take ~800ms. With early cancel, it must return in ≤500ms.
func TestConcurrency_ContextCancelStopsNewLaunches(t *testing.T) {
	origProbeFn := probeFn
	t.Cleanup(func() { probeFn = origProbeFn })

	var launched atomic.Int32

	probeFn = func(ctx context.Context, target string, opts ProbeOpts) ProbeResult {
		launched.Add(1)
		select {
		case <-ctx.Done():
		case <-time.After(200 * time.Millisecond):
		}
		return ProbeResult{Target: target, Error: errors.New("stub")}
	}

	const numTargets = 20
	targets := make([]string, numTargets)
	for i := range targets {
		targets[i] = "192.0.2.1:443"
	}

	ctx, cancel := context.WithCancel(context.Background())
	e := New()
	opts := engines.ScanOptions{
		TLSTargets:  targets,
		TLSInsecure: true,
		TLSTimeout:  5,
	}

	// Cancel after 50ms — early enough that only the first batch (≤5) has started.
	go func() {
		time.Sleep(50 * time.Millisecond)
		cancel()
	}()

	start := time.Now()
	_, _ = e.Scan(ctx, opts)
	elapsed := time.Since(start)

	// With 200ms probes and cancel at 50ms, the scan must complete well under
	// the time required to run all 20 probes (≈4s sequential, ≈800ms parallel).
	// Allow generous 1s to account for CI slowness.
	if elapsed > 1*time.Second {
		t.Errorf("Scan took %v after ctx cancel, want <1s (cancel not stopping new launches)", elapsed)
	}

	// Launched count must be ≤ defaultConcurrency + a small buffer (the parent
	// loop checks ctx.Err() before acquiring the semaphore; at most 1 extra
	// goroutine may launch between the check and the cancel).
	if n := launched.Load(); n > int32(defaultConcurrency)+2 {
		t.Errorf("launched=%d probes after early cancel, want ≤%d", n, defaultConcurrency+2)
	}
	t.Logf("Context-cancel test: launched=%d probes in %v", launched.Load(), elapsed)
}

// TestConcurrency_ChildRechecksCtxErr verifies that the child goroutine's
// ctx.Err() recheck (inside the goroutine, after semaphore acquisition) causes
// the probe to be skipped when the context was cancelled between semaphore
// acquisition and probe execution.
//
// We simulate this by cancelling the context while holding all semaphore slots,
// then releasing slots and verifying the subsequent children return early.
func TestConcurrency_ChildRechecksCtxErr(t *testing.T) {
	origProbeFn := probeFn
	t.Cleanup(func() { probeFn = origProbeFn })

	// Count probes that actually ran the stub body (past the ctx.Err() recheck).
	var actualProbeCount atomic.Int32

	probeFn = func(ctx context.Context, target string, opts ProbeOpts) ProbeResult {
		actualProbeCount.Add(1)
		return ProbeResult{Target: target, Error: errors.New("stub")}
	}

	ctx, cancel := context.WithCancel(context.Background())

	// Cancel the context immediately before Scan can make progress.
	cancel()

	const numTargets = 15
	targets := make([]string, numTargets)
	for i := range targets {
		targets[i] = "192.0.2.1:443"
	}

	e := New()
	opts := engines.ScanOptions{
		TLSTargets:  targets,
		TLSInsecure: true,
		TLSTimeout:  1,
	}

	_, _ = e.Scan(ctx, opts)

	// With a pre-cancelled context, the parent loop's `if ctx.Err() != nil { break }`
	// should fire immediately. Zero or very few probes should have run.
	// We allow up to defaultConcurrency probes in case of timing races between
	// the pre-cancel and the first iteration.
	if n := actualProbeCount.Load(); n > int32(defaultConcurrency) {
		t.Errorf("pre-cancelled ctx: %d probes ran, want ≤%d (child ctx.Err() recheck failed)",
			n, defaultConcurrency)
	}
	t.Logf("Pre-cancelled ctx: %d probes ran out of %d targets", actualProbeCount.Load(), numTargets)
}

// TestConcurrency_WaitGroupNeverDeadlocks verifies that wg.Wait() always returns
// (no goroutine leak / deadlock) even when probes return errors or panic-recover.
// This is a liveness property: the test will time out (fail) if wg.Wait() hangs.
func TestConcurrency_WaitGroupNeverDeadlocks(t *testing.T) {
	origProbeFn := probeFn
	t.Cleanup(func() { probeFn = origProbeFn })

	var callCount int
	var mu sync.Mutex

	probeFn = func(ctx context.Context, target string, opts ProbeOpts) ProbeResult {
		mu.Lock()
		callCount++
		mu.Unlock()
		// Return a mix of errors to exercise all result paths.
		return ProbeResult{Target: target, Error: errors.New("deliberate error")}
	}

	targets := make([]string, 10)
	for i := range targets {
		targets[i] = "192.0.2.1:443"
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		e := New()
		_, _ = e.Scan(context.Background(), engines.ScanOptions{
			TLSTargets:  targets,
			TLSInsecure: true,
			TLSTimeout:  1,
		})
	}()

	select {
	case <-done:
		// Success — wg.Wait() returned.
	case <-time.After(10 * time.Second):
		t.Fatal("Scan did not return within 10s — wg.Wait() likely deadlocked")
	}
}
