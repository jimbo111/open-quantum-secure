package tlsprobe

import (
	"context"
	"errors"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/jimbo111/open-quantum-secure/pkg/engines"
)

// concurrency_test.go — verifies that the engine's semaphore correctly limits
// simultaneous TLS probes to defaultConcurrency (5) at any instant.
//
// Uses the probeFn hook (comparable to Sprint 0's nowFn) to inject an
// instrumented stub that tracks peak concurrency without making real network
// connections. Also verifies no goroutine leaks after Scan completes.
//
// Run the race detector:
//   go test -race -count=10 ./pkg/engines/tlsprobe/ -run TestConcurrency

// TestConcurrency_DefaultIs5 is a compile-time constant check. If anyone bumps
// defaultConcurrency back above 5, this test immediately fails with a clear
// message explaining the regression.
func TestConcurrency_DefaultIs5(t *testing.T) {
	if defaultConcurrency != 5 {
		t.Errorf("defaultConcurrency = %d, want 5 (regression: S1.4 lowered it from 10 to 5 to prevent server-side rate limiting)",
			defaultConcurrency)
	}
}

// TestConcurrency_MaxSimultaneousProbesCappedAt5 submits 20 fake targets and
// verifies that at no instant do more than defaultConcurrency (5) probes execute
// simultaneously. It also checks for goroutine leaks after Scan returns.
func TestConcurrency_MaxSimultaneousProbesCappedAt5(t *testing.T) {
	var (
		mu          sync.Mutex
		activeCnt   int
		peakCnt     int
	)

	// Save and restore the production probeFn.
	origProbeFn := probeFn
	t.Cleanup(func() { probeFn = origProbeFn })

	// Instrumented stub: counts concurrent calls and sleeps briefly so multiple
	// probes are in-flight simultaneously.
	probeFn = func(ctx context.Context, target string, opts ProbeOpts) ProbeResult {
		mu.Lock()
		activeCnt++
		if activeCnt > peakCnt {
			peakCnt = activeCnt
		}
		mu.Unlock()

		// Hold the slot long enough that batches of goroutines pile up, giving
		// the peak counter a chance to see the real maximum concurrency.
		select {
		case <-ctx.Done():
		case <-time.After(15 * time.Millisecond):
		}

		mu.Lock()
		activeCnt--
		mu.Unlock()

		return ProbeResult{
			Target: target,
			Error:  errors.New("stub: not a real server"),
		}
	}

	// Build 20 fake targets — more than 4× the semaphore cap to ensure the
	// semaphore is actually exercised and not bypassed.
	const numTargets = 20
	targets := make([]string, numTargets)
	for i := range targets {
		targets[i] = "192.0.2.1:443" // TEST-NET, guaranteed unreachable in production
	}

	goroutinesBefore := runtime.NumGoroutine()

	e := New()
	opts := engines.ScanOptions{
		TLSTargets:  targets,
		TLSInsecure: true,
		TLSTimeout:  2,
	}

	// All targets fail (stub returns Error) → engine returns an error. We only
	// care about the concurrency bound, not the scan result.
	_, _ = e.Scan(context.Background(), opts)

	// After Scan returns (wg.Wait() inside), all goroutines must have exited.
	// Allow a small window for the runtime to reap them.
	time.Sleep(25 * time.Millisecond)
	goroutinesAfter := runtime.NumGoroutine()

	// ── Assertion 1: peak concurrent probes must not exceed the semaphore cap. ──
	if peakCnt > defaultConcurrency {
		t.Errorf("peak simultaneous probes = %d, want ≤ %d (semaphore leak or wrong cap)",
			peakCnt, defaultConcurrency)
	}
	if peakCnt == 0 {
		t.Errorf("peak concurrent probes = 0 — instrumentation never fired (stub not called?)")
	}

	// ── Assertion 2: no goroutine leak. ──
	// We tolerate a small delta for background goroutines created by the test
	// runtime itself (e.g., finalizer goroutines, GC helpers). 5 is generous.
	const leakTolerance = 5
	if goroutinesAfter > goroutinesBefore+leakTolerance {
		t.Errorf("goroutine leak: before=%d after=%d (delta=%d, tolerance=%d)",
			goroutinesBefore, goroutinesAfter,
			goroutinesAfter-goroutinesBefore, leakTolerance)
	}

	t.Logf("peak concurrent probes: %d (limit: %d); goroutines before/after: %d/%d",
		peakCnt, defaultConcurrency, goroutinesBefore, goroutinesAfter)
}

// TestConcurrency_SemaphoreRespectedUnderRace is a lighter stress run designed
// specifically for -race -count=10. It verifies that shared counter mutations
// via sync.Mutex are race-free across repeated invocations.
func TestConcurrency_SemaphoreRespectedUnderRace(t *testing.T) {
	var (
		mu    sync.Mutex
		peak  int
		calls int
	)

	origProbeFn := probeFn
	t.Cleanup(func() { probeFn = origProbeFn })

	probeFn = func(ctx context.Context, target string, opts ProbeOpts) ProbeResult {
		mu.Lock()
		calls++
		if calls > peak {
			peak = calls
		}
		mu.Unlock()

		time.Sleep(5 * time.Millisecond)

		mu.Lock()
		calls--
		mu.Unlock()

		return ProbeResult{Target: target, Error: errors.New("stub")}
	}

	const numTargets = 15
	targets := make([]string, numTargets)
	for i := range targets {
		targets[i] = "192.0.2.1:443"
	}

	e := New()
	opts := engines.ScanOptions{TLSTargets: targets, TLSInsecure: true, TLSTimeout: 2}
	_, _ = e.Scan(context.Background(), opts)

	if peak > defaultConcurrency {
		t.Errorf("race run: peak=%d > defaultConcurrency=%d", peak, defaultConcurrency)
	}
}
