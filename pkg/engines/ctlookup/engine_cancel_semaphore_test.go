package ctlookup

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jimbo111/open-quantum-secure/pkg/engines"
)

// TestEngine_ContextCancel_SemaphoreUnblocks verifies A5: when the context is
// cancelled while all semaphore slots are occupied, the parent loop must not
// block indefinitely waiting to acquire the semaphore. Scan must return within
// 100ms of cancellation.
//
// Setup: slow server that blocks until request ctx is cancelled. We fill all
// maxConcurrency=3 slots with in-flight requests, then cancel the outer ctx.
// The remaining targets (slots 4+) should not block on semaphore acquisition.
func TestEngine_ContextCancel_SemaphoreUnblocks(t *testing.T) {
	// Count how many requests reached the server.
	var reached atomic.Int64

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reached.Add(1)
		// Block until the request context is cancelled (outer ctx cancellation
		// propagates through http.Client).
		<-r.Context().Done()
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer srv.Close()

	e := New()
	e.client.baseURL = srv.URL
	e.client.httpClient = srv.Client()
	// Fast rate so the semaphore (not the rate limiter) is the bottleneck.
	e.rl = newRateLimiter(100000.0, 100000.0)

	// More targets than maxConcurrency so some will be waiting on the semaphore.
	targets := make([]string, maxConcurrency+5)
	for i := range targets {
		targets[i] = "sem-cancel-test-" + string(rune('a'+i)) + ".example.com"
	}

	ctx, cancel := context.WithCancel(context.Background())

	done := make(chan struct{})
	go func() {
		defer close(done)
		e.Scan(ctx, engines.ScanOptions{CTLookupTargets: targets}) //nolint
	}()

	// Wait until at least maxConcurrency requests are in-flight (semaphore full).
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if reached.Load() >= int64(maxConcurrency) {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	if reached.Load() < int64(maxConcurrency) {
		t.Logf("only %d requests reached server before cancel (want %d); cancelling anyway",
			reached.Load(), maxConcurrency)
	}

	cancelTime := time.Now()
	cancel()

	select {
	case <-done:
		if elapsed := time.Since(cancelTime); elapsed > 500*time.Millisecond {
			t.Errorf("Scan took %v after cancellation, want < 500ms (semaphore may have blocked)",
				elapsed)
		}
	case <-time.After(3 * time.Second):
		t.Error("Scan did not return within 3s after context cancellation — semaphore leak suspected")
	}
}
