// engine_stress_test.go — Concurrency stress tests for the CT lookup engine.
// Validates that the per-engine concurrency cap (maxConcurrency = 3) is never
// exceeded, that the engine is race-free under -race, and that context
// cancellation stops all in-flight work promptly.
package ctlookup

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jimbo111/open-quantum-secure/pkg/engines"
)

// TestEngine_Stress_100Hostnames launches a scan over 100 unique hostnames
// against a mock crt.sh server. It asserts:
//  1. The maximum observed concurrent in-flight requests never exceeds maxConcurrency.
//  2. The scan completes without error.
//  3. The test passes under -race (go test -race).
func TestEngine_Stress_100Hostnames(t *testing.T) {
	var (
		mu            sync.Mutex
		concurrent    int
		maxConcurrent int
	)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		concurrent++
		if concurrent > maxConcurrent {
			maxConcurrent = concurrent
		}
		mu.Unlock()

		defer func() {
			mu.Lock()
			concurrent--
			mu.Unlock()
		}()

		// Tiny sleep to let goroutines pile up and reveal any concurrency violations.
		time.Sleep(2 * time.Millisecond)
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintln(w, "[]")
	}))
	defer srv.Close()

	e := New()
	e.client.baseURL = srv.URL
	e.client.httpClient = srv.Client()
	// Use a high rate so the test doesn't take 100+ seconds.
	e.rl = newRateLimiter(10000.0, 10000.0)

	targets := make([]string, 100)
	for i := range targets {
		targets[i] = fmt.Sprintf("stress%04d.example.com", i)
	}

	_, err := e.Scan(context.Background(), engines.ScanOptions{CTLookupTargets: targets})
	if err != nil {
		t.Fatalf("Scan error: %v", err)
	}

	if maxConcurrent > maxConcurrency {
		t.Errorf("concurrency cap violated: %d simultaneous in-flight requests, cap=%d",
			maxConcurrent, maxConcurrency)
	}
	if maxConcurrent == 0 {
		t.Error("no concurrent requests observed — test may not have executed any HTTP calls")
	}
}

// TestEngine_Stress_RateLimiterNotBypassed verifies that even under stress the
// engine never sends more total requests per second than the rate allows. It
// uses a server-side atomic counter over a 100ms window to assert a plausible
// lower bound relative to burst size.
func TestEngine_Stress_RateLimiterNotBypassed(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping timing-sensitive stress test in short mode")
	}
	var totalCalls atomic.Int64

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		totalCalls.Add(1)
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintln(w, "[]")
	}))
	defer srv.Close()

	e := New()
	e.client.baseURL = srv.URL
	e.client.httpClient = srv.Client()
	// Rate = 5/sec, burst = 5 — at most 5 requests should land almost instantly.
	e.rl = newRateLimiter(5.0, 5.0)

	targets := make([]string, 20)
	for i := range targets {
		targets[i] = fmt.Sprintf("rl%04d.example.com", i)
	}

	// Give it enough time to use the burst but cut off well before 20 tokens refill.
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()

	e.Scan(ctx, engines.ScanOptions{CTLookupTargets: targets}) //nolint

	got := totalCalls.Load()
	// With burst=5 and rate=5/sec over ~300ms: max tokens ≈ 5 (burst) + 5*0.3 ≈ 6.5
	// Each hostname consumes 1 token for the JSON query (no DER since empty result).
	// Allow generous upper bound of 10 to avoid flakiness.
	if got > 10 {
		t.Errorf("rate limiter appears bypassed: %d requests in 300ms (burst=5, rate=5/sec)", got)
	}
}

// TestEngine_Stress_ContextCancel_StopsWithin2s verifies that cancelling ctx
// causes Scan to return within 2 seconds even when the server is intentionally
// slow (simulating a stalled or unreachable host).
func TestEngine_Stress_ContextCancel_StopsWithin2s(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Block until request context is cancelled — simulates a slow server.
		<-r.Context().Done()
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer srv.Close()

	e := New()
	e.client.baseURL = srv.URL
	e.client.httpClient = srv.Client()
	e.rl = newRateLimiter(10000.0, 10000.0) // no rate-limit delay in this test

	targets := make([]string, 20)
	for i := range targets {
		targets[i] = fmt.Sprintf("slow%04d.example.com", i)
	}

	ctx, cancel := context.WithCancel(context.Background())

	done := make(chan struct{})
	go func() {
		defer close(done)
		e.Scan(ctx, engines.ScanOptions{CTLookupTargets: targets}) //nolint
	}()

	// Let a few goroutines start.
	time.Sleep(30 * time.Millisecond)
	cancelTime := time.Now()
	cancel()

	select {
	case <-done:
		if elapsed := time.Since(cancelTime); elapsed > 2*time.Second {
			t.Errorf("Scan took %v after cancellation, want < 2s", elapsed)
		}
	case <-time.After(3 * time.Second):
		t.Error("Scan did not return within 3s after context cancellation (goroutine leak?)")
	}
}
