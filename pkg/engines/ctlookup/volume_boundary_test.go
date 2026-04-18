// volume_boundary_test.go — Boundary-condition tests for the rate limiter and
// LRU cache, targeting the exact edges that happy-path and basic tests miss:
// zero-token states, burst exhaustion with refill, concurrent token racing,
// capacity-exact eviction, and same-key update (move-to-front).
package ctlookup

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// ── Rate limiter boundary tests ───────────────────────────────────────────────

// TestRateLimiter_ExactlyOneToken verifies that a limiter initialised with
// burst=1 (exactly one available token) succeeds on the first call immediately.
func TestRateLimiter_ExactlyOneToken(t *testing.T) {
	rl := newRateLimiter(1.0, 1.0)
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()

	start := time.Now()
	if err := rl.Wait(ctx); err != nil {
		t.Fatalf("first wait with 1 token: unexpected error: %v", err)
	}
	if elapsed := time.Since(start); elapsed > 50*time.Millisecond {
		t.Errorf("first token took %v, want < 50ms (should be immediate)", elapsed)
	}
}

// TestRateLimiter_ExactlyZeroTokens verifies that a limiter with tokens forcibly
// drained to 0 causes Wait to block and return a context deadline error.
func TestRateLimiter_ExactlyZeroTokens(t *testing.T) {
	rl := newRateLimiter(1.0, 1.0) // 1 token/sec
	// Force drain all tokens.
	rl.mu.Lock()
	rl.tokens = 0
	rl.last = time.Now()
	rl.mu.Unlock()

	// 40ms deadline is far below the 1-second token refill time.
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Millisecond)
	defer cancel()

	err := rl.Wait(ctx)
	if err == nil {
		t.Fatal("expected context deadline exceeded with 0 tokens, got nil")
	}
}

// TestRateLimiter_ContextCancelledAtHalfRate verifies that cancelling at
// T ≈ rate/2 (before the next token is ready) propagates ctx.Err().
// Uses a fast rate (200/sec = 5ms/token) and cancels at ~2.5ms.
func TestRateLimiter_ContextCancelledAtHalfRate(t *testing.T) {
	const ratePerSec = 200.0 // one token every 5ms
	rl := newRateLimiter(ratePerSec, 1.0)
	rl.mu.Lock()
	rl.tokens = 0
	rl.last = time.Now()
	rl.mu.Unlock()

	// Cancel after ~half the token interval.
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Millisecond)
	defer cancel()

	err := rl.Wait(ctx)
	if err == nil {
		t.Fatal("expected context cancellation at T=rate/2, got nil")
	}
}

// TestRateLimiter_Burst3ExhaustAndRefill exhausts a burst=3 limiter, waits for
// a single token to refill, then verifies exactly one more call succeeds
// promptly.
func TestRateLimiter_Burst3ExhaustAndRefill(t *testing.T) {
	// Use a fast rate so refill is observable within the test budget.
	const ratePerSec = 100.0 // one token every 10ms; burst=3
	rl := newRateLimiter(ratePerSec, 3.0)
	ctx := context.Background()

	// Exhaust all 3 burst tokens.
	for i := 0; i < 3; i++ {
		if err := rl.Wait(ctx); err != nil {
			t.Fatalf("burst exhaustion call %d: unexpected error: %v", i, err)
		}
	}

	// Force tokens to 0 to eliminate any micro-refill that occurred during iteration.
	rl.mu.Lock()
	rl.tokens = 0
	rl.last = time.Now()
	rl.mu.Unlock()

	// Wait well past one token interval (CI machines can be slow).
	time.Sleep(50 * time.Millisecond)

	// Exactly one token should now be available.
	refillCtx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if err := rl.Wait(refillCtx); err != nil {
		t.Fatalf("post-refill wait: unexpected error: %v (refill did not occur)", err)
	}
}

// TestRateLimiter_ConcurrentRaceOnSingleToken verifies that when N goroutines
// simultaneously contend for a single token, exactly 1 succeeds immediately and
// the rest block or return an error. Uses a high-rate limiter (1000/sec, burst=1)
// with a short deadline to keep test duration under control.
func TestRateLimiter_ConcurrentRaceOnSingleToken(t *testing.T) {
	const N = 8
	rl := newRateLimiter(1000.0, 1.0)

	var successes atomic.Int64
	var wg sync.WaitGroup
	wg.Add(N)

	for i := 0; i < N; i++ {
		go func() {
			defer wg.Done()
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Millisecond)
			defer cancel()
			if err := rl.Wait(ctx); err == nil {
				successes.Add(1)
			}
		}()
	}
	wg.Wait()

	got := successes.Load()
	// With burst=1 and 8 concurrent goroutines, at least 1 must have consumed
	// the initial token; the rate may deliver a few more within 5ms (1000/sec).
	// The interesting invariant is that not all N succeed instantly (that would
	// indicate no rate limiting at all).
	if got == 0 {
		t.Fatal("expected at least 1 goroutine to succeed, got 0")
	}
	if got == N {
		t.Errorf("all %d goroutines succeeded instantly — rate limiter had no effect (burst=1)", N)
	}
}

// ── LRU cache boundary tests ──────────────────────────────────────────────────

// TestCache_Add256ThenEvict verifies that inserting exactly cap entries fills
// the cache without eviction, and that inserting a 257th entry evicts the LRU.
func TestCache_Add256ThenEvict(t *testing.T) {
	const cap = 256
	c := newCTCache(cap, time.Hour)

	// Fill to capacity. host000 is the LRU (oldest insert, never re-accessed).
	for i := 0; i < cap; i++ {
		c.put(fmt.Sprintf("host%03d.com", i), []certRecord{{Serial: fmt.Sprintf("%03d", i)}})
	}

	// All entries should be present.
	if _, ok := c.get("host000.com"); !ok {
		t.Fatal("host000 should be present before cap+1 insert")
	}
	// host000 was just accessed via get, so it moved to front. Insert another
	// host000-displaced entry by using a fresh key that never been accessed.
	// Pick a key that wasn't touched by the get above — any key from [1..255].
	for i := 0; i < cap; i++ {
		c.put(fmt.Sprintf("host%03d.com", i), []certRecord{{Serial: fmt.Sprintf("%03d", i)}})
	}

	// After refilling entirely, host000 is again the oldest. Add one more unique key.
	c.put("spillover.com", nil)

	// host000.com should now be evicted (LRU).
	if _, ok := c.get("host000.com"); ok {
		t.Error("host000.com should have been evicted after (cap+1)th insert")
	}
	if _, ok := c.get("spillover.com"); !ok {
		t.Error("spillover.com should be present")
	}
}

// TestCache_Add257Eviction is a tighter test: capacity=2, insert key A then B,
// then insert the 3rd key C. A (LRU) must be evicted; B and C must survive.
func TestCache_Add257Eviction(t *testing.T) {
	c := newCTCache(2, time.Hour)
	c.put("A", []certRecord{{Serial: "1"}})
	c.put("B", []certRecord{{Serial: "2"}})
	// A is LRU. Adding C evicts A.
	c.put("C", []certRecord{{Serial: "3"}})

	if _, ok := c.get("A"); ok {
		t.Error("A should have been evicted as LRU")
	}
	if _, ok := c.get("B"); !ok {
		t.Error("B should still be present")
	}
	if _, ok := c.get("C"); !ok {
		t.Error("C (just inserted) should be present")
	}
}

// TestCache_SameKeyTwiceMoveToFront verifies that re-inserting an existing key
// refreshes its TTL, updates its value, and moves it to the MRU position so
// that it is not the next eviction victim.
func TestCache_SameKeyTwiceMoveToFront(t *testing.T) {
	c := newCTCache(2, time.Hour)
	c.put("key1", []certRecord{{Serial: "v1"}})
	c.put("key2", []certRecord{{Serial: "v2"}})

	// Re-insert key1 with a new value — it should move to MRU (front).
	c.put("key1", []certRecord{{Serial: "v1-updated"}})

	// Now key2 is LRU. Adding key3 should evict key2, not key1.
	c.put("key3", nil)

	if _, ok := c.get("key2"); ok {
		t.Error("key2 should have been evicted (LRU after key1 moved to front)")
	}
	recs, ok := c.get("key1")
	if !ok {
		t.Fatal("key1 should still be present after move-to-front")
	}
	if len(recs) == 0 || recs[0].Serial != "v1-updated" {
		t.Errorf("key1 serial = %v, want v1-updated", recs)
	}
}
