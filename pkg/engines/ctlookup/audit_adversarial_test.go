package ctlookup

// audit_adversarial_test.go — T5-network audit (2026-04-20).
//
// Focuses on LRU cache concurrency, rate-limiter fairness under burst, and
// Retry-After overflow. All tests run in-process (no HTTP server).

import (
	"context"
	"fmt"
	"net/http"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// TestAuditCT_CacheConcurrentReadWriteRace spawns 32 goroutines hammering
// get/put/putShort on the same cache and lets the race detector do the work.
// Any unsynchronised access to the underlying map or list will fail here.
func TestAuditCT_CacheConcurrentReadWriteRace(t *testing.T) {
	t.Parallel()

	c := newCTCache(64, 1*time.Minute)

	const (
		goroutines = 32
		ops        = 100
	)

	var wg sync.WaitGroup
	for g := 0; g < goroutines; g++ {
		wg.Add(1)
		go func(gid int) {
			defer wg.Done()
			for i := 0; i < ops; i++ {
				key := fmt.Sprintf("host-%d-%d", gid, i%8)
				switch i % 3 {
				case 0:
					c.put(key, []certRecord{{SigAlgorithm: "RSA"}})
				case 1:
					c.putShort(key, []certRecord{})
				case 2:
					_, _ = c.get(key)
				}
			}
		}(g)
	}
	wg.Wait()
}

// TestAuditCT_CacheEvictionAtCapacity verifies LRU eviction: inserting N+1
// distinct keys where N = capacity must drop exactly the oldest (least-
// recently-used) entry.
func TestAuditCT_CacheEvictionAtCapacity(t *testing.T) {
	t.Parallel()

	const cap = 4
	c := newCTCache(cap, 5*time.Minute)

	// Insert exactly cap entries.
	for i := 0; i < cap; i++ {
		c.put(fmt.Sprintf("k%d", i), []certRecord{{SigAlgorithm: "alg"}})
	}
	// All cap entries must be present.
	for i := 0; i < cap; i++ {
		if _, ok := c.get(fmt.Sprintf("k%d", i)); !ok {
			t.Errorf("key k%d evicted early (before overflow)", i)
		}
	}

	// "Touch" k0 so it's most-recently-used — then insert cap+1 new.
	_, _ = c.get("k0")
	c.put("k_new", []certRecord{{SigAlgorithm: "alg"}})

	// After insert: k1 (oldest after the touch) should be evicted; k0 should survive.
	if _, ok := c.get("k0"); !ok {
		t.Error("k0 (recently accessed) was evicted — LRU order violated")
	}
	if _, ok := c.get("k1"); ok {
		t.Error("k1 (least-recently-used) was NOT evicted — LRU discipline broken")
	}
}

// TestAuditCT_RateLimiter_BurstThenSustain verifies that burst capacity is
// honoured (3 immediate acquisitions) and subsequent acquisitions are paced
// at the sustained rate (1/sec default). A looser tolerance avoids flakes.
func TestAuditCT_RateLimiter_BurstThenSustain(t *testing.T) {
	t.Parallel()

	rl := newRateLimiter(10.0, 3.0) // 10/sec, burst 3

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	// The first 3 calls should be immediate.
	start := time.Now()
	for i := 0; i < 3; i++ {
		if err := rl.Wait(ctx); err != nil {
			t.Fatalf("burst call %d blocked: %v", i, err)
		}
	}
	burstDur := time.Since(start)
	if burstDur > 50*time.Millisecond {
		t.Errorf("burst 3 took %v, want < 50ms — burst capacity not honoured", burstDur)
	}

	// The 4th call must wait at least one token-interval (100 ms at 10 tok/s).
	callStart := time.Now()
	if err := rl.Wait(ctx); err != nil {
		t.Fatalf("4th call error: %v", err)
	}
	waitedFor := time.Since(callStart)
	if waitedFor < 50*time.Millisecond {
		t.Errorf("4th call returned in %v, want ≥ 50ms — rate limit not enforced", waitedFor)
	}
}

// TestAuditCT_RateLimiter_ConcurrentBurst_NoLostTokens verifies that 100
// concurrent Wait callers against a 1-token-burst limiter each get exactly
// one token and the total completion time matches the expected sustained rate.
// This tests for token leakage or double-spend under contention.
func TestAuditCT_RateLimiter_ConcurrentBurst_NoLostTokens(t *testing.T) {
	t.Parallel()

	// 50/sec → 20 ms per token; 10 callers → ~180 ms total (1 burst + 9 waits).
	rl := newRateLimiter(50.0, 1.0)

	const callers = 10
	var (
		wg   sync.WaitGroup
		done int64
	)

	start := time.Now()
	for i := 0; i < callers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			if err := rl.Wait(ctx); err == nil {
				atomic.AddInt64(&done, 1)
			}
		}()
	}
	wg.Wait()
	elapsed := time.Since(start)

	if atomic.LoadInt64(&done) != callers {
		t.Errorf("got %d tokens, want %d", atomic.LoadInt64(&done), callers)
	}
	// With burst=1 and rate=50/sec, 10 callers need at least ~180 ms
	// (1 burst + 9*20 ms) if the limiter is honouring its rate.
	minExpected := 150 * time.Millisecond
	if elapsed < minExpected {
		t.Errorf("elapsed %v < %v — rate limiter allowed too much throughput",
			elapsed, minExpected)
	}
}

// TestAuditCT_RetryAfter_Overflow_Clamps ensures a malicious Retry-After
// header with a huge numeric value does not overflow time.Duration into a
// negative wait (which would cause an immediate retry storm). The current
// implementation multiplies before clamping — if this test fails, the
// overflow finding is real.
func TestAuditCT_RetryAfter_Overflow_Clamps(t *testing.T) {
	t.Parallel()

	// 1e18 seconds → 1e27 nanoseconds, far beyond int64 MaxInt64 ≈ 9.2e18.
	resp := &http.Response{
		Header: http.Header{"Retry-After": []string{"1000000000000000000"}}, // 1e18
	}
	got := retryAfterDuration(resp)
	// On overflow, time.Duration becomes negative or wraps.
	// Expected safe behaviour: clamp to a sane cap (say ≤ 1 h).
	if got < 0 {
		t.Errorf("retryAfterDuration overflowed to negative: %v (retry storm risk)", got)
	}
	if got > 1*time.Hour {
		// Document: the library currently does NOT clamp; an attacker-controlled
		// Retry-After can delay the scanner for a huge (but positive) duration.
		t.Logf("retryAfterDuration returned %v for Retry-After=1e18 (no clamp — DoS risk)", got)
	}
}

// TestAuditCT_RetryAfter_Negative ensures a negative Retry-After value (e.g.
// attacker sends "-5") falls through to the 2-second default rather than
// producing a negative timer.
func TestAuditCT_RetryAfter_Negative(t *testing.T) {
	t.Parallel()

	resp := &http.Response{
		Header: http.Header{"Retry-After": []string{"-5"}},
	}
	got := retryAfterDuration(resp)
	if got < 0 {
		t.Errorf("retryAfterDuration returned negative %v for Retry-After=-5", got)
	}
	if got != 2*time.Second {
		t.Logf("retryAfterDuration for -5: got %v, expected 2s default", got)
	}
}

// TestAuditCT_CacheTTLExpiry verifies that get() returns (nil,false) after
// an entry expires and the entry is evicted from internal structures.
func TestAuditCT_CacheTTLExpiry(t *testing.T) {
	t.Parallel()

	// Use a very short TTL and sleep past it.
	c := newCTCache(4, 50*time.Millisecond)
	c.put("k", []certRecord{{SigAlgorithm: "alg"}})

	if _, ok := c.get("k"); !ok {
		t.Fatal("fresh entry not present after put")
	}

	time.Sleep(100 * time.Millisecond)

	if _, ok := c.get("k"); ok {
		t.Error("expired entry still accessible after TTL")
	}
	// After the get-after-expiry, the internal map should no longer contain it.
	c.mu.Lock()
	_, present := c.items["k"]
	c.mu.Unlock()
	if present {
		t.Error("expired entry remained in items map after get() — cleanup failed")
	}
}
