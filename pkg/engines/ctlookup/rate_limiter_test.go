package ctlookup

import (
	"context"
	"testing"
	"time"
)

func TestRateLimiter_ImmediateBurst(t *testing.T) {
	// Burst of 3: the first three calls should succeed without blocking.
	rl := newRateLimiter(1.0, 3.0)
	ctx := context.Background()
	start := time.Now()
	for i := 0; i < 3; i++ {
		if err := rl.Wait(ctx); err != nil {
			t.Fatalf("call %d: unexpected error: %v", i, err)
		}
	}
	if elapsed := time.Since(start); elapsed > 50*time.Millisecond {
		t.Errorf("burst consumed %v, want < 50ms (no blocking expected)", elapsed)
	}
}

func TestRateLimiter_RefillRate(t *testing.T) {
	// After exhausting the burst, the next token should arrive in ~1s.
	rl := newRateLimiter(1.0, 1.0)
	ctx := context.Background()

	// Consume the only token.
	if err := rl.Wait(ctx); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Force-drain any refill that accumulated during the first Wait call.
	rl.mu.Lock()
	rl.tokens = 0
	rl.last = time.Now()
	rl.mu.Unlock()

	// The next token should arrive in ~1s.
	start := time.Now()
	if err := rl.Wait(ctx); err != nil {
		t.Fatalf("second wait: unexpected error: %v", err)
	}
	elapsed := time.Since(start)
	// Allow generous bounds: 800ms–2s.
	if elapsed < 800*time.Millisecond || elapsed > 2*time.Second {
		t.Errorf("second token arrived after %v, expected ~1s", elapsed)
	}
}

func TestRateLimiter_ContextCancel(t *testing.T) {
	rl := newRateLimiter(1.0, 1.0)
	ctx, cancel := context.WithCancel(context.Background())

	// Drain the token.
	_ = rl.Wait(ctx)
	rl.mu.Lock()
	rl.tokens = 0
	rl.last = time.Now()
	rl.mu.Unlock()

	// Cancel immediately so the next Wait returns ctx.Err().
	cancel()

	err := rl.Wait(ctx)
	if err == nil {
		t.Fatal("expected error after context cancellation, got nil")
	}
}

func TestRateLimiter_ConcurrentCallers(t *testing.T) {
	// 5 goroutines share a rate limiter with burst 5, rate 10/sec.
	// All should succeed in a short window without data races.
	rl := newRateLimiter(10.0, 5.0)
	ctx := context.Background()

	done := make(chan error, 5)
	for i := 0; i < 5; i++ {
		go func() {
			done <- rl.Wait(ctx)
		}()
	}
	for i := 0; i < 5; i++ {
		if err := <-done; err != nil {
			t.Errorf("goroutine %d: unexpected error: %v", i, err)
		}
	}
}
