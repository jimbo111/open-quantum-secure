// Package ctlookup implements a Tier 5 (Network) engine that queries Certificate
// Transparency logs (crt.sh) to recover certificate signing algorithms on TLS 1.3
// hosts where ECH or ordinary TLS 1.3 hides the Certificate message.
package ctlookup

import (
	"context"
	"sync"
	"time"
)

// rateLimiter implements a token-bucket rate limiter that is safe for concurrent
// use. Default configuration: 1 token/sec sustained with a burst of 3.
type rateLimiter struct {
	mu     sync.Mutex
	tokens float64
	burst  float64
	// rate is tokens per nanosecond — avoids float64 division in the hot path.
	rate float64
	last time.Time
}

func newRateLimiter(ratePerSec, burst float64) *rateLimiter {
	return &rateLimiter{
		tokens: burst,
		burst:  burst,
		rate:   ratePerSec / float64(time.Second),
		last:   time.Now(),
	}
}

// Wait blocks until a token is available or ctx is cancelled.
// Multiple goroutines may call Wait concurrently; the mutex serialises token
// accounting so that the shared rate limit is respected across callers.
func (r *rateLimiter) Wait(ctx context.Context) error {
	for {
		wait, ok := r.tryConsume()
		if ok {
			return nil
		}
		t := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			t.Stop()
			return ctx.Err()
		case <-t.C:
			t.Stop()
		}
	}
}

// tryConsume attempts to consume one token without blocking.
// Returns (waitDuration, false) when no token is available, (0, true) on success.
func (r *rateLimiter) tryConsume() (time.Duration, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	now := time.Now()
	r.tokens += float64(now.Sub(r.last)) * r.rate
	r.last = now
	if r.tokens > r.burst {
		r.tokens = r.burst
	}
	if r.tokens >= 1 {
		r.tokens--
		return 0, true
	}
	// Time until one full token accumulates.
	needed := time.Duration((1.0 - r.tokens) / r.rate)
	return needed, false
}
