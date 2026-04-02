package api

import (
	"context"
	"math/rand"
	"net/http"
	"strconv"
	"time"
)

const (
	maxAttempts    = 3
	baseDelay      = time.Second
	jitterFactor   = 0.25
	maxRetryAfter  = 60 // seconds — cap Retry-After to prevent unbounded waits
)

// retryable returns true for transient HTTP status codes that warrant a retry.
func retryable(status int) bool {
	return status == http.StatusTooManyRequests ||
		status == http.StatusServiceUnavailable ||
		status == http.StatusGatewayTimeout
}

// doWithRetry wraps do() with retry logic using exponential backoff + jitter.
//
// Retry policy:
//   - Max 3 attempts total.
//   - Retries on 429, 503, 504 only.
//   - Exponential backoff: 1s → 2s → 4s with ±25% jitter.
//   - 429 Retry-After header is respected when present and parseable.
//   - Stops immediately on context cancellation.
//   - Returns the last error after all attempts are exhausted.
func (c *Client) doWithRetry(ctx context.Context, method, path string, body interface{}) (*http.Response, error) {
	var (
		resp *http.Response
		err  error
	)

	delay := baseDelay

	for attempt := 0; attempt < maxAttempts; attempt++ {
		// Check context before each attempt.
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}

		resp, err = c.do(ctx, method, path, body)
		if err != nil {
			// Network / context error — do not retry.
			return nil, err
		}

		if !retryable(resp.StatusCode) {
			// Success or a non-transient error — return as-is.
			return resp, nil
		}

		// Last attempt — return the response without sleeping.
		if attempt == maxAttempts-1 {
			return resp, nil
		}

		// Determine sleep duration.
		sleep := retryDelay(resp, delay)
		resp.Body.Close()

		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(sleep):
		}

		delay *= 2
	}

	return resp, err
}

// retryDelay returns the sleep duration before the next retry attempt.
// It respects Retry-After header on 429 responses when parseable.
func retryDelay(resp *http.Response, base time.Duration) time.Duration {
	if resp.StatusCode == http.StatusTooManyRequests {
		if ra := resp.Header.Get("Retry-After"); ra != "" {
			if secs, err := strconv.Atoi(ra); err == nil && secs > 0 {
				if secs > maxRetryAfter {
					secs = maxRetryAfter
				}
				return time.Duration(secs) * time.Second
			}
		}
	}
	return withJitter(base, jitterFactor)
}

// withJitter applies ±factor random jitter to d.
func withJitter(d time.Duration, factor float64) time.Duration {
	jitter := float64(d) * factor * (rand.Float64()*2 - 1) //nolint:gosec // jitter doesn't require crypto rand
	return d + time.Duration(jitter)
}
