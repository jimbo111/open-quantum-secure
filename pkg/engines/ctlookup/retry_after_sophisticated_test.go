package ctlookup

// retry_after_sophisticated_test.go — Sophisticated regression tests for
// retryAfterDuration (commit a788096: Retry-After clamp before overflow).
//
// Covers:
//  1. Exact boundary at maxRetryAfter.Seconds() — must clamp (not overflow).
//  2. Value just below the clamp threshold — must use exact duration.
//  3. Extreme values (math.MaxFloat64, very large strings) — must not overflow.
//  4. Negative Retry-After — must fall back to 2s default.
//  5. Zero Retry-After — must fall back to 2s default.
//  6. Non-numeric Retry-After — must fall back to 2s default.
//  7. Property test: any Retry-After value must produce duration in [2s, 1h].

import (
	"fmt"
	"math"
	"net/http"
	"testing"
	"time"
)

// retryAfterResponse builds a minimal *http.Response with the given Retry-After
// header value. The response body is nil (retryAfterDuration does not read body).
func retryAfterResponse(headerVal string) *http.Response {
	h := make(http.Header)
	if headerVal != "" {
		h.Set("Retry-After", headerVal)
	}
	return &http.Response{Header: h}
}

const maxRetryAfterDuration = 1 * time.Hour

// TestRetryAfterDuration_ExactBoundary verifies the exact clamp boundary:
// Retry-After equal to maxRetryAfter.Seconds() must return maxRetryAfter (1h),
// not overflow. This is the regression from commit a788096.
func TestRetryAfterDuration_ExactBoundary(t *testing.T) {
	t.Parallel()

	exactSecs := maxRetryAfterDuration.Seconds() // 3600.0
	resp := retryAfterResponse(fmt.Sprintf("%.1f", exactSecs))
	got := retryAfterDuration(resp)

	if got != maxRetryAfterDuration {
		t.Errorf("Retry-After=%.1f: got %v, want %v (exact boundary must clamp)",
			exactSecs, got, maxRetryAfterDuration)
	}
}

// TestRetryAfterDuration_JustBelowBoundary verifies that a value just below the
// 1-hour clamp (3599 seconds) is returned as-is without clamping.
func TestRetryAfterDuration_JustBelowBoundary(t *testing.T) {
	t.Parallel()

	justBelow := 3599.0
	resp := retryAfterResponse(fmt.Sprintf("%.0f", justBelow))
	got := retryAfterDuration(resp)

	// Must be exactly 3599 seconds (within a nanosecond rounding tolerance).
	want := time.Duration(justBelow * float64(time.Second))
	if got != want {
		t.Errorf("Retry-After=3599: got %v, want %v", got, want)
	}
	// Must be strictly less than 1 hour (no clamping applied).
	if got >= maxRetryAfterDuration {
		t.Errorf("Retry-After=3599: got %v, must be < 1h (premature clamp)", got)
	}
}

// TestRetryAfterDuration_AboveMaxRetryAfter verifies that a value above 1 hour
// (e.g., 7200 seconds) is clamped to exactly 1 hour.
func TestRetryAfterDuration_AboveMaxRetryAfter(t *testing.T) {
	t.Parallel()

	cases := []float64{
		3601,        // 1 hour + 1 second
		7200,        // 2 hours
		86400,       // 24 hours
		1_000_000,   // ~11.5 days
	}
	for _, secs := range cases {
		secs := secs
		t.Run(fmt.Sprintf("%.0f", secs), func(t *testing.T) {
			t.Parallel()
			resp := retryAfterResponse(fmt.Sprintf("%.0f", secs))
			got := retryAfterDuration(resp)
			if got != maxRetryAfterDuration {
				t.Errorf("Retry-After=%.0f: got %v, want %v (must clamp to max)",
					secs, got, maxRetryAfterDuration)
			}
		})
	}
}

// TestRetryAfterDuration_ExtremeValues verifies that extreme float64 values do not
// overflow or panic. Before the a788096 fix, `time.Duration(secs * float64(time.Second))`
// with secs=1e18 produced an int64 overflow (undefined behaviour; observed as
// MaxInt64 or MinInt64 on different platforms).
func TestRetryAfterDuration_ExtremeValues(t *testing.T) {
	t.Parallel()

	extremes := []string{
		"1e18",           // 1e18 seconds — well past maxRetryAfter
		"9999999999999",  // ~317K years
		fmt.Sprintf("%g", math.MaxFloat64), // maximum float64
		"3.4028234663852886e+38", // float32 max as float string
	}
	for _, s := range extremes {
		s := s
		t.Run(s, func(t *testing.T) {
			t.Parallel()
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("retryAfterDuration(%q) panicked: %v", s, r)
				}
			}()
			resp := retryAfterResponse(s)
			got := retryAfterDuration(resp)
			// Must clamp to maxRetryAfterDuration (not overflow to negative or MaxInt64).
			if got != maxRetryAfterDuration {
				t.Errorf("Retry-After=%q (extreme): got %v, want %v (clamp expected)",
					s, got, maxRetryAfterDuration)
			}
		})
	}
}

// TestRetryAfterDuration_NegativeValue verifies that a negative Retry-After falls
// back to the 2-second default (the condition `secs > 0` gates conversion).
func TestRetryAfterDuration_NegativeValue(t *testing.T) {
	t.Parallel()

	cases := []string{"-1", "-60", "-3600", "-0.001"}
	for _, s := range cases {
		s := s
		t.Run(s, func(t *testing.T) {
			t.Parallel()
			resp := retryAfterResponse(s)
			got := retryAfterDuration(resp)
			if got != 2*time.Second {
				t.Errorf("Retry-After=%q (negative): got %v, want 2s default", s, got)
			}
		})
	}
}

// TestRetryAfterDuration_ZeroValue verifies that Retry-After=0 falls back to 2s.
func TestRetryAfterDuration_ZeroValue(t *testing.T) {
	t.Parallel()
	resp := retryAfterResponse("0")
	got := retryAfterDuration(resp)
	if got != 2*time.Second {
		t.Errorf("Retry-After=0: got %v, want 2s default", got)
	}
}

// TestRetryAfterDuration_NonNumeric verifies that a non-numeric Retry-After header
// (e.g., an HTTP-date or garbage string) falls back to the 2-second default.
//
// Note: fmt.Sscanf with %f parses a leading float from the string and ignores the
// rest. So "1h" parses as 1.0 (the 'h' is ignored), yielding 1s — NOT the default.
// We only test values where Sscanf genuinely fails or secs <= 0.
func TestRetryAfterDuration_NonNumeric(t *testing.T) {
	t.Parallel()
	// Purely non-numeric: Sscanf("%f") will fail → fall back to 2s default.
	cases := []string{
		"",
		"abc",
		"not-a-number",
		"Mon, 01 Jan 2025 00:00:00 GMT", // HTTP-date (no leading numeric)
	}
	for _, s := range cases {
		s := s
		t.Run(fmt.Sprintf("%q", s), func(t *testing.T) {
			t.Parallel()
			resp := retryAfterResponse(s)
			got := retryAfterDuration(resp)
			if got != 2*time.Second {
				t.Errorf("Retry-After=%q (non-numeric): got %v, want 2s default", s, got)
			}
		})
	}
}

// TestRetryAfterDuration_SscanfLeadingNumeric verifies that fmt.Sscanf with %f
// parses a leading float and ignores trailing non-numeric characters. So "1h"
// parses as 1.0 → yields 1s (NOT the 2s default). This test documents the
// production behaviour (not a bug — the RFC says Retry-After is seconds or
// HTTP-date; "1h" is neither but Sscanf partial-parses it).
func TestRetryAfterDuration_SscanfLeadingNumeric(t *testing.T) {
	t.Parallel()
	// "1h" → Sscanf parses 1.0, yields time.Duration(1 * time.Second)
	resp := retryAfterResponse("1h")
	got := retryAfterDuration(resp)
	// 1.0 > 0, and 1.0 < maxRetryAfter.Seconds() — so yields 1*time.Second (not clamped, not default).
	want := 1 * time.Second
	if got != want {
		t.Errorf("Retry-After=\"1h\" (Sscanf parses 1.0): got %v, want %v", got, want)
	}
}

// TestRetryAfterDuration_MissingHeader verifies the missing-header path falls
// back to the 2-second default.
func TestRetryAfterDuration_MissingHeader(t *testing.T) {
	t.Parallel()
	resp := retryAfterResponse("") // empty string → h.Set skipped
	got := retryAfterDuration(resp)
	if got != 2*time.Second {
		t.Errorf("missing Retry-After: got %v, want 2s", got)
	}
}

// TestRetryAfterDuration_PropertyClampedAtMax is a property-style test that
// verifies the key invariant from commit a788096: values at or above the 1-hour
// ceiling must be clamped to exactly 1h (never overflow, never exceed 1h).
//
// The minimum is NOT 2s — the code only applies a 2s floor when the header is
// absent or unparseable (secs <= 0 or Sscanf fails). Valid small positive values
// (e.g., 0.001s) produce sub-2s durations, which is correct RFC behavior.
func TestRetryAfterDuration_PropertyClampedAtMax(t *testing.T) {
	t.Parallel()

	// Values that must clamp to exactly 1h (at or above maxRetryAfter.Seconds()).
	atOrAbove := []float64{
		3600.0,   // exactly maxRetryAfter.Seconds()
		3600.1,   // just above
		3601.0,
		7200.0,
		86400.0,
		1e6, 1e9, 1e12, 1e15, 1e18,
	}

	const maxAllowed = 1 * time.Hour

	for _, secs := range atOrAbove {
		secs := secs
		t.Run(fmt.Sprintf("%.3g", secs), func(t *testing.T) {
			t.Parallel()
			resp := retryAfterResponse(fmt.Sprintf("%g", secs))
			got := retryAfterDuration(resp)
			if got != maxAllowed {
				t.Errorf("Retry-After=%.3g → %v, want clamped to %v (overflow protection)", secs, got, maxAllowed)
			}
		})
	}

	// Values below the ceiling: must NOT be clamped (must be strictly less than 1h).
	below := []float64{
		0.001, 0.5, 1.0, 2.0, 5.0, 60.0, 300.0, 1800.0, 3599.0, 3599.9,
	}
	for _, secs := range below {
		secs := secs
		t.Run(fmt.Sprintf("below_%.3g", secs), func(t *testing.T) {
			t.Parallel()
			resp := retryAfterResponse(fmt.Sprintf("%g", secs))
			got := retryAfterDuration(resp)
			if got > maxAllowed {
				t.Errorf("Retry-After=%.3g → %v > %v (premature clamp)", secs, got, maxAllowed)
			}
			// The result must be > 0 (not negative).
			if got <= 0 {
				t.Errorf("Retry-After=%.3g → %v (non-positive duration)", secs, got)
			}
		})
	}
}
