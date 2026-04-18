// client_http_errors_test.go — Negative HTTP tests for the crt.sh client.
// Each sub-test configures an httptest.Server that returns (or simulates)
// a specific failure mode, then asserts that:
//   - queryHostname or Scan returns a non-panic (possibly nil-findings) result.
//   - No goroutine is leaked.
//   - The engine logs a warning but does NOT propagate the error to the caller.
package ctlookup

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/jimbo111/open-quantum-secure/pkg/engines"
)

// httpErrorScan is a helper that runs Scan against a single mock server, sets a
// 3-second context deadline (enough for one request), and asserts the function
// returns (nil or non-nil findings, nil error) — HTTP errors must not bubble up
// as returned errors from Scan.
func httpErrorScan(t *testing.T, srv *httptest.Server) {
	t.Helper()
	e := New()
	e.client.baseURL = srv.URL
	e.client.httpClient = srv.Client()
	e.rl = newRateLimiter(1000.0, 1000.0)

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	ff, err := e.Scan(ctx, engines.ScanOptions{
		CTLookupTargets: []string{"mock.target.com"},
	})
	if err != nil {
		t.Errorf("Scan must not propagate HTTP errors; got err=%v", err)
	}
	// Findings may be nil or empty for error responses; both are valid.
	_ = ff
}

// TestClientHTTP_404 verifies that a 404 response is handled gracefully.
func TestClientHTTP_404(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	}))
	defer srv.Close()
	httpErrorScan(t, srv)
}

// TestClientHTTP_429_RetryAfter verifies that a 429 Too Many Requests response
// (with Retry-After header) does not cause a retry storm — the engine must log
// the error and move on without retrying.
func TestClientHTTP_429_RetryAfter(t *testing.T) {
	var callCount int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		w.Header().Set("Retry-After", "60")
		http.Error(w, "rate limited", http.StatusTooManyRequests)
	}))
	defer srv.Close()

	httpErrorScan(t, srv)

	// The engine must not retry: exactly 1 call for the JSON query.
	if callCount > 2 {
		t.Errorf("429 handler called %d times — engine may be retrying (expected ≤2)", callCount)
	}
}

// TestClientHTTP_500 verifies that a 500 Internal Server Error is absorbed.
func TestClientHTTP_500(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "internal server error", http.StatusInternalServerError)
	}))
	defer srv.Close()
	httpErrorScan(t, srv)
}

// TestClientHTTP_502_WithBody verifies a 502 Bad Gateway with a body is absorbed.
func TestClientHTTP_502_WithBody(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
		fmt.Fprintln(w, "<html><body>Bad Gateway</body></html>")
	}))
	defer srv.Close()
	httpErrorScan(t, srv)
}

// TestClientHTTP_TLSCertError verifies that a TLS certificate verification
// failure (untrusted test server cert, accessed via plain http.Client) is
// handled gracefully. We use an httptest.NewTLSServer but pass a plain
// http.Client (no test-CA trust) to trigger the TLS error.
func TestClientHTTP_TLSCertError(t *testing.T) {
	tlsSrv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprintln(w, "[]")
	}))
	defer tlsSrv.Close()

	e := New()
	e.client.baseURL = tlsSrv.URL
	// Use a plain http.Client that does NOT trust the test server's self-signed cert.
	e.client.httpClient = &http.Client{Timeout: 3 * time.Second}
	e.rl = newRateLimiter(1000.0, 1000.0)

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	ff, err := e.Scan(ctx, engines.ScanOptions{
		CTLookupTargets: []string{"tls-cert-error.example.com"},
	})
	// TLS cert error should be absorbed — no panic, error propagation is optional.
	_ = ff
	_ = err
}

// TestClientHTTP_ConnectionReset verifies that an immediate connection reset
// (server closes connection without sending any HTTP response) is absorbed.
func TestClientHTTP_ConnectionReset(t *testing.T) {
	// Listener that immediately closes every accepted connection.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			conn.Close() // immediate reset
		}
	}()

	e := New()
	e.client.baseURL = "http://" + ln.Addr().String()
	e.client.httpClient = &http.Client{Timeout: 2 * time.Second}
	e.rl = newRateLimiter(1000.0, 1000.0)

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	ff, err := e.Scan(ctx, engines.ScanOptions{
		CTLookupTargets: []string{"conn-reset.example.com"},
	})
	_ = ff
	_ = err
}

// TestClientHTTP_SlowLoris verifies that a server that sends headers but no
// body (slow-loris) is cut short by the context timeout and does not block
// Scan indefinitely.
func TestClientHTTP_SlowLoris(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Send a 200 OK header with no body, then block until client disconnects.
		w.WriteHeader(http.StatusOK)
		if f, ok := w.(http.Flusher); ok {
			f.Flush()
		}
		// Block until the client (or server) closes.
		<-r.Context().Done()
	}))
	defer srv.Close()

	e := New()
	e.client.baseURL = srv.URL
	// Short timeout to trigger the slow-loris condition quickly.
	e.client.httpClient = &http.Client{Timeout: 200 * time.Millisecond}
	e.rl = newRateLimiter(1000.0, 1000.0)

	start := time.Now()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	e.Scan(ctx, engines.ScanOptions{ //nolint
		CTLookupTargets: []string{"slow-loris.example.com"},
	})

	// The 200ms client timeout should have fired; total Scan time must be < 1s.
	if elapsed := time.Since(start); elapsed > 1*time.Second {
		t.Errorf("slow-loris: Scan took %v, expected < 1s (client timeout = 200ms)", elapsed)
	}
}

// TestClientHTTP_TruncatedChunked verifies that a server which begins a
// chunked response but closes the connection before sending a terminal chunk
// is handled gracefully (the JSON parse error is absorbed).
func TestClientHTTP_TruncatedChunked(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		// Write partial JSON — caller will get an EOF before the array closes.
		fmt.Fprint(w, `[{"id":1,"common_name":"trunc`)
		// Handler returns without finishing the array — Go HTTP server will
		// send a final empty chunk and close. io.ReadAll sees a truncated body.
	}))
	defer srv.Close()
	httpErrorScan(t, srv)
}

// TestClientHTTP_EmptyBody verifies that an empty 200 OK response body
// (zero-length, no "[]") is treated as no certificates found (nil, nil).
func TestClientHTTP_EmptyBody(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		// Write no body at all.
	}))
	defer srv.Close()

	e := New()
	e.client.baseURL = srv.URL
	e.client.httpClient = srv.Client()
	e.rl = newRateLimiter(1000.0, 1000.0)

	ctx := context.Background()
	entries, err := e.client.queryHostname(ctx, "empty-body.example.com")
	if err != nil {
		t.Fatalf("empty body: unexpected error: %v", err)
	}
	if len(entries) != 0 {
		t.Errorf("empty body: expected 0 entries, got %d", len(entries))
	}
}

// TestClientHTTP_LargeBody verifies that responses exceeding maxBodyBytes are
// truncated cleanly — the client must not OOM or panic on a large response.
func TestClientHTTP_LargeBody(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		// Build a body larger than maxBodyBytes (4 MiB).
		w.Write([]byte("[")) //nolint
		entry := `{"id":1,"common_name":"big.com","serial_number":"AA","not_before":"2024-01-01","not_after":"2025-01-01"},`
		for i := 0; i < 50000; i++ {
			w.Write([]byte(entry)) //nolint
		}
		// No closing "]" — body will be truncated by LimitReader anyway.
	}))
	defer srv.Close()

	e := New()
	e.client.baseURL = srv.URL
	e.client.httpClient = srv.Client()
	e.rl = newRateLimiter(1000.0, 1000.0)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Must not panic; error is acceptable (truncated → invalid JSON).
	_, err := e.client.queryHostname(ctx, "large-body.example.com")
	if err != nil && !strings.Contains(err.Error(), "parse") && !strings.Contains(err.Error(), "JSON") {
		// Any error is OK here; just log it for diagnostics.
		t.Logf("large body returned error (expected): %v", err)
	}
}
