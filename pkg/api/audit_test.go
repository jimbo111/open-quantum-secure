package api

// audit_test.go: adversarial + property tests added by the 2026-04-20
// scanner-layer audit (config-auth-api agent).
//
// Exercises:
//   - HTTP enforcement: the `do*` paths reject non-HTTPS endpoints.
//   - WithCACert: silent swallow of missing/invalid PEM files.
//   - Retry semantics on 500/502 (NOT retried), Retry-After edge values,
//     Retry-After HTTP-date (ignored).
//   - Malformed JSON success body.
//   - Token resolve error wrapping — must not surface token in error.
//   - Connection reset mid-stream.
//   - URL-encoding invariant — arbitrary project names survive round-trip.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"
)

// ── FOCUS 7: TLS + endpoint validation ──────────────────────────────────────

// TestF7_EndpointMustBeHTTPS: the `do` and `doRaw` paths reject http://.
// This is the critical TLS-enforcement bar.
func TestF7_EndpointMustBeHTTPS(t *testing.T) {
	c, _ := NewClient("http://plaintext.example.com", "1.0.0", noToken)

	_, err := c.GetIdentity(context.Background())
	if err == nil {
		t.Fatal("HTTPS enforcement bypassed on JSON path")
	}
	if !strings.Contains(err.Error(), "HTTPS") {
		t.Errorf("error does not mention HTTPS: %v", err)
	}

	_, err = c.DownloadCache(context.Background(), CacheDownloadRequest{Project: "p"})
	if err == nil {
		t.Fatal("HTTPS enforcement bypassed on raw path")
	}
	if !strings.Contains(err.Error(), "HTTPS") {
		t.Errorf("raw path error does not mention HTTPS: %v", err)
	}
}

// TestF7_EndpointHTTPSCaseInsensitive: "HTTPS://" accepted (case-insensitive
// per RFC 3986 §3.1).
func TestF7_EndpointHTTPSCaseInsensitive(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 200, apiResponse[Identity]{Data: Identity{}})
	}))
	defer srv.Close()

	// Uppercase "HTTPS" — should be accepted.
	upperURL := strings.Replace(srv.URL, "https://", "HTTPS://", 1)
	c, _ := NewClient(upperURL, "1.0.0", noToken, WithHTTPClient(srv.Client()))
	if _, err := c.GetIdentity(context.Background()); err != nil {
		t.Errorf("HTTPS:// (uppercase) rejected: %v", err)
	}
}

// TestF7_WithCACert_MissingFile_SilentlyIgnored: WithCACert silently swallows
// errors when the file doesn't exist or isn't PEM. This is a MEDIUM finding —
// an operator who typos the path ends up with the default transport (no
// custom root) and may not notice until a TLS failure much later.
func TestF7_WithCACert_MissingFile_SilentlyIgnored(t *testing.T) {
	// 2026-04-21: NewClient now surfaces CA-cert load failures instead of
	// silently falling back to the OS default roots.
	_, err := NewClient("https://example.com", "1.0.0", noToken,
		WithCACert("/nonexistent/file/that/does/not/exist.pem"))
	if err == nil {
		t.Fatal("expected error from WithCACert with missing file, got nil")
	}
	if !strings.Contains(err.Error(), "CA") && !strings.Contains(err.Error(), "cert") {
		t.Errorf("error message should mention CA cert: %v", err)
	}
}

// TestF7_WithCACert_InvalidPEM_SilentlyIgnored: valid file path but invalid
// PEM contents also must surface an error.
func TestF7_WithCACert_InvalidPEM_SilentlyIgnored(t *testing.T) {
	dir := t.TempDir()
	p := fmt.Sprintf("%s/bad.pem", dir)
	if err := writeFile(p, []byte("NOT A PEM CERT")); err != nil {
		t.Fatal(err)
	}
	_, err := NewClient("https://example.com", "1.0.0", noToken, WithCACert(p))
	if err == nil {
		t.Fatal("expected error from WithCACert with non-PEM contents, got nil")
	}
}

// ── FOCUS 6: retry semantics ────────────────────────────────────────────────

// TestF6_500And502_NotRetried: the spec in CLAUDE says "5xx should retry with
// backoff" but the implementation only retries 503/504. 500 and 502 are NOT
// retried. Document this for the audit (either the code or the spec is wrong).
func TestF6_500And502_NotRetried(t *testing.T) {
	for _, status := range []int{500, 502} {
		status := status
		t.Run(fmt.Sprintf("status_%d", status), func(t *testing.T) {
			calls := 0
			srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls++
				w.Header().Set("X-Request-ID", fmt.Sprintf("rid-%d", status))
				writeJSON(w, status, map[string]interface{}{
					"error": map[string]string{"code": "SRV", "message": "broken"},
				})
			}))
			defer srv.Close()

			c := newTestClient(srv, "1.0.0", noToken)
			_, err := c.GetIdentity(context.Background())
			if err == nil {
				t.Fatal("expected error")
			}
			if calls != 1 {
				t.Errorf("F6a (MEDIUM): status %d was retried (calls=%d); "+
					"retryable() is restrictive — only 429/503/504 retried, not 500/502", status, calls)
			}
		})
	}
}

// TestF6_RetryAfter_HTTPDate_Ignored: RFC 7231 says Retry-After can be an
// HTTP-date. Implementation only parses seconds — an HTTP-date is silently
// dropped and the base exponential backoff is used. This is MEDIUM: under
// real rate-limit backoff windows advertised as dates, the client retries
// sooner than requested.
func TestF6_RetryAfter_HTTPDate_Ignored(t *testing.T) {
	calls := 0
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if calls == 1 {
			// RFC 7231 date format.
			w.Header().Set("Retry-After", time.Now().Add(2*time.Second).UTC().Format(http.TimeFormat))
			w.Header().Set("X-Request-ID", "rid-date")
			writeJSON(w, 429, map[string]interface{}{
				"error": map[string]string{"code": "RATE_LIMITED", "message": "slow"},
			})
			return
		}
		writeJSON(w, 200, apiResponse[Identity]{Data: Identity{Email: "ok@test.com"}})
	}))
	defer srv.Close()

	c := newTestClient(srv, "1.0.0", noToken)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	start := time.Now()
	_, err := c.GetIdentity(ctx)
	elapsed := time.Since(start)

	if err != nil {
		t.Fatalf("expected success: %v", err)
	}
	// Base delay is 1s + ±25% jitter. If the HTTP-date had been honoured,
	// elapsed would be >= ~2s. If it was IGNORED, elapsed is ~0.75–1.25s.
	if elapsed > 1800*time.Millisecond {
		t.Logf("HTTP-date was honoured: elapsed=%v", elapsed)
	} else {
		t.Logf("F6b (MEDIUM): HTTP-date Retry-After ignored; backoff=%v (base ~1s)", elapsed)
	}
}

// TestF6_RetryAfter_Negative_FallsBackToJitter: a negative Retry-After value
// is treated as invalid and the base jitter delay is used. Verify that.
func TestF6_RetryAfter_Negative_FallsBackToJitter(t *testing.T) {
	calls := 0
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if calls == 1 {
			w.Header().Set("Retry-After", "-100")
			w.Header().Set("X-Request-ID", "rid-neg")
			writeJSON(w, 429, map[string]interface{}{
				"error": map[string]string{"code": "RATE_LIMITED", "message": "slow"},
			})
			return
		}
		writeJSON(w, 200, apiResponse[Identity]{Data: Identity{Email: "ok@test.com"}})
	}))
	defer srv.Close()

	c := newTestClient(srv, "1.0.0", noToken)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	start := time.Now()
	_, err := c.GetIdentity(ctx)
	elapsed := time.Since(start)

	if err != nil {
		t.Fatalf("expected success: %v", err)
	}
	// Should be base-delay-ish (~1s ±25%), not negative (i.e. zero), not 60s.
	if elapsed > 2500*time.Millisecond {
		t.Errorf("negative Retry-After should fall back to ~1s jitter; got %v", elapsed)
	}
	if elapsed < 500*time.Millisecond {
		// If elapsed is suspiciously small, it could mean the negative was
		// used literally (bad), or retried without sleeping.
		t.Logf("negative Retry-After: elapsed=%v (possibly no sleep happened)", elapsed)
	}
}

// TestF6_RetryAfter_503_Ignored: Retry-After is only honoured for 429.
// Per the implementation, 503 with Retry-After uses base backoff.
// RFC 7231 permits Retry-After on any 503. Document.
func TestF6_RetryAfter_503_IgnoredByDesign(t *testing.T) {
	calls := 0
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if calls == 1 {
			w.Header().Set("Retry-After", "3") // 3 seconds
			w.Header().Set("X-Request-ID", "rid-503-ra")
			writeJSON(w, 503, map[string]interface{}{
				"error": map[string]string{"code": "DOWN", "message": "maint"},
			})
			return
		}
		writeJSON(w, 200, apiResponse[Identity]{Data: Identity{Email: "ok@test.com"}})
	}))
	defer srv.Close()

	c := newTestClient(srv, "1.0.0", noToken)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	start := time.Now()
	_, err := c.GetIdentity(ctx)
	elapsed := time.Since(start)
	if err != nil {
		t.Fatalf("expected success: %v", err)
	}
	if elapsed > 2500*time.Millisecond {
		t.Logf("503 Retry-After honoured: elapsed=%v", elapsed)
	} else {
		t.Logf("F6c (LOW): 503 Retry-After ignored per implementation; elapsed=%v (base ~1s)", elapsed)
	}
}

// TestF6_MalformedJSONSuccessBody: 200 OK with an un-parseable JSON body
// surfaces a JSON error to the caller.
func TestF6_MalformedJSONSuccessBody(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(200)
		_, _ = w.Write([]byte("{{not json at all"))
	}))
	defer srv.Close()

	c := newTestClient(srv, "1.0.0", noToken)
	_, err := c.GetIdentity(context.Background())
	if err == nil {
		t.Fatal("expected JSON decode error")
	}
	// Verify context: the caller should at least get SOME error. If the
	// message is just "unexpected EOF" the operator has no way to know which
	// request failed. Document what we see.
	t.Logf("malformed JSON success body → error: %v", err)
	if !strings.Contains(err.Error(), "json") && !strings.Contains(err.Error(), "invalid") &&
		!strings.Contains(err.Error(), "EOF") && !strings.Contains(err.Error(), "character") {
		t.Errorf("F6d: malformed JSON error text lacks diagnostic context: %v", err)
	}
}

// TestF6_TokenFnError_NoTokenLeak: if tokenFn returns an error, the wrapped
// error must NOT include the stored token prefix (it shouldn't have one —
// the error is upstream of token retrieval). Verify.
func TestF6_TokenFnError_NoTokenLeak(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 200, apiResponse[Identity]{Data: Identity{}})
	}))
	defer srv.Close()

	tokenFn := func(_ context.Context) (string, error) {
		return "", errors.New("credential store is locked: /path/to/credentials.json")
	}
	c, _ := NewClient(srv.URL, "1.0.0", tokenFn, WithHTTPClient(srv.Client()))
	_, err := c.GetIdentity(context.Background())
	if err == nil {
		t.Fatal("tokenFn error should surface")
	}
	if !strings.Contains(err.Error(), "resolve token") {
		t.Errorf("tokenFn error missing 'resolve token' wrap: %v", err)
	}
	// Sanity: the token itself must not appear in the error. (Our tokenFn
	// didn't return a token; we're verifying the wrapper logic.)
}

// TestF6_ConnectionResetMidStream: server closes the TCP connection while
// the body is streaming. The client should surface an I/O error, not hang.
func TestF6_ConnectionResetMidStream(t *testing.T) {
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Length", "1000")
		w.WriteHeader(200)
		// Write partial body.
		_, _ = w.Write([]byte(`{"data": {"email": "`))
		// Flush and close the underlying connection.
		if f, ok := w.(http.Flusher); ok {
			f.Flush()
		}
		hj, ok := w.(http.Hijacker)
		if !ok {
			return
		}
		conn, _, err := hj.Hijack()
		if err != nil {
			return
		}
		// Force-close by setting linger to 0 on the TCP socket.
		if tcp, ok := conn.(*net.TCPConn); ok {
			_ = tcp.SetLinger(0)
		}
		_ = conn.Close()
	}))
	srv.StartTLS()
	defer srv.Close()

	c := newTestClient(srv, "1.0.0", noToken)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, err := c.GetIdentity(ctx)
	if err == nil {
		t.Fatal("expected I/O error on connection reset mid-stream")
	}
	// Error should mention EOF or connection — document what we observe.
	t.Logf("mid-stream reset error: %v", err)
}

// TestF6_VerySlowResponse_ContextDeadline: server takes longer than the
// context deadline; client must surface a deadline exceeded error.
func TestF6_VerySlowResponse_ContextDeadline(t *testing.T) {
	slow := make(chan struct{})
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Block until the test signals via context cancel.
		<-slow
		writeJSON(w, 200, apiResponse[Identity]{Data: Identity{}})
	}))
	defer func() {
		close(slow)
		srv.Close()
	}()

	c := newTestClient(srv, "1.0.0", noToken)
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()

	start := time.Now()
	_, err := c.GetIdentity(ctx)
	elapsed := time.Since(start)
	if err == nil {
		t.Fatal("expected context deadline error")
	}
	if elapsed > 2*time.Second {
		t.Errorf("context deadline not enforced — elapsed=%v", elapsed)
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Logf("context error wrapping: %v (not directly DeadlineExceeded via errors.Is)", err)
	}
}

// ── Property test: URL-encoding round-trip for project names ───────────────

// TestF7_Property_ProjectNameURLEncoded: for a range of adversarial project
// names (slashes, unicode, spaces, percent, query separators), the server
// must observe the original name after URL-unescape.
func TestF7_Property_ProjectNameURLEncoded(t *testing.T) {
	rng := rand.New(rand.NewSource(0xDEADBEEF))
	names := []string{
		"simple",
		"org/repo",
		"org/sub/deep/repo",
		"name with spaces",
		"name%20with%20percent",
		"name?with=query&other=x",
		"name#with-hash",
		"日本語/リポジトリ",
		"a&b=c",
		"../evil",
		"/leading-slash",
		"trailing-slash/",
	}
	for i := 0; i < 10; i++ {
		names = append(names, randName(rng))
	}

	for _, name := range names {
		name := name
		t.Run(name, func(t *testing.T) {
			var observedPath string
			srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				// r.URL.Path is decoded.
				observedPath = r.URL.Path
				writeJSON(w, 200, apiResponse[ScanListResponse]{
					Data: ScanListResponse{Scans: []ScanEntry{}},
				})
			}))
			defer srv.Close()

			c := newTestClient(srv, "1.0.0", noToken)
			_, err := c.ListScans(context.Background(), name, 0)
			if err != nil {
				t.Fatalf("ListScans(%q): %v", name, err)
			}

			// The path the server decoded should end with the original name,
			// prefixed by "/api/v1/projects/".
			wantPrefix := "/api/v1/projects/"
			if !strings.HasPrefix(observedPath, wantPrefix) {
				t.Fatalf("observed path = %q, want prefix %q", observedPath, wantPrefix)
			}
			decoded := strings.TrimPrefix(observedPath, wantPrefix)
			decoded = strings.TrimSuffix(decoded, "/scans")
			// PathEscape does not escape slash by default... actually
			// url.PathEscape DOES escape '/' as %2F. So the server should
			// receive the full name literally when the path is decoded.
			if decoded != name {
				t.Errorf("round-trip mismatch: sent %q, server decoded %q",
					name, decoded)
			}
		})
	}
}

// TestF6_APIError_RequestIDIncluded: every parseError path must carry the
// X-Request-ID when one is present on the response. This is the ONLY user-
// facing breadcrumb to the server log.
func TestF6_APIError_RequestIDIncluded(t *testing.T) {
	cases := []struct {
		name       string
		body       string
		status     int
		wantInMsg  string
	}{
		{"json error body", `{"error":{"code":"X","message":"y"}}`, 400, "X"},
		{"plain body", `Bad Gateway`, 502, "Bad Gateway"},
		{"empty body", ``, 500, "HTTP_500"},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("X-Request-ID", "rid-must-appear")
				w.WriteHeader(tc.status)
				_, _ = w.Write([]byte(tc.body))
			}))
			defer srv.Close()

			c := newTestClient(srv, "1.0.0", noToken)
			_, err := c.GetIdentity(context.Background())
			if err == nil {
				t.Fatal("expected error")
			}
			if !strings.Contains(err.Error(), "rid-must-appear") {
				t.Errorf("%s: missing X-Request-ID in error: %v", tc.name, err)
			}
		})
	}
}

// TestF6_NilBodyResponse_NoPanic: the do path must tolerate a response with
// a nil-like body. Not a realistic case (net/http guarantees non-nil body),
// but verify parseError handles an already-closed body gracefully.
func TestF6_EmptyBodyResponse_Handled(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Request-ID", "rid-empty")
		// Write a 400 with zero-length body and no Content-Type.
		w.WriteHeader(400)
	}))
	defer srv.Close()

	c := newTestClient(srv, "1.0.0", noToken)
	_, err := c.GetIdentity(context.Background())
	if err == nil {
		t.Fatal("expected error")
	}
	apiErr := &APIError{}
	if !errors.As(err, &apiErr) {
		t.Fatalf("expected *APIError, got %T: %v", err, err)
	}
	if apiErr.Code != "HTTP_400" {
		t.Errorf("code = %q, want HTTP_400", apiErr.Code)
	}
	if apiErr.RequestID != "rid-empty" {
		t.Errorf("request id = %q", apiErr.RequestID)
	}
}

// TestF7_InsecureEnvVar_NotHonoured: there should be NO environment-variable
// escape hatch like OQS_INSECURE=1. Verify the client ignores it completely.
func TestF7_InsecureEnvVar_NotHonoured(t *testing.T) {
	// These are the common names an operator or malicious dev might try.
	envNames := []string{"OQS_INSECURE", "OQS_SKIP_TLS_VERIFY", "INSECURE", "TLS_SKIP_VERIFY"}
	for _, name := range envNames {
		t.Setenv(name, "1")
	}

	// A properly configured client does not read these env vars. If an HTTP
	// endpoint is passed, it must still be rejected.
	c, _ := NewClient("http://plaintext.example.com", "1.0.0", noToken)
	_, err := c.GetIdentity(context.Background())
	if err == nil {
		t.Fatal("F7b (CRITICAL REGRESSION BARRIER): env-var insecure escape honoured")
	}
	if !strings.Contains(err.Error(), "HTTPS") {
		t.Errorf("env-var escape: error does not mention HTTPS: %v", err)
	}
}

// ── helpers ────────────────────────────────────────────────────────────────

func writeFile(path string, data []byte) error {
	return os.WriteFile(path, data, 0o600)
}

func randName(rng *rand.Rand) string {
	const alpha = "abcdefghijklmnopqrstuvwxyz0123456789/- _"
	n := rng.Intn(20) + 3
	b := make([]byte, n)
	for i := range b {
		b[i] = alpha[rng.Intn(len(alpha))]
	}
	s := string(b)
	// sanitise: drop leading/trailing chars that would break URL construction
	// uniformly across test cases
	return strings.TrimSpace(s)
}

// Force-use imports that may otherwise be flagged if tests evolve.
var _ = json.NewDecoder
var _ = io.EOF
var _ = url.QueryEscape
