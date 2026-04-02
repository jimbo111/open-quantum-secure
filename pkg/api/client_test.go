package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// noToken is a tokenFn that always returns an empty token (anonymous).
func noToken(_ context.Context) (string, error) { return "", nil }

// fixedToken returns a tokenFn that always returns the given token.
func fixedToken(tok string) func(context.Context) (string, error) {
	return func(_ context.Context) (string, error) { return tok, nil }
}

// newTestClient creates a Client that trusts the TLS server's certificate.
func newTestClient(srv *httptest.Server, version string, tokenFn func(context.Context) (string, error), opts ...ClientOption) *Client {
	all := append([]ClientOption{WithHTTPClient(srv.Client())}, opts...)
	return NewClient(srv.URL, version, tokenFn, all...)
}

// writeJSON encodes v as JSON to w with the given status code.
func writeJSON(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// ---- Client header tests ----

func TestClientHeaders(t *testing.T) {
	t.Run("standard headers set", func(t *testing.T) {
		var captured *http.Request
		srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			captured = r
			writeJSON(w, 200, apiResponse[Identity]{Data: Identity{Email: "a@b.com"}})
		}))
		defer srv.Close()

		c := newTestClient(srv, "1.2.3", noToken)
		_, _ = c.GetIdentity(context.Background())

		// Content-Type should NOT be set on bodyless GET requests.
		if got := captured.Header.Get("Content-Type"); got != "" {
			t.Errorf("Content-Type on GET: got %q, want empty", got)
		}
		if got := captured.Header.Get("Accept"); got != "application/json" {
			t.Errorf("Accept: got %q", got)
		}
		if got := captured.Header.Get("User-Agent"); !strings.HasPrefix(got, "oqs-scanner/1.2.3") {
			t.Errorf("User-Agent: got %q", got)
		}
		if got := captured.Header.Get("X-Request-ID"); got == "" {
			t.Error("X-Request-ID: not set")
		}
	})

	t.Run("content-type set on POST with body", func(t *testing.T) {
		var captured *http.Request
		srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			captured = r
			writeJSON(w, 200, apiResponse[UploadResponse]{Data: UploadResponse{ScanID: "s1"}})
		}))
		defer srv.Close()

		c := newTestClient(srv, "1.0.0", noToken)
		_, _ = c.UploadCBOM(context.Background(), UploadRequest{Project: "p"})

		if got := captured.Header.Get("Content-Type"); got != "application/json" {
			t.Errorf("Content-Type on POST: got %q, want %q", got, "application/json")
		}
	})

	t.Run("authorization header set when token present", func(t *testing.T) {
		var captured *http.Request
		srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			captured = r
			writeJSON(w, 200, apiResponse[Identity]{Data: Identity{Email: "a@b.com"}})
		}))
		defer srv.Close()

		c := newTestClient(srv, "1.0.0", fixedToken("tok-secret"))
		_, _ = c.GetIdentity(context.Background())

		if got := captured.Header.Get("Authorization"); got != "Bearer tok-secret" {
			t.Errorf("Authorization: got %q, want %q", got, "Bearer tok-secret")
		}
	})

	t.Run("authorization header absent when token empty", func(t *testing.T) {
		var captured *http.Request
		srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			captured = r
			writeJSON(w, 200, apiResponse[Identity]{Data: Identity{Email: "a@b.com"}})
		}))
		defer srv.Close()

		c := newTestClient(srv, "1.0.0", noToken)
		_, _ = c.GetIdentity(context.Background())

		if got := captured.Header.Get("Authorization"); got != "" {
			t.Errorf("Authorization: expected absent, got %q", got)
		}
	})

	t.Run("request body correctly serialized", func(t *testing.T) {
		var body map[string]interface{}
		srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_ = json.NewDecoder(r.Body).Decode(&body)
			writeJSON(w, 201, apiResponse[UploadResponse]{Data: UploadResponse{ScanID: "s1"}})
		}))
		defer srv.Close()

		c := newTestClient(srv, "1.0.0", noToken)
		req := UploadRequest{Project: "myproj", Branch: "main", CommitSHA: "abc123", ScanMode: "full"}
		_, _ = c.UploadCBOM(context.Background(), req)

		if body["project"] != "myproj" {
			t.Errorf("project field: got %v", body["project"])
		}
		if body["branch"] != "main" {
			t.Errorf("branch field: got %v", body["branch"])
		}
		if body["commitSha"] != "abc123" {
			t.Errorf("commitSha field: got %v", body["commitSha"])
		}
	})

	t.Run("X-Request-ID unique per request", func(t *testing.T) {
		ids := make([]string, 0, 3)
		srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ids = append(ids, r.Header.Get("X-Request-ID"))
			writeJSON(w, 200, apiResponse[Identity]{Data: Identity{}})
		}))
		defer srv.Close()

		c := newTestClient(srv, "1.0.0", noToken)
		for i := 0; i < 3; i++ {
			_, _ = c.GetIdentity(context.Background())
		}

		seen := map[string]bool{}
		for _, id := range ids {
			if seen[id] {
				t.Errorf("duplicate X-Request-ID: %s", id)
			}
			seen[id] = true
		}
	})
}

// ---- Retry tests ----

func TestRetry(t *testing.T) {
	t.Run("200 does not retry", func(t *testing.T) {
		calls := 0
		srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			calls++
			writeJSON(w, 200, apiResponse[Identity]{Data: Identity{Email: "x@y.com"}})
		}))
		defer srv.Close()

		c := newTestClient(srv, "1.0.0", noToken)
		_, err := c.GetIdentity(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		if calls != 1 {
			t.Errorf("expected 1 call, got %d", calls)
		}
	})

	t.Run("400 does not retry", func(t *testing.T) {
		calls := 0
		srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			calls++
			w.Header().Set("X-Request-ID", "rid-400")
			writeJSON(w, 400, map[string]interface{}{
				"error": map[string]string{"code": "BAD_REQUEST", "message": "bad"},
			})
		}))
		defer srv.Close()

		c := newTestClient(srv, "1.0.0", noToken)
		_, err := c.GetIdentity(context.Background())
		if err == nil {
			t.Fatal("expected error")
		}
		if calls != 1 {
			t.Errorf("expected 1 call, got %d", calls)
		}
	})

	t.Run("503 retries 3 times then fails", func(t *testing.T) {
		calls := 0
		srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			calls++
			w.Header().Set("X-Request-ID", "rid-503")
			writeJSON(w, 503, map[string]interface{}{
				"error": map[string]string{"code": "SERVICE_UNAVAILABLE", "message": "down"},
			})
		}))
		defer srv.Close()

		c := newTestClient(srv, "1.0.0", noToken)
		// Use very short backoff via context timeout to avoid long test.
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		// Patch delays to near-zero by using a test-scoped context.
		// Because we can't inject delay fn, we rely on context timeout
		// to bound test duration (retry delays are at most 1.25s each).
		_, err := c.GetIdentity(ctx)
		if err == nil {
			t.Fatal("expected error after 3 retries")
		}
		if calls != maxAttempts {
			t.Errorf("expected %d calls, got %d", maxAttempts, calls)
		}
	})

	t.Run("429 retries with backoff", func(t *testing.T) {
		calls := 0
		srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			calls++
			if calls < maxAttempts {
				w.Header().Set("X-Request-ID", "rid-429")
				writeJSON(w, 429, map[string]interface{}{
					"error": map[string]string{"code": "RATE_LIMITED", "message": "slow down"},
				})
				return
			}
			writeJSON(w, 200, apiResponse[Identity]{Data: Identity{Email: "ok@test.com"}})
		}))
		defer srv.Close()

		c := newTestClient(srv, "1.0.0", noToken)
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		ident, err := c.GetIdentity(ctx)
		if err != nil {
			t.Fatalf("expected success after retries: %v", err)
		}
		if ident.Email != "ok@test.com" {
			t.Errorf("identity email: got %q", ident.Email)
		}
		if calls != maxAttempts {
			t.Errorf("expected %d calls, got %d", maxAttempts, calls)
		}
	})

	t.Run("429 respects Retry-After header", func(t *testing.T) {
		calls := 0
		srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			calls++
			if calls == 1 {
				w.Header().Set("Retry-After", "1")
				w.Header().Set("X-Request-ID", "rid-ra")
				writeJSON(w, 429, map[string]interface{}{
					"error": map[string]string{"code": "RATE_LIMITED", "message": "slow"},
				})
				return
			}
			writeJSON(w, 200, apiResponse[Identity]{Data: Identity{Email: "retry@ok.com"}})
		}))
		defer srv.Close()

		c := newTestClient(srv, "1.0.0", noToken)
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		start := time.Now()
		ident, err := c.GetIdentity(ctx)
		elapsed := time.Since(start)

		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if ident.Email != "retry@ok.com" {
			t.Errorf("identity email: got %q", ident.Email)
		}
		// Retry-After: 1 second — elapsed should be at least 900ms.
		if elapsed < 900*time.Millisecond {
			t.Errorf("expected at least 900ms delay, got %v", elapsed)
		}
	})

	t.Run("context cancellation stops retries", func(t *testing.T) {
		calls := 0
		srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			calls++
			w.Header().Set("X-Request-ID", "rid-ctx")
			writeJSON(w, 503, map[string]interface{}{
				"error": map[string]string{"code": "DOWN", "message": "unavailable"},
			})
		}))
		defer srv.Close()

		c := newTestClient(srv, "1.0.0", noToken)
		ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
		defer cancel()

		_, err := c.GetIdentity(ctx)
		if err == nil {
			t.Fatal("expected context error")
		}
		// Should have cancelled after the first attempt + short sleep.
		if calls > maxAttempts {
			t.Errorf("too many calls: %d", calls)
		}
	})
}

// ---- Upload tests ----

func TestUploadCBOM(t *testing.T) {
	t.Run("successful upload returns UploadResponse", func(t *testing.T) {
		srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodPost || r.URL.Path != "/api/v1/scans" {
				t.Errorf("unexpected: %s %s", r.Method, r.URL.Path)
			}
			writeJSON(w, 201, apiResponse[UploadResponse]{
				Data: UploadResponse{
					ScanID:                "scan-123",
					DashboardURL:          "https://dashboard.oqs.dev/s/scan-123",
					QuantumReadinessScore: 72,
					QuantumReadinessGrade: "B",
					FindingSummary:        FindingSummary{Total: 5, High: 2},
				},
			})
		}))
		defer srv.Close()

		c := newTestClient(srv, "1.0.0", noToken)
		result, err := c.UploadCBOM(context.Background(), UploadRequest{
			Project: "acme", Branch: "main", CommitSHA: "deadbeef", ScanMode: "full",
		})
		if err != nil {
			t.Fatal(err)
		}
		if result.ScanID != "scan-123" {
			t.Errorf("ScanID: got %q", result.ScanID)
		}
		if result.QuantumReadinessScore != 72 {
			t.Errorf("QRS: got %d", result.QuantumReadinessScore)
		}
		if result.FindingSummary.High != 2 {
			t.Errorf("High findings: got %d", result.FindingSummary.High)
		}
	})

	t.Run("401 returns auth error", func(t *testing.T) {
		srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("X-Request-ID", "req-401")
			writeJSON(w, 401, map[string]interface{}{
				"error": map[string]string{"code": "UNAUTHORIZED", "message": "invalid token"},
			})
		}))
		defer srv.Close()

		c := newTestClient(srv, "1.0.0", noToken)
		_, err := c.UploadCBOM(context.Background(), UploadRequest{Project: "p"})
		if err == nil {
			t.Fatal("expected error")
		}
		apiErr, ok := err.(*APIError)
		if !ok {
			t.Fatalf("expected *APIError, got %T: %v", err, err)
		}
		if apiErr.Code != "UNAUTHORIZED" {
			t.Errorf("code: got %q", apiErr.Code)
		}
		if apiErr.RequestID != "req-401" {
			t.Errorf("request ID: got %q", apiErr.RequestID)
		}
	})

	t.Run("413 returns CBOM too large error", func(t *testing.T) {
		srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("X-Request-ID", "req-413")
			writeJSON(w, 413, map[string]interface{}{
				"error": map[string]string{"code": "PAYLOAD_TOO_LARGE", "message": "CBOM too large"},
			})
		}))
		defer srv.Close()

		c := newTestClient(srv, "1.0.0", noToken)
		_, err := c.UploadCBOM(context.Background(), UploadRequest{Project: "p"})
		if err == nil {
			t.Fatal("expected error")
		}
		apiErr, ok := err.(*APIError)
		if !ok {
			t.Fatalf("expected *APIError, got %T", err)
		}
		if apiErr.Code != "PAYLOAD_TOO_LARGE" {
			t.Errorf("code: got %q", apiErr.Code)
		}
		if !strings.Contains(apiErr.Message, "large") {
			t.Errorf("message: got %q", apiErr.Message)
		}
	})

	t.Run("409 returns scan duplicate error", func(t *testing.T) {
		srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("X-Request-ID", "req-409")
			writeJSON(w, 409, map[string]interface{}{
				"error": map[string]string{"code": "DUPLICATE_SCAN", "message": "scan duplicate"},
			})
		}))
		defer srv.Close()

		c := newTestClient(srv, "1.0.0", noToken)
		_, err := c.UploadCBOM(context.Background(), UploadRequest{Project: "p"})
		if err == nil {
			t.Fatal("expected error")
		}
		apiErr, ok := err.(*APIError)
		if !ok {
			t.Fatalf("expected *APIError, got %T", err)
		}
		if apiErr.Code != "DUPLICATE_SCAN" {
			t.Errorf("code: got %q", apiErr.Code)
		}
	})
}

// ---- History tests ----

func TestListScans(t *testing.T) {
	t.Run("returns paginated results", func(t *testing.T) {
		srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			writeJSON(w, 200, apiResponse[ScanListResponse]{
				Data: ScanListResponse{
					Scans: []ScanEntry{
						{ScanID: "s1", Branch: "main"},
						{ScanID: "s2", Branch: "dev"},
					},
					Pagination: struct {
						Cursor  string `json:"cursor"`
						HasMore bool   `json:"hasMore"`
					}{Cursor: "tok-next", HasMore: true},
				},
			})
		}))
		defer srv.Close()

		c := newTestClient(srv, "1.0.0", noToken)
		result, err := c.ListScans(context.Background(), "myproject", 10)
		if err != nil {
			t.Fatal(err)
		}
		if len(result.Scans) != 2 {
			t.Errorf("scans count: got %d", len(result.Scans))
		}
		if result.Scans[0].ScanID != "s1" {
			t.Errorf("first scan ID: got %q", result.Scans[0].ScanID)
		}
		if !result.Pagination.HasMore {
			t.Error("HasMore should be true")
		}
	})

	t.Run("empty project name returns error", func(t *testing.T) {
		c := NewClient("http://localhost", "1.0.0", noToken)
		_, err := c.ListScans(context.Background(), "", 10)
		if err == nil {
			t.Fatal("expected error for empty project")
		}
	})

	t.Run("project with slash properly URL-encoded", func(t *testing.T) {
		var capturedRawPath string
		srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// RawPath preserves percent-encoding; Path is the decoded form.
			capturedRawPath = r.URL.RawPath
			if capturedRawPath == "" {
				// No special encoding in path — fall back to decoded path.
				capturedRawPath = r.URL.Path
			}
			writeJSON(w, 200, apiResponse[ScanListResponse]{
				Data: ScanListResponse{Scans: []ScanEntry{}},
			})
		}))
		defer srv.Close()

		c := newTestClient(srv, "1.0.0", noToken)
		_, err := c.ListScans(context.Background(), "org/repo", 5)
		if err != nil {
			t.Fatal(err)
		}
		// org/repo should appear as org%2Frepo in the raw path.
		if !strings.Contains(capturedRawPath, "org%2Frepo") {
			t.Errorf("path not URL-encoded: got %q", capturedRawPath)
		}
	})
}

// ---- Identity tests ----

func TestGetIdentity(t *testing.T) {
	t.Run("success returns Identity struct", func(t *testing.T) {
		srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/api/v1/auth/me" {
				t.Errorf("unexpected path: %s", r.URL.Path)
			}
			writeJSON(w, 200, apiResponse[Identity]{
				Data: Identity{
					Email:    "alice@example.com",
					Org:      "acme-corp",
					Plan:     "enterprise",
					Endpoint: "https://api.oqs.dev",
				},
			})
		}))
		defer srv.Close()

		c := newTestClient(srv, "1.0.0", fixedToken("secret"))
		ident, err := c.GetIdentity(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		if ident.Email != "alice@example.com" {
			t.Errorf("email: got %q", ident.Email)
		}
		if ident.Org != "acme-corp" {
			t.Errorf("org: got %q", ident.Org)
		}
		if ident.Plan != "enterprise" {
			t.Errorf("plan: got %q", ident.Plan)
		}
	})

	t.Run("401 returns auth error", func(t *testing.T) {
		srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("X-Request-ID", "rid-me-401")
			writeJSON(w, 401, map[string]interface{}{
				"error": map[string]string{"code": "UNAUTHORIZED", "message": "not authenticated"},
			})
		}))
		defer srv.Close()

		c := newTestClient(srv, "1.0.0", noToken)
		_, err := c.GetIdentity(context.Background())
		if err == nil {
			t.Fatal("expected error")
		}
		apiErr, ok := err.(*APIError)
		if !ok {
			t.Fatalf("expected *APIError, got %T: %v", err, err)
		}
		if apiErr.Code != "UNAUTHORIZED" {
			t.Errorf("code: got %q", apiErr.Code)
		}
		if apiErr.RequestID != "rid-me-401" {
			t.Errorf("request ID: got %q", apiErr.RequestID)
		}
	})
}

// ---- Error parsing tests ----

func TestParseError(t *testing.T) {
	t.Run("valid JSON error response returns APIError", func(t *testing.T) {
		srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("X-Request-ID", "rid-json")
			writeJSON(w, 422, map[string]interface{}{
				"error": map[string]string{
					"code":    "VALIDATION_ERROR",
					"message": "field 'project' is required",
				},
			})
		}))
		defer srv.Close()

		c := newTestClient(srv, "1.0.0", noToken)
		_, err := c.GetIdentity(context.Background())
		apiErr, ok := err.(*APIError)
		if !ok {
			t.Fatalf("expected *APIError, got %T: %v", err, err)
		}
		if apiErr.Code != "VALIDATION_ERROR" {
			t.Errorf("code: got %q", apiErr.Code)
		}
		if apiErr.Message != "field 'project' is required" {
			t.Errorf("message: got %q", apiErr.Message)
		}
		if apiErr.RequestID != "rid-json" {
			t.Errorf("requestID: got %q", apiErr.RequestID)
		}
	})

	t.Run("non-JSON body produces fallback error with body text", func(t *testing.T) {
		srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("X-Request-ID", "rid-plain")
			w.WriteHeader(502)
			_, _ = w.Write([]byte("Bad Gateway from proxy"))
		}))
		defer srv.Close()

		c := newTestClient(srv, "1.0.0", noToken)
		_, err := c.GetIdentity(context.Background())
		apiErr, ok := err.(*APIError)
		if !ok {
			t.Fatalf("expected *APIError, got %T: %v", err, err)
		}
		if !strings.Contains(apiErr.Message, "Bad Gateway from proxy") {
			t.Errorf("message: got %q", apiErr.Message)
		}
		if apiErr.RequestID != "rid-plain" {
			t.Errorf("requestID: got %q", apiErr.RequestID)
		}
	})

	t.Run("empty body returns generic error with status code", func(t *testing.T) {
		srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("X-Request-ID", "rid-empty")
			w.WriteHeader(500)
		}))
		defer srv.Close()

		c := newTestClient(srv, "1.0.0", noToken)
		_, err := c.GetIdentity(context.Background())
		apiErr, ok := err.(*APIError)
		if !ok {
			t.Fatalf("expected *APIError, got %T: %v", err, err)
		}
		if !strings.Contains(apiErr.Code, "500") {
			t.Errorf("code: expected 500, got %q", apiErr.Code)
		}
		if apiErr.RequestID != "rid-empty" {
			t.Errorf("requestID: got %q", apiErr.RequestID)
		}
	})

	t.Run("X-Request-ID included in error message", func(t *testing.T) {
		srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("X-Request-ID", "rid-msg-check")
			writeJSON(w, 403, map[string]interface{}{
				"error": map[string]string{"code": "FORBIDDEN", "message": "access denied"},
			})
		}))
		defer srv.Close()

		c := newTestClient(srv, "1.0.0", noToken)
		_, err := c.GetIdentity(context.Background())
		if err == nil {
			t.Fatal("expected error")
		}
		errMsg := err.Error()
		if !strings.Contains(errMsg, "rid-msg-check") {
			t.Errorf("error message does not contain request ID: %q", errMsg)
		}
	})
}

// ---- generateRequestID tests ----

func TestGenerateRequestID(t *testing.T) {
	t.Run("UUID v4 format 8-4-4-4-12", func(t *testing.T) {
		id, err := generateRequestID()
		if err != nil {
			t.Fatal(err)
		}
		parts := strings.Split(id, "-")
		if len(parts) != 5 {
			t.Fatalf("expected 5 parts, got %d: %q", len(parts), id)
		}
		lengths := []int{8, 4, 4, 4, 12}
		for i, p := range parts {
			if len(p) != lengths[i] {
				t.Errorf("part %d: expected len %d, got %d (%q)", i, lengths[i], len(p), p)
			}
		}
	})

	t.Run("UUID v4 version bits set", func(t *testing.T) {
		id, err := generateRequestID()
		if err != nil {
			t.Fatal(err)
		}
		parts := strings.Split(id, "-")
		// Version nibble is the first char of group 3 (index 2), must be '4'.
		if parts[2][0] != '4' {
			t.Errorf("version nibble: got %q, want '4'", string(parts[2][0]))
		}
	})
}

// ---- WithHTTPClient option test ----

func TestWithHTTPClient(t *testing.T) {
	custom := &http.Client{}
	c := NewClient("http://localhost", "1.0.0", noToken, WithHTTPClient(custom))
	if c.httpClient != custom {
		t.Error("WithHTTPClient did not set custom client")
	}
}
