package api

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// gzipJSON gzip-compresses a JSON-marshalled value and returns the bytes.
func gzipJSON(t *testing.T, v interface{}) []byte {
	t.Helper()
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	if _, err := gz.Write(raw); err != nil {
		t.Fatalf("gzip write: %v", err)
	}
	if err := gz.Close(); err != nil {
		t.Fatalf("gzip close: %v", err)
	}
	return buf.Bytes()
}

// ---- UploadCache tests ----

func TestUploadCache_Success(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPut {
			t.Errorf("expected PUT, got %s", r.Method)
		}
		if !strings.HasPrefix(r.URL.Path, "/api/v1/cache/") {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		writeJSON(w, 200, apiResponse[CacheUploadResponse]{
			Data: CacheUploadResponse{
				SizeBytes:          1024,
				EngineVersionsHash: "abc123",
				Branch:             "main",
			},
		})
	}))
	defer srv.Close()

	payload := gzipJSON(t, map[string]string{"version": "2"})
	c := newTestClient(srv, "1.0.0", noToken)
	resp, err := c.UploadCache(context.Background(), CacheUploadRequest{
		Project:            "org/repo",
		Branch:             "main",
		EngineVersionsHash: "abc123",
		Data:               payload,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.SizeBytes != 1024 {
		t.Errorf("SizeBytes: got %d, want 1024", resp.SizeBytes)
	}
	if resp.Branch != "main" {
		t.Errorf("Branch: got %q, want %q", resp.Branch, "main")
	}
}

func TestUploadCache_TooLarge(t *testing.T) {
	calls := 0
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.Header().Set("X-Request-ID", "req-413")
		writeJSON(w, 413, map[string]interface{}{
			"error": map[string]string{"code": "PAYLOAD_TOO_LARGE", "message": "cache too large"},
		})
	}))
	defer srv.Close()

	// Build a payload larger than 50 MB.
	oversized := make([]byte, maxCacheUploadBytes+1)

	c := newTestClient(srv, "1.0.0", noToken)
	_, err := c.UploadCache(context.Background(), CacheUploadRequest{
		Project: "acme",
		Data:    oversized,
	})
	if err == nil {
		t.Fatal("expected error for oversized payload")
	}
	// Must be rejected client-side before hitting the server.
	if calls != 0 {
		t.Errorf("server should not have been called for oversized payload, got %d calls", calls)
	}
	if !strings.Contains(err.Error(), "too large") {
		t.Errorf("error message should mention 'too large': %v", err)
	}
}

func TestUploadCache_Unauthorized(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Request-ID", "req-401")
		writeJSON(w, 401, map[string]interface{}{
			"error": map[string]string{"code": "UNAUTHORIZED", "message": "invalid token"},
		})
	}))
	defer srv.Close()

	c := newTestClient(srv, "1.0.0", noToken)
	_, err := c.UploadCache(context.Background(), CacheUploadRequest{
		Project: "acme",
		Data:    gzipJSON(t, map[string]string{"v": "2"}),
	})
	if err == nil {
		t.Fatal("expected error")
	}
	apiErr, ok := err.(*APIError)
	if !ok {
		t.Fatalf("expected *APIError, got %T: %v", err, err)
	}
	if apiErr.Code != "UNAUTHORIZED" {
		t.Errorf("code: got %q, want UNAUTHORIZED", apiErr.Code)
	}
}

func TestUploadCache_Headers(t *testing.T) {
	var captured *http.Request
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		captured = r
		writeJSON(w, 200, apiResponse[CacheUploadResponse]{
			Data: CacheUploadResponse{SizeBytes: 10},
		})
	}))
	defer srv.Close()

	payload := gzipJSON(t, map[string]string{"version": "2"})
	c := newTestClient(srv, "1.0.0", fixedToken("tok-secret"))
	_, err := c.UploadCache(context.Background(), CacheUploadRequest{
		Project:            "myorg/myrepo",
		Branch:             "feature/x",
		EngineVersionsHash: "deadbeefcafe",
		Data:               payload,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if ct := captured.Header.Get("Content-Type"); ct != "application/gzip" {
		t.Errorf("Content-Type: got %q, want application/gzip", ct)
	}
	if evh := captured.Header.Get("X-Engine-Versions-Hash"); evh != "deadbeefcafe" {
		t.Errorf("X-Engine-Versions-Hash: got %q, want deadbeefcafe", evh)
	}
	if br := captured.Header.Get("X-Branch"); br != "feature/x" {
		t.Errorf("X-Branch: got %q, want feature/x", br)
	}
	if auth := captured.Header.Get("Authorization"); auth != "Bearer tok-secret" {
		t.Errorf("Authorization: got %q, want Bearer tok-secret", auth)
	}
}

func TestUploadCache_EmptyProject(t *testing.T) {
	c, _ := NewClient("https://localhost", "1.0.0", noToken)
	_, err := c.UploadCache(context.Background(), CacheUploadRequest{
		Project: "",
		Data:    []byte("x"),
	})
	if err == nil {
		t.Fatal("expected error for empty project")
	}
}

// ---- DownloadCache tests ----

func TestDownloadCache_Success(t *testing.T) {
	payload := gzipJSON(t, map[string]string{"version": "2", "scannerVersion": "1.0.0"})

	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Errorf("expected GET, got %s", r.Method)
		}
		if !strings.HasPrefix(r.URL.Path, "/api/v1/cache/") {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/gzip")
		w.WriteHeader(200)
		_, _ = w.Write(payload)
	}))
	defer srv.Close()

	c := newTestClient(srv, "1.0.0", noToken)
	data, err := c.DownloadCache(context.Background(), CacheDownloadRequest{
		Project:            "org/repo",
		Branch:             "main",
		EngineVersionsHash: "abc123",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if data == nil {
		t.Fatal("expected non-nil data")
	}
	// Verify the data is actually gzip by decompressing it.
	gr, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		t.Fatalf("response is not valid gzip: %v", err)
	}
	raw, err := io.ReadAll(gr)
	if err != nil {
		t.Fatalf("gzip read: %v", err)
	}
	if !strings.Contains(string(raw), "scannerVersion") {
		t.Errorf("decompressed data missing expected field: %s", raw)
	}
}

func TestDownloadCache_NotFound(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(404)
	}))
	defer srv.Close()

	c := newTestClient(srv, "1.0.0", noToken)
	data, err := c.DownloadCache(context.Background(), CacheDownloadRequest{
		Project:            "org/repo",
		Branch:             "main",
		EngineVersionsHash: "abc123",
	})
	if err != nil {
		t.Fatalf("expected nil error on 404, got: %v", err)
	}
	if data != nil {
		t.Fatalf("expected nil data on 404, got %d bytes", len(data))
	}
}

func TestDownloadCache_ServerError(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Request-ID", "req-500")
		writeJSON(w, 500, map[string]interface{}{
			"error": map[string]string{"code": "INTERNAL_ERROR", "message": "db down"},
		})
	}))
	defer srv.Close()

	c := newTestClient(srv, "1.0.0", noToken)
	_, err := c.DownloadCache(context.Background(), CacheDownloadRequest{
		Project:            "org/repo",
		Branch:             "main",
		EngineVersionsHash: "abc123",
	})
	if err == nil {
		t.Fatal("expected error on 500")
	}
	apiErr, ok := err.(*APIError)
	if !ok {
		t.Fatalf("expected *APIError, got %T: %v", err, err)
	}
	if apiErr.Code != "INTERNAL_ERROR" {
		t.Errorf("code: got %q, want INTERNAL_ERROR", apiErr.Code)
	}
}

func TestDownloadCache_QueryParams(t *testing.T) {
	var capturedQuery string
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedQuery = r.URL.RawQuery
		payload := gzipJSON(t, map[string]string{"v": "2"})
		w.Header().Set("Content-Type", "application/gzip")
		w.WriteHeader(200)
		_, _ = w.Write(payload)
	}))
	defer srv.Close()

	c := newTestClient(srv, "1.0.0", noToken)
	_, err := c.DownloadCache(context.Background(), CacheDownloadRequest{
		Project:            "org/repo",
		Branch:             "feat/pqc",
		EngineVersionsHash: "hash999",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(capturedQuery, "branch=feat") {
		t.Errorf("query should contain branch: %s", capturedQuery)
	}
	if !strings.Contains(capturedQuery, "engineVersionsHash=hash999") {
		t.Errorf("query should contain engineVersionsHash: %s", capturedQuery)
	}
}

// ---- InvalidateCache tests ----

func TestInvalidateCache_Success(t *testing.T) {
	var capturedRawPath string
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// RawPath preserves percent-encoding; fall back to Path when no encoding.
		capturedRawPath = r.URL.RawPath
		if capturedRawPath == "" {
			capturedRawPath = r.URL.Path
		}
		if r.Method != http.MethodDelete {
			t.Errorf("expected DELETE, got %s", r.Method)
		}
		w.WriteHeader(204)
	}))
	defer srv.Close()

	c := newTestClient(srv, "1.0.0", noToken)
	err := c.InvalidateCache(context.Background(), "org/repo", "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(capturedRawPath, "org%2Frepo") {
		t.Errorf("path should contain org%%2Frepo (URL-encoded slash), got %q", capturedRawPath)
	}
}

func TestInvalidateCache_WithBranch(t *testing.T) {
	var capturedQuery string
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedQuery = r.URL.RawQuery
		w.WriteHeader(204)
	}))
	defer srv.Close()

	c := newTestClient(srv, "1.0.0", noToken)
	err := c.InvalidateCache(context.Background(), "acme/scanner", "main")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(capturedQuery, "branch=main") {
		t.Errorf("query should contain branch=main, got %q", capturedQuery)
	}
}

func TestInvalidateCache_EmptyProject(t *testing.T) {
	c, _ := NewClient("https://localhost", "1.0.0", noToken)
	err := c.InvalidateCache(context.Background(), "", "main")
	if err == nil {
		t.Fatal("expected error for empty project")
	}
}

func TestInvalidateCache_ServerError(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Request-ID", "req-del-500")
		writeJSON(w, 500, map[string]interface{}{
			"error": map[string]string{"code": "INTERNAL_ERROR", "message": "db down"},
		})
	}))
	defer srv.Close()

	c := newTestClient(srv, "1.0.0", noToken)
	err := c.InvalidateCache(context.Background(), "org/repo", "")
	if err == nil {
		t.Fatal("expected error on 500")
	}
	apiErr, ok := err.(*APIError)
	if !ok {
		t.Fatalf("expected *APIError, got %T: %v", err, err)
	}
	if apiErr.Code != "INTERNAL_ERROR" {
		t.Errorf("code: got %q, want INTERNAL_ERROR", apiErr.Code)
	}
}

// ---- doRaw HTTPS enforcement ----

func TestDoRaw_HTTPSEnforcement(t *testing.T) {
	// NewClient with plain HTTP endpoint.
	c, _ := NewClient("http://not-https.example.com", "1.0.0", noToken)
	_, err := c.DownloadCache(context.Background(), CacheDownloadRequest{
		Project: "org/repo",
		Branch:  "main",
	})
	if err == nil {
		t.Fatal("expected error for HTTP endpoint")
	}
	if !strings.Contains(err.Error(), "HTTPS") {
		t.Errorf("error should mention HTTPS: %v", err)
	}
}
