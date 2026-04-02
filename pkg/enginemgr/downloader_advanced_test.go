package enginemgr

// downloader_advanced_test.go — production-readiness gap coverage for Phase 10
// engine binary download feature.
//
// Covers six gap categories not addressed by downloader_test.go:
//   1. Concurrency stress tests (parallel downloads, context cancellation, progress thread-safety)
//   2. Network failure simulation (mid-stream drop, truncated body, size boundary, HTTP 504)
//   3. Filesystem edge cases (read-only dir, unicode path, symlink at destination)
//   4. Manifest robustness (unknown fields, missing fields, oversized payload, negative schemaVersion)
//   5. Security boundary tests (URL with credentials, fragment, query params, double-encoded traversal)
//   6. Integration flows (mixed success/skip/fail, idempotent install, DownloadResult JSON fields)
//   7. Regression tests for known patterns (placeholder SHA-256, exe suffix, progress monotonicity)
//
// Run with: go test -race -count=1 ./pkg/enginemgr/

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// ============================================================
// Helpers shared across advanced tests
// ============================================================

// makeBody returns a byte slice and its lowercase hex SHA-256 digest.
func makeBody(content string) ([]byte, string) {
	b := []byte(content)
	h := sha256.Sum256(b)
	return b, hex.EncodeToString(h[:])
}

// tempExeFile creates a named executable file in dir and returns its path.
func tempExeFile(t *testing.T, dir, name, content string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(content), 0755); err != nil {
		t.Fatalf("tempExeFile %s: %v", name, err)
	}
	return p
}

// ============================================================
// 1. Concurrency stress tests
// ============================================================

// TestAdvanced_DownloadEngines_10Parallel verifies that downloading 10 engines
// simultaneously produces correct, non-corrupted results with no data races.
// The race detector must be active (go test -race) to catch any issues.
func TestAdvanced_DownloadEngines_10Parallel(t *testing.T) {
	t.Parallel()

	const n = 10
	type engineData struct {
		body []byte
		hash string
	}
	data := make(map[string]engineData, n)
	for i := 0; i < n; i++ {
		name := fmt.Sprintf("engine%02d", i)
		b, h := makeBody(fmt.Sprintf("binary-content-for-%s", name))
		data[name] = engineData{body: b, hash: h}
	}

	ts, client := newTLSTestServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		name := strings.TrimPrefix(r.URL.Path, "/")
		if d, ok := data[name]; ok {
			w.Write(d.body)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer ts.Close()

	dir := t.TempDir()
	engines := make([]EngineInfo, n)
	manifest := &Manifest{SchemaVersion: 1, Engines: make(map[string]ManifestEngine, n)}
	for i := 0; i < n; i++ {
		name := fmt.Sprintf("engine%02d", i)
		engines[i] = EngineInfo{Name: name, BinaryName: name}
		manifest.Engines[name] = ManifestEngine{
			Version:           "1.0.0",
			DownloadSupported: true,
			Platforms: map[string]ManifestPlatform{
				PlatformKey(): {URL: ts.URL + "/" + name, SHA256: data[name].hash},
			},
		}
	}

	results := DownloadEngines(context.Background(), engines, manifest, DownloadOptions{
		InstallDir: dir,
		HTTPClient: client,
	})

	if len(results) != n {
		t.Fatalf("expected %d results, got %d", n, len(results))
	}
	for i, r := range results {
		if r.Err != nil {
			t.Errorf("result[%d] (%s): %v", i, r.Name, r.Err)
		}
		if r.Name != engines[i].Name {
			t.Errorf("result[%d]: order mismatch — expected %q, got %q", i, engines[i].Name, r.Name)
		}
		// Verify on-disk content integrity — not just error absence.
		got, err := os.ReadFile(filepath.Join(dir, engines[i].Name))
		if err != nil {
			t.Errorf("result[%d]: read file: %v", i, err)
			continue
		}
		want := data[engines[i].Name].body
		if !bytes.Equal(got, want) {
			t.Errorf("result[%d]: content mismatch (got %d bytes, want %d bytes)", i, len(got), len(want))
		}
	}
}

// TestAdvanced_DownloadEngines_ContextCancelMidParallel cancels the context while
// parallel downloads are in-flight and verifies all goroutines return (no hang)
// and no final file exists at any destination path.
func TestAdvanced_DownloadEngines_ContextCancelMidParallel(t *testing.T) {
	t.Parallel()

	const n = 5
	ts, client := newTLSTestServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(10 * time.Second)
		w.Write([]byte("too-late"))
	}))
	defer ts.Close()

	dir := t.TempDir()
	engines := make([]EngineInfo, n)
	manifest := &Manifest{SchemaVersion: 1, Engines: make(map[string]ManifestEngine, n)}
	for i := 0; i < n; i++ {
		name := fmt.Sprintf("slow%d", i)
		engines[i] = EngineInfo{Name: name, BinaryName: name}
		manifest.Engines[name] = ManifestEngine{
			Version:           "1.0.0",
			DownloadSupported: true,
			Platforms: map[string]ManifestPlatform{
				PlatformKey(): {URL: ts.URL + "/" + name, SHA256: "placeholder"},
			},
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()

	done := make(chan []DownloadResult, 1)
	go func() {
		done <- DownloadEngines(ctx, engines, manifest, DownloadOptions{
			InstallDir: dir,
			HTTPClient: client,
		})
	}()

	var results []DownloadResult
	select {
	case results = <-done:
		// Good — all goroutines returned.
	case <-time.After(5 * time.Second):
		t.Fatal("DownloadEngines hung after context cancellation — goroutine leak suspected")
	}

	if len(results) != n {
		t.Fatalf("expected %d results, got %d", n, len(results))
	}
	var anyErr bool
	for _, r := range results {
		if r.Err != nil {
			anyErr = true
			break
		}
	}
	if !anyErr {
		t.Error("expected at least one error after context cancellation")
	}

	// No final binary files should exist at any destination.
	for _, eng := range engines {
		dest := filepath.Join(dir, eng.BinaryName)
		if _, err := os.Stat(dest); err == nil {
			t.Errorf("unexpected file at %s after context cancellation", dest)
		}
	}
}

// TestAdvanced_ProgressFunc_ThreadSafety verifies that a ProgressFunc shared
// across multiple goroutines in DownloadEngines does not cause data races.
// The race detector validates this when run with -race.
func TestAdvanced_ProgressFunc_ThreadSafety(t *testing.T) {
	t.Parallel()

	const n = 6
	type edata struct {
		body []byte
		hash string
	}
	data := make(map[string]edata, n)
	for i := 0; i < n; i++ {
		name := fmt.Sprintf("prog%d", i)
		b, h := makeBody(fmt.Sprintf("content-%d", i))
		data[name] = edata{body: b, hash: h}
	}

	ts, client := newTLSTestServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		name := strings.TrimPrefix(r.URL.Path, "/")
		if d, ok := data[name]; ok {
			w.Write(d.body)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer ts.Close()

	dir := t.TempDir()
	engines := make([]EngineInfo, n)
	manifest := &Manifest{SchemaVersion: 1, Engines: make(map[string]ManifestEngine, n)}
	for i := 0; i < n; i++ {
		name := fmt.Sprintf("prog%d", i)
		engines[i] = EngineInfo{Name: name, BinaryName: name}
		manifest.Engines[name] = ManifestEngine{
			Version:           "1.0.0",
			DownloadSupported: true,
			Platforms: map[string]ManifestPlatform{
				PlatformKey(): {URL: ts.URL + "/" + name, SHA256: data[name].hash},
			},
		}
	}

	// Use a mutex-protected counter — the race detector will flag unguarded access.
	var mu sync.Mutex
	callCount := 0
	progressFn := func(_ string, _ int64) {
		mu.Lock()
		callCount++
		mu.Unlock()
	}

	results := DownloadEngines(context.Background(), engines, manifest, DownloadOptions{
		InstallDir:   dir,
		HTTPClient:   client,
		ProgressFunc: progressFn,
	})

	for i, r := range results {
		if r.Err != nil {
			t.Errorf("result[%d] (%s): %v", i, r.Name, r.Err)
		}
	}

	mu.Lock()
	got := callCount
	mu.Unlock()
	if got == 0 {
		t.Error("ProgressFunc was never called across parallel downloads")
	}
}

// TestAdvanced_ProgressFunc_AtomicCounter verifies ProgressFunc safety using
// atomic operations — a stricter test for the race detector than mutex-based.
func TestAdvanced_ProgressFunc_AtomicCounter(t *testing.T) {
	t.Parallel()

	const n = 4
	type edata struct {
		body []byte
		hash string
	}
	data := make(map[string]edata, n)
	for i := 0; i < n; i++ {
		name := fmt.Sprintf("atomic%d", i)
		b, h := makeBody(fmt.Sprintf("atomic-content-%d", i))
		data[name] = edata{body: b, hash: h}
	}

	ts, client := newTLSTestServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		name := strings.TrimPrefix(r.URL.Path, "/")
		if d, ok := data[name]; ok {
			w.Write(d.body)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer ts.Close()

	dir := t.TempDir()
	engines := make([]EngineInfo, n)
	manifest := &Manifest{SchemaVersion: 1, Engines: make(map[string]ManifestEngine, n)}
	for i := 0; i < n; i++ {
		name := fmt.Sprintf("atomic%d", i)
		engines[i] = EngineInfo{Name: name, BinaryName: name}
		manifest.Engines[name] = ManifestEngine{
			Version:           "1.0.0",
			DownloadSupported: true,
			Platforms: map[string]ManifestPlatform{
				PlatformKey(): {URL: ts.URL + "/" + name, SHA256: data[name].hash},
			},
		}
	}

	var totalCalls int64
	results := DownloadEngines(context.Background(), engines, manifest, DownloadOptions{
		InstallDir:   dir,
		HTTPClient:   client,
		ProgressFunc: func(_ string, _ int64) { atomic.AddInt64(&totalCalls, 1) },
	})

	for _, r := range results {
		if r.Err != nil {
			t.Errorf("engine %s: %v", r.Name, r.Err)
		}
	}
	if atomic.LoadInt64(&totalCalls) == 0 {
		t.Error("ProgressFunc was never called")
	}
}

// ============================================================
// 2. Network failure simulation
// ============================================================

// TestAdvanced_ServerDropsMidDownload simulates a server that drops the connection
// after sending partial data. Must return an error and leave no partial file at
// the destination path and no temp file in the install dir.
func TestAdvanced_ServerDropsMidDownload(t *testing.T) {
	t.Parallel()

	ts, client := newTLSTestServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", "65536")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("partial-data-only"))
		if hj, ok := w.(http.Hijacker); ok {
			conn, _, _ := hj.Hijack()
			if conn != nil {
				conn.Close()
			}
		}
	}))
	defer ts.Close()

	dir := t.TempDir()
	info := EngineInfo{Name: "drop-engine", BinaryName: "drop-engine"}
	entry := ManifestEngine{
		Version:           "1.0.0",
		DownloadSupported: true,
		Platforms: map[string]ManifestPlatform{
			PlatformKey(): {
				URL:    ts.URL + "/drop",
				SHA256: "0000000000000000000000000000000000000000000000000000000000000000",
			},
		},
	}

	result := downloadOne(context.Background(), info, entry, DownloadOptions{
		InstallDir: dir,
		HTTPClient: client,
	})

	if result.Err == nil {
		t.Fatal("expected error when server drops connection mid-download")
	}
	if _, err := os.Stat(filepath.Join(dir, "drop-engine")); err == nil {
		t.Error("no file should exist at destination after connection drop")
	}
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".engine-download-") {
			t.Errorf("temp file leaked: %s", e.Name())
		}
	}
}

// TestAdvanced_TruncatedBody verifies that a server sending valid HTTP headers
// but a body shorter than Content-Length results in a failure with no corrupt
// file at the destination (hash mismatch catches the truncation).
func TestAdvanced_TruncatedBody(t *testing.T) {
	t.Parallel()

	fullBody := []byte("full-body-content-that-will-be-truncated")
	_, correctHash := makeBody(string(fullBody))

	ts, client := newTLSTestServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", fmt.Sprintf("%d", len(fullBody)))
		w.WriteHeader(http.StatusOK)
		// Write only first half, then drop.
		w.Write(fullBody[:len(fullBody)/2])
		if hj, ok := w.(http.Hijacker); ok {
			conn, _, _ := hj.Hijack()
			if conn != nil {
				conn.Close()
			}
		}
	}))
	defer ts.Close()

	dir := t.TempDir()
	info := EngineInfo{Name: "truncated", BinaryName: "truncated"}
	entry := ManifestEngine{
		Version:           "1.0.0",
		DownloadSupported: true,
		Platforms: map[string]ManifestPlatform{
			PlatformKey(): {URL: ts.URL + "/truncated", SHA256: correctHash},
		},
	}

	result := downloadOne(context.Background(), info, entry, DownloadOptions{
		InstallDir: dir,
		HTTPClient: client,
	})

	if result.Err == nil {
		t.Fatal("expected error for truncated body (hash must mismatch)")
	}
	if _, err := os.Stat(filepath.Join(dir, "truncated")); err == nil {
		t.Error("corrupt partial file must not be left at destination")
	}
}

// TestAdvanced_MaxSizeEnforced verifies that a response body exceeding
// maxEngineSize is rejected with a size error and no file is left on disk.
func TestAdvanced_MaxSizeEnforced(t *testing.T) {
	t.Parallel()

	oversize := int64(maxEngineSize) + 1

	ts, client := newTLSTestServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		chunk := make([]byte, 32*1024)
		var written int64
		for written < oversize {
			toWrite := int64(len(chunk))
			if written+toWrite > oversize {
				toWrite = oversize - written
			}
			w.Write(chunk[:toWrite])
			if f, ok := w.(http.Flusher); ok {
				f.Flush()
			}
			written += toWrite
		}
	}))
	defer ts.Close()

	dir := t.TempDir()
	info := EngineInfo{Name: "oversize-engine", BinaryName: "oversize-engine"}
	entry := ManifestEngine{
		Version:           "1.0.0",
		DownloadSupported: true,
		Platforms: map[string]ManifestPlatform{
			PlatformKey(): {URL: ts.URL + "/oversize", SHA256: "placeholder"},
		},
	}

	result := downloadOne(context.Background(), info, entry, DownloadOptions{
		InstallDir: dir,
		HTTPClient: client,
	})

	if result.Err == nil {
		t.Fatal("expected error for oversized download")
	}
	if !strings.Contains(result.Err.Error(), "maximum size") {
		t.Errorf("expected 'maximum size' in error, got: %v", result.Err)
	}
	if _, err := os.Stat(filepath.Join(dir, "oversize-engine")); err == nil {
		t.Error("no file should exist after size-limit rejection")
	}
}

// TestAdvanced_ExactlyMaxSize verifies that a body equal to maxEngineSize (not
// exceeding it) is accepted when SHA-256 matches. The limit is exclusive.
func TestAdvanced_ExactlyMaxSize(t *testing.T) {
	t.Parallel()

	exactBody := bytes.Repeat([]byte{0xAB}, maxEngineSize)
	h := sha256.Sum256(exactBody)
	exactHash := hex.EncodeToString(h[:])

	ts, client := newTLSTestServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write(exactBody)
	}))
	defer ts.Close()

	dir := t.TempDir()
	info := EngineInfo{Name: "exact-size", BinaryName: "exact-size"}
	entry := ManifestEngine{
		Version:           "1.0.0",
		DownloadSupported: true,
		Platforms: map[string]ManifestPlatform{
			PlatformKey(): {URL: ts.URL + "/exact", SHA256: exactHash},
		},
	}

	result := downloadOne(context.Background(), info, entry, DownloadOptions{
		InstallDir: dir,
		HTTPClient: client,
	})

	if result.Err != nil {
		t.Fatalf("expected success for exactly-max-size download: %v", result.Err)
	}
	if result.BytesRead != int64(maxEngineSize) {
		t.Errorf("expected %d bytes read, got %d", maxEngineSize, result.BytesRead)
	}
}

// TestAdvanced_HTTP504Retry verifies that HTTP 504 Gateway Timeout triggers the
// same retry logic as 429/503 — all three are marked transient in the code.
func TestAdvanced_HTTP504Retry(t *testing.T) {
	t.Parallel()

	var attempts int32
	body, hash := makeBody("ok-after-504")

	ts, client := newTLSTestServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := atomic.AddInt32(&attempts, 1)
		if n < 2 {
			w.WriteHeader(http.StatusGatewayTimeout)
			return
		}
		w.Write(body)
	}))
	defer ts.Close()

	dir := t.TempDir()
	info := EngineInfo{Name: "retry504", BinaryName: "retry504"}
	entry := ManifestEngine{
		Version:           "1.0.0",
		DownloadSupported: true,
		Platforms: map[string]ManifestPlatform{
			PlatformKey(): {URL: ts.URL + "/retry504", SHA256: hash},
		},
	}

	result := downloadOne(context.Background(), info, entry, DownloadOptions{
		InstallDir: dir,
		HTTPClient: client,
	})

	if result.Err != nil {
		t.Fatalf("expected success after 504 retry: %v", result.Err)
	}
	if atomic.LoadInt32(&attempts) < 2 {
		t.Errorf("expected at least 2 HTTP attempts, got %d", atomic.LoadInt32(&attempts))
	}
}

// TestAdvanced_RetryDoesNotRetryContextCancel verifies that context cancellation
// during a retry backoff sleep is respected immediately via the select statement,
// not after the full backoff duration.
func TestAdvanced_RetryDoesNotRetryContextCancel(t *testing.T) {
	t.Parallel()

	var attempts int32
	ts, client := newTLSTestServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&attempts, 1)
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer ts.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()

	dir := t.TempDir()
	info := EngineInfo{Name: "cancel-retry", BinaryName: "cancel-retry"}
	entry := ManifestEngine{
		Version:           "1.0.0",
		DownloadSupported: true,
		Platforms: map[string]ManifestPlatform{
			PlatformKey(): {URL: ts.URL + "/x", SHA256: "placeholder"},
		},
	}

	start := time.Now()
	result := downloadOne(ctx, info, entry, DownloadOptions{
		InstallDir: dir,
		HTTPClient: client,
	})
	elapsed := time.Since(start)

	if result.Err == nil {
		t.Fatal("expected error")
	}
	// With a 300ms context the function must abort well before the 1s initialBackoff
	// per retry gap times maxDownloadRetries (3s total) would elapse.
	if elapsed > 2*time.Second {
		t.Errorf("context cancellation not respected during retry backoff: elapsed=%v", elapsed)
	}
}

// ============================================================
// 3. Filesystem edge cases
// ============================================================

// TestAdvanced_ReadOnlyInstallDir verifies that a read-only install directory
// produces a graceful error from os.CreateTemp, not a panic or silent failure.
func TestAdvanced_ReadOnlyInstallDir(t *testing.T) {
	t.Parallel()

	if runtime.GOOS == "windows" {
		t.Skip("read-only directory semantics differ on Windows")
	}

	body, hash := makeBody("binary-content")
	ts, client := newTLSTestServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(body)
	}))
	defer ts.Close()

	parent := t.TempDir()
	roDir := filepath.Join(parent, "read-only")
	if err := os.MkdirAll(roDir, 0555); err != nil {
		t.Fatalf("MkdirAll read-only: %v", err)
	}
	t.Cleanup(func() { os.Chmod(roDir, 0755) }) // restore so TempDir cleanup can remove it

	info := EngineInfo{Name: "ro-engine", BinaryName: "ro-engine"}
	entry := ManifestEngine{
		Version:           "1.0.0",
		DownloadSupported: true,
		Platforms: map[string]ManifestPlatform{
			PlatformKey(): {URL: ts.URL + "/ro", SHA256: hash},
		},
	}

	result := downloadOne(context.Background(), info, entry, DownloadOptions{
		InstallDir: roDir,
		HTTPClient: client,
	})

	if result.Err == nil {
		t.Fatal("expected error when install dir is read-only")
	}
}

// TestAdvanced_InstallDirWithUnicode verifies that install paths containing
// unicode characters (common on macOS/Linux) work correctly end-to-end.
func TestAdvanced_InstallDirWithUnicode(t *testing.T) {
	t.Parallel()

	if runtime.GOOS == "windows" {
		t.Skip("unicode path handling differs significantly on Windows")
	}

	body, hash := makeBody("unicode-path-binary")
	ts, client := newTLSTestServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(body)
	}))
	defer ts.Close()

	parent := t.TempDir()
	unicodeDir := filepath.Join(parent, "engines-日本語-크립토")
	if err := os.MkdirAll(unicodeDir, 0755); err != nil {
		t.Fatalf("MkdirAll unicode dir: %v", err)
	}

	info := EngineInfo{Name: "unicode-engine", BinaryName: "unicode-engine"}
	entry := ManifestEngine{
		Version:           "1.0.0",
		DownloadSupported: true,
		Platforms: map[string]ManifestPlatform{
			PlatformKey(): {URL: ts.URL + "/unicode", SHA256: hash},
		},
	}

	result := downloadOne(context.Background(), info, entry, DownloadOptions{
		InstallDir: unicodeDir,
		HTTPClient: client,
	})

	if result.Err != nil {
		t.Fatalf("expected success with unicode install dir: %v", result.Err)
	}
	got, err := os.ReadFile(filepath.Join(unicodeDir, "unicode-engine"))
	if err != nil {
		t.Fatalf("read file at unicode path: %v", err)
	}
	if !bytes.Equal(got, body) {
		t.Errorf("content mismatch: got %d bytes, want %d bytes", len(got), len(body))
	}
}

// TestAdvanced_InstallDirWithSpaces verifies that install paths containing
// ASCII spaces are handled correctly.
func TestAdvanced_InstallDirWithSpaces(t *testing.T) {
	t.Parallel()

	body, hash := makeBody("space-path-binary")
	ts, client := newTLSTestServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(body)
	}))
	defer ts.Close()

	parent := t.TempDir()
	spaceDir := filepath.Join(parent, "my engines dir")
	if err := os.MkdirAll(spaceDir, 0755); err != nil {
		t.Fatalf("MkdirAll space dir: %v", err)
	}

	info := EngineInfo{Name: "space-engine", BinaryName: "space-engine"}
	entry := ManifestEngine{
		Version:           "1.0.0",
		DownloadSupported: true,
		Platforms: map[string]ManifestPlatform{
			PlatformKey(): {URL: ts.URL + "/space", SHA256: hash},
		},
	}

	result := downloadOne(context.Background(), info, entry, DownloadOptions{
		InstallDir: spaceDir,
		HTTPClient: client,
	})

	if result.Err != nil {
		t.Fatalf("expected success with space in path: %v", result.Err)
	}
}

// TestAdvanced_SymlinkAtDestination verifies that the downloader refuses to
// overwrite a symlink at the destination path. The production code contains an
// explicit symlink guard in downloadAtomicVerify that returns an error rather
// than following or replacing the symlink — preventing symlink-following attacks.
// The symlink and its target must be untouched after the refused write.
func TestAdvanced_SymlinkAtDestination(t *testing.T) {
	t.Parallel()

	if runtime.GOOS == "windows" {
		t.Skip("symlink creation requires elevated privileges on Windows")
	}

	body, hash := makeBody("replace-symlink-content")
	ts, client := newTLSTestServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(body)
	}))
	defer ts.Close()

	dir := t.TempDir()
	destName := "symlinked-engine"
	destPath := filepath.Join(dir, destName)

	// Create a symlink at the destination pointing to a readable target.
	symlinkTarget := filepath.Join(dir, "original-target")
	originalContent := []byte("original")
	if err := os.WriteFile(symlinkTarget, originalContent, 0600); err != nil {
		t.Fatalf("write original target: %v", err)
	}
	if err := os.Symlink(symlinkTarget, destPath); err != nil {
		t.Fatalf("symlink: %v", err)
	}

	info := EngineInfo{Name: destName, BinaryName: destName}
	entry := ManifestEngine{
		Version:           "1.0.0",
		DownloadSupported: true,
		Platforms: map[string]ManifestPlatform{
			PlatformKey(): {URL: ts.URL + "/sym", SHA256: hash},
		},
	}

	// Force=true bypasses the skip-if-exists check, but the symlink guard inside
	// downloadAtomicVerify still fires and rejects the write.
	result := downloadOne(context.Background(), info, entry, DownloadOptions{
		InstallDir: dir,
		Force:      true,
		HTTPClient: client,
	})

	// Expect an explicit refusal — not a silent success.
	if result.Err == nil {
		t.Fatal("expected error: downloader must refuse to overwrite a symlink at destination")
	}
	if !strings.Contains(result.Err.Error(), "symlink") {
		t.Errorf("expected 'symlink' in error message, got: %v", result.Err)
	}

	// The symlink itself must still exist and still point to the original target.
	fi, err := os.Lstat(destPath)
	if err != nil {
		t.Fatalf("Lstat dest after refused write: %v", err)
	}
	if fi.Mode()&os.ModeSymlink == 0 {
		t.Error("destPath must still be a symlink after the refused write")
	}

	// The symlink target content must be untouched.
	orig, err := os.ReadFile(symlinkTarget)
	if err != nil {
		t.Fatalf("read original target: %v", err)
	}
	if !bytes.Equal(orig, originalContent) {
		t.Error("symlink target content must not be modified after refused write")
	}
}

// TestAdvanced_SkipChecksSymlink verifies that the skip-if-exists check uses
// os.Lstat so a dangling symlink at destPath counts as "existing" and is skipped
// without Force even though the symlink target does not exist.
func TestAdvanced_SkipChecksSymlink(t *testing.T) {
	t.Parallel()

	if runtime.GOOS == "windows" {
		t.Skip("symlink creation requires elevated privileges on Windows")
	}

	dir := t.TempDir()
	destName := "lstat-check-engine"
	destPath := filepath.Join(dir, destName)

	// Dangling symlink — target does not exist.
	danglingTarget := filepath.Join(dir, "nonexistent-target")
	if err := os.Symlink(danglingTarget, destPath); err != nil {
		t.Fatalf("symlink: %v", err)
	}

	info := EngineInfo{Name: destName, BinaryName: destName}
	entry := ManifestEngine{
		Version:           "1.0.0",
		DownloadSupported: true,
		Platforms: map[string]ManifestPlatform{
			PlatformKey(): {URL: "https://should-not-be-called.example.com/", SHA256: "abc"},
		},
	}

	result := downloadOne(context.Background(), info, entry, DownloadOptions{
		InstallDir: dir,
	})

	// Lstat sees the symlink as existing — must skip without any network call.
	if result.Err != nil {
		t.Fatalf("unexpected error: %v", result.Err)
	}
	if !result.Skipped {
		t.Error("expected Skipped=true for dangling symlink at destination (Lstat reports it exists)")
	}
}

// TestAdvanced_DownloadOne_TempCleanupOnContextCancel verifies that when context
// is cancelled during an active download (temp file already created), the deferred
// cleanup removes the temp file before returning.
func TestAdvanced_DownloadOne_TempCleanupOnContextCancel(t *testing.T) {
	t.Parallel()

	started := make(chan struct{}, 1)
	ts, client := newTLSTestServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		if f, ok := w.(http.Flusher); ok {
			f.Flush()
		}
		select {
		case started <- struct{}{}:
		default:
		}
		time.Sleep(10 * time.Second)
	}))
	defer ts.Close()

	dir := t.TempDir()
	info := EngineInfo{Name: "cancel-cleanup", BinaryName: "cancel-cleanup"}
	entry := ManifestEngine{
		Version:           "1.0.0",
		DownloadSupported: true,
		Platforms: map[string]ManifestPlatform{
			PlatformKey(): {URL: ts.URL + "/slow", SHA256: "placeholder"},
		},
	}

	ctx, cancel := context.WithCancel(context.Background())

	done := make(chan DownloadResult, 1)
	go func() {
		done <- downloadOne(ctx, info, entry, DownloadOptions{
			InstallDir: dir,
			HTTPClient: client,
		})
	}()

	// Wait until the server has started responding, then cancel.
	select {
	case <-started:
	case <-time.After(3 * time.Second):
		t.Fatal("server did not start in time")
	}
	cancel()

	select {
	case result := <-done:
		if result.Err == nil {
			t.Error("expected error from context cancellation")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("downloadOne did not return after context cancellation")
	}

	// No temp files should remain.
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".engine-download-") {
			t.Errorf("temp file not cleaned up after context cancel: %s", e.Name())
		}
	}
}

// ============================================================
// 4. Manifest robustness
// ============================================================

// TestAdvanced_ParseManifest_UnknownFields verifies forward-compatibility:
// extra unknown fields in the JSON must not cause a parse error.
func TestAdvanced_ParseManifest_UnknownFields(t *testing.T) {
	t.Parallel()

	raw := `{
		"schemaVersion": 1,
		"generatedAt": "2026-03-06T00:00:00Z",
		"engines": {
			"myengine": {
				"version": "1.0.0",
				"downloadSupported": true,
				"newFieldForV2": "ignored",
				"platforms": {
					"linux/amd64": {
						"url": "https://example.com/bin",
						"sha256": "abc",
						"checksum_type": "sha256-future-field"
					}
				}
			}
		}
	}`
	m, err := parseManifest([]byte(raw))
	if err != nil {
		t.Fatalf("unknown fields must be silently ignored for forward-compatibility: %v", err)
	}
	if m.SchemaVersion != 1 {
		t.Errorf("expected schemaVersion 1, got %d", m.SchemaVersion)
	}
	if len(m.Engines) != 1 {
		t.Errorf("expected 1 engine, got %d", len(m.Engines))
	}
}

// TestAdvanced_ParseManifest_EmptyEngines verifies that a valid manifest with
// an empty engines map is accepted.
func TestAdvanced_ParseManifest_EmptyEngines(t *testing.T) {
	t.Parallel()

	m, err := parseManifest([]byte(`{"schemaVersion": 1, "engines": {}}`))
	if err != nil {
		t.Fatalf("empty engines map should be valid: %v", err)
	}
	if len(m.Engines) != 0 {
		t.Errorf("expected 0 engines, got %d", len(m.Engines))
	}
}

// TestAdvanced_ParseManifest_NullEngines verifies that a null engines value
// results in a nil map (not a crash) — JSON null is valid for a Go map field.
func TestAdvanced_ParseManifest_NullEngines(t *testing.T) {
	t.Parallel()

	m, err := parseManifest([]byte(`{"schemaVersion": 1, "engines": null}`))
	if err != nil {
		t.Fatalf("null engines should be valid JSON: %v", err)
	}
	// A nil map is safe: len() returns 0, range is a no-op.
	if len(m.Engines) != 0 {
		t.Errorf("expected 0 engines for null, got %d", len(m.Engines))
	}
}

// TestAdvanced_ParseManifest_NegativeSchemaVersion verifies that a negative
// schemaVersion is rejected (same branch as 0, both < 1).
func TestAdvanced_ParseManifest_NegativeSchemaVersion(t *testing.T) {
	t.Parallel()

	_, err := parseManifest([]byte(`{"schemaVersion": -1, "engines": {}}`))
	if err == nil {
		t.Fatal("expected error for negative schemaVersion")
	}
	if !strings.Contains(err.Error(), "schemaVersion") {
		t.Errorf("expected 'schemaVersion' in error, got: %v", err)
	}
}

// TestAdvanced_ParseManifest_MissingEnginesField verifies that a manifest
// without an "engines" key at all produces a valid manifest with a nil map.
func TestAdvanced_ParseManifest_MissingEnginesField(t *testing.T) {
	t.Parallel()

	m, err := parseManifest([]byte(`{"schemaVersion": 1}`))
	if err != nil {
		t.Fatalf("missing engines field should parse without error: %v", err)
	}
	if m == nil {
		t.Fatal("expected non-nil manifest")
	}
}

// TestAdvanced_ParseManifest_OversizedRemote verifies that a remote manifest
// exceeding 1 MB is rejected and LoadManifest falls back to the embedded manifest.
func TestAdvanced_ParseManifest_OversizedRemote(t *testing.T) {
	t.Parallel()

	const maxManifestSize = 1 << 20
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"schemaVersion":1,"engines":{`))
		// Pad well past the 1 MB limit.
		pad := make([]byte, maxManifestSize)
		for i := range pad {
			pad[i] = ' '
		}
		w.Write(pad)
		w.Write([]byte(`}}`))
	}))
	defer ts.Close()

	m, fallback, remoteErr, err := LoadManifest(context.Background(), ts.URL, ts.Client())
	if err != nil {
		t.Fatalf("LoadManifest: %v", err)
	}
	if !fallback {
		t.Error("expected fallback=true for oversized remote manifest")
	}
	if remoteErr == nil {
		t.Error("expected remoteErr to be non-nil for oversized manifest")
	}
	if !strings.Contains(remoteErr.Error(), "size limit") {
		t.Errorf("expected 'size limit' in remoteErr, got: %v", remoteErr)
	}
	if m.SchemaVersion < 1 {
		t.Errorf("expected valid fallback manifest, got schemaVersion %d", m.SchemaVersion)
	}
}

// TestAdvanced_FetchManifest_ContextTimeout verifies that context cancellation
// is respected during a slow remote manifest fetch, triggering fallback.
// Uses httptest.NewTLSServer because fetchRemoteManifest enforces HTTPS.
func TestAdvanced_FetchManifest_ContextTimeout(t *testing.T) {
	t.Parallel()

	ts, client := newTLSTestServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(10 * time.Second)
		w.Write([]byte(`{"schemaVersion":1,"engines":{}}`))
	}))
	defer ts.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()

	m, fallback, remoteErr, err := LoadManifest(ctx, ts.URL, client)
	if err != nil {
		t.Fatalf("LoadManifest should not return hard error on timeout: %v", err)
	}
	if !fallback {
		t.Error("expected fallback=true on context timeout")
	}
	if remoteErr == nil {
		t.Error("expected remoteErr on context timeout")
	}
	if m == nil || m.SchemaVersion < 1 {
		t.Error("expected valid embedded fallback manifest")
	}
}

// TestAdvanced_FetchManifest_AcceptHeader verifies that the remote manifest
// request carries the Accept: application/json header.
// Uses httptest.NewTLSServer because fetchRemoteManifest enforces HTTPS.
func TestAdvanced_FetchManifest_AcceptHeader(t *testing.T) {
	t.Parallel()

	var gotAccept string
	ts, client := newTLSTestServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAccept = r.Header.Get("Accept")
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"schemaVersion":1,"engines":{}}`))
	}))
	defer ts.Close()

	_, _, _, err := LoadManifest(context.Background(), ts.URL, client)
	if err != nil {
		t.Fatalf("LoadManifest: %v", err)
	}
	if gotAccept != "application/json" {
		t.Errorf("expected Accept: application/json, got %q", gotAccept)
	}
}

// TestAdvanced_ParseManifest_LongFieldValues verifies that very long field values
// (e.g., a 4096-char SHA string) do not corrupt the parser or get silently truncated.
func TestAdvanced_ParseManifest_LongFieldValues(t *testing.T) {
	t.Parallel()

	longStr := strings.Repeat("a", 4096)
	raw := fmt.Sprintf(`{
		"schemaVersion": 1,
		"engines": {
			"eng": {
				"version": "1.0",
				"downloadSupported": true,
				"platforms": {
					"linux/amd64": {
						"url": "https://example.com/bin",
						"sha256": "%s"
					}
				}
			}
		}
	}`, longStr)

	m, err := parseManifest([]byte(raw))
	if err != nil {
		t.Fatalf("long field values must not cause parse errors: %v", err)
	}
	plat := m.Engines["eng"].Platforms["linux/amd64"]
	if plat.SHA256 != longStr {
		t.Error("sha256 field not preserved correctly for long value")
	}
}

// ============================================================
// 5. Security boundary tests
// ============================================================

// TestAdvanced_ValidateDownloadURL_TableDriven provides comprehensive URL
// validation coverage across scheme variants, edge cases, and malformed inputs.
func TestAdvanced_ValidateDownloadURL_TableDriven(t *testing.T) {
	t.Parallel()

	type tc struct {
		url     string
		wantErr bool
		desc    string
	}

	cases := []tc{
		// Valid HTTPS URLs.
		{"https://example.com/binary", false, "plain HTTPS"},
		{"https://releases.oqs.dev/engines/v1/bin", false, "HTTPS with path"},
		{"https://user:pass@example.com/bin", false, "HTTPS with credentials (transport concern)"},
		{"https://example.com/bin?v=1&arch=amd64", false, "HTTPS with query"},
		{"https://example.com/bin#fragment", false, "HTTPS with fragment"},
		{"https://192.168.1.1/binary", false, "HTTPS with IP"},

		// Rejected schemes.
		{"http://example.com/binary", true, "plain HTTP"},
		{"ftp://example.com/binary", true, "FTP"},
		{"file:///etc/passwd", true, "file scheme"},
		{"data:text/plain,evil", true, "data URI"},
		{"javascript:alert(1)", true, "javascript scheme"},
		{"", true, "empty string"},
		{"//example.com/binary", true, "protocol-relative"},
		{"example.com/binary", true, "no scheme"},
		// url.Parse normalises the scheme to lowercase before comparison, so
		// "HTTPS://" becomes "https" and passes the check. This documents the
		// actual behaviour: uppercase schemes are accepted.
		{"HTTPS://example.com/binary", false, "uppercase scheme normalised to https by url.Parse"},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.desc, func(t *testing.T) {
			t.Parallel()
			err := validateDownloadURL(tc.url)
			if tc.wantErr && err == nil {
				t.Errorf("expected error for %q (%s), got nil", tc.url, tc.desc)
			}
			if !tc.wantErr && err != nil {
				t.Errorf("expected no error for %q (%s), got: %v", tc.url, tc.desc, err)
			}
		})
	}
}

// TestAdvanced_DoubleEncodedPathTraversal verifies that both raw and
// percent-encoded path separators in binary names are handled safely.
// Percent-encoded separators (%2F) do not contain a literal slash so they pass
// filepath.Base; the test documents that they cannot traverse the filesystem.
func TestAdvanced_DoubleEncodedPathTraversal(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()

	cases := []struct {
		name        string
		wantRejected bool
	}{
		{"../etc/passwd", true},          // raw slash — rejected by filepath.Base check
		{"sub/dir/engine", true},          // innocent relative path — still rejected
		{"..%2F..%2Fetc%2Fpasswd", false}, // percent-encoded: no literal slash, passes Base check
	}

	for _, c := range cases {
		c := c
		t.Run(c.name, func(t *testing.T) {
			info := EngineInfo{Name: "traversal-test", BinaryName: c.name}
			entry := ManifestEngine{
				Version:           "1.0.0",
				DownloadSupported: true,
				Platforms: map[string]ManifestPlatform{
					PlatformKey(): {URL: "https://example.com/x", SHA256: "abc"},
				},
			}

			result := downloadOne(context.Background(), info, entry, DownloadOptions{
				InstallDir: dir,
			})

			if c.wantRejected {
				if result.Err == nil {
					t.Errorf("binary name %q should be rejected (contains path separator)", c.name)
				}
			}
			// For percent-encoded names: verify no file escaped the install dir.
			entries, _ := os.ReadDir(dir)
			for _, e := range entries {
				p := filepath.Join(dir, e.Name())
				clean := filepath.Clean(p)
				cleanDir := filepath.Clean(dir)
				if !strings.HasPrefix(clean, cleanDir) {
					t.Errorf("file escaped install dir: %s", p)
				}
			}
		})
	}
}

// TestAdvanced_BinaryNameWithNullBytes documents null-byte handling in binary
// names — verifies no out-of-dir write occurs regardless of OS behaviour.
func TestAdvanced_BinaryNameWithNullBytes(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	info := EngineInfo{Name: "null-byte-engine", BinaryName: "engine\x00malicious"}
	entry := ManifestEngine{
		Version:           "1.0.0",
		DownloadSupported: true,
		Platforms: map[string]ManifestPlatform{
			PlatformKey(): {URL: "https://example.com/x", SHA256: "abc"},
		},
	}

	result := downloadOne(context.Background(), info, entry, DownloadOptions{
		InstallDir: dir,
	})

	// Either an error is returned, or the file lands safely inside the install dir.
	if result.Err == nil {
		entries, _ := os.ReadDir(dir)
		for _, e := range entries {
			p := filepath.Join(dir, e.Name())
			clean := filepath.Clean(p)
			cleanDir := filepath.Clean(dir)
			if !strings.HasPrefix(clean, cleanDir) {
				t.Errorf("file with null-byte name escaped install dir: %s", p)
			}
		}
	}
}

// TestAdvanced_BinaryNameWithWindowsSeparator verifies that backslash path
// traversal is caught on Windows via filepath.Base.
func TestAdvanced_BinaryNameWithWindowsSeparator(t *testing.T) {
	t.Parallel()

	if runtime.GOOS != "windows" {
		t.Skip("backslash path traversal guard is only relevant on Windows")
	}

	dir := t.TempDir()
	info := EngineInfo{Name: "win-traversal", BinaryName: `..\..\etc\passwd`}
	entry := ManifestEngine{
		Version:           "1.0.0",
		DownloadSupported: true,
		Platforms: map[string]ManifestPlatform{
			PlatformKey(): {URL: "https://example.com/x", SHA256: "abc"},
		},
	}

	result := downloadOne(context.Background(), info, entry, DownloadOptions{
		InstallDir: dir,
	})

	if result.Err == nil {
		t.Fatal("expected error for backslash path traversal on Windows")
	}
	if !strings.Contains(result.Err.Error(), "path separator") {
		t.Errorf("expected 'path separator' in error, got: %v", result.Err)
	}
}

// ============================================================
// 6. Integration flows
// ============================================================

// TestAdvanced_MixedResults_SuccessSkipFail verifies the final state when
// DownloadEngines runs with engines that succeed, are skipped, and fail.
// Result order must match input order and each status must be correct.
func TestAdvanced_MixedResults_SuccessSkipFail(t *testing.T) {
	t.Parallel()

	goodBody, goodHash := makeBody("good-binary")

	ts, client := newTLSTestServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.Contains(r.URL.Path, "good"):
			w.Write(goodBody)
		case strings.Contains(r.URL.Path, "fail"):
			w.WriteHeader(http.StatusNotFound)
		default:
			w.WriteHeader(http.StatusInternalServerError)
		}
	}))
	defer ts.Close()

	dir := t.TempDir()
	// Pre-create the "skip" binary so it is detected as already installed.
	tempExeFile(t, dir, "skip-engine", "pre-existing binary")

	engines := []EngineInfo{
		{Name: "good", BinaryName: "good"},
		{Name: "skip-engine", BinaryName: "skip-engine"},
		{Name: "fail", BinaryName: "fail"},
	}
	manifest := &Manifest{
		SchemaVersion: 1,
		Engines: map[string]ManifestEngine{
			"good": {
				Version:           "1.0.0",
				DownloadSupported: true,
				Platforms:         map[string]ManifestPlatform{PlatformKey(): {URL: ts.URL + "/good", SHA256: goodHash}},
			},
			"skip-engine": {
				Version:           "1.0.0",
				DownloadSupported: true,
				Platforms:         map[string]ManifestPlatform{PlatformKey(): {URL: ts.URL + "/skip-engine", SHA256: goodHash}},
			},
			"fail": {
				Version:           "1.0.0",
				DownloadSupported: true,
				Platforms:         map[string]ManifestPlatform{PlatformKey(): {URL: ts.URL + "/fail", SHA256: "placeholder"}},
			},
		},
	}

	results := DownloadEngines(context.Background(), engines, manifest, DownloadOptions{
		InstallDir: dir,
		HTTPClient: client,
	})

	if len(results) != 3 {
		t.Fatalf("expected 3 results, got %d", len(results))
	}

	// results[0] — good: success
	if results[0].Name != "good" {
		t.Errorf("results[0]: expected 'good', got %q", results[0].Name)
	}
	if results[0].Err != nil {
		t.Errorf("results[0] (good): expected success, got: %v", results[0].Err)
	}
	if results[0].Skipped {
		t.Error("results[0] (good): expected Skipped=false")
	}

	// results[1] — skip-engine: skipped
	if results[1].Name != "skip-engine" {
		t.Errorf("results[1]: expected 'skip-engine', got %q", results[1].Name)
	}
	if results[1].Err != nil {
		t.Errorf("results[1] (skip): expected nil Err, got: %v", results[1].Err)
	}
	if !results[1].Skipped {
		t.Error("results[1] (skip-engine): expected Skipped=true")
	}

	// results[2] — fail: error
	if results[2].Name != "fail" {
		t.Errorf("results[2]: expected 'fail', got %q", results[2].Name)
	}
	if results[2].Err == nil {
		t.Error("results[2] (fail): expected non-nil Err")
	}
	if results[2].Skipped {
		t.Error("results[2] (fail): expected Skipped=false")
	}
}

// TestAdvanced_IdempotentInstall tests the three-phase flow:
// first call downloads, second call skips, third call with Force=true re-downloads.
// Verifies HTTP request counts to confirm no spurious network calls.
func TestAdvanced_IdempotentInstall(t *testing.T) {
	t.Parallel()

	var serveCount int32
	body, hash := makeBody("idempotent-binary-content")

	ts, client := newTLSTestServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&serveCount, 1)
		w.Write(body)
	}))
	defer ts.Close()

	dir := t.TempDir()
	info := EngineInfo{Name: "idempotent", BinaryName: "idempotent"}
	entry := ManifestEngine{
		Version:           "1.0.0",
		DownloadSupported: true,
		Platforms: map[string]ManifestPlatform{
			PlatformKey(): {URL: ts.URL + "/idempotent", SHA256: hash},
		},
	}
	opts := DownloadOptions{InstallDir: dir, HTTPClient: client}

	// Phase 1: first install.
	r1 := downloadOne(context.Background(), info, entry, opts)
	if r1.Err != nil {
		t.Fatalf("first install: %v", r1.Err)
	}
	if r1.Skipped {
		t.Error("first install: expected Skipped=false")
	}
	if atomic.LoadInt32(&serveCount) != 1 {
		t.Errorf("expected 1 HTTP request for first install, got %d", atomic.LoadInt32(&serveCount))
	}

	// Phase 2: second install (same options) — must skip, no HTTP request.
	r2 := downloadOne(context.Background(), info, entry, opts)
	if r2.Err != nil {
		t.Fatalf("second install (skip): %v", r2.Err)
	}
	if !r2.Skipped {
		t.Error("second install: expected Skipped=true (binary already exists)")
	}
	if atomic.LoadInt32(&serveCount) != 1 {
		t.Errorf("expected no additional HTTP request on skip, serve count: %d", atomic.LoadInt32(&serveCount))
	}

	// Phase 3: force reinstall — must re-download.
	forceOpts := DownloadOptions{InstallDir: dir, Force: true, HTTPClient: client}
	r3 := downloadOne(context.Background(), info, entry, forceOpts)
	if r3.Err != nil {
		t.Fatalf("force reinstall: %v", r3.Err)
	}
	if r3.Skipped {
		t.Error("force reinstall: expected Skipped=false with Force=true")
	}
	if atomic.LoadInt32(&serveCount) != 2 {
		t.Errorf("expected 2 total HTTP requests after force reinstall, got %d", atomic.LoadInt32(&serveCount))
	}
}

// TestAdvanced_DownloadResult_JSONSerialisation verifies the JSON output shape
// of DownloadResult: Err must be absent (json:"-"), ErrMsg carries the error
// string, and zero-value fields obey omitempty.
func TestAdvanced_DownloadResult_JSONSerialisation(t *testing.T) {
	t.Parallel()

	t.Run("success_result", func(t *testing.T) {
		t.Parallel()
		r := DownloadResult{Name: "my-engine", Version: "1.2.3", BytesRead: 12345}
		data, err := json.Marshal(r)
		if err != nil {
			t.Fatalf("json.Marshal: %v", err)
		}
		s := string(data)
		if !strings.Contains(s, `"name":"my-engine"`) {
			t.Errorf("expected name in JSON: %s", s)
		}
		if !strings.Contains(s, `"version":"1.2.3"`) {
			t.Errorf("expected version in JSON: %s", s)
		}
		if !strings.Contains(s, `"bytesRead":12345`) {
			t.Errorf("expected bytesRead in JSON: %s", s)
		}
		// Err must not appear in JSON (json:"-").
		if strings.Contains(s, `"err"`) || strings.Contains(s, `"Err"`) {
			t.Errorf("Err field must be absent from JSON: %s", s)
		}
		// skipped and error must be omitted when zero.
		if strings.Contains(s, `"skipped"`) {
			t.Errorf("skipped must be omitted when false: %s", s)
		}
		if strings.Contains(s, `"error"`) {
			t.Errorf("error must be omitted when empty: %s", s)
		}
	})

	t.Run("error_result", func(t *testing.T) {
		t.Parallel()
		r := DownloadResult{Name: "fail-engine", Version: "0.1.0"}
		r.setErr(fmt.Errorf("network timeout"))
		data, err := json.Marshal(r)
		if err != nil {
			t.Fatalf("json.Marshal: %v", err)
		}
		s := string(data)
		if !strings.Contains(s, `"error":"network timeout"`) {
			t.Errorf("expected error field in JSON: %s", s)
		}
		if strings.Contains(s, `"Err"`) {
			t.Errorf("Err must be absent from JSON: %s", s)
		}
		// bytesRead must be omitted (zero value with omitempty).
		if strings.Contains(s, `"bytesRead"`) {
			t.Errorf("bytesRead must be omitted when zero: %s", s)
		}
	})

	t.Run("skipped_result", func(t *testing.T) {
		t.Parallel()
		r := DownloadResult{Name: "skip-engine", Version: "1.0.0", Skipped: true}
		data, err := json.Marshal(r)
		if err != nil {
			t.Fatalf("json.Marshal: %v", err)
		}
		s := string(data)
		if !strings.Contains(s, `"skipped":true`) {
			t.Errorf("expected skipped:true in JSON: %s", s)
		}
	})
}

// TestAdvanced_DownloadEngines_ResultOrderWithErrors verifies that DownloadEngines
// preserves the input order even when goroutines complete out of order (alternating
// success/fail across 7 engines).
func TestAdvanced_DownloadEngines_ResultOrderWithErrors(t *testing.T) {
	t.Parallel()

	const n = 7
	type edata struct {
		body []byte
		hash string
	}
	data := make(map[int]edata, n)
	for i := 0; i < n; i++ {
		if i%2 == 0 {
			b, h := makeBody(fmt.Sprintf("engine-%d-content", i))
			data[i] = edata{body: b, hash: h}
		}
	}

	ts, client := newTLSTestServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		name := strings.TrimPrefix(r.URL.Path, "/eng")
		var idx int
		fmt.Sscan(name, &idx)
		if d, ok := data[idx]; ok {
			w.Write(d.body)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer ts.Close()

	dir := t.TempDir()
	engines := make([]EngineInfo, n)
	manifest := &Manifest{SchemaVersion: 1, Engines: make(map[string]ManifestEngine, n)}
	for i := 0; i < n; i++ {
		name := fmt.Sprintf("eng%d", i)
		engines[i] = EngineInfo{Name: name, BinaryName: name}
		var platHash string
		if d, ok := data[i]; ok {
			platHash = d.hash
		} else {
			platHash = "0000000000000000000000000000000000000000000000000000000000000000"
		}
		manifest.Engines[name] = ManifestEngine{
			Version:           "1.0.0",
			DownloadSupported: true,
			Platforms: map[string]ManifestPlatform{
				PlatformKey(): {URL: ts.URL + "/" + name, SHA256: platHash},
			},
		}
	}

	results := DownloadEngines(context.Background(), engines, manifest, DownloadOptions{
		InstallDir: dir,
		HTTPClient: client,
	})

	if len(results) != n {
		t.Fatalf("expected %d results, got %d", n, len(results))
	}
	for i, r := range results {
		expectedName := fmt.Sprintf("eng%d", i)
		if r.Name != expectedName {
			t.Errorf("results[%d]: expected name %q, got %q (order violated)", i, expectedName, r.Name)
		}
		if i%2 == 0 {
			if r.Err != nil {
				t.Errorf("results[%d] (even/success): expected nil Err, got: %v", i, r.Err)
			}
		} else {
			if r.Err == nil {
				t.Errorf("results[%d] (odd/fail): expected non-nil Err", i)
			}
		}
	}
}

// TestAdvanced_FetchRemoteManifest_NonOKStatus verifies that 403, 404, and 500
// all cause fallback to the embedded manifest with a non-nil remoteErr.
func TestAdvanced_FetchRemoteManifest_NonOKStatus(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name   string
		status int
	}{
		{"403_Forbidden", http.StatusForbidden},
		{"404_NotFound", http.StatusNotFound},
		{"500_ServerError", http.StatusInternalServerError},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			// Must use TLS server: fetchRemoteManifest enforces HTTPS on manifest URL.
			ts, client := newTLSTestServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tc.status)
			}))
			defer ts.Close()

			m, fallback, remoteErr, err := LoadManifest(context.Background(), ts.URL, client)
			if err != nil {
				t.Fatalf("LoadManifest: %v", err)
			}
			if !fallback {
				t.Errorf("expected fallback=true for HTTP %d", tc.status)
			}
			if remoteErr == nil {
				t.Errorf("expected remoteErr for HTTP %d", tc.status)
			}
			if m == nil || m.SchemaVersion < 1 {
				t.Error("expected valid embedded fallback manifest")
			}
		})
	}
}

// ============================================================
// 7. Regression tests for known patterns
// ============================================================

// TestAdvanced_PlaceholderSHA256_NotProductionSafe documents and verifies that
// the "placeholder" sentinel bypasses SHA-256 verification. A CI gate must
// reject manifest releases that still contain placeholder hashes.
func TestAdvanced_PlaceholderSHA256_NotProductionSafe(t *testing.T) {
	t.Parallel()

	wrongBody := []byte("this-is-not-the-real-binary-content")
	ts, client := newTLSTestServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(wrongBody)
	}))
	defer ts.Close()

	dir := t.TempDir()
	info := EngineInfo{Name: "pre-release", BinaryName: "pre-release"}
	entry := ManifestEngine{
		Version:           "0.0.1-dev",
		DownloadSupported: true,
		Platforms: map[string]ManifestPlatform{
			PlatformKey(): {URL: ts.URL + "/pre-release", SHA256: "placeholder"},
		},
	}

	result := downloadOne(context.Background(), info, entry, DownloadOptions{
		InstallDir: dir,
		HTTPClient: client,
	})

	// CURRENT BEHAVIOUR: placeholder bypasses verification and succeeds.
	// A CI gate is expected to block manifest releases with placeholder hashes.
	if result.Err != nil {
		t.Logf("NOTE: if this fails, the placeholder bypass has been removed — update this test")
		t.Fatalf("unexpected error with placeholder SHA256: %v", result.Err)
	}
	// The file IS written without verification — document this explicitly.
	dest := filepath.Join(dir, "pre-release")
	if _, err := os.Stat(dest); os.IsNotExist(err) {
		t.Error("expected file to be written even with placeholder hash")
	}
}

// TestAdvanced_EmbeddedManifest_PlaceholderAudit logs every manifest entry that
// still carries a placeholder or empty SHA-256. This is the CI gate candidate:
// run with -run TestAdvanced_EmbeddedManifest_PlaceholderAudit and fail if the
// logged count > 0 before any production release.
func TestAdvanced_EmbeddedManifest_PlaceholderAudit(t *testing.T) {
	m, err := LoadEmbeddedManifest()
	if err != nil {
		t.Fatalf("LoadEmbeddedManifest: %v", err)
	}

	var placeholderCount int
	for name, engine := range m.Engines {
		if !engine.DownloadSupported {
			continue
		}
		for plat, p := range engine.Platforms {
			if p.SHA256 == "placeholder" || p.SHA256 == "" {
				placeholderCount++
				t.Logf("WARN: engine %q platform %q has unverified SHA256 %q — CI gate required before release",
					name, plat, p.SHA256)
			}
		}
	}
	t.Logf("Total placeholder/empty SHA256 entries: %d (must be 0 in production releases)", placeholderCount)
}

// TestAdvanced_WindowsExeNotDoubleAppended verifies that a BinaryName already
// ending in ".exe" does not gain a second ".exe" suffix on Windows.
func TestAdvanced_WindowsExeNotDoubleAppended(t *testing.T) {
	t.Parallel()

	if runtime.GOOS != "windows" {
		t.Skip("Windows-only suffix test")
	}

	body, hash := makeBody("windows-binary-with-exe-suffix")
	ts, client := newTLSTestServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(body)
	}))
	defer ts.Close()

	dir := t.TempDir()
	info := EngineInfo{Name: "win-engine", BinaryName: "win-engine.exe"}
	entry := ManifestEngine{
		Version:           "1.0.0",
		DownloadSupported: true,
		Platforms: map[string]ManifestPlatform{
			PlatformKey(): {URL: ts.URL + "/win", SHA256: hash},
		},
	}

	result := downloadOne(context.Background(), info, entry, DownloadOptions{
		InstallDir: dir,
		HTTPClient: client,
	})
	if result.Err != nil {
		t.Fatalf("downloadOne: %v", result.Err)
	}
	if _, err := os.Stat(filepath.Join(dir, "win-engine.exe")); err != nil {
		t.Error("expected file at win-engine.exe")
	}
	if _, err := os.Stat(filepath.Join(dir, "win-engine.exe.exe")); err == nil {
		t.Error("double .exe suffix must not occur")
	}
}

// TestAdvanced_ProgressReaderMonotonicBytes verifies that the progressReader
// reports monotonically increasing byte counts and that the final count equals
// the total bytes in the response body.
func TestAdvanced_ProgressReaderMonotonicBytes(t *testing.T) {
	t.Parallel()

	// 10 KB body to generate multiple Read calls.
	body := bytes.Repeat([]byte("ABCDEFGHIJ"), 1024)
	h := sha256.Sum256(body)
	hashStr := hex.EncodeToString(h[:])

	ts, client := newTLSTestServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(body)
	}))
	defer ts.Close()

	dir := t.TempDir()
	info := EngineInfo{Name: "monotonic", BinaryName: "monotonic"}
	entry := ManifestEngine{
		Version:           "1.0.0",
		DownloadSupported: true,
		Platforms: map[string]ManifestPlatform{
			PlatformKey(): {URL: ts.URL + "/monotonic", SHA256: hashStr},
		},
	}

	var mu sync.Mutex
	var prevBytes int64
	var notMonotonic bool
	var lastBytes int64

	result := downloadOne(context.Background(), info, entry, DownloadOptions{
		InstallDir: dir,
		HTTPClient: client,
		ProgressFunc: func(_ string, b int64) {
			mu.Lock()
			defer mu.Unlock()
			if b < prevBytes {
				notMonotonic = true
			}
			prevBytes = b
			lastBytes = b
		},
	})

	if result.Err != nil {
		t.Fatalf("downloadOne: %v", result.Err)
	}

	mu.Lock()
	mono := notMonotonic
	last := lastBytes
	mu.Unlock()

	if mono {
		t.Error("progress byte counts were not monotonically increasing")
	}
	if last != int64(len(body)) {
		t.Errorf("expected final progress = %d bytes, got %d", len(body), last)
	}
}

// TestAdvanced_DownloadEngines_NilManifest_DoesNotPanic verifies that passing a
// nil *Manifest returns a clean error for each engine without panicking.
func TestAdvanced_DownloadEngines_NilManifest_DoesNotPanic(t *testing.T) {
	t.Parallel()

	defer func() {
		if r := recover(); r != nil {
			t.Errorf("DownloadEngines panicked with nil manifest: %v", r)
		}
	}()

	engines := []EngineInfo{{Name: "nil-manifest-engine", BinaryName: "nil-manifest-engine"}}

	// nil *Manifest is caught by the upfront guard and returns errors
	// without spawning goroutines.
	results := DownloadEngines(context.Background(), engines, nil, DownloadOptions{
		InstallDir: t.TempDir(),
	})

	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	if results[0].Err == nil {
		t.Error("expected non-nil Err for nil manifest")
	}
	if !strings.Contains(results[0].ErrMsg, "manifest is nil") {
		t.Errorf("expected 'manifest is nil' in ErrMsg, got: %q", results[0].ErrMsg)
	}
}

// TestAdvanced_ManifestEngine_PlatformMapNil verifies that a ManifestEngine
// with a nil Platforms map produces a clear "no binary for platform" error
// without panicking (nil map indexing in Go returns zero value).
func TestAdvanced_ManifestEngine_PlatformMapNil(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	info := EngineInfo{Name: "nil-platforms", BinaryName: "nil-platforms"}
	entry := ManifestEngine{
		Version:           "1.0.0",
		DownloadSupported: true,
		Platforms:         nil,
	}

	result := downloadOne(context.Background(), info, entry, DownloadOptions{
		InstallDir: dir,
	})

	if result.Err == nil {
		t.Fatal("expected error for engine with nil platforms map")
	}
	if !strings.Contains(result.Err.Error(), "no binary for platform") {
		t.Errorf("expected 'no binary for platform', got: %v", result.Err)
	}
}

// TestAdvanced_DownloadOne_ErrMsgMirrorsErr verifies the invariant that whenever
// Err is non-nil, ErrMsg must equal Err.Error(). This is critical for JSON
// serialisation because Err is json:"-" and ErrMsg carries the error over the wire.
func TestAdvanced_DownloadOne_ErrMsgMirrorsErr(t *testing.T) {
	t.Parallel()

	ts, client := newTLSTestServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer ts.Close()

	dir := t.TempDir()
	info := EngineInfo{Name: "errmsg-check", BinaryName: "errmsg-check"}
	entry := ManifestEngine{
		Version:           "1.0.0",
		DownloadSupported: true,
		Platforms: map[string]ManifestPlatform{
			PlatformKey(): {URL: ts.URL + "/errmsg", SHA256: "abc"},
		},
	}

	result := downloadOne(context.Background(), info, entry, DownloadOptions{
		InstallDir: dir,
		HTTPClient: client,
	})

	if result.Err == nil {
		t.Fatal("expected error")
	}
	if result.ErrMsg != result.Err.Error() {
		t.Errorf("ErrMsg must equal Err.Error(): ErrMsg=%q, Err=%q", result.ErrMsg, result.Err.Error())
	}
}

// TestAdvanced_BytesReadZeroOnSkip verifies that BytesRead is 0 (omitempty)
// when a download is skipped — no bytes were transferred from the network.
func TestAdvanced_BytesReadZeroOnSkip(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	tempExeFile(t, dir, "zero-bytes-engine", "pre-existing content")

	info := EngineInfo{Name: "zero-bytes-engine", BinaryName: "zero-bytes-engine"}
	entry := ManifestEngine{
		Version:           "1.0.0",
		DownloadSupported: true,
		Platforms: map[string]ManifestPlatform{
			PlatformKey(): {URL: "https://should-not-be-called.example.com/", SHA256: "abc"},
		},
	}

	result := downloadOne(context.Background(), info, entry, DownloadOptions{
		InstallDir: dir,
	})

	if result.Err != nil {
		t.Fatalf("expected skip, got: %v", result.Err)
	}
	if !result.Skipped {
		t.Error("expected Skipped=true")
	}
	if result.BytesRead != 0 {
		t.Errorf("expected BytesRead=0 for skipped download, got %d", result.BytesRead)
	}
}

// TestAdvanced_VersionFieldPopulated verifies that the Version field in
// DownloadResult is populated from the manifest entry, not from the HTTP
// response or the installed binary.
func TestAdvanced_VersionFieldPopulated(t *testing.T) {
	t.Parallel()

	body, hash := makeBody("versioned-binary")
	ts, client := newTLSTestServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(body)
	}))
	defer ts.Close()

	dir := t.TempDir()
	const expectedVersion = "3.14.159"
	info := EngineInfo{Name: "versioned", BinaryName: "versioned"}
	entry := ManifestEngine{
		Version:           expectedVersion,
		DownloadSupported: true,
		Platforms: map[string]ManifestPlatform{
			PlatformKey(): {URL: ts.URL + "/versioned", SHA256: hash},
		},
	}

	result := downloadOne(context.Background(), info, entry, DownloadOptions{
		InstallDir: dir,
		HTTPClient: client,
	})

	if result.Err != nil {
		t.Fatalf("downloadOne: %v", result.Err)
	}
	if result.Version != expectedVersion {
		t.Errorf("expected Version=%q, got %q", expectedVersion, result.Version)
	}
}

// TestAdvanced_DownloadOne_InstallDirCreatedWith0700 verifies that newly created
// install directories receive 0700 permissions (owner-only, not world-readable).
func TestAdvanced_DownloadOne_InstallDirCreatedWith0700(t *testing.T) {
	t.Parallel()

	if runtime.GOOS == "windows" {
		t.Skip("POSIX permission model not applicable on Windows")
	}

	body, hash := makeBody("perm-test-binary")
	ts, client := newTLSTestServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(body)
	}))
	defer ts.Close()

	base := t.TempDir()
	newDir := filepath.Join(base, "deep", "new", "dir")

	info := EngineInfo{Name: "perm-engine", BinaryName: "perm-engine"}
	entry := ManifestEngine{
		Version:           "1.0.0",
		DownloadSupported: true,
		Platforms: map[string]ManifestPlatform{
			PlatformKey(): {URL: ts.URL + "/perm", SHA256: hash},
		},
	}

	result := downloadOne(context.Background(), info, entry, DownloadOptions{
		InstallDir: newDir,
		HTTPClient: client,
	})
	if result.Err != nil {
		t.Fatalf("downloadOne: %v", result.Err)
	}

	fi, err := os.Stat(newDir)
	if err != nil {
		t.Fatalf("stat install dir: %v", err)
	}
	perm := fi.Mode().Perm()
	if perm&0o077 != 0 {
		t.Errorf("install dir permissions should be 0700, got %o (group/world bits set)", perm)
	}
}

// TestAdvanced_DownloadOne_BinaryIsExecutable verifies that a successfully
// downloaded binary has the executable bit set (as applied by Chmod before write).
func TestAdvanced_DownloadOne_BinaryIsExecutable(t *testing.T) {
	t.Parallel()

	if runtime.GOOS == "windows" {
		t.Skip("executable bit not applicable on Windows")
	}

	body, hash := makeBody("executable-binary")
	ts, client := newTLSTestServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(body)
	}))
	defer ts.Close()

	dir := t.TempDir()
	info := EngineInfo{Name: "exe-check", BinaryName: "exe-check"}
	entry := ManifestEngine{
		Version:           "1.0.0",
		DownloadSupported: true,
		Platforms: map[string]ManifestPlatform{
			PlatformKey(): {URL: ts.URL + "/exe", SHA256: hash},
		},
	}

	result := downloadOne(context.Background(), info, entry, DownloadOptions{
		InstallDir: dir,
		HTTPClient: client,
	})
	if result.Err != nil {
		t.Fatalf("downloadOne: %v", result.Err)
	}

	fi, err := os.Stat(filepath.Join(dir, "exe-check"))
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if fi.Mode()&0o111 == 0 {
		t.Errorf("downloaded binary must be executable, got mode %o", fi.Mode())
	}
}

// TestAdvanced_LargeConcurrentProgressCalls stress-tests the ProgressFunc
// callback with 8 concurrent 64 KB downloads to surface any race conditions
// in caller-provided progress implementations under -race.
func TestAdvanced_LargeConcurrentProgressCalls(t *testing.T) {
	t.Parallel()

	const n = 8
	type edata struct {
		body []byte
		hash string
	}
	data := make(map[string]edata, n)
	for i := 0; i < n; i++ {
		name := fmt.Sprintf("big%d", i)
		b := bytes.Repeat([]byte{byte(i + 1)}, 64*1024)
		h := sha256.Sum256(b)
		data[name] = edata{body: b, hash: hex.EncodeToString(h[:])}
	}

	ts, client := newTLSTestServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		name := strings.TrimPrefix(r.URL.Path, "/")
		if d, ok := data[name]; ok {
			w.Write(d.body)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer ts.Close()

	dir := t.TempDir()
	engines := make([]EngineInfo, n)
	manifest := &Manifest{SchemaVersion: 1, Engines: make(map[string]ManifestEngine, n)}
	for i := 0; i < n; i++ {
		name := fmt.Sprintf("big%d", i)
		engines[i] = EngineInfo{Name: name, BinaryName: name}
		manifest.Engines[name] = ManifestEngine{
			Version:           "1.0.0",
			DownloadSupported: true,
			Platforms: map[string]ManifestPlatform{
				PlatformKey(): {URL: ts.URL + "/" + name, SHA256: data[name].hash},
			},
		}
	}

	var totalCalls int64
	results := DownloadEngines(context.Background(), engines, manifest, DownloadOptions{
		InstallDir:   dir,
		HTTPClient:   client,
		ProgressFunc: func(_ string, _ int64) { atomic.AddInt64(&totalCalls, 1) },
	})

	for i, r := range results {
		if r.Err != nil {
			t.Errorf("results[%d] (%s): %v", i, r.Name, r.Err)
		}
	}
	if atomic.LoadInt64(&totalCalls) == 0 {
		t.Error("expected progress callbacks across 8 concurrent 64KB downloads")
	}
}

// TestAdvanced_NoGoroutineLeak verifies that DownloadEngines returns within a
// reasonable deadline, confirming all spawned goroutines complete and are not
// leaked. Not a precise leak detector but catches obvious hang scenarios.
func TestAdvanced_NoGoroutineLeak(t *testing.T) {
	t.Parallel()

	const n = 5
	type edata struct {
		body []byte
		hash string
	}
	data := make(map[string]edata, n)
	for i := 0; i < n; i++ {
		name := fmt.Sprintf("leak%d", i)
		b, h := makeBody(fmt.Sprintf("leak-content-%d", i))
		data[name] = edata{body: b, hash: h}
	}

	ts, client := newTLSTestServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		name := strings.TrimPrefix(r.URL.Path, "/")
		if d, ok := data[name]; ok {
			w.Write(d.body)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer ts.Close()

	dir := t.TempDir()
	engines := make([]EngineInfo, n)
	manifest := &Manifest{SchemaVersion: 1, Engines: make(map[string]ManifestEngine, n)}
	for i := 0; i < n; i++ {
		name := fmt.Sprintf("leak%d", i)
		engines[i] = EngineInfo{Name: name, BinaryName: name}
		manifest.Engines[name] = ManifestEngine{
			Version:           "1.0.0",
			DownloadSupported: true,
			Platforms: map[string]ManifestPlatform{
				PlatformKey(): {URL: ts.URL + "/" + name, SHA256: data[name].hash},
			},
		}
	}

	done := make(chan struct{})
	go func() {
		DownloadEngines(context.Background(), engines, manifest, DownloadOptions{
			InstallDir: dir,
			HTTPClient: client,
		})
		close(done)
	}()

	select {
	case <-done:
		// All goroutines returned — no leak.
	case <-time.After(30 * time.Second):
		t.Fatal("DownloadEngines did not complete within 30s — goroutine leak suspected")
	}
}

// TestAdvanced_DownloadOne_ForceFalse_SkipsExistingFile verifies that Force=false
// (the default) skips an existing file and does not modify its content.
func TestAdvanced_DownloadOne_ForceFalse_SkipsExistingFile(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	existingPath := filepath.Join(dir, "force-false-engine")
	originalContent := []byte("original-content-must-be-preserved")
	if err := os.WriteFile(existingPath, originalContent, 0755); err != nil {
		t.Fatalf("write: %v", err)
	}

	info := EngineInfo{Name: "force-false-engine", BinaryName: "force-false-engine"}
	entry := ManifestEngine{
		Version:           "2.0.0",
		DownloadSupported: true,
		Platforms: map[string]ManifestPlatform{
			PlatformKey(): {URL: "https://should-not-be-called.example.com/", SHA256: "abc"},
		},
	}

	result := downloadOne(context.Background(), info, entry, DownloadOptions{
		InstallDir: dir,
		Force:      false,
	})

	if result.Err != nil {
		t.Fatalf("expected skip, got: %v", result.Err)
	}
	if !result.Skipped {
		t.Error("expected Skipped=true")
	}

	got, err := os.ReadFile(existingPath)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if !bytes.Equal(got, originalContent) {
		t.Error("original file content was modified despite Force=false")
	}
}

// TestAdvanced_DownloadOne_NoHTTPClientUsesDefault verifies that a nil HTTPClient
// in DownloadOptions does not panic. The skip path is taken (binary pre-exists)
// so no actual network call is made, but the nil-client code path is exercised.
func TestAdvanced_DownloadOne_NoHTTPClientUsesDefault(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	tempExeFile(t, dir, "default-client-engine", "pre-existing")

	info := EngineInfo{Name: "default-client-engine", BinaryName: "default-client-engine"}
	entry := ManifestEngine{
		Version:           "1.0.0",
		DownloadSupported: true,
		Platforms: map[string]ManifestPlatform{
			PlatformKey(): {URL: "https://example.com/engine", SHA256: "placeholder"},
		},
	}

	// HTTPClient is nil — must not panic; skip path avoids any network call.
	result := downloadOne(context.Background(), info, entry, DownloadOptions{
		InstallDir: dir,
		HTTPClient: nil,
	})

	if result.Err != nil {
		t.Fatalf("expected skip (binary pre-exists), got: %v", result.Err)
	}
	if !result.Skipped {
		t.Error("expected Skipped=true for pre-existing binary with nil HTTPClient")
	}
}

// TestAdvanced_DownloadEngines_SingleEngine verifies that DownloadEngines with a
// single-element input slice returns exactly one result at index 0 with the
// correct name — regression guard for the indexed channel logic at n=1.
func TestAdvanced_DownloadEngines_SingleEngine(t *testing.T) {
	t.Parallel()

	body, hash := makeBody("single-engine-binary")
	ts, client := newTLSTestServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(body)
	}))
	defer ts.Close()

	dir := t.TempDir()
	engines := []EngineInfo{{Name: "solo", BinaryName: "solo"}}
	manifest := &Manifest{
		SchemaVersion: 1,
		Engines: map[string]ManifestEngine{
			"solo": {
				Version:           "1.0.0",
				DownloadSupported: true,
				Platforms:         map[string]ManifestPlatform{PlatformKey(): {URL: ts.URL + "/solo", SHA256: hash}},
			},
		},
	}

	results := DownloadEngines(context.Background(), engines, manifest, DownloadOptions{
		InstallDir: dir,
		HTTPClient: client,
	})

	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	if results[0].Name != "solo" {
		t.Errorf("expected name 'solo', got %q", results[0].Name)
	}
	if results[0].Err != nil {
		t.Fatalf("expected success: %v", results[0].Err)
	}
}

// TestAdvanced_ProgressReader_DirectUnit is a direct unit test for progressReader
// that bypasses the full download stack, verifying the struct's Read method
// accumulates bytes and calls fn correctly.
func TestAdvanced_ProgressReader_DirectUnit(t *testing.T) {
	t.Parallel()

	payload := []byte("hello world, this is a test payload for progress reader")
	var calls []int64

	pr := &progressReader{
		r:      bytes.NewReader(payload),
		engine: "unit-test",
		fn: func(_ string, b int64) {
			calls = append(calls, b)
		},
	}

	out, err := io.ReadAll(pr)
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	if !bytes.Equal(out, payload) {
		t.Error("progressReader must not modify the underlying bytes")
	}
	if len(calls) == 0 {
		t.Fatal("expected at least one progress callback")
	}
	// Final reported value must equal total payload length.
	if calls[len(calls)-1] != int64(len(payload)) {
		t.Errorf("final progress = %d, want %d", calls[len(calls)-1], len(payload))
	}
	// Each call must be >= the previous (monotonic).
	for i := 1; i < len(calls); i++ {
		if calls[i] < calls[i-1] {
			t.Errorf("progress decreased at call %d: %d < %d", i, calls[i], calls[i-1])
		}
	}
}
