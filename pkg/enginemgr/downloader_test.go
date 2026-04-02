package enginemgr

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// newTLSTestServer creates an httptest TLS server and returns the server plus
// an HTTP client configured to trust its certificate. All download tests must
// use TLS because downloadOne enforces HTTPS URLs.
func newTLSTestServer(handler http.HandlerFunc) (*httptest.Server, *http.Client) {
	ts := httptest.NewTLSServer(handler)
	return ts, ts.Client()
}

func TestDownloadOne_Success(t *testing.T) {
	body := []byte("#!/bin/sh\necho fake-engine v1.0.0\n")
	hash := sha256.Sum256(body)
	hashStr := hex.EncodeToString(hash[:])

	ts, client := newTLSTestServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(body)
	}))
	defer ts.Close()

	dir := t.TempDir()
	info := EngineInfo{Name: "test-engine", BinaryName: "test-engine"}
	entry := ManifestEngine{
		Version:           "1.0.0",
		DownloadSupported: true,
		Platforms: map[string]ManifestPlatform{
			PlatformKey(): {URL: ts.URL + "/test-engine", SHA256: hashStr},
		},
	}

	result := downloadOne(context.Background(), info, entry, DownloadOptions{
		InstallDir: dir,
		HTTPClient: client,
	})
	if result.Err != nil {
		t.Fatalf("downloadOne: %v", result.Err)
	}
	if result.Skipped {
		t.Error("expected Skipped=false")
	}
	if result.BytesRead != int64(len(body)) {
		t.Errorf("expected %d bytes, got %d", len(body), result.BytesRead)
	}

	// Verify file exists and is executable.
	destPath := filepath.Join(dir, "test-engine")
	fi, err := os.Stat(destPath)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if fi.Mode()&0111 == 0 {
		t.Error("expected executable permissions")
	}
}

func TestDownloadOne_SHA256Mismatch(t *testing.T) {
	ts, client := newTLSTestServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("wrong content"))
	}))
	defer ts.Close()

	dir := t.TempDir()
	info := EngineInfo{Name: "test-engine", BinaryName: "test-engine"}
	entry := ManifestEngine{
		Version:           "1.0.0",
		DownloadSupported: true,
		Platforms: map[string]ManifestPlatform{
			PlatformKey(): {URL: ts.URL + "/test-engine", SHA256: "0000000000000000000000000000000000000000000000000000000000000000"},
		},
	}

	result := downloadOne(context.Background(), info, entry, DownloadOptions{
		InstallDir: dir,
		HTTPClient: client,
	})
	if result.Err == nil {
		t.Fatal("expected SHA-256 mismatch error")
	}
	if !strings.Contains(result.Err.Error(), "SHA-256 mismatch") {
		t.Errorf("expected SHA-256 mismatch, got: %v", result.Err)
	}

	// Verify no corrupt file on disk.
	destPath := filepath.Join(dir, "test-engine")
	if _, err := os.Stat(destPath); !os.IsNotExist(err) {
		t.Error("expected no file on disk after SHA-256 mismatch")
	}
}

func TestDownloadOne_SHA256Mismatch_TempFileCleanup(t *testing.T) {
	ts, client := newTLSTestServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("some content"))
	}))
	defer ts.Close()

	dir := t.TempDir()
	info := EngineInfo{Name: "cleanup-test", BinaryName: "cleanup-test"}
	entry := ManifestEngine{
		Version:           "1.0.0",
		DownloadSupported: true,
		Platforms: map[string]ManifestPlatform{
			PlatformKey(): {URL: ts.URL + "/x", SHA256: "0000000000000000000000000000000000000000000000000000000000000000"},
		},
	}

	_ = downloadOne(context.Background(), info, entry, DownloadOptions{
		InstallDir: dir,
		HTTPClient: client,
	})

	// Verify no temp files remain in directory.
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("readdir: %v", err)
	}
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".engine-download-") {
			t.Errorf("temp file not cleaned up: %s", e.Name())
		}
	}
}

func TestDownloadOne_AlreadyExists_Skip(t *testing.T) {
	dir := t.TempDir()
	destPath := filepath.Join(dir, "existing-engine")
	if err := os.WriteFile(destPath, []byte("existing"), 0755); err != nil {
		t.Fatalf("write: %v", err)
	}

	info := EngineInfo{Name: "existing-engine", BinaryName: "existing-engine"}
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
		t.Fatalf("downloadOne: %v", result.Err)
	}
	if !result.Skipped {
		t.Error("expected Skipped=true for existing binary")
	}
}

func TestDownloadOne_Force_Reinstall(t *testing.T) {
	body := []byte("new-binary-content")
	hash := sha256.Sum256(body)
	hashStr := hex.EncodeToString(hash[:])

	ts, client := newTLSTestServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(body)
	}))
	defer ts.Close()

	dir := t.TempDir()
	destPath := filepath.Join(dir, "force-engine")
	if err := os.WriteFile(destPath, []byte("old-content"), 0755); err != nil {
		t.Fatalf("write: %v", err)
	}

	info := EngineInfo{Name: "force-engine", BinaryName: "force-engine"}
	entry := ManifestEngine{
		Version:           "2.0.0",
		DownloadSupported: true,
		Platforms: map[string]ManifestPlatform{
			PlatformKey(): {URL: ts.URL + "/force-engine", SHA256: hashStr},
		},
	}

	result := downloadOne(context.Background(), info, entry, DownloadOptions{
		InstallDir: dir,
		Force:      true,
		HTTPClient: client,
	})
	if result.Err != nil {
		t.Fatalf("downloadOne: %v", result.Err)
	}
	if result.Skipped {
		t.Error("expected Skipped=false with Force=true")
	}

	// Verify new content.
	got, err := os.ReadFile(destPath)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(got) != string(body) {
		t.Error("expected new content after forced reinstall")
	}
}

func TestDownloadOne_UnsupportedPlatform(t *testing.T) {
	dir := t.TempDir()
	info := EngineInfo{Name: "test-engine", BinaryName: "test-engine"}
	entry := ManifestEngine{
		Version:           "1.0.0",
		DownloadSupported: true,
		Platforms: map[string]ManifestPlatform{
			"plan9/riscv64": {URL: "https://example.com/test", SHA256: "abc"},
		},
	}

	result := downloadOne(context.Background(), info, entry, DownloadOptions{
		InstallDir: dir,
	})
	if result.Err == nil {
		t.Fatal("expected error for unsupported platform")
	}
	if !strings.Contains(result.Err.Error(), "no binary for platform") {
		t.Errorf("expected 'no binary for platform', got: %v", result.Err)
	}
}

func TestDownloadOne_ContextCancellation(t *testing.T) {
	// Server that delays response.
	ts, client := newTLSTestServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(5 * time.Second)
		w.Write([]byte("too late"))
	}))
	defer ts.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	dir := t.TempDir()
	info := EngineInfo{Name: "slow-engine", BinaryName: "slow-engine"}
	entry := ManifestEngine{
		Version:           "1.0.0",
		DownloadSupported: true,
		Platforms: map[string]ManifestPlatform{
			PlatformKey(): {URL: ts.URL + "/slow", SHA256: "abc"},
		},
	}

	result := downloadOne(ctx, info, entry, DownloadOptions{
		InstallDir: dir,
		HTTPClient: client,
	})
	if result.Err == nil {
		t.Fatal("expected error from context cancellation")
	}
}

func TestDownloadOne_Retry429(t *testing.T) {
	var attempts int32
	body := []byte("success-after-retry")
	hash := sha256.Sum256(body)
	hashStr := hex.EncodeToString(hash[:])

	ts, client := newTLSTestServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := atomic.AddInt32(&attempts, 1)
		if n < 3 {
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		w.Write(body)
	}))
	defer ts.Close()

	dir := t.TempDir()
	info := EngineInfo{Name: "retry-engine", BinaryName: "retry-engine"}
	entry := ManifestEngine{
		Version:           "1.0.0",
		DownloadSupported: true,
		Platforms: map[string]ManifestPlatform{
			PlatformKey(): {URL: ts.URL + "/retry", SHA256: hashStr},
		},
	}

	result := downloadOne(context.Background(), info, entry, DownloadOptions{
		InstallDir: dir,
		HTTPClient: client,
	})
	if result.Err != nil {
		t.Fatalf("downloadOne: %v", result.Err)
	}
	if atomic.LoadInt32(&attempts) < 3 {
		t.Errorf("expected at least 3 attempts, got %d", atomic.LoadInt32(&attempts))
	}
}

func TestDownloadOne_Retry503(t *testing.T) {
	var attempts int32
	body := []byte("ok")
	hash := sha256.Sum256(body)
	hashStr := hex.EncodeToString(hash[:])

	ts, client := newTLSTestServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := atomic.AddInt32(&attempts, 1)
		if n < 2 {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		w.Write(body)
	}))
	defer ts.Close()

	dir := t.TempDir()
	info := EngineInfo{Name: "retry503", BinaryName: "retry503"}
	entry := ManifestEngine{
		Version:           "1.0.0",
		DownloadSupported: true,
		Platforms: map[string]ManifestPlatform{
			PlatformKey(): {URL: ts.URL + "/x", SHA256: hashStr},
		},
	}

	result := downloadOne(context.Background(), info, entry, DownloadOptions{
		InstallDir: dir,
		HTTPClient: client,
	})
	if result.Err != nil {
		t.Fatalf("downloadOne: %v", result.Err)
	}
}

func TestDownloadOne_RetryExhaustion(t *testing.T) {
	var attempts int32

	ts, client := newTLSTestServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&attempts, 1)
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer ts.Close()

	dir := t.TempDir()
	info := EngineInfo{Name: "exhaust-engine", BinaryName: "exhaust-engine"}
	entry := ManifestEngine{
		Version:           "1.0.0",
		DownloadSupported: true,
		Platforms: map[string]ManifestPlatform{
			PlatformKey(): {URL: ts.URL + "/exhaust", SHA256: "abc123"},
		},
	}

	result := downloadOne(context.Background(), info, entry, DownloadOptions{
		InstallDir: dir,
		HTTPClient: client,
	})
	if result.Err == nil {
		t.Fatal("expected error after retry exhaustion")
	}
	if !strings.Contains(result.Err.Error(), "download failed after") {
		t.Errorf("expected 'download failed after' error, got: %v", result.Err)
	}
	if got := atomic.LoadInt32(&attempts); got != int32(maxDownloadRetries) {
		t.Errorf("expected %d attempts, got %d", maxDownloadRetries, got)
	}
}

func TestDownloadOne_NonTransientError(t *testing.T) {
	ts, client := newTLSTestServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer ts.Close()

	dir := t.TempDir()
	info := EngineInfo{Name: "notfound", BinaryName: "notfound"}
	entry := ManifestEngine{
		Version:           "1.0.0",
		DownloadSupported: true,
		Platforms: map[string]ManifestPlatform{
			PlatformKey(): {URL: ts.URL + "/nope", SHA256: "abc"},
		},
	}

	result := downloadOne(context.Background(), info, entry, DownloadOptions{
		InstallDir: dir,
		HTTPClient: client,
	})
	if result.Err == nil {
		t.Fatal("expected error for 404")
	}
	if !strings.Contains(result.Err.Error(), "HTTP 404") {
		t.Errorf("expected HTTP 404 error, got: %v", result.Err)
	}
}

func TestDownloadOne_BinaryOverride(t *testing.T) {
	body := []byte("override-binary-content")
	hash := sha256.Sum256(body)
	hashStr := hex.EncodeToString(hash[:])

	ts, client := newTLSTestServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(body)
	}))
	defer ts.Close()

	dir := t.TempDir()
	info := EngineInfo{Name: "astgrep", BinaryName: "ast-grep-original"}
	entry := ManifestEngine{
		Version:           "1.0.0",
		DownloadSupported: true,
		BinaryOverride:    "ast-grep",
		Platforms: map[string]ManifestPlatform{
			PlatformKey(): {URL: ts.URL + "/ast-grep", SHA256: hashStr},
		},
	}

	result := downloadOne(context.Background(), info, entry, DownloadOptions{
		InstallDir: dir,
		HTTPClient: client,
	})
	if result.Err != nil {
		t.Fatalf("downloadOne: %v", result.Err)
	}

	// Verify file uses the override name, not the original BinaryName.
	overridePath := filepath.Join(dir, "ast-grep")
	if _, err := os.Stat(overridePath); err != nil {
		t.Errorf("expected binary at %s (override name), got error: %v", overridePath, err)
	}

	originalPath := filepath.Join(dir, "ast-grep-original")
	if _, err := os.Stat(originalPath); !os.IsNotExist(err) {
		t.Error("expected no file at original BinaryName path")
	}
}

func TestDownloadOne_PathTraversal(t *testing.T) {
	dir := t.TempDir()
	info := EngineInfo{Name: "evil-engine", BinaryName: "../../../etc/passwd"}
	entry := ManifestEngine{
		Version:           "1.0.0",
		DownloadSupported: true,
		Platforms: map[string]ManifestPlatform{
			PlatformKey(): {URL: "https://example.com/evil", SHA256: "abc"},
		},
	}

	result := downloadOne(context.Background(), info, entry, DownloadOptions{
		InstallDir: dir,
	})
	if result.Err == nil {
		t.Fatal("expected error for path traversal in BinaryName")
	}
	if !strings.Contains(result.Err.Error(), "path separator") {
		t.Errorf("expected 'path separator' error, got: %v", result.Err)
	}
}

func TestDownloadOne_PathTraversal_BinaryOverride(t *testing.T) {
	dir := t.TempDir()
	info := EngineInfo{Name: "evil-engine", BinaryName: "safe-name"}
	entry := ManifestEngine{
		Version:           "1.0.0",
		DownloadSupported: true,
		BinaryOverride:    "../../../tmp/evil",
		Platforms: map[string]ManifestPlatform{
			PlatformKey(): {URL: "https://example.com/evil", SHA256: "abc"},
		},
	}

	result := downloadOne(context.Background(), info, entry, DownloadOptions{
		InstallDir: dir,
	})
	if result.Err == nil {
		t.Fatal("expected error for path traversal in BinaryOverride")
	}
	if !strings.Contains(result.Err.Error(), "path separator") {
		t.Errorf("expected 'path separator' error, got: %v", result.Err)
	}
}

func TestDownloadEngines_Parallel(t *testing.T) {
	var served int32

	// Pre-compute bodies and hashes for each engine.
	type engineData struct {
		body []byte
		hash string
	}
	data := map[string]engineData{}
	for _, name := range []string{"eng1", "eng2", "eng3"} {
		b := []byte(fmt.Sprintf("binary for /%s", name))
		h := sha256.Sum256(b)
		data[name] = engineData{body: b, hash: hex.EncodeToString(h[:])}
	}

	ts, client := newTLSTestServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&served, 1)
		name := strings.TrimPrefix(r.URL.Path, "/")
		if d, ok := data[name]; ok {
			w.Write(d.body)
		} else {
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer ts.Close()

	dir := t.TempDir()
	engines := []EngineInfo{
		{Name: "eng1", BinaryName: "eng1"},
		{Name: "eng2", BinaryName: "eng2"},
		{Name: "eng3", BinaryName: "eng3"},
	}
	manifest := &Manifest{
		SchemaVersion: 1,
		Engines: map[string]ManifestEngine{
			"eng1": {Version: "1.0", DownloadSupported: true, Platforms: map[string]ManifestPlatform{
				PlatformKey(): {URL: ts.URL + "/eng1", SHA256: data["eng1"].hash},
			}},
			"eng2": {Version: "2.0", DownloadSupported: true, Platforms: map[string]ManifestPlatform{
				PlatformKey(): {URL: ts.URL + "/eng2", SHA256: data["eng2"].hash},
			}},
			"eng3": {Version: "3.0", DownloadSupported: true, Platforms: map[string]ManifestPlatform{
				PlatformKey(): {URL: ts.URL + "/eng3", SHA256: data["eng3"].hash},
			}},
		},
	}

	results := DownloadEngines(context.Background(), engines, manifest, DownloadOptions{
		InstallDir: dir,
		HTTPClient: client,
	})

	if len(results) != 3 {
		t.Fatalf("expected 3 results, got %d", len(results))
	}

	for i, r := range results {
		if r.Err != nil {
			t.Errorf("result[%d] (%s): %v", i, r.Name, r.Err)
		}
		if r.Name != engines[i].Name {
			t.Errorf("result[%d]: expected name %q, got %q", i, engines[i].Name, r.Name)
		}
	}

	if s := atomic.LoadInt32(&served); s != 3 {
		t.Errorf("expected 3 HTTP requests, got %d", s)
	}
}

func TestDownloadEngines_PartialFailure(t *testing.T) {
	goodBody := []byte("ok")
	goodHash := sha256.Sum256(goodBody)
	goodHashStr := hex.EncodeToString(goodHash[:])

	ts, client := newTLSTestServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "fail") {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.Write(goodBody)
	}))
	defer ts.Close()

	dir := t.TempDir()
	engines := []EngineInfo{
		{Name: "good", BinaryName: "good"},
		{Name: "fail", BinaryName: "fail"},
	}
	manifest := &Manifest{
		SchemaVersion: 1,
		Engines: map[string]ManifestEngine{
			"good": {Version: "1.0", DownloadSupported: true, Platforms: map[string]ManifestPlatform{
				PlatformKey(): {URL: ts.URL + "/good", SHA256: goodHashStr},
			}},
			"fail": {Version: "1.0", DownloadSupported: true, Platforms: map[string]ManifestPlatform{
				PlatformKey(): {URL: ts.URL + "/fail", SHA256: "placeholder"},
			}},
		},
	}

	results := DownloadEngines(context.Background(), engines, manifest, DownloadOptions{
		InstallDir: dir,
		HTTPClient: client,
	})

	if results[0].Err != nil {
		t.Errorf("good engine should succeed: %v", results[0].Err)
	}
	if results[1].Err == nil {
		t.Error("fail engine should fail")
	}
}

func TestDownloadEngines_EmptyList(t *testing.T) {
	manifest := &Manifest{SchemaVersion: 1, Engines: map[string]ManifestEngine{}}
	results := DownloadEngines(context.Background(), nil, manifest, DownloadOptions{
		InstallDir: t.TempDir(),
	})
	if len(results) != 0 {
		t.Errorf("expected 0 results for empty engine list, got %d", len(results))
	}
}

func TestDownloadOne_EmbeddedEngine_NoBinaryName(t *testing.T) {
	dir := t.TempDir()
	info := EngineInfo{Name: "binary-scanner", BinaryName: ""}
	entry := ManifestEngine{
		Version:           "1.0.0",
		DownloadSupported: true,
		Platforms:         map[string]ManifestPlatform{},
	}

	result := downloadOne(context.Background(), info, entry, DownloadOptions{
		InstallDir: dir,
	})
	if result.Err == nil {
		t.Fatal("expected error for empty BinaryName")
	}
	if !strings.Contains(result.Err.Error(), "no binary name") {
		t.Errorf("expected 'no binary name' error, got: %v", result.Err)
	}
}

func TestDownloadOne_AtomicWrite_NoCorruptFile(t *testing.T) {
	// Server that serves partial content then closes connection.
	ts, client := newTLSTestServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", "1000")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("partial"))
		// Force close connection by hijacking.
		if hj, ok := w.(http.Hijacker); ok {
			conn, _, _ := hj.Hijack()
			if conn != nil {
				conn.Close()
			}
		}
	}))
	defer ts.Close()

	dir := t.TempDir()
	info := EngineInfo{Name: "corrupt-test", BinaryName: "corrupt-test"}
	entry := ManifestEngine{
		Version:           "1.0.0",
		DownloadSupported: true,
		Platforms: map[string]ManifestPlatform{
			PlatformKey(): {URL: ts.URL + "/partial", SHA256: "abc123def456abc123def456abc123def456abc123def456abc123def456abcd"},
		},
	}

	result := downloadOne(context.Background(), info, entry, DownloadOptions{
		InstallDir: dir,
		HTTPClient: client,
	})
	// Should error (incomplete download or hash mismatch).
	if result.Err == nil {
		t.Fatal("expected error for partial download")
	}

	// Verify no partial file at final destination.
	destPath := filepath.Join(dir, "corrupt-test")
	if _, err := os.Stat(destPath); err == nil {
		t.Error("expected no file at final destination after failed download")
	}

	// Verify no temp files left behind.
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("readdir: %v", err)
	}
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".engine-download-") {
			t.Errorf("temp file not cleaned up: %s", e.Name())
		}
	}
}

func TestDownloadOne_WindowsExeSuffix(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("skipping Windows-only test")
	}

	body := []byte("windows binary")
	hash := sha256.Sum256(body)
	hashStr := hex.EncodeToString(hash[:])

	ts, client := newTLSTestServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(body)
	}))
	defer ts.Close()

	dir := t.TempDir()
	info := EngineInfo{Name: "win-engine", BinaryName: "win-engine"}
	entry := ManifestEngine{
		Version:           "1.0.0",
		DownloadSupported: true,
		Platforms: map[string]ManifestPlatform{
			PlatformKey(): {URL: ts.URL + "/win", SHA256: hashStr},
		},
	}

	result := downloadOne(context.Background(), info, entry, DownloadOptions{
		InstallDir: dir,
		HTTPClient: client,
	})
	if result.Err != nil {
		t.Fatalf("downloadOne: %v", result.Err)
	}

	// Check .exe suffix.
	destPath := filepath.Join(dir, "win-engine.exe")
	if _, err := os.Stat(destPath); err != nil {
		t.Errorf("expected %s to exist", destPath)
	}
}

func TestDownloadEngines_NotInManifest(t *testing.T) {
	engines := []EngineInfo{{Name: "unknown", BinaryName: "unknown"}}
	manifest := &Manifest{SchemaVersion: 1, Engines: map[string]ManifestEngine{}}

	results := DownloadEngines(context.Background(), engines, manifest, DownloadOptions{
		InstallDir: t.TempDir(),
	})

	if results[0].Err == nil {
		t.Fatal("expected error for engine not in manifest")
	}
	if !strings.Contains(results[0].Err.Error(), "not in manifest") {
		t.Errorf("expected 'not in manifest', got: %v", results[0].Err)
	}
}

func TestDownloadOne_ProgressFunc(t *testing.T) {
	body := []byte("progress-test-body-with-some-content")
	hash := sha256.Sum256(body)
	hashStr := hex.EncodeToString(hash[:])

	ts, client := newTLSTestServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(body)
	}))
	defer ts.Close()

	var lastBytes int64
	progressCalled := false

	dir := t.TempDir()
	info := EngineInfo{Name: "prog-engine", BinaryName: "prog-engine"}
	entry := ManifestEngine{
		Version:           "1.0.0",
		DownloadSupported: true,
		Platforms: map[string]ManifestPlatform{
			PlatformKey(): {URL: ts.URL + "/prog", SHA256: hashStr},
		},
	}

	result := downloadOne(context.Background(), info, entry, DownloadOptions{
		InstallDir: dir,
		HTTPClient: client,
		ProgressFunc: func(engine string, bytesRead int64) {
			progressCalled = true
			lastBytes = bytesRead
			if engine != "prog-engine" {
				t.Errorf("expected engine name 'prog-engine', got %q", engine)
			}
		},
	})
	if result.Err != nil {
		t.Fatalf("downloadOne: %v", result.Err)
	}
	if !progressCalled {
		t.Error("expected ProgressFunc to be called")
	}
	if lastBytes != int64(len(body)) {
		t.Errorf("expected final bytes %d, got %d", len(body), lastBytes)
	}
}

func TestDownloadOne_NonExistentInstallDir(t *testing.T) {
	body := []byte("nested-dir-content")
	hash := sha256.Sum256(body)
	hashStr := hex.EncodeToString(hash[:])

	ts, client := newTLSTestServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(body)
	}))
	defer ts.Close()

	// Use a nested path that doesn't exist yet.
	dir := filepath.Join(t.TempDir(), "deeply", "nested", "dir")

	info := EngineInfo{Name: "nested-engine", BinaryName: "nested-engine"}
	entry := ManifestEngine{
		Version:           "1.0.0",
		DownloadSupported: true,
		Platforms: map[string]ManifestPlatform{
			PlatformKey(): {URL: ts.URL + "/nested", SHA256: hashStr},
		},
	}

	result := downloadOne(context.Background(), info, entry, DownloadOptions{
		InstallDir: dir,
		HTTPClient: client,
	})
	if result.Err != nil {
		t.Fatalf("downloadOne: %v (should create nested dirs)", result.Err)
	}

	// Verify directory was created with restrictive permissions.
	fi, err := os.Stat(dir)
	if err != nil {
		t.Fatalf("stat install dir: %v", err)
	}
	if runtime.GOOS != "windows" {
		if fi.Mode().Perm()&0077 != 0 {
			t.Errorf("expected restrictive dir permissions (0700), got %o", fi.Mode().Perm())
		}
	}
}

// --- Unit tests for validateDownloadURL ---

func TestValidateDownloadURL_HTTPS(t *testing.T) {
	if err := validateDownloadURL("https://example.com/binary"); err != nil {
		t.Errorf("expected HTTPS URL to be valid, got: %v", err)
	}
}

func TestValidateDownloadURL_HTTP_Rejected(t *testing.T) {
	err := validateDownloadURL("http://example.com/binary")
	if err == nil {
		t.Fatal("expected error for HTTP URL")
	}
	if !strings.Contains(err.Error(), "non-HTTPS") {
		t.Errorf("expected 'non-HTTPS' error, got: %v", err)
	}
}

func TestValidateDownloadURL_FTP_Rejected(t *testing.T) {
	err := validateDownloadURL("ftp://example.com/binary")
	if err == nil {
		t.Fatal("expected error for FTP URL")
	}
}

func TestValidateDownloadURL_Empty(t *testing.T) {
	err := validateDownloadURL("")
	if err == nil {
		t.Fatal("expected error for empty URL")
	}
}

// --- Unit tests for isTransientErr ---

func TestIsTransientErr(t *testing.T) {
	if !isTransientErr(&transientError{StatusCode: 429}) {
		t.Error("expected 429 to be transient")
	}
	if !isTransientErr(&transientError{StatusCode: 503}) {
		t.Error("expected 503 to be transient")
	}
	if !isTransientErr(&transientError{StatusCode: 504}) {
		t.Error("expected 504 to be transient")
	}
	if isTransientErr(fmt.Errorf("not transient")) {
		t.Error("expected regular error to not be transient")
	}
}

func TestIsTransientErr_Wrapped(t *testing.T) {
	wrapped := fmt.Errorf("wrapper: %w", &transientError{StatusCode: 429})
	if !isTransientErr(wrapped) {
		t.Error("expected wrapped transient error to be detected via errors.As")
	}
}

// --- Unit tests for setErr ---

func TestDownloadResult_SetErr(t *testing.T) {
	r := &DownloadResult{Name: "test"}
	r.setErr(fmt.Errorf("something failed"))
	if r.Err == nil {
		t.Fatal("expected Err to be set")
	}
	if r.ErrMsg != "something failed" {
		t.Errorf("expected ErrMsg='something failed', got %q", r.ErrMsg)
	}
}

// --- DownloadOne with placeholder SHA-256 ---

func TestDownloadOne_PlaceholderSHA256(t *testing.T) {
	body := []byte("any content — hash not verified")

	ts, client := newTLSTestServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(body)
	}))
	defer ts.Close()

	dir := t.TempDir()
	info := EngineInfo{Name: "placeholder-engine", BinaryName: "placeholder-engine"}
	entry := ManifestEngine{
		Version:           "1.0.0",
		DownloadSupported: true,
		Platforms: map[string]ManifestPlatform{
			PlatformKey(): {URL: ts.URL + "/placeholder", SHA256: "placeholder"},
		},
	}

	result := downloadOne(context.Background(), info, entry, DownloadOptions{
		InstallDir: dir,
		HTTPClient: client,
	})
	if result.Err != nil {
		t.Fatalf("downloadOne with placeholder SHA256 should succeed: %v", result.Err)
	}
}

func TestDownloadOne_EmptySHA256(t *testing.T) {
	body := []byte("any content — hash not verified")

	ts, client := newTLSTestServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(body)
	}))
	defer ts.Close()

	dir := t.TempDir()
	info := EngineInfo{Name: "empty-hash", BinaryName: "empty-hash"}
	entry := ManifestEngine{
		Version:           "1.0.0",
		DownloadSupported: true,
		Platforms: map[string]ManifestPlatform{
			PlatformKey(): {URL: ts.URL + "/empty-hash", SHA256: ""},
		},
	}

	result := downloadOne(context.Background(), info, entry, DownloadOptions{
		InstallDir: dir,
		HTTPClient: client,
	})
	if result.Err != nil {
		t.Fatalf("downloadOne with empty SHA256 should succeed: %v", result.Err)
	}
}

func TestHTTPSOnlyRedirectPolicy_AllowsHTTPS(t *testing.T) {
	t.Parallel()
	req, _ := http.NewRequest("GET", "https://example.com/binary", nil)
	err := httpsOnlyRedirectPolicy(req, []*http.Request{req})
	if err != nil {
		t.Fatalf("expected HTTPS redirect to be allowed, got: %v", err)
	}
}

func TestHTTPSOnlyRedirectPolicy_RejectsHTTP(t *testing.T) {
	t.Parallel()
	req, _ := http.NewRequest("GET", "http://evil.com/binary", nil)
	err := httpsOnlyRedirectPolicy(req, []*http.Request{req})
	if err == nil {
		t.Fatal("expected error for HTTP redirect")
	}
	if !strings.Contains(err.Error(), "non-HTTPS") {
		t.Errorf("expected 'non-HTTPS' in error, got: %v", err)
	}
}

func TestHTTPSOnlyRedirectPolicy_RejectsTooManyRedirects(t *testing.T) {
	t.Parallel()
	req, _ := http.NewRequest("GET", "https://example.com/binary", nil)
	via := make([]*http.Request, 10)
	err := httpsOnlyRedirectPolicy(req, via)
	if err == nil {
		t.Fatal("expected error for too many redirects")
	}
	if !strings.Contains(err.Error(), "too many redirects") {
		t.Errorf("expected 'too many redirects' in error, got: %v", err)
	}
}

func TestSecureHTTPClient_TimeoutAndRedirectPolicy(t *testing.T) {
	t.Parallel()
	client := SecureHTTPClient(42 * time.Second)
	if client.Timeout != 42*time.Second {
		t.Errorf("expected timeout 42s, got %v", client.Timeout)
	}
	if client.CheckRedirect == nil {
		t.Fatal("expected CheckRedirect to be set")
	}
}

func TestDownloadEngines_NilManifest(t *testing.T) {
	t.Parallel()
	engines := []EngineInfo{{Name: "test-engine", BinaryName: "test"}}
	results := DownloadEngines(context.Background(), engines, nil, DownloadOptions{
		InstallDir: t.TempDir(),
	})
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	if results[0].Err == nil {
		t.Fatal("expected error for nil manifest")
	}
	if !strings.Contains(results[0].ErrMsg, "manifest is nil") {
		t.Errorf("expected 'manifest is nil' in error, got: %s", results[0].ErrMsg)
	}
}
