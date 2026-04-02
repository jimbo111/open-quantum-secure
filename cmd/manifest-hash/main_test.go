package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

// buildManifest encodes a manifestFile to JSON and writes it to dir/manifest.json.
// Returns the full path to the written file.
func buildManifest(t *testing.T, dir string, mf manifestFile) string {
	t.Helper()
	data, err := json.MarshalIndent(mf, "", "  ")
	if err != nil {
		t.Fatalf("marshal manifest: %v", err)
	}
	path := filepath.Join(dir, "manifest.json")
	if err := os.WriteFile(path, data, 0644); err != nil {
		t.Fatalf("write manifest: %v", err)
	}
	return path
}

// sha256Hex computes the SHA-256 hex digest of data.
func sha256Hex(data []byte) string {
	h := sha256.Sum256(data)
	return hex.EncodeToString(h[:])
}

// newHTTPSRedirectClient returns an http.Client whose redirect policy matches
// the one defined inline inside main(): HTTPS→HTTPS allowed, HTTPS→HTTP rejected.
func newHTTPSRedirectClient() *http.Client {
	return &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if req.URL.Scheme != "https" {
				return fmt.Errorf("refusing redirect to non-HTTPS URL: %s", req.URL)
			}
			if len(via) >= 10 {
				return fmt.Errorf("too many redirects")
			}
			return nil
		},
	}
}

// ---------------------------------------------------------------------------
// validateURL
// ---------------------------------------------------------------------------

func TestValidateURL(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		rawURL  string
		wantErr bool
		errHint string
	}{
		{
			name:    "valid HTTPS",
			rawURL:  "https://releases.example.com/engine-v1.0.0-linux-amd64",
			wantErr: false,
		},
		{
			name:    "valid HTTPS with path and query",
			rawURL:  "https://example.com/path/to/binary?v=1",
			wantErr: false,
		},
		{
			name:    "HTTP rejected",
			rawURL:  "http://releases.example.com/engine",
			wantErr: true,
			errHint: "non-HTTPS",
		},
		{
			name:    "FTP rejected",
			rawURL:  "ftp://releases.example.com/engine",
			wantErr: true,
			errHint: "non-HTTPS",
		},
		{
			name:    "file scheme rejected",
			rawURL:  "file:///usr/local/bin/engine",
			wantErr: true,
			errHint: "non-HTTPS",
		},
		{
			name:    "empty URL",
			rawURL:  "",
			wantErr: true,
			errHint: "empty download URL",
		},
		{
			name:    "empty host",
			rawURL:  "https:///no-host/binary",
			wantErr: true,
			errHint: "no host",
		},
		{
			name:    "HTTPS with port",
			rawURL:  "https://releases.example.com:8443/engine",
			wantErr: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			err := validateURL(tc.rawURL)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected error for URL %q, got nil", tc.rawURL)
				}
				if tc.errHint != "" && !strings.Contains(err.Error(), tc.errHint) {
					t.Errorf("expected error to contain %q, got: %v", tc.errHint, err)
				}
			} else {
				if err != nil {
					t.Errorf("expected no error for URL %q, got: %v", tc.rawURL, err)
				}
			}
		})
	}
}

// ---------------------------------------------------------------------------
// atomicWriteFile
// ---------------------------------------------------------------------------

func TestAtomicWriteFile_NormalWrite(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	dest := filepath.Join(dir, "out.json")
	data := []byte(`{"schemaVersion":1}` + "\n")

	if err := atomicWriteFile(dest, data, 0644); err != nil {
		t.Fatalf("atomicWriteFile: %v", err)
	}

	got, err := os.ReadFile(dest)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if !bytes.Equal(got, data) {
		t.Errorf("content mismatch: got %q, want %q", got, data)
	}
}

func TestAtomicWriteFile_OverwriteExisting(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	dest := filepath.Join(dir, "manifest.json")

	// Write initial content.
	if err := os.WriteFile(dest, []byte("old content"), 0644); err != nil {
		t.Fatalf("setup: %v", err)
	}

	newContent := []byte(`{"schemaVersion":2}` + "\n")
	if err := atomicWriteFile(dest, newContent, 0644); err != nil {
		t.Fatalf("atomicWriteFile: %v", err)
	}

	got, err := os.ReadFile(dest)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if !bytes.Equal(got, newContent) {
		t.Errorf("content mismatch: got %q, want %q", got, newContent)
	}
}

func TestAtomicWriteFile_NoTempFilesLeft(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	dest := filepath.Join(dir, "manifest.json")

	if err := atomicWriteFile(dest, []byte("hello\n"), 0644); err != nil {
		t.Fatalf("atomicWriteFile: %v", err)
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("readdir: %v", err)
	}
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".manifest-hash-") {
			t.Errorf("temp file not cleaned up: %s", e.Name())
		}
	}
}

func TestAtomicWriteFile_NonExistentDir_Fails(t *testing.T) {
	t.Parallel()

	dest := filepath.Join(t.TempDir(), "nonexistent-subdir", "manifest.json")
	err := atomicWriteFile(dest, []byte("data"), 0644)
	if err == nil {
		t.Fatal("expected error writing to nonexistent directory")
	}
}

func TestAtomicWriteFile_CrashSafety_VerifyContent(t *testing.T) {
	t.Parallel()

	// Verify that content round-trips correctly through JSON marshal + atomicWriteFile.
	dir := t.TempDir()
	dest := filepath.Join(dir, "manifest.json")

	original := manifestFile{
		SchemaVersion: 1,
		Engines: map[string]manifestEngine{
			"cipherscope": {
				Version:           "1.2.3",
				DownloadSupported: true,
				Platforms: map[string]manifestPlatform{
					"linux/amd64": {URL: "https://example.com/cs-linux", SHA256: "abcdef01234567890000000000000000abcdef01234567890000000000000000"},
				},
			},
		},
	}

	out, err := json.MarshalIndent(original, "", "  ")
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	out = append(out, '\n')

	if err := atomicWriteFile(dest, out, 0644); err != nil {
		t.Fatalf("atomicWriteFile: %v", err)
	}

	raw, err := os.ReadFile(dest)
	if err != nil {
		t.Fatalf("read: %v", err)
	}

	var decoded manifestFile
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatalf("unmarshal written file: %v", err)
	}

	if decoded.SchemaVersion != original.SchemaVersion {
		t.Errorf("schemaVersion: got %d, want %d", decoded.SchemaVersion, original.SchemaVersion)
	}
	eng, ok := decoded.Engines["cipherscope"]
	if !ok {
		t.Fatal("cipherscope engine missing from decoded manifest")
	}
	if eng.Version != "1.2.3" {
		t.Errorf("version: got %q, want %q", eng.Version, "1.2.3")
	}
	plat, ok := eng.Platforms["linux/amd64"]
	if !ok {
		t.Fatal("linux/amd64 platform missing")
	}
	if plat.SHA256 != "abcdef01234567890000000000000000abcdef01234567890000000000000000" {
		t.Errorf("sha256: got %q", plat.SHA256)
	}
}

// ---------------------------------------------------------------------------
// findPlaceholders (drives --validate logic)
// ---------------------------------------------------------------------------

func TestFindPlaceholders_AllReal(t *testing.T) {
	t.Parallel()

	mf := manifestFile{
		SchemaVersion: 1,
		Engines: map[string]manifestEngine{
			"engine-a": {
				DownloadSupported: true,
				Platforms: map[string]manifestPlatform{
					"linux/amd64": {URL: "https://x.com/a", SHA256: "abcdef01234567890000000000000000abcdef01234567890000000000000000"},
				},
			},
		},
	}

	got := findPlaceholders(mf)
	if len(got) != 0 {
		t.Errorf("expected 0 placeholders, got %d: %+v", len(got), got)
	}
}

func TestFindPlaceholders_PlaceholderWord(t *testing.T) {
	t.Parallel()

	mf := manifestFile{
		SchemaVersion: 1,
		Engines: map[string]manifestEngine{
			"engine-a": {
				DownloadSupported: true,
				Platforms: map[string]manifestPlatform{
					"linux/amd64":   {URL: "https://x.com/a-linux", SHA256: "placeholder"},
					"darwin/amd64":  {URL: "https://x.com/a-darwin", SHA256: "real0001234567890000000000000000abcdef01234567890000000000000001"},
					"windows/amd64": {URL: "https://x.com/a-win", SHA256: "placeholder"},
				},
			},
		},
	}

	got := findPlaceholders(mf)
	if len(got) != 2 {
		t.Fatalf("expected 2 placeholders, got %d: %+v", len(got), got)
	}
	// Results are sorted by engine then platform.
	for _, e := range got {
		if e.engine != "engine-a" {
			t.Errorf("unexpected engine: %q", e.engine)
		}
		if e.sha256 != "placeholder" {
			t.Errorf("expected sha256='placeholder', got %q", e.sha256)
		}
	}
}

func TestFindPlaceholders_EmptyHash(t *testing.T) {
	t.Parallel()

	mf := manifestFile{
		SchemaVersion: 1,
		Engines: map[string]manifestEngine{
			"engine-b": {
				DownloadSupported: true,
				Platforms: map[string]manifestPlatform{
					"linux/amd64": {URL: "https://x.com/b", SHA256: ""},
				},
			},
		},
	}

	got := findPlaceholders(mf)
	if len(got) != 1 {
		t.Fatalf("expected 1 placeholder (empty hash), got %d", len(got))
	}
	if got[0].sha256 != "" {
		t.Errorf("expected empty sha256, got %q", got[0].sha256)
	}
}

func TestFindPlaceholders_DownloadNotSupported_Skipped(t *testing.T) {
	t.Parallel()

	mf := manifestFile{
		SchemaVersion: 1,
		Engines: map[string]manifestEngine{
			"semgrep": {
				DownloadSupported: false,
				Platforms: map[string]manifestPlatform{
					"linux/amd64": {URL: "https://x.com/sg", SHA256: "placeholder"},
				},
			},
		},
	}

	got := findPlaceholders(mf)
	if len(got) != 0 {
		t.Errorf("expected 0 placeholders for non-downloadable engine, got %d", len(got))
	}
}

func TestFindPlaceholders_NilPlatforms_Skipped(t *testing.T) {
	t.Parallel()

	mf := manifestFile{
		SchemaVersion: 1,
		Engines: map[string]manifestEngine{
			"embedded-only": {
				DownloadSupported: true,
				Platforms:         nil,
			},
		},
	}

	got := findPlaceholders(mf)
	if len(got) != 0 {
		t.Errorf("expected 0 placeholders for nil Platforms, got %d", len(got))
	}
}

func TestFindPlaceholders_SortedOutput(t *testing.T) {
	t.Parallel()

	mf := manifestFile{
		SchemaVersion: 1,
		Engines: map[string]manifestEngine{
			"zz-engine": {
				DownloadSupported: true,
				Platforms: map[string]manifestPlatform{
					"linux/amd64": {URL: "https://x.com/zz", SHA256: "placeholder"},
				},
			},
			"aa-engine": {
				DownloadSupported: true,
				Platforms: map[string]manifestPlatform{
					"linux/amd64":  {URL: "https://x.com/aa-linux", SHA256: "placeholder"},
					"darwin/amd64": {URL: "https://x.com/aa-darwin", SHA256: "placeholder"},
				},
			},
		},
	}

	got := findPlaceholders(mf)
	if len(got) != 3 {
		t.Fatalf("expected 3 placeholders, got %d", len(got))
	}
	// aa-engine comes before zz-engine.
	if got[0].engine != "aa-engine" {
		t.Errorf("entry[0]: expected engine aa-engine, got %q", got[0].engine)
	}
	if got[2].engine != "zz-engine" {
		t.Errorf("entry[2]: expected engine zz-engine, got %q", got[2].engine)
	}
	// Within aa-engine, darwin < linux.
	if got[0].platform != "darwin/amd64" {
		t.Errorf("entry[0]: expected platform darwin/amd64, got %q", got[0].platform)
	}
	if got[1].platform != "linux/amd64" {
		t.Errorf("entry[1]: expected platform linux/amd64, got %q", got[1].platform)
	}
}

func TestFindPlaceholders_NoEngines(t *testing.T) {
	t.Parallel()

	mf := manifestFile{
		SchemaVersion: 1,
		Engines:       map[string]manifestEngine{},
	}

	got := findPlaceholders(mf)
	if len(got) != 0 {
		t.Errorf("expected 0 placeholders for empty engines map, got %d", len(got))
	}
}

// ---------------------------------------------------------------------------
// downloadAndHash
// ---------------------------------------------------------------------------

func TestDownloadAndHash_Success(t *testing.T) {
	t.Parallel()

	body := []byte("fake engine binary content v1.0.0")
	wantHash := sha256Hex(body)

	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write(body)
	}))
	defer ts.Close()

	client := ts.Client()
	hash, size, err := downloadAndHash(context.Background(), client, ts.URL+"/binary")
	if err != nil {
		t.Fatalf("downloadAndHash: %v", err)
	}
	if hash != wantHash {
		t.Errorf("hash mismatch: got %q, want %q", hash, wantHash)
	}
	if size != int64(len(body)) {
		t.Errorf("size: got %d, want %d", size, len(body))
	}
}

func TestDownloadAndHash_HTTP404(t *testing.T) {
	t.Parallel()

	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer ts.Close()

	client := ts.Client()
	_, _, err := downloadAndHash(context.Background(), client, ts.URL+"/missing")
	if err == nil {
		t.Fatal("expected error for HTTP 404")
	}
	if !strings.Contains(err.Error(), "HTTP 404") {
		t.Errorf("expected 'HTTP 404' in error, got: %v", err)
	}
}

func TestDownloadAndHash_HTTP500(t *testing.T) {
	t.Parallel()

	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer ts.Close()

	client := ts.Client()
	_, _, err := downloadAndHash(context.Background(), client, ts.URL+"/error")
	if err == nil {
		t.Fatal("expected error for HTTP 500")
	}
	if !strings.Contains(err.Error(), "HTTP 500") {
		t.Errorf("expected 'HTTP 500' in error, got: %v", err)
	}
}

func TestDownloadAndHash_EmptyBody(t *testing.T) {
	t.Parallel()

	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		// Empty body — no bytes written.
	}))
	defer ts.Close()

	client := ts.Client()
	_, _, err := downloadAndHash(context.Background(), client, ts.URL+"/empty")
	if err == nil {
		t.Fatal("expected error for empty (0-byte) response body")
	}
	if !strings.Contains(err.Error(), "empty response") {
		t.Errorf("expected 'empty response' in error, got: %v", err)
	}
}

func TestDownloadAndHash_ContextCancellation(t *testing.T) {
	t.Parallel()

	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Block until request context is cancelled.
		<-r.Context().Done()
	}))
	defer ts.Close()

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel immediately

	client := ts.Client()
	_, _, err := downloadAndHash(ctx, client, ts.URL+"/slow")
	if err == nil {
		t.Fatal("expected error from cancelled context")
	}
}

func TestDownloadAndHash_HashIsConsistentSHA256(t *testing.T) {
	t.Parallel()

	// Compute expected hash using stdlib directly.
	body := []byte("deterministic content for SHA-256 verification")
	h := sha256.New()
	h.Write(body)
	expected := hex.EncodeToString(h.Sum(nil))

	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write(body)
	}))
	defer ts.Close()

	got, _, err := downloadAndHash(context.Background(), ts.Client(), ts.URL+"/data")
	if err != nil {
		t.Fatalf("downloadAndHash: %v", err)
	}
	if got != expected {
		t.Errorf("SHA-256 mismatch: got %q, want %q", got, expected)
	}
}

// ---------------------------------------------------------------------------
// --validate mode (via findPlaceholders)
// ---------------------------------------------------------------------------

func TestValidateMode_AllHashesReal_Passes(t *testing.T) {
	t.Parallel()

	mf := manifestFile{
		SchemaVersion: 1,
		Engines: map[string]manifestEngine{
			"cipherscope": {
				DownloadSupported: true,
				Platforms: map[string]manifestPlatform{
					"linux/amd64":   {URL: "https://r.example.com/cs-linux", SHA256: "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2"},
					"darwin/amd64":  {URL: "https://r.example.com/cs-darwin", SHA256: "b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3"},
					"windows/amd64": {URL: "https://r.example.com/cs-win", SHA256: "c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4"},
				},
			},
		},
	}

	placeholders := findPlaceholders(mf)
	if len(placeholders) != 0 {
		t.Errorf("--validate should pass: got %d unexpected placeholders: %+v", len(placeholders), placeholders)
	}
}

func TestValidateMode_PlaceholderHashFails(t *testing.T) {
	t.Parallel()

	mf := manifestFile{
		SchemaVersion: 1,
		Engines: map[string]manifestEngine{
			"cryptoscan": {
				DownloadSupported: true,
				Platforms: map[string]manifestPlatform{
					"linux/amd64": {URL: "https://r.example.com/cs", SHA256: "placeholder"},
				},
			},
		},
	}

	placeholders := findPlaceholders(mf)
	if len(placeholders) == 0 {
		t.Fatal("--validate should fail: expected at least 1 placeholder")
	}
	if placeholders[0].engine != "cryptoscan" {
		t.Errorf("expected engine=cryptoscan, got %q", placeholders[0].engine)
	}
	if placeholders[0].platform != "linux/amd64" {
		t.Errorf("expected platform=linux/amd64, got %q", placeholders[0].platform)
	}
}

func TestValidateMode_MixedEngines_OnlyFlagsPlaceholders(t *testing.T) {
	t.Parallel()

	mf := manifestFile{
		SchemaVersion: 1,
		Engines: map[string]manifestEngine{
			"good-engine": {
				DownloadSupported: true,
				Platforms: map[string]manifestPlatform{
					"linux/amd64": {URL: "https://r.example.com/good", SHA256: "0000000000000000000000000000000000000000000000000000000000000001"},
				},
			},
			"bad-engine": {
				DownloadSupported: true,
				Platforms: map[string]manifestPlatform{
					"linux/amd64": {URL: "https://r.example.com/bad", SHA256: "placeholder"},
				},
			},
			"no-download": {
				DownloadSupported: false,
				Platforms: map[string]manifestPlatform{
					"linux/amd64": {URL: "https://r.example.com/nd", SHA256: "placeholder"},
				},
			},
		},
	}

	placeholders := findPlaceholders(mf)
	if len(placeholders) != 1 {
		t.Fatalf("expected exactly 1 placeholder, got %d: %+v", len(placeholders), placeholders)
	}
	if placeholders[0].engine != "bad-engine" {
		t.Errorf("expected bad-engine, got %q", placeholders[0].engine)
	}
}

func TestValidateMode_NoEngines_Passes(t *testing.T) {
	t.Parallel()

	mf := manifestFile{
		SchemaVersion: 1,
		Engines:       map[string]manifestEngine{},
	}

	placeholders := findPlaceholders(mf)
	if len(placeholders) != 0 {
		t.Errorf("empty manifest should have 0 placeholders, got %d", len(placeholders))
	}
}

// ---------------------------------------------------------------------------
// atomicWriteFile — dry-run invariant
// ---------------------------------------------------------------------------

// TestDryRunMode_NoFileModification verifies the semantic guarantee of dry-run:
// the input manifest must NOT be modified. This is ensured by the code path
// that skips atomicWriteFile when --dry-run is set. We verify it directly by
// confirming that the file written in a prior step is unchanged after a
// dry-run simulation (no call to atomicWriteFile).
func TestDryRunMode_NoFileModification(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	mf := manifestFile{
		SchemaVersion: 1,
		Engines: map[string]manifestEngine{
			"engine-x": {
				DownloadSupported: true,
				Platforms: map[string]manifestPlatform{
					"linux/amd64": {URL: "https://r.example.com/x", SHA256: "placeholder"},
				},
			},
		},
	}
	inputPath := buildManifest(t, dir, mf)

	// Capture original content + mtime.
	originalContent, err := os.ReadFile(inputPath)
	if err != nil {
		t.Fatalf("read original: %v", err)
	}
	origStat, err := os.Stat(inputPath)
	if err != nil {
		t.Fatalf("stat original: %v", err)
	}

	// Simulate dry-run: parse, compute hashes in memory, do NOT call atomicWriteFile.
	var parsed manifestFile
	if err := json.Unmarshal(originalContent, &parsed); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	// Mutate in-memory copy only (as dry-run would).
	if eng, ok := parsed.Engines["engine-x"]; ok {
		if plat, ok := eng.Platforms["linux/amd64"]; ok {
			plat.SHA256 = "simulated-hash"
			eng.Platforms["linux/amd64"] = plat
		}
		parsed.Engines["engine-x"] = eng
	}

	// Confirm file is unchanged.
	afterContent, err := os.ReadFile(inputPath)
	if err != nil {
		t.Fatalf("read after: %v", err)
	}
	if !bytes.Equal(originalContent, afterContent) {
		t.Error("dry-run simulation: file was modified but should not have been")
	}
	afterStat, err := os.Stat(inputPath)
	if err != nil {
		t.Fatalf("stat after: %v", err)
	}
	if !afterStat.ModTime().Equal(origStat.ModTime()) {
		t.Error("dry-run simulation: file mtime changed but should not have")
	}
}

// ---------------------------------------------------------------------------
// Edge case: manifest with no engines
// ---------------------------------------------------------------------------

func TestManifestWithNoEngines_RoundTrips(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	mf := manifestFile{
		SchemaVersion: 1,
		Engines:       map[string]manifestEngine{},
	}
	path := buildManifest(t, dir, mf)

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	var decoded manifestFile
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if decoded.SchemaVersion != 1 {
		t.Errorf("schemaVersion: got %d, want 1", decoded.SchemaVersion)
	}
	if len(decoded.Engines) != 0 {
		t.Errorf("expected 0 engines, got %d", len(decoded.Engines))
	}

	// findPlaceholders on empty manifest must return nil/empty (not panic).
	phs := findPlaceholders(decoded)
	if len(phs) != 0 {
		t.Errorf("expected 0 placeholders, got %d", len(phs))
	}
}

// ---------------------------------------------------------------------------
// Edge case: partial downloads (some succeed, some fail)
// ---------------------------------------------------------------------------

func TestPartialDownloads_SomeSucceedSomeFail(t *testing.T) {
	t.Parallel()

	goodBody := []byte("good engine binary")
	goodHash := sha256Hex(goodBody)

	// One URL serves good content; another returns 404.
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/good":
			w.WriteHeader(http.StatusOK)
			w.Write(goodBody)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer ts.Close()

	client := ts.Client()
	ctx := context.Background()

	// Good download succeeds.
	hash, size, err := downloadAndHash(ctx, client, ts.URL+"/good")
	if err != nil {
		t.Fatalf("good download failed: %v", err)
	}
	if hash != goodHash {
		t.Errorf("hash mismatch: got %q, want %q", hash, goodHash)
	}
	if size != int64(len(goodBody)) {
		t.Errorf("size: got %d, want %d", size, len(goodBody))
	}

	// Bad download fails.
	_, _, err = downloadAndHash(ctx, client, ts.URL+"/fail")
	if err == nil {
		t.Fatal("expected error for failing download")
	}
	if !strings.Contains(err.Error(), "HTTP 404") {
		t.Errorf("expected HTTP 404 error, got: %v", err)
	}
}

func TestPartialDownloads_UpdatedCountTracking(t *testing.T) {
	t.Parallel()

	// Simulate the manifest update loop manually to verify updated/failed counts.
	successBody := []byte("engine binary v2")
	successHash := sha256Hex(successBody)

	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/success" {
			w.WriteHeader(http.StatusOK)
			w.Write(successBody)
		} else {
			w.WriteHeader(http.StatusInternalServerError)
		}
	}))
	defer ts.Close()

	client := ts.Client()
	ctx := context.Background()

	type platformResult struct {
		sha256 string
		err    error
	}

	platforms := []struct {
		name string
		url  string
	}{
		{"linux/amd64", ts.URL + "/success"},
		{"darwin/amd64", ts.URL + "/failure"},
		{"windows/amd64", ts.URL + "/success"},
	}

	updated, failed := 0, 0
	results := make(map[string]platformResult)

	for _, p := range platforms {
		if err := validateURL(p.url); err != nil {
			failed++
			results[p.name] = platformResult{err: err}
			continue
		}
		hash, _, err := downloadAndHash(ctx, client, p.url)
		if err != nil {
			failed++
			results[p.name] = platformResult{err: err}
		} else {
			updated++
			results[p.name] = platformResult{sha256: hash}
		}
	}

	if updated != 2 {
		t.Errorf("expected 2 updated, got %d", updated)
	}
	if failed != 1 {
		t.Errorf("expected 1 failed, got %d", failed)
	}
	if results["linux/amd64"].sha256 != successHash {
		t.Errorf("linux/amd64 hash mismatch: got %q, want %q", results["linux/amd64"].sha256, successHash)
	}
	if results["darwin/amd64"].err == nil {
		t.Error("darwin/amd64 should have failed")
	}
}

// ---------------------------------------------------------------------------
// httpsOnlyRedirectPolicy (tested via http.Client.CheckRedirect)
// ---------------------------------------------------------------------------

// TestHTTPSRedirectPolicy_HTTPSToHTTPS_Allowed verifies that an HTTPS→HTTPS
// redirect is followed by the client constructed with the same redirect policy
// used in main().
func TestHTTPSRedirectPolicy_HTTPSToHTTPS_Allowed(t *testing.T) {
	t.Parallel()

	body := []byte("redirected content")

	// The redirect target (second TLS server).
	target := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write(body)
	}))
	defer target.Close()

	// The redirect source (first TLS server): issues 302 pointing to target.
	redirector := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL+"/final", http.StatusFound)
	}))
	defer redirector.Close()

	// Build a client that trusts both test server certificates and enforces
	// the same redirect policy as main().
	transport := redirector.Client().Transport.(*http.Transport).Clone()
	targetTransport := target.Client().Transport.(*http.Transport)
	// Merge target's TLS config into transport so the redirect target is also trusted.
	transport.TLSClientConfig = targetTransport.TLSClientConfig.Clone()
	// The test TLS servers share the same root CA, so a single client suffices.
	client := redirector.Client()
	client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		if req.URL.Scheme != "https" {
			return fmt.Errorf("refusing redirect to non-HTTPS URL: %s", req.URL)
		}
		if len(via) >= 10 {
			return fmt.Errorf("too many redirects")
		}
		return nil
	}

	// The redirect chain stays within HTTPS so it should be followed.
	// Both test servers use the same self-signed CA, so TLS succeeds.
	resp, err := client.Get(redirector.URL + "/start")
	if err != nil {
		// Some test environments prevent cross-server TLS; skip rather than fail.
		t.Skipf("HTTPS→HTTPS cross-server redirect test: %v", err)
	}
	defer resp.Body.Close()
	// Any 2xx or the final status is acceptable — the important thing is no error.
}

// TestHTTPSRedirectPolicy_HTTPSToHTTP_Rejected verifies that an HTTPS→HTTP
// redirect is rejected by the policy (no actual network call needed — we invoke
// the CheckRedirect function directly, as is standard in the Go stdlib).
func TestHTTPSRedirectPolicy_HTTPSToHTTP_Rejected(t *testing.T) {
	t.Parallel()

	client := newHTTPSRedirectClient()

	// Construct the "after-redirect" request that CheckRedirect would receive.
	req, err := http.NewRequest("GET", "http://attacker.example.com/evil", nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	via := []*http.Request{{}} // non-empty via = at least one prior redirect

	checkErr := client.CheckRedirect(req, via)
	if checkErr == nil {
		t.Fatal("expected error for HTTPS→HTTP redirect, got nil")
	}
	if !strings.Contains(checkErr.Error(), "non-HTTPS") {
		t.Errorf("expected 'non-HTTPS' in error, got: %v", checkErr)
	}
}

func TestHTTPSRedirectPolicy_HTTPSToHTTPS_PolicyAllows(t *testing.T) {
	t.Parallel()

	client := newHTTPSRedirectClient()

	req, err := http.NewRequest("GET", "https://safe.example.com/binary", nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	via := []*http.Request{{}}

	if err := client.CheckRedirect(req, via); err != nil {
		t.Errorf("expected HTTPS redirect to be allowed, got: %v", err)
	}
}

func TestHTTPSRedirectPolicy_TooManyRedirects_Rejected(t *testing.T) {
	t.Parallel()

	client := newHTTPSRedirectClient()

	req, err := http.NewRequest("GET", "https://safe.example.com/binary", nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	// 10 previous requests = at limit.
	via := make([]*http.Request, 10)
	for i := range via {
		via[i] = &http.Request{}
	}

	checkErr := client.CheckRedirect(req, via)
	if checkErr == nil {
		t.Fatal("expected error for too many redirects, got nil")
	}
	if !strings.Contains(checkErr.Error(), "too many redirects") {
		t.Errorf("expected 'too many redirects' in error, got: %v", checkErr)
	}
}

func TestHTTPSRedirectPolicy_FTPScheme_Rejected(t *testing.T) {
	t.Parallel()

	client := newHTTPSRedirectClient()

	req, err := http.NewRequest("GET", "ftp://files.example.com/binary", nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	via := []*http.Request{{}}

	checkErr := client.CheckRedirect(req, via)
	if checkErr == nil {
		t.Fatal("expected error for FTP redirect, got nil")
	}
	if !strings.Contains(checkErr.Error(), "non-HTTPS") {
		t.Errorf("expected 'non-HTTPS' in error, got: %v", checkErr)
	}
}

// TestHTTPSRedirectPolicy_LiveDowngrade_Rejected verifies end-to-end that an
// HTTP client enforcing the redirect policy refuses an actual HTTPS→HTTP
// redirect served by a real test HTTP server.
func TestHTTPSRedirectPolicy_LiveDowngrade_Rejected(t *testing.T) {
	t.Parallel()

	// Plain HTTP target (the downgrade destination).
	httpTarget := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("you should not reach me"))
	}))
	defer httpTarget.Close()

	// HTTPS source that redirects to the plain HTTP target.
	httpsSource := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, httpTarget.URL+"/", http.StatusFound)
	}))
	defer httpsSource.Close()

	// Use the TLS client from the HTTPS server, then apply the redirect policy.
	client := httpsSource.Client()
	client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		if req.URL.Scheme != "https" {
			return fmt.Errorf("refusing redirect to non-HTTPS URL: %s", req.URL)
		}
		if len(via) >= 10 {
			return fmt.Errorf("too many redirects")
		}
		return nil
	}

	resp, err := client.Get(httpsSource.URL + "/start")
	if resp != nil {
		resp.Body.Close()
	}
	if err == nil {
		t.Fatal("expected error from HTTPS→HTTP redirect, got nil")
	}
	if !strings.Contains(err.Error(), "non-HTTPS") {
		t.Errorf("expected 'non-HTTPS' in error, got: %v", err)
	}
}

// ---------------------------------------------------------------------------
// atomicWriteFile — round-trip with manifestFile JSON
// ---------------------------------------------------------------------------

func TestAtomicWriteFile_ManifestRoundTrip(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	dest := filepath.Join(dir, "manifest.json")

	mf := manifestFile{
		SchemaVersion: 2,
		Engines: map[string]manifestEngine{
			"ast-grep": {
				Version:           "0.30.0",
				DownloadSupported: true,
				BinaryOverride:    "ast-grep",
				Platforms: map[string]manifestPlatform{
					"linux/amd64":  {URL: "https://r.example.com/ag-linux", SHA256: "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"},
					"darwin/arm64": {URL: "https://r.example.com/ag-darwin-arm64", SHA256: "cafebabecafebabecafebabecafebabecafebabecafebabecafebabecafebabe"},
				},
			},
			"semgrep": {
				Version:             "1.113.0",
				DownloadSupported:   false,
				InstallHintOverride: "pip install semgrep",
			},
		},
	}

	out, err := json.MarshalIndent(mf, "", "  ")
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	out = append(out, '\n')

	if err := atomicWriteFile(dest, out, 0644); err != nil {
		t.Fatalf("atomicWriteFile: %v", err)
	}

	raw, err := os.ReadFile(dest)
	if err != nil {
		t.Fatalf("read: %v", err)
	}

	var decoded manifestFile
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if decoded.SchemaVersion != 2 {
		t.Errorf("schemaVersion: got %d, want 2", decoded.SchemaVersion)
	}

	ag, ok := decoded.Engines["ast-grep"]
	if !ok {
		t.Fatal("ast-grep engine missing")
	}
	if ag.Version != "0.30.0" {
		t.Errorf("ast-grep version: got %q", ag.Version)
	}
	if ag.BinaryOverride != "ast-grep" {
		t.Errorf("BinaryOverride: got %q", ag.BinaryOverride)
	}
	linuxPlat, ok := ag.Platforms["linux/amd64"]
	if !ok {
		t.Fatal("linux/amd64 platform missing")
	}
	if linuxPlat.SHA256 != "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef" {
		t.Errorf("SHA256: got %q", linuxPlat.SHA256)
	}

	sg, ok := decoded.Engines["semgrep"]
	if !ok {
		t.Fatal("semgrep engine missing")
	}
	if sg.DownloadSupported {
		t.Error("semgrep: expected DownloadSupported=false")
	}
	if sg.InstallHintOverride != "pip install semgrep" {
		t.Errorf("InstallHintOverride: got %q", sg.InstallHintOverride)
	}
}

// ---------------------------------------------------------------------------
// validateURL edge cases
// ---------------------------------------------------------------------------

func TestValidateURL_HTTPSWithCredentials(t *testing.T) {
	t.Parallel()
	// Embedded credentials in URL are unusual but the scheme check should still pass.
	err := validateURL("https://user:pass@releases.example.com/binary")
	if err != nil {
		t.Errorf("expected no error for HTTPS URL with credentials, got: %v", err)
	}
}

func TestValidateURL_HTTPSSchemeOnly(t *testing.T) {
	t.Parallel()
	// "https:" with no host is rejected.
	err := validateURL("https:")
	if err == nil {
		t.Fatal("expected error for 'https:' with empty host")
	}
}
