package enginemgr

import (
	"context"
	"net/http"
	"net/http/httptest"
	"runtime"
	"strings"
	"testing"
)

func TestParseManifest_Valid(t *testing.T) {
	m, err := LoadEmbeddedManifest()
	if err != nil {
		t.Fatalf("LoadEmbeddedManifest: %v", err)
	}
	if m.SchemaVersion != 1 {
		t.Errorf("expected schemaVersion 1, got %d", m.SchemaVersion)
	}
	if len(m.Engines) == 0 {
		t.Fatal("expected at least one engine in manifest")
	}
}

func TestParseManifest_AllRegisteredEngines(t *testing.T) {
	m, err := LoadEmbeddedManifest()
	if err != nil {
		t.Fatalf("LoadEmbeddedManifest: %v", err)
	}

	// All external (non-embedded) engines should appear in the manifest.
	for _, info := range Registry() {
		if info.BinaryName == "" {
			continue // embedded engines not in manifest
		}
		if _, ok := m.Engines[info.Name]; !ok {
			t.Errorf("engine %q from registry not found in manifest", info.Name)
		}
	}
}

func TestParseManifest_DownloadSupported(t *testing.T) {
	m, err := LoadEmbeddedManifest()
	if err != nil {
		t.Fatalf("LoadEmbeddedManifest: %v", err)
	}

	// semgrep and cdxgen should not be downloadable.
	for _, name := range []string{"semgrep", "cdxgen"} {
		e, ok := m.Engines[name]
		if !ok {
			t.Errorf("engine %q missing from manifest", name)
			continue
		}
		if e.DownloadSupported {
			t.Errorf("engine %q should have downloadSupported=false", name)
		}
		if e.InstallHintOverride == "" {
			t.Errorf("engine %q should have installHintOverride", name)
		}
	}

	// cipherscope should be downloadable.
	cs, ok := m.Engines["cipherscope"]
	if !ok {
		t.Fatal("cipherscope missing from manifest")
	}
	if !cs.DownloadSupported {
		t.Error("cipherscope should have downloadSupported=true")
	}
	if len(cs.Platforms) == 0 {
		t.Error("cipherscope should have platform entries")
	}
}

func TestParseManifest_PlatformEntries(t *testing.T) {
	m, err := LoadEmbeddedManifest()
	if err != nil {
		t.Fatalf("LoadEmbeddedManifest: %v", err)
	}

	expectedPlatforms := []string{
		"darwin/arm64", "darwin/amd64", "linux/amd64", "linux/arm64", "windows/amd64",
	}

	for name, engine := range m.Engines {
		if !engine.DownloadSupported {
			continue
		}
		for _, plat := range expectedPlatforms {
			p, ok := engine.Platforms[plat]
			if !ok {
				t.Errorf("engine %q missing platform %q", name, plat)
				continue
			}
			if p.URL == "" {
				t.Errorf("engine %q platform %q has empty URL", name, plat)
			}
			if p.SHA256 == "" {
				t.Errorf("engine %q platform %q has empty SHA256", name, plat)
			}
		}
	}
}

func TestParseManifest_InvalidJSON(t *testing.T) {
	_, err := parseManifest([]byte(`not json`))
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
}

func TestParseManifest_InvalidSchemaVersion(t *testing.T) {
	_, err := parseManifest([]byte(`{"schemaVersion": 0, "engines": {}}`))
	if err == nil {
		t.Fatal("expected error for schemaVersion 0")
	}
}

func TestParseManifest_FutureSchemaVersion(t *testing.T) {
	// schemaVersion > 1 is accepted (forward-compatible).
	m, err := parseManifest([]byte(`{"schemaVersion": 2, "engines": {}}`))
	if err != nil {
		t.Fatalf("expected schemaVersion 2 to be accepted, got: %v", err)
	}
	if m.SchemaVersion != 2 {
		t.Errorf("expected schemaVersion 2, got %d", m.SchemaVersion)
	}
}

func TestPlatformKey(t *testing.T) {
	key := PlatformKey()
	expected := runtime.GOOS + "/" + runtime.GOARCH
	if key != expected {
		t.Errorf("expected %q, got %q", expected, key)
	}
}

func TestLoadManifest_Remote(t *testing.T) {
	manifest := `{
		"schemaVersion": 1,
		"engines": {
			"test-engine": {
				"version": "9.9.9",
				"downloadSupported": true,
				"platforms": {
					"linux/amd64": {"url": "https://example.com/test", "sha256": "abc123"}
				}
			}
		}
	}`

	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(manifest))
	}))
	defer ts.Close()

	m, fallback, _, err := LoadManifest(context.Background(), ts.URL, ts.Client())
	if err != nil {
		t.Fatalf("LoadManifest: %v", err)
	}
	if fallback {
		t.Error("expected remote manifest, got fallback")
	}
	if _, ok := m.Engines["test-engine"]; !ok {
		t.Error("expected test-engine in remote manifest")
	}
	if m.Engines["test-engine"].Version != "9.9.9" {
		t.Errorf("expected version 9.9.9, got %s", m.Engines["test-engine"].Version)
	}
}

func TestLoadManifest_FallbackOnRemoteFailure(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer ts.Close()

	m, fallback, remoteErr, err := LoadManifest(context.Background(), ts.URL, ts.Client())
	if err != nil {
		t.Fatalf("LoadManifest: %v", err)
	}
	if !fallback {
		t.Error("expected fallback=true on remote failure")
	}
	if remoteErr == nil {
		t.Error("expected remoteErr to be non-nil on HTTP 500")
	}
	if m.SchemaVersion != 1 {
		t.Errorf("expected embedded manifest schemaVersion 1, got %d", m.SchemaVersion)
	}
}

func TestLoadManifest_FallbackOnEmptyURL(t *testing.T) {
	m, fallback, _, err := LoadManifest(context.Background(), "", nil)
	if err != nil {
		t.Fatalf("LoadManifest: %v", err)
	}
	if !fallback {
		t.Error("expected fallback=true for empty URL")
	}
	if m.SchemaVersion != 1 {
		t.Errorf("expected embedded manifest schemaVersion 1, got %d", m.SchemaVersion)
	}
}

func TestLoadManifest_FallbackOnInvalidJSON(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{invalid json!!!`))
	}))
	defer ts.Close()

	m, fallback, remoteErr, err := LoadManifest(context.Background(), ts.URL, ts.Client())
	if err != nil {
		t.Fatalf("LoadManifest: %v", err)
	}
	if !fallback {
		t.Error("expected fallback=true on invalid JSON")
	}
	if remoteErr == nil {
		t.Error("expected remoteErr for invalid JSON")
	}
	if m.SchemaVersion != 1 {
		t.Errorf("expected embedded manifest schemaVersion 1, got %d", m.SchemaVersion)
	}
}

func TestLoadManifest_FallbackOnConnectionRefused(t *testing.T) {
	// Use a URL that will fail to connect.
	m, fallback, remoteErr, err := LoadManifest(context.Background(), "http://127.0.0.1:1", &http.Client{})
	if err != nil {
		t.Fatalf("LoadManifest: %v", err)
	}
	if !fallback {
		t.Error("expected fallback=true on connection refused")
	}
	if remoteErr == nil {
		t.Error("expected remoteErr on connection refused")
	}
	if m.SchemaVersion != 1 {
		t.Errorf("expected embedded manifest, got schemaVersion %d", m.SchemaVersion)
	}
}

func TestManifest_BinaryOverride(t *testing.T) {
	m, err := LoadEmbeddedManifest()
	if err != nil {
		t.Fatalf("LoadEmbeddedManifest: %v", err)
	}

	ag, ok := m.Engines["astgrep"]
	if !ok {
		t.Fatal("astgrep missing from manifest")
	}
	if ag.BinaryOverride != "ast-grep" {
		t.Errorf("expected binaryOverride='ast-grep', got %q", ag.BinaryOverride)
	}
}

func TestFetchRemoteManifest_HTTPRejected(t *testing.T) {
	// fetchRemoteManifest enforces HTTPS. An HTTP URL should be rejected
	// before any network request is made.
	_, err := fetchRemoteManifest(context.Background(), "http://example.com/manifest.json", &http.Client{})
	if err == nil {
		t.Fatal("expected error for HTTP manifest URL")
	}
	if !strings.Contains(err.Error(), "HTTPS") {
		t.Errorf("expected 'HTTPS' in error message, got: %v", err)
	}
}

func TestManifest_AllURLsAreHTTPS(t *testing.T) {
	m, err := LoadEmbeddedManifest()
	if err != nil {
		t.Fatalf("LoadEmbeddedManifest: %v", err)
	}

	for name, engine := range m.Engines {
		for plat, p := range engine.Platforms {
			if !strings.HasPrefix(p.URL, "https://") {
				t.Errorf("engine %q platform %q has non-HTTPS URL: %s", name, plat, p.URL)
			}
		}
	}
}
