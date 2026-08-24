package configscanner

// Multi-format test:
// - nginx.conf (directive syntax — supported since the server-config sprint
//   via parseDirectives; historically this file asserted nginx.conf was
//   SKIPPED, but well-known server configs are now first-class inputs)
// - server.toml (supported)
// Both mention TLS ciphers. Verify configscanner picks up BOTH: the TOML
// key-value pairs and the nginx ssl_protocols/ssl_ciphers directives
// (decomposed into per-algorithm findings).

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/jimbo111/open-quantum-secure/pkg/engines"
)

func TestMultiFormat_NginxAndTOML(t *testing.T) {
	dir := t.TempDir()

	nginx := `server {
    listen 443 ssl;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-RSA-AES256-GCM-SHA384;
}
`
	toml := `[tls]
protocol = "TLSv1.2"
cipher = "AES-256-GCM"
`
	if err := os.WriteFile(filepath.Join(dir, "nginx.conf"), []byte(nginx), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "server.toml"), []byte(toml), 0o644); err != nil {
		t.Fatal(err)
	}

	// Create a crypto-named subdir so the toml file is matched even though
	// server.toml is not in wellKnownConfigs.
	cryptoDir := filepath.Join(dir, "config")
	if err := os.MkdirAll(cryptoDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(filepath.Join(dir, "server.toml"), filepath.Join(cryptoDir, "server.toml")); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(filepath.Join(dir, "nginx.conf"), filepath.Join(cryptoDir, "nginx.conf")); err != nil {
		t.Fatal(err)
	}

	e := New()
	fds, err := e.Scan(context.Background(), engines.ScanOptions{TargetPath: dir, Mode: engines.ModeFull})
	if err != nil {
		t.Fatal(err)
	}

	// Expect findings from BOTH server.toml and nginx.conf.
	seenTOML := false
	seenNginx := false
	seenNginxCipherAtom := false
	for _, f := range fds {
		t.Logf("finding: file=%s algo=%v line=%d", f.Location.File, f.Algorithm, f.Location.Line)
		if filepath.Ext(f.Location.File) == ".toml" {
			seenTOML = true
		}
		if filepath.Ext(f.Location.File) == ".conf" {
			seenNginx = true
			if f.Algorithm != nil && f.Algorithm.Name == "ECDHE" {
				// ssl_ciphers ECDHE-RSA-AES256-GCM-SHA384 decomposed.
				seenNginxCipherAtom = true
			}
		}
	}

	if !seenTOML {
		t.Error("expected findings from server.toml (TOML is declarative config)")
	}
	if !seenNginx {
		t.Error("expected findings from nginx.conf — well-known server configs are supported (parseDirectives)")
	}
	if !seenNginxCipherAtom {
		t.Error("expected an ECDHE finding from the decomposed nginx ssl_ciphers directive")
	}
}

// TestDetectTotality_EveryExtension creates a minimal fixture for each
// extension in configExtensions and confirms at least one crypto finding is
// produced. This acts as a smoke test that every registered extension's parser
// + vocabulary pipeline works end-to-end.
func TestDetectTotality_EveryExtension(t *testing.T) {
	// Fixtures: (extension, content that should produce at least one finding)
	fixtures := map[string]string{
		".yaml":       "algorithm: AES\n",
		".yml":        "algorithm: AES\n",
		".json":       `{"algorithm":"AES"}`,
		".toml":       `algorithm = "AES"` + "\n",
		".xml":        `<config><algorithm>AES</algorithm></config>`,
		".config":     `<config><algorithm>AES</algorithm></config>`,
		".ini":        "[s]\nalgorithm=AES\n",
		".cfg":        "[s]\nalgorithm=AES\n",
		".cnf":        "[s]\nalgorithm=AES\n",
		".tf":         `algorithm = "AES"` + "\n",
		".hcl":        `algorithm = "AES"` + "\n",
		".tfvars":     `algorithm = "AES"` + "\n",
		".properties": "algorithm=AES\n",
	}

	dir := t.TempDir()
	// Place files in a "config" subdirectory so they get past isConfigFile's
	// dir-keyword gate regardless of filename.
	cfg := filepath.Join(dir, "config")
	if err := os.MkdirAll(cfg, 0o755); err != nil {
		t.Fatal(err)
	}

	for ext, content := range fixtures {
		path := filepath.Join(cfg, "crypto"+ext)
		if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
			t.Fatalf("write %s: %v", path, err)
		}
	}

	e := New()
	fds, err := e.Scan(context.Background(), engines.ScanOptions{TargetPath: dir, Mode: engines.ModeFull})
	if err != nil {
		t.Fatal(err)
	}

	seenExt := make(map[string]int)
	for _, f := range fds {
		seenExt[filepath.Ext(f.Location.File)]++
	}

	for ext := range fixtures {
		if seenExt[ext] == 0 {
			t.Errorf("extension %s produced no findings despite containing algorithm=AES", ext)
		} else {
			t.Logf("extension %s: %d finding(s)", ext, seenExt[ext])
		}
	}
}
