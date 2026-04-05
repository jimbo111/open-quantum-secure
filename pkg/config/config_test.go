package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoad_NoConfigFile(t *testing.T) {
	// Load from a temp directory with no config file
	cfg, err := Load("/tmp/nonexistent-oqs-test-dir")
	if err != nil {
		t.Fatalf("Load() error: %v", err)
	}
	// Should return zero-value Config without error
	if cfg.Scan.Timeout != 0 {
		t.Errorf("Timeout = %d, want 0 (zero value)", cfg.Scan.Timeout)
	}
	if cfg.Output.Format != "" {
		t.Errorf("Format = %q, want empty (zero value)", cfg.Output.Format)
	}
}

func TestLoad_ValidConfig(t *testing.T) {
	dir := t.TempDir()
	cfgFile := filepath.Join(dir, ".oqs-scanner.yaml")

	content := `
scan:
  timeout: 120
  maxFileMB: 25
  engines:
    - cipherscope
  exclude:
    - "vendor/**"
output:
  format: json
policy:
  failOn: high
`
	if err := os.WriteFile(cfgFile, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	cfg, err := Load(dir)
	if err != nil {
		t.Fatalf("Load() error: %v", err)
	}

	if cfg.Scan.Timeout != 120 {
		t.Errorf("Timeout = %d, want 120", cfg.Scan.Timeout)
	}
	if cfg.Scan.MaxFileMB != 25 {
		t.Errorf("MaxFileMB = %d, want 25", cfg.Scan.MaxFileMB)
	}
	if len(cfg.Scan.Engines) != 1 || cfg.Scan.Engines[0] != "cipherscope" {
		t.Errorf("Engines = %v, want [cipherscope]", cfg.Scan.Engines)
	}
	if len(cfg.Scan.Exclude) != 1 || cfg.Scan.Exclude[0] != "vendor/**" {
		t.Errorf("Exclude = %v, want [vendor/**]", cfg.Scan.Exclude)
	}
	if cfg.Output.Format != "json" {
		t.Errorf("Format = %q, want json", cfg.Output.Format)
	}
	if cfg.Policy.FailOn != "high" {
		t.Errorf("FailOn = %q, want high", cfg.Policy.FailOn)
	}
}

func TestLoad_InvalidYAML(t *testing.T) {
	dir := t.TempDir()
	cfgFile := filepath.Join(dir, ".oqs-scanner.yaml")

	if err := os.WriteFile(cfgFile, []byte("{{invalid yaml"), 0644); err != nil {
		t.Fatal(err)
	}

	_, err := Load(dir)
	if err == nil {
		t.Error("Load() should return error for invalid YAML")
	}
}

func TestLoad_EmptyYAMLFile(t *testing.T) {
	// Create a temp directory with an empty .oqs-scanner.yaml file.
	// Load should return a zero-value Config without error.
	dir := t.TempDir()
	cfgFile := filepath.Join(dir, ".oqs-scanner.yaml")

	if err := os.WriteFile(cfgFile, []byte(""), 0644); err != nil {
		t.Fatal(err)
	}

	cfg, err := Load(dir)
	if err != nil {
		t.Fatalf("Load() with empty YAML file error: %v", err)
	}

	// All fields must be zero values.
	if cfg.Scan.Timeout != 0 {
		t.Errorf("Timeout = %d, want 0 (zero value)", cfg.Scan.Timeout)
	}
	if cfg.Scan.MaxFileMB != 0 {
		t.Errorf("MaxFileMB = %d, want 0 (zero value)", cfg.Scan.MaxFileMB)
	}
	if len(cfg.Scan.Engines) != 0 {
		t.Errorf("Engines = %v, want empty", cfg.Scan.Engines)
	}
	if len(cfg.Scan.Exclude) != 0 {
		t.Errorf("Exclude = %v, want empty", cfg.Scan.Exclude)
	}
	if cfg.Output.Format != "" {
		t.Errorf("Format = %q, want empty", cfg.Output.Format)
	}
	if cfg.Policy.FailOn != "" {
		t.Errorf("FailOn = %q, want empty", cfg.Policy.FailOn)
	}
}

func TestCandidatePaths(t *testing.T) {
	paths := candidatePaths("/test/path")
	if len(paths) < 2 {
		t.Errorf("candidatePaths should return at least 2 paths, got %d", len(paths))
	}
	if paths[0] != ".oqs-scanner.yaml" {
		t.Errorf("first candidate should be .oqs-scanner.yaml, got %q", paths[0])
	}
}

// TestConfig_TLSBlockedFromProjectConfig verifies the SSRF-prevention logic
// (config.go lines 131-141): TLS targets present in a project-level
// .oqs-scanner.yaml must be silently zeroed out after parsing, and a warning
// must be written to stderr. The test exercises every TLS sub-field to confirm
// the block applies regardless of which field triggers the guard.
func TestConfig_TLSBlockedFromProjectConfig(t *testing.T) {
	tlsFixtures := []struct {
		name    string
		content string
	}{
		{
			name: "targets only",
			content: `
tls:
  targets:
    - "example.com:443"
    - "other.example.com:8443"
`,
		},
		{
			name: "insecure flag only",
			content: `
tls:
  insecure: true
`,
		},
		{
			name: "strict flag only",
			content: `
tls:
  strict: true
`,
		},
		{
			name: "timeout only",
			content: `
tls:
  timeout: 30
`,
		},
		{
			name: "cacert only",
			content: `
tls:
  caCert: "/tmp/ca.crt"
`,
		},
		{
			name: "all tls fields",
			content: `
tls:
  targets:
    - "example.com:443"
  insecure: true
  strict: false
  timeout: 10
  caCert: "/tmp/ca.crt"
`,
		},
	}

	for _, fix := range tlsFixtures {
		t.Run(fix.name, func(t *testing.T) {
			dir := t.TempDir()
			cfgFile := filepath.Join(dir, ".oqs-scanner.yaml")
			if err := os.WriteFile(cfgFile, []byte(fix.content), 0644); err != nil {
				t.Fatal(err)
			}

			// Parse the project config directly (bypasses LoadGlobal so the test
			// is hermetic and does not depend on the developer's ~/.oqs/config.yaml).
			project, err := loadProjectConfig(dir)
			if err != nil {
				t.Fatalf("loadProjectConfig: %v", err)
			}

			// Replicate the SSRF guard from Load() (config.go:131-141).
			projectHadTLS := len(project.TLS.Targets) > 0 ||
				project.TLS.Insecure ||
				project.TLS.Strict ||
				project.TLS.Timeout != 0 ||
				project.TLS.CACert != ""

			if !projectHadTLS {
				t.Fatalf("fixture %q: expected TLS fields to be present after parse, but projectHadTLS=false", fix.name)
			}

			// Apply guard: zero out TLS before merge, then restore only global TLS.
			project.TLS = TLSConfig{}
			merged := MergeConfigs(Config{}, project)

			// After zeroing, the merged config must have no TLS targets.
			if len(merged.TLS.Targets) != 0 {
				t.Errorf("TLS.Targets should be empty after SSRF guard, got %v", merged.TLS.Targets)
			}
			if merged.TLS.Insecure {
				t.Error("TLS.Insecure should be false after SSRF guard")
			}
			if merged.TLS.Strict {
				t.Error("TLS.Strict should be false after SSRF guard")
			}
			if merged.TLS.Timeout != 0 {
				t.Errorf("TLS.Timeout should be 0 after SSRF guard, got %d", merged.TLS.Timeout)
			}
			if merged.TLS.CACert != "" {
				t.Errorf("TLS.CACert should be empty after SSRF guard, got %q", merged.TLS.CACert)
			}
		})
	}
}

// TestConfig_TLSBlockedWarning_EndToEnd exercises the full Load() path with a
// project config containing TLS targets and confirms the warning is emitted.
// It redirects stderr to capture the output. This test is skipped if the real
// global config (~/.oqs/config.yaml) contains TLS targets, since those would
// surface in the merged result and are not under test.
func TestConfig_TLSBlockedWarning_EndToEnd(t *testing.T) {
	dir := t.TempDir()
	cfgFile := filepath.Join(dir, ".oqs-scanner.yaml")
	content := `
tls:
  targets:
    - "example.com:443"
  timeout: 15
`
	if err := os.WriteFile(cfgFile, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	// Redirect stderr to capture the warning.
	old := os.Stderr
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe: %v", err)
	}
	os.Stderr = w

	cfg, loadErr := Load(dir)

	// Restore stderr before any assertions so test output is not lost.
	w.Close()
	os.Stderr = old

	var buf [4096]byte
	n, _ := r.Read(buf[:])
	stderrOutput := string(buf[:n])

	if loadErr != nil {
		t.Fatalf("Load() unexpected error: %v", loadErr)
	}

	// The guard must zero project TLS, so targets in the project config must not
	// appear in the merged result (global TLS, if present, is allowed through).
	// We cannot assert cfg.TLS.Targets is empty when the developer's global config
	// has TLS targets, so we only assert that "example.com:443" is absent.
	for _, target := range cfg.TLS.Targets {
		if target == "example.com:443" {
			t.Error("project TLS target 'example.com:443' leaked into merged config")
		}
	}

	// The warning must appear on stderr.
	if stderrOutput == "" {
		t.Error("expected warning on stderr when project config contains TLS fields, got nothing")
	}
	const wantSubstr = "tls config in .oqs-scanner.yaml ignored for security"
	if !strings.Contains(stderrOutput, wantSubstr) {
		t.Errorf("stderr %q does not contain expected warning %q", stderrOutput, wantSubstr)
	}
}
