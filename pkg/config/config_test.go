package config

import (
	"os"
	"path/filepath"
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
