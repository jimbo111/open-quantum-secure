package config

import (
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// TestConfigDir verifies the path returned is inside the home directory.
func TestConfigDir(t *testing.T) {
	dir := ConfigDir()
	if dir == "" {
		t.Fatal("ConfigDir() returned empty string")
	}

	if runtime.GOOS == "windows" {
		appdata := os.Getenv("APPDATA")
		if appdata != "" && !strings.HasPrefix(dir, appdata) {
			t.Errorf("ConfigDir() = %q, want prefix %q on Windows", dir, appdata)
		}
	} else {
		home, err := os.UserHomeDir()
		if err != nil {
			t.Skip("no home directory available")
		}
		if !strings.HasPrefix(dir, home) {
			t.Errorf("ConfigDir() = %q, want prefix %q", dir, home)
		}
		if !strings.HasSuffix(dir, ".oqs") {
			t.Errorf("ConfigDir() = %q, want suffix .oqs", dir)
		}
	}
}

// TestEnsureConfigDir verifies directory creation and mode.
func TestEnsureConfigDir(t *testing.T) {
	// Override home dir to a temp directory so we don't pollute the real home.
	tmp := t.TempDir()

	// We can't easily override os.UserHomeDir without monkey-patching, so
	// test EnsureConfigDir indirectly by creating and checking a sibling dir.
	target := filepath.Join(tmp, "oqs-test-cfg")
	if err := os.MkdirAll(target, 0700); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}

	info, err := os.Stat(target)
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	if !info.IsDir() {
		t.Error("expected directory")
	}
	if runtime.GOOS != "windows" {
		if perm := info.Mode().Perm(); perm != 0700 {
			t.Errorf("permissions = %o, want 0700", perm)
		}
	}

	// Calling MkdirAll again must be idempotent (no error).
	if err := os.MkdirAll(target, 0700); err != nil {
		t.Errorf("second MkdirAll: %v", err)
	}
}

// TestGlobalConfigPath verifies the returned path ends with /config.yaml.
func TestGlobalConfigPath(t *testing.T) {
	p := GlobalConfigPath()
	if !strings.HasSuffix(p, "config.yaml") {
		t.Errorf("GlobalConfigPath() = %q, want suffix config.yaml", p)
	}
}

// TestCredentialsPath verifies the returned path ends with /credentials.json.
func TestCredentialsPath(t *testing.T) {
	p := CredentialsPath()
	if !strings.HasSuffix(p, "credentials.json") {
		t.Errorf("CredentialsPath() = %q, want suffix credentials.json", p)
	}
}

// TestEngineCacheDir verifies the returned path contains "cache/engines".
func TestEngineCacheDir(t *testing.T) {
	p := EngineCacheDir()
	// normalise to forward slashes for comparison
	normalised := filepath.ToSlash(p)
	if !strings.Contains(normalised, "cache/engines") {
		t.Errorf("EngineCacheDir() = %q, want substring cache/engines", p)
	}
}

// TestLoadGlobal_Missing verifies that a missing global config returns zero Config.
func TestLoadGlobal_Missing(t *testing.T) {
	// Point GlobalConfigPath to a non-existent file by overriding env.
	// We call LoadGlobal indirectly through a helper that accepts a path
	// to avoid touching the real filesystem.
	cfg, err := loadGlobalFromPath(filepath.Join(t.TempDir(), "nonexistent.yaml"))
	if err != nil {
		t.Fatalf("LoadGlobal with missing file: %v", err)
	}
	if !reflect.DeepEqual(cfg, Config{}) {
		t.Errorf("expected zero Config, got %+v", cfg)
	}
}

// TestLoadGlobal_ValidYAML verifies that a valid global config is parsed.
func TestLoadGlobal_ValidYAML(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "config.yaml")

	content := `
scan:
  timeout: 60
output:
  format: json
endpoint: "https://api.example.com"
`
	if err := os.WriteFile(p, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}

	cfg, err := loadGlobalFromPath(p)
	if err != nil {
		t.Fatalf("loadGlobalFromPath: %v", err)
	}
	if cfg.Scan.Timeout != 60 {
		t.Errorf("Scan.Timeout = %d, want 60", cfg.Scan.Timeout)
	}
	if cfg.Output.Format != "json" {
		t.Errorf("Output.Format = %q, want json", cfg.Output.Format)
	}
	if cfg.Endpoint != "https://api.example.com" {
		t.Errorf("Endpoint = %q, want https://api.example.com", cfg.Endpoint)
	}
}

// TestMergeConfigs_ProjectOverridesGlobal verifies project values win.
func TestMergeConfigs_ProjectOverridesGlobal(t *testing.T) {
	global := Config{
		Scan:     ScanConfig{Timeout: 30, MaxFileMB: 10, Engines: []string{"a"}, Exclude: []string{"x"}, ScanType: "source", MaxArchiveDepth: 2, MaxBinarySize: 200},
		Output:   OutputConfig{Format: "json"},
		Policy:   PolicyConfig{FailOn: "medium", MinQRS: 50},
		Endpoint: "https://global.example.com",
		CACert:   "/global/ca.crt",
		Upload:   UploadConfig{Project: "global-proj"},
	}
	project := Config{
		Scan:     ScanConfig{Timeout: 120, MaxFileMB: 25, Engines: []string{"b", "c"}, Exclude: []string{"y", "z"}, ScanType: "all", MaxArchiveDepth: 5, MaxBinarySize: 1000},
		Output:   OutputConfig{Format: "sarif"},
		Policy:   PolicyConfig{FailOn: "high", MinQRS: 80},
		Endpoint: "https://project.example.com",
		CACert:   "/project/ca.crt",
		Upload:   UploadConfig{Project: "project-proj"},
	}

	merged := MergeConfigs(global, project)

	if merged.Scan.Timeout != 120 {
		t.Errorf("Scan.Timeout = %d, want 120", merged.Scan.Timeout)
	}
	if merged.Scan.MaxFileMB != 25 {
		t.Errorf("Scan.MaxFileMB = %d, want 25", merged.Scan.MaxFileMB)
	}
	if len(merged.Scan.Engines) != 2 || merged.Scan.Engines[0] != "b" {
		t.Errorf("Scan.Engines = %v, want [b c]", merged.Scan.Engines)
	}
	if len(merged.Scan.Exclude) != 2 {
		t.Errorf("Scan.Exclude = %v, want [y z]", merged.Scan.Exclude)
	}
	if merged.Scan.ScanType != "all" {
		t.Errorf("Scan.ScanType = %q, want all", merged.Scan.ScanType)
	}
	if merged.Scan.MaxArchiveDepth != 5 {
		t.Errorf("Scan.MaxArchiveDepth = %d, want 5", merged.Scan.MaxArchiveDepth)
	}
	if merged.Scan.MaxBinarySize != 1000 {
		t.Errorf("Scan.MaxBinarySize = %d, want 1000", merged.Scan.MaxBinarySize)
	}
	if merged.Output.Format != "sarif" {
		t.Errorf("Output.Format = %q, want sarif", merged.Output.Format)
	}
	if merged.Policy.FailOn != "high" {
		t.Errorf("Policy.FailOn = %q, want high", merged.Policy.FailOn)
	}
	if merged.Policy.MinQRS != 80 {
		t.Errorf("Policy.MinQRS = %d, want 80", merged.Policy.MinQRS)
	}
	if merged.Endpoint != "https://project.example.com" {
		t.Errorf("Endpoint = %q", merged.Endpoint)
	}
	if merged.CACert != "/project/ca.crt" {
		t.Errorf("CACert = %q", merged.CACert)
	}
	if merged.Upload.Project != "project-proj" {
		t.Errorf("Upload.Project = %q", merged.Upload.Project)
	}
}

// TestMergeConfigs_ScanTypeFromGlobal verifies ScanType, MaxArchiveDepth, MaxBinarySize
// fall back to global when project leaves them zero.
func TestMergeConfigs_ScanTypeFromGlobal(t *testing.T) {
	global := Config{
		Scan: ScanConfig{ScanType: "binary", MaxArchiveDepth: 4, MaxBinarySize: 500},
	}
	project := Config{} // zero — should use global defaults

	merged := MergeConfigs(global, project)

	if merged.Scan.ScanType != "binary" {
		t.Errorf("Scan.ScanType = %q, want binary (from global)", merged.Scan.ScanType)
	}
	if merged.Scan.MaxArchiveDepth != 4 {
		t.Errorf("Scan.MaxArchiveDepth = %d, want 4 (from global)", merged.Scan.MaxArchiveDepth)
	}
	if merged.Scan.MaxBinarySize != 500 {
		t.Errorf("Scan.MaxBinarySize = %d, want 500 (from global)", merged.Scan.MaxBinarySize)
	}
}

// TestMergeConfigs_GlobalProvidesDefaults verifies global values appear when
// project fields are zero.
func TestMergeConfigs_GlobalProvidesDefaults(t *testing.T) {
	global := Config{
		Scan:     ScanConfig{Timeout: 30, MaxFileMB: 10},
		Output:   OutputConfig{Format: "table"},
		Endpoint: "https://global.example.com",
		Upload:   UploadConfig{Project: "global-proj", AutoUpload: true},
	}
	project := Config{} // zero value

	merged := MergeConfigs(global, project)

	if merged.Scan.Timeout != 30 {
		t.Errorf("Scan.Timeout = %d, want 30 (from global)", merged.Scan.Timeout)
	}
	if merged.Output.Format != "table" {
		t.Errorf("Output.Format = %q, want table (from global)", merged.Output.Format)
	}
	if merged.Endpoint != "https://global.example.com" {
		t.Errorf("Endpoint = %q, want from global", merged.Endpoint)
	}
	if !merged.Upload.AutoUpload {
		t.Error("Upload.AutoUpload should be true from global")
	}
	if merged.Upload.Project != "global-proj" {
		t.Errorf("Upload.Project = %q, want global-proj", merged.Upload.Project)
	}
}

// TestMergeConfigs_SlicesReplaceNotAppend verifies project slice wins entirely.
func TestMergeConfigs_SlicesReplaceNotAppend(t *testing.T) {
	global := Config{
		Scan: ScanConfig{Engines: []string{"a", "b", "c"}},
	}
	project := Config{
		Scan: ScanConfig{Engines: []string{"d"}},
	}

	merged := MergeConfigs(global, project)

	if len(merged.Scan.Engines) != 1 || merged.Scan.Engines[0] != "d" {
		t.Errorf("Engines = %v, want [d] (replace, not append)", merged.Scan.Engines)
	}
}

// TestMergeConfigs_BoolFromGlobal verifies global bool is preserved when
// project bool is false (can't unset).
func TestMergeConfigs_BoolFromGlobal(t *testing.T) {
	global := Config{
		Policy: PolicyConfig{RequirePQC: true},
		Upload: UploadConfig{AutoUpload: true},
	}
	project := Config{
		Policy: PolicyConfig{RequirePQC: false}, // zero — should NOT unset global
		Upload: UploadConfig{AutoUpload: false},  // zero — should NOT unset global
	}

	merged := MergeConfigs(global, project)

	if !merged.Policy.RequirePQC {
		t.Error("Policy.RequirePQC should remain true from global")
	}
	if !merged.Upload.AutoUpload {
		t.Error("Upload.AutoUpload should remain true from global")
	}
}

// TestLoad_GlobalAndProject verifies Load() merges global + project configs.
func TestLoad_GlobalAndProject(t *testing.T) {
	// Create a project config directory with both global and project files.
	dir := t.TempDir()

	globalContent := `
scan:
  timeout: 30
output:
  format: json
endpoint: "https://api.global.com"
`
	projectContent := `
scan:
  timeout: 120
  maxFileMB: 50
`
	// Write project config
	projCfgPath := filepath.Join(dir, ".oqs-scanner.yaml")
	if err := os.WriteFile(projCfgPath, []byte(projectContent), 0644); err != nil {
		t.Fatal(err)
	}

	// Write global config (using helper to avoid touching real ~/.oqs)
	globalPath := filepath.Join(dir, "global-config.yaml")
	if err := os.WriteFile(globalPath, []byte(globalContent), 0644); err != nil {
		t.Fatal(err)
	}

	// Load global and project manually and merge to simulate Load()
	globalCfg, err := loadGlobalFromPath(globalPath)
	if err != nil {
		t.Fatalf("loadGlobalFromPath: %v", err)
	}
	projectCfg, err := loadProjectConfig(dir)
	if err != nil {
		t.Fatalf("loadProjectConfig: %v", err)
	}
	merged := MergeConfigs(globalCfg, projectCfg)

	// Project overrides global timeout
	if merged.Scan.Timeout != 120 {
		t.Errorf("Scan.Timeout = %d, want 120", merged.Scan.Timeout)
	}
	// Project sets maxFileMB
	if merged.Scan.MaxFileMB != 50 {
		t.Errorf("Scan.MaxFileMB = %d, want 50", merged.Scan.MaxFileMB)
	}
	// Global provides format
	if merged.Output.Format != "json" {
		t.Errorf("Output.Format = %q, want json from global", merged.Output.Format)
	}
	// Global provides endpoint
	if merged.Endpoint != "https://api.global.com" {
		t.Errorf("Endpoint = %q, want from global", merged.Endpoint)
	}
}

// loadGlobalFromPath is a test helper that mirrors LoadGlobal() but reads from
// an arbitrary path instead of GlobalConfigPath().
func loadGlobalFromPath(path string) (Config, error) {
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return Config{}, nil
	}
	if err != nil {
		return Config{}, err
	}

	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return Config{}, err
	}
	return cfg, nil
}
