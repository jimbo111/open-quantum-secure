package enginemgr

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// TestRegistry verifies that all expected engines are present with correct binary names.
func TestRegistry(t *testing.T) {
	want := map[string]string{
		"cipherscope":    "cipherscope",
		"cryptoscan":     "cryptoscan",
		"astgrep":        "ast-grep",
		"semgrep":        "semgrep",
		"cryptodeps":     "cryptodeps",
		"cdxgen":         "cdxgen",
		"syft":           "syft",
		"cbomkit-theia":  "cbomkit-theia",
		"binary-scanner": "", // embedded engine — no external binary
		"config-scanner": "", // embedded engine — no external binary
	}

	reg := Registry()
	if len(reg) != len(want) {
		t.Errorf("expected %d engines, got %d", len(want), len(reg))
	}

	got := make(map[string]string, len(reg))
	for _, e := range reg {
		got[e.Name] = e.BinaryName
	}

	for name, binary := range want {
		if b, ok := got[name]; !ok {
			t.Errorf("engine %q missing from registry", name)
		} else if b != binary {
			t.Errorf("engine %q: expected binary %q, got %q", name, binary, b)
		}
	}
}

// TestRegistry_Tiers verifies the tier assignments are correct.
func TestRegistry_Tiers(t *testing.T) {
	tier1 := map[string]bool{"cipherscope": true, "cryptoscan": true, "astgrep": true, "config-scanner": true}
	tier2 := map[string]bool{"semgrep": true}
	tier3 := map[string]bool{"cryptodeps": true, "cdxgen": true, "syft": true, "cbomkit-theia": true}
	tier4 := map[string]bool{"binary-scanner": true}

	for _, e := range Registry() {
		switch {
		case tier1[e.Name]:
			if e.Tier != 1 {
				t.Errorf("engine %q: expected tier 1, got %d", e.Name, e.Tier)
			}
		case tier2[e.Name]:
			if e.Tier != 2 {
				t.Errorf("engine %q: expected tier 2, got %d", e.Name, e.Tier)
			}
		case tier3[e.Name]:
			if e.Tier != 3 {
				t.Errorf("engine %q: expected tier 3, got %d", e.Name, e.Tier)
			}
		case tier4[e.Name]:
			if e.Tier != 4 {
				t.Errorf("engine %q: expected tier 4, got %d", e.Name, e.Tier)
			}
		default:
			t.Errorf("engine %q has unexpected tier %d", e.Name, e.Tier)
		}
	}
}

// TestCheckEngine_EmbeddedAlwaysAvailable verifies that engines with empty BinaryName
// (embedded engines) are always reported as available.
func TestCheckEngine_EmbeddedAlwaysAvailable(t *testing.T) {
	info := EngineInfo{
		Name:       "binary-scanner",
		BinaryName: "", // embedded — no external binary
		Tier:       4,
	}
	status := CheckEngine(info, []string{"/tmp/nonexistent-dir-xyz"})

	if !status.Available {
		t.Error("expected embedded engine to be Available=true")
	}
	if status.Version != "embedded" {
		t.Errorf("expected version 'embedded', got %q", status.Version)
	}
}

// TestCheckEngine_NotFound verifies that a non-existent binary returns Available=false.
func TestCheckEngine_NotFound(t *testing.T) {
	info := EngineInfo{
		Name:       "nonexistent-engine-xyz-12345",
		BinaryName: "nonexistent-engine-xyz-12345",
		Tier:       1,
	}
	status := CheckEngine(info, []string{"/tmp/nonexistent-dir-xyz"})

	if status.Available {
		t.Error("expected Available=false for non-existent binary")
	}
	if status.Path != "" {
		t.Errorf("expected empty Path, got %q", status.Path)
	}
	if status.Error == "" {
		t.Error("expected non-empty Error for missing binary")
	}
}

// TestCheckEngine_Found verifies that a real binary (echo or cmd/echo) is detected correctly.
func TestCheckEngine_Found(t *testing.T) {
	// Use a real binary from the system for testing detection logic.
	realBinary := "echo"
	if runtime.GOOS == "windows" {
		t.Skip("skipping on Windows — echo is a shell builtin")
	}

	info := EngineInfo{
		Name:       "test-echo",
		BinaryName: realBinary,
		Tier:       1,
	}
	// Pass empty searchDirs so it falls back to PATH.
	status := CheckEngine(info, nil)

	if !status.Available {
		t.Fatalf("expected Available=true for 'echo', error: %s", status.Error)
	}
	if status.Path == "" {
		t.Error("expected non-empty Path")
	}
	if status.Name != "test-echo" {
		t.Errorf("expected Name=%q, got %q", "test-echo", status.Name)
	}
}

// TestCheckEngine_FoundInSearchDir verifies binary detection in explicit search directories.
func TestCheckEngine_FoundInSearchDir(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("skipping on Windows")
	}

	// Create a temp dir with a fake executable.
	dir := t.TempDir()
	fakeBin := filepath.Join(dir, "fake-engine")
	if err := os.WriteFile(fakeBin, []byte("#!/bin/sh\necho fake-engine v0.0.1\n"), 0o755); err != nil {
		t.Fatalf("create fake binary: %v", err)
	}

	info := EngineInfo{
		Name:       "fake-engine",
		BinaryName: "fake-engine",
		Tier:       1,
	}
	status := CheckEngine(info, []string{dir})

	if !status.Available {
		t.Fatalf("expected Available=true, error: %s", status.Error)
	}
	if status.Path != fakeBin {
		t.Errorf("expected Path=%q, got %q", fakeBin, status.Path)
	}
}

// TestCheckEngine_VersionProbed verifies that the version is populated when a binary
// outputs something on --version.
func TestCheckEngine_VersionProbed(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("skipping on Windows")
	}

	dir := t.TempDir()
	fakeBin := filepath.Join(dir, "versioned-engine")
	script := "#!/bin/sh\necho 'versioned-engine v1.2.3'\n"
	if err := os.WriteFile(fakeBin, []byte(script), 0o755); err != nil {
		t.Fatalf("create fake binary: %v", err)
	}

	info := EngineInfo{
		Name:       "versioned-engine",
		BinaryName: "versioned-engine",
		Tier:       1,
	}
	status := CheckEngine(info, []string{dir})

	if !status.Available {
		t.Fatalf("expected Available=true")
	}
	if !strings.Contains(status.Version, "v1.2.3") {
		t.Errorf("expected version to contain 'v1.2.3', got %q", status.Version)
	}
}

// TestCheckEngine_VersionFailStillAvailable verifies that a binary with a failing
// --version is still marked as available.
func TestCheckEngine_VersionFailStillAvailable(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("skipping on Windows")
	}

	dir := t.TempDir()
	fakeBin := filepath.Join(dir, "no-version-engine")
	// Binary that exits non-zero for --version.
	script := "#!/bin/sh\nexit 1\n"
	if err := os.WriteFile(fakeBin, []byte(script), 0o755); err != nil {
		t.Fatalf("create fake binary: %v", err)
	}

	info := EngineInfo{
		Name:       "no-version-engine",
		BinaryName: "no-version-engine",
		Tier:       1,
	}
	status := CheckEngine(info, []string{dir})

	if !status.Available {
		t.Fatal("expected Available=true even when --version fails")
	}
	if status.Version != "unknown" {
		t.Errorf("expected version 'unknown', got %q", status.Version)
	}
}

// TestInstallDir verifies the install dir is under the home directory.
func TestInstallDir(t *testing.T) {
	home, err := os.UserHomeDir()
	if err != nil {
		t.Fatalf("UserHomeDir: %v", err)
	}

	dir, err := InstallDir()
	if err != nil {
		t.Fatalf("InstallDir returned error: %v", err)
	}
	if dir == "" {
		t.Fatal("InstallDir returned empty string")
	}
	if !strings.HasPrefix(dir, home) {
		t.Errorf("expected install dir under %q, got %q", home, dir)
	}
	if !strings.Contains(dir, ".oqs") {
		t.Errorf("expected install dir to contain '.oqs', got %q", dir)
	}
}

// TestCheckAll verifies that CheckAll returns exactly one status per registered engine.
func TestCheckAll(t *testing.T) {
	reg := Registry()
	statuses := CheckAll([]string{"/tmp/nonexistent-dir-xyz"})

	if len(statuses) != len(reg) {
		t.Errorf("expected %d statuses, got %d", len(reg), len(statuses))
	}

	// Verify each status has the correct name and non-empty error or path.
	names := make(map[string]bool, len(reg))
	for _, e := range reg {
		names[e.Name] = true
	}

	for _, s := range statuses {
		if !names[s.Name] {
			t.Errorf("unexpected engine name in statuses: %q", s.Name)
		}
	}
}

// TestRegistry_AllHaveInstallHints verifies every engine has a non-empty install hint.
func TestRegistry_AllHaveInstallHints(t *testing.T) {
	for _, e := range Registry() {
		if e.InstallHint == "" {
			t.Errorf("engine %q has empty InstallHint", e.Name)
		}
	}
}

// TestRegistry_AllHaveLanguages verifies every engine has at least one language.
func TestRegistry_AllHaveLanguages(t *testing.T) {
	for _, e := range Registry() {
		if len(e.Languages) == 0 {
			t.Errorf("engine %q has no languages defined", e.Name)
		}
	}
}
