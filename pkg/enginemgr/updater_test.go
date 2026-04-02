package enginemgr

import (
	"context"
	"testing"
)

func TestVersionMatches(t *testing.T) {
	tests := []struct {
		name     string
		inst     string
		manifest string
		want     bool
	}{
		{"exact", "0.5.0", "0.5.0", true},
		{"name-prefixed", "cipherscope 0.5.0", "0.5.0", true},
		{"v-prefix-installed", "v0.5.0", "0.5.0", true},
		{"v-prefix-manifest", "0.5.0", "v0.5.0", true},
		{"both-v-prefix", "v0.5.0", "v0.5.0", true},
		{"name-with-v", "syft v1.21.0", "1.21.0", true},
		{"hyphenated-name", "ast-grep 0.38.0", "0.38.0", true},
		{"different-version", "0.4.0", "0.5.0", false},
		{"unknown-installed", "unknown", "0.5.0", false},
		{"empty-installed", "", "0.5.0", false},
		{"empty-manifest", "0.5.0", "", false},
		{"both-empty", "", "", false},
		{"partial-mismatch", "0.5.1", "0.5.0", false},
		{"manifest-in-installed", "cipherscope 0.5.0-beta", "0.5.0", true},
		{"no-false-positive-substring", "1.21.0", "1.2", false},    // word-boundary prevents "1.2" matching "1.21.0"
		{"no-false-positive-prefix", "21.2.0", "1.2", false},       // "1.2" must not match "21.2.0"
		{"major-minor-match", "syft 1.2.0", "1.2.0", true},        // exact semver match
		{"two-component-exact", "tool 1.2", "1.2", true},           // 2-component match
		{"build-metadata", "tool 0.5.0+build123", "0.5.0", true},   // build metadata doesn't affect version
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := versionMatches(tt.inst, tt.manifest)
			if got != tt.want {
				t.Errorf("versionMatches(%q, %q) = %v, want %v", tt.inst, tt.manifest, got, tt.want)
			}
		})
	}
}

func TestCheckForUpdates_EmbeddedEngine(t *testing.T) {
	targets := []EngineInfo{{
		Name:       "binary-scanner",
		BinaryName: "",
		BuildTool:  "embedded",
	}}
	manifest := &Manifest{
		SchemaVersion: 1,
		Engines:       map[string]ManifestEngine{},
	}

	checks := CheckForUpdates(context.Background(), targets, manifest, nil)
	if len(checks) != 1 {
		t.Fatalf("expected 1 check, got %d", len(checks))
	}
	if checks[0].UpdateAvailable {
		t.Error("embedded engine should not have update available")
	}
	if checks[0].Reason != "built-in engine (no update needed)" {
		t.Errorf("unexpected reason: %s", checks[0].Reason)
	}
}

func TestCheckForUpdates_NotInManifest(t *testing.T) {
	targets := []EngineInfo{{
		Name:       "custom-engine",
		BinaryName: "custom",
	}}
	manifest := &Manifest{
		SchemaVersion: 1,
		Engines:       map[string]ManifestEngine{},
	}

	checks := CheckForUpdates(context.Background(), targets, manifest, nil)
	if len(checks) != 1 {
		t.Fatalf("expected 1 check, got %d", len(checks))
	}
	if checks[0].Reason != "not in manifest" {
		t.Errorf("unexpected reason: %s", checks[0].Reason)
	}
}

func TestCheckForUpdates_NotDownloadable(t *testing.T) {
	targets := []EngineInfo{{
		Name:       "semgrep",
		BinaryName: "semgrep",
	}}
	manifest := &Manifest{
		SchemaVersion: 1,
		Engines: map[string]ManifestEngine{
			"semgrep": {
				Version:           "1.113.0",
				DownloadSupported: false,
			},
		},
	}

	checks := CheckForUpdates(context.Background(), targets, manifest, nil)
	if len(checks) != 1 {
		t.Fatalf("expected 1 check, got %d", len(checks))
	}
	if checks[0].ManifestVersion != "1.113.0" {
		t.Errorf("unexpected manifest version: %s", checks[0].ManifestVersion)
	}
	if checks[0].Reason != "not available for download" {
		t.Errorf("unexpected reason: %s", checks[0].Reason)
	}
}

func TestCheckForUpdates_NotInstalled(t *testing.T) {
	targets := []EngineInfo{{
		Name:       "cipherscope",
		BinaryName: "cipherscope-nonexistent-binary-xyz",
	}}
	manifest := &Manifest{
		SchemaVersion: 1,
		Engines: map[string]ManifestEngine{
			"cipherscope": {
				Version:           "0.5.0",
				DownloadSupported: true,
			},
		},
	}

	// Search in non-existent dirs so nothing is found.
	checks := CheckForUpdates(context.Background(), targets, manifest, []string{"/nonexistent-dir-xyz"})
	if len(checks) != 1 {
		t.Fatalf("expected 1 check, got %d", len(checks))
	}
	if checks[0].Installed {
		t.Error("engine should not be installed")
	}
	if checks[0].Reason != "not installed" {
		t.Errorf("unexpected reason: %s", checks[0].Reason)
	}
}

func TestCheckForUpdates_MultipleTargets(t *testing.T) {
	targets := []EngineInfo{
		{Name: "binary-scanner", BinaryName: ""},
		{Name: "semgrep", BinaryName: "semgrep"},
		{Name: "missing", BinaryName: "missing-xyz"},
	}
	manifest := &Manifest{
		SchemaVersion: 1,
		Engines: map[string]ManifestEngine{
			"semgrep": {Version: "1.113.0", DownloadSupported: false},
		},
	}

	checks := CheckForUpdates(context.Background(), targets, manifest, nil)
	if len(checks) != 3 {
		t.Fatalf("expected 3 checks, got %d", len(checks))
	}

	// Order matches target order.
	if checks[0].Name != "binary-scanner" {
		t.Errorf("check[0] should be binary-scanner, got %s", checks[0].Name)
	}
	if checks[1].Name != "semgrep" {
		t.Errorf("check[1] should be semgrep, got %s", checks[1].Name)
	}
	if checks[2].Name != "missing" {
		t.Errorf("check[2] should be missing, got %s", checks[2].Name)
	}
}

func TestVersionMatches_WordBoundaryEdgeCases(t *testing.T) {
	// "1.2" must NOT match "1.21.0" — semver extraction prevents false positives.
	if versionMatches("syft 1.21.0", "1.2") {
		t.Error("word-boundary: '1.2' should NOT match '1.21.0'")
	}
	// "0.5" must NOT match "0.50" — they are different versions.
	if versionMatches("0.50", "0.5") {
		t.Error("word-boundary: '0.5' should NOT match '0.50'")
	}
	// "3" must NOT match "build 13.0" — word boundary prevents.
	if versionMatches("build 13.0", "3") {
		t.Error("word-boundary: '3' should NOT match '13.0'")
	}
	// Exact match after v-strip should work.
	if !versionMatches("v2.1.0", "2.1.0") {
		t.Error("v-strip: 'v2.1.0' should match '2.1.0'")
	}
}

func TestCheckForUpdates_NilManifest(t *testing.T) {
	targets := []EngineInfo{{Name: "cipherscope", BinaryName: "cipherscope"}}
	checks := CheckForUpdates(context.Background(), targets, nil, nil)
	if len(checks) != 1 {
		t.Fatalf("expected 1 check, got %d", len(checks))
	}
	if checks[0].Reason != "no manifest available" {
		t.Errorf("unexpected reason: %s", checks[0].Reason)
	}
}

func TestCheckForUpdates_ContextCancelled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel immediately

	targets := []EngineInfo{{
		Name:       "cipherscope",
		BinaryName: "cipherscope-nonexistent-xyz",
	}}
	manifest := &Manifest{
		SchemaVersion: 1,
		Engines: map[string]ManifestEngine{
			"cipherscope": {Version: "0.5.0", DownloadSupported: true},
		},
	}

	// With cancelled context, the loop should short-circuit via ctx.Err() check.
	checks := CheckForUpdates(ctx, targets, manifest, nil)
	if len(checks) != 1 {
		t.Fatalf("expected 1 check, got %d", len(checks))
	}
	if checks[0].Reason != "cancelled" {
		t.Errorf("unexpected reason: %s", checks[0].Reason)
	}
}
