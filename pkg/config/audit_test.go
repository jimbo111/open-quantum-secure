package config

// audit_test.go: adversarial + property-based tests added by the
// 2026-04-20 scanner-layer audit (config-auth-api agent).
//
// These tests exercise:
//   - Config precedence (project > global > defaults).
//   - Malformed YAML fixtures (tabs, dup keys, unknown keys, BOM, huge files).
//   - List/map merge determinism.
//   - Global-TLS preservation across Load() with a project config present.
//
// All fixtures are ephemeral (t.TempDir); no external process or network.

import (
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// ── Helpers ─────────────────────────────────────────────────────────────────

// writeProjectConfig writes YAML to dir/.oqs-scanner.yaml and returns the path.
func writeProjectConfig(t *testing.T, dir, content string) string {
	t.Helper()
	p := filepath.Join(dir, ".oqs-scanner.yaml")
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatalf("write project config: %v", err)
	}
	return p
}

// ── FOCUS 1: precedence (project > global > defaults) ──────────────────────

// TestF1_PrecedenceProjectOverGlobal: same key set at global + project with
// different values; project must win for all scalar kinds. This is the 3-way
// conflict within the package layer (CLI flags are resolved by the caller).
func TestF1_PrecedenceProjectOverGlobal(t *testing.T) {
	global := Config{
		Scan:     ScanConfig{Timeout: 10, MaxFileMB: 5, ScanType: "source", Engines: []string{"g1", "g2"}, Exclude: []string{"gx"}},
		Output:   OutputConfig{Format: "table"},
		Policy:   PolicyConfig{FailOn: "low", MinQRS: 10},
		Endpoint: "https://global.example.com",
		CACert:   "/global/ca.crt",
		Upload:   UploadConfig{Project: "g-proj", AutoUpload: true},
	}
	project := Config{
		Scan:     ScanConfig{Timeout: 120, MaxFileMB: 50, ScanType: "binary", Engines: []string{"p1"}, Exclude: []string{"px", "py"}},
		Output:   OutputConfig{Format: "sarif"},
		Policy:   PolicyConfig{FailOn: "high", MinQRS: 90},
		Endpoint: "https://proj.example.com",
		CACert:   "/proj/ca.crt",
		Upload:   UploadConfig{Project: "p-proj"},
	}

	m := MergeConfigs(global, project)

	if m.Scan.Timeout != 120 {
		t.Errorf("Scan.Timeout = %d, want 120 (project)", m.Scan.Timeout)
	}
	if m.Scan.ScanType != "binary" {
		t.Errorf("Scan.ScanType = %q, want binary", m.Scan.ScanType)
	}
	if m.Output.Format != "sarif" {
		t.Errorf("Output.Format = %q, want sarif", m.Output.Format)
	}
	if m.Policy.FailOn != "high" {
		t.Errorf("Policy.FailOn = %q, want high", m.Policy.FailOn)
	}
	if m.Endpoint != "https://proj.example.com" {
		t.Errorf("Endpoint = %q", m.Endpoint)
	}
	if m.CACert != "/proj/ca.crt" {
		t.Errorf("CACert = %q", m.CACert)
	}
	if m.Upload.Project != "p-proj" {
		t.Errorf("Upload.Project = %q", m.Upload.Project)
	}
	// Project did NOT set AutoUpload — global's true survives (this is the
	// documented "bool can't be unset" semantics).
	if !m.Upload.AutoUpload {
		t.Errorf("AutoUpload lost from global: bool semantics documented as non-unset")
	}
	if !reflect.DeepEqual(m.Scan.Engines, []string{"p1"}) {
		t.Errorf("Engines = %v, want [p1] (replace-not-append)", m.Scan.Engines)
	}
}

// TestF1_PrecedenceGlobalAppliesWhenProjectZero: project fields that are zero
// must NOT clobber global values.
func TestF1_PrecedenceGlobalAppliesWhenProjectZero(t *testing.T) {
	global := Config{
		Scan:     ScanConfig{Timeout: 42, MaxFileMB: 7, Engines: []string{"g"}, ScanType: "source"},
		Output:   OutputConfig{Format: "json"},
		Endpoint: "https://g",
	}
	project := Config{} // everything zero

	m := MergeConfigs(global, project)
	if m.Scan.Timeout != 42 {
		t.Errorf("Scan.Timeout = %d, want 42", m.Scan.Timeout)
	}
	if m.Output.Format != "json" {
		t.Errorf("Format = %q, want json", m.Output.Format)
	}
	if m.Endpoint != "https://g" {
		t.Errorf("Endpoint = %q", m.Endpoint)
	}
	if len(m.Scan.Engines) != 1 || m.Scan.Engines[0] != "g" {
		t.Errorf("Engines = %v, want [g]", m.Scan.Engines)
	}
}

// ── FOCUS 2: malformed configs ──────────────────────────────────────────────

// TestF2_MalformedYAML_TabIndent: YAML does NOT allow tabs for indentation.
// The parser must reject with an error, not silently accept.
func TestF2_MalformedYAML_TabIndent(t *testing.T) {
	dir := t.TempDir()
	content := "scan:\n\ttimeout: 60\n" // tab inside mapping
	writeProjectConfig(t, dir, content)
	_, err := Load(dir)
	if err == nil {
		t.Fatal("expected error for tab-indented YAML")
	}
}

// TestF2_MalformedYAML_UnclosedQuote: malformed scalar must error.
func TestF2_MalformedYAML_UnclosedQuote(t *testing.T) {
	dir := t.TempDir()
	content := "scan:\n  scanType: \"source\nendpoint: https://a\n"
	writeProjectConfig(t, dir, content)
	_, err := Load(dir)
	if err == nil {
		t.Fatal("expected error for unclosed quote")
	}
}

// TestF2_UnknownTopLevelKey: after the KnownFields fix, unknown top-level
// keys produce an error instead of being silently dropped. A typo like
// `fail_on` (vs canonical `failOn`) surfaces at config load rather than
// leaving the rule silently disabled.
func TestF2_UnknownTopLevelKey(t *testing.T) {
	dir := t.TempDir()
	content := `
does_not_exist: "typo-key"
scan:
  timeout: 60
`
	writeProjectConfig(t, dir, content)
	_, err := Load(dir)
	if err == nil {
		t.Fatal("expected error for unknown key, got nil")
	}
	if !strings.Contains(err.Error(), "does_not_exist") {
		t.Errorf("error should name the unknown field: %v", err)
	}
}

// TestF2_DuplicateKey: YAML spec says duplicate mapping keys are an error
// per 1.2, but historically many parsers accept last-wins. Verify what yaml.v3
// does in-tree.
func TestF2_DuplicateKey(t *testing.T) {
	dir := t.TempDir()
	content := `
scan:
  timeout: 10
  timeout: 99
`
	writeProjectConfig(t, dir, content)
	cfg, err := Load(dir)
	// yaml.v3 historically rejects duplicate keys. Either result is
	// acceptable, but the behaviour MUST be deterministic.
	if err == nil {
		t.Logf("duplicate key accepted; Scan.Timeout = %d (last-wins semantics)", cfg.Scan.Timeout)
		// We do not assert a value — we only assert determinism across runs.
		cfg2, err2 := Load(dir)
		if err2 != nil {
			t.Fatalf("second Load produced divergent error: %v", err2)
		}
		if cfg2.Scan.Timeout != cfg.Scan.Timeout {
			t.Errorf("duplicate-key resolution non-deterministic: run1=%d run2=%d",
				cfg.Scan.Timeout, cfg2.Scan.Timeout)
		}
	} else {
		// Error on duplicate is the stricter, safer behaviour.
		t.Logf("duplicate key rejected: %v", err)
	}
}

// TestF2_LargeConfigFile: very large config file (>10MB) must not crash.
func TestF2_LargeConfigFile(t *testing.T) {
	dir := t.TempDir()
	// 2 MB of comments + a valid scan block. We avoid 10 MB to keep the test
	// fast while still exercising the "large file" path.
	var b strings.Builder
	b.WriteString("# ")
	for i := 0; i < 2*1024*1024/16; i++ {
		b.WriteString("xxxxxxxxxxxxxxx\n# ")
	}
	b.WriteString("\nscan:\n  timeout: 31\n")
	writeProjectConfig(t, dir, b.String())
	cfg, err := Load(dir)
	if err != nil {
		t.Fatalf("large config rejected: %v", err)
	}
	if cfg.Scan.Timeout != 31 {
		t.Errorf("Scan.Timeout = %d, want 31", cfg.Scan.Timeout)
	}
}

// TestF2_BOMPrefix: UTF-8 BOM at the start of the file is a common
// Windows-editor artifact. yaml.v3 does not handle BOM — document behaviour.
func TestF2_BOMPrefix(t *testing.T) {
	dir := t.TempDir()
	bom := "\xef\xbb\xbf"
	content := bom + "scan:\n  timeout: 77\n"
	writeProjectConfig(t, dir, content)
	cfg, err := Load(dir)
	if err != nil {
		// yaml.v3 does not strip BOM — this is a documented behaviour.
		t.Logf("BOM rejected by yaml parser: %v (F2b in audit report)", err)
		return
	}
	if cfg.Scan.Timeout != 77 {
		t.Errorf("Scan.Timeout with BOM = %d, want 77", cfg.Scan.Timeout)
	}
}

// ── FOCUS 3: merge semantics — property test ───────────────────────────────

// TestF3_Property_SlicesReplaceNotAppend: for any non-nil project slice,
// the merged result equals the project slice exactly (deep equal), never
// appended to or merged with the global slice.
func TestF3_Property_SlicesReplaceNotAppend(t *testing.T) {
	rng := rand.New(rand.NewSource(0xC0FFEE))
	for i := 0; i < 40; i++ {
		globalEngines := randStrings(rng, rng.Intn(5)+1)
		projectEngines := randStrings(rng, rng.Intn(5)+1)
		globalExclude := randStrings(rng, rng.Intn(5)+1)
		projectExclude := randStrings(rng, rng.Intn(5)+1)
		globalAllow := randStrings(rng, rng.Intn(5)+1)
		projectAllow := randStrings(rng, rng.Intn(5)+1)

		g := Config{
			Scan:   ScanConfig{Engines: globalEngines, Exclude: globalExclude},
			Policy: PolicyConfig{AllowedAlgorithms: globalAllow},
		}
		p := Config{
			Scan:   ScanConfig{Engines: projectEngines, Exclude: projectExclude},
			Policy: PolicyConfig{AllowedAlgorithms: projectAllow},
		}
		m := MergeConfigs(g, p)

		if !reflect.DeepEqual(m.Scan.Engines, projectEngines) {
			t.Errorf("trial %d: Engines merged=%v, want project=%v", i, m.Scan.Engines, projectEngines)
		}
		if !reflect.DeepEqual(m.Scan.Exclude, projectExclude) {
			t.Errorf("trial %d: Exclude merged=%v, want project=%v", i, m.Scan.Exclude, projectExclude)
		}
		if !reflect.DeepEqual(m.Policy.AllowedAlgorithms, projectAllow) {
			t.Errorf("trial %d: Allowed merged=%v, want project=%v", i, m.Policy.AllowedAlgorithms, projectAllow)
		}
	}
}

// TestF3_Property_NilSlicePreservesGlobal: for any global slice and a nil
// project slice, the merged result must equal the global slice. This is
// the counterpart to the replace-semantics property.
func TestF3_Property_NilSlicePreservesGlobal(t *testing.T) {
	rng := rand.New(rand.NewSource(42))
	for i := 0; i < 40; i++ {
		gEngines := randStrings(rng, rng.Intn(5)+1)
		g := Config{Scan: ScanConfig{Engines: gEngines}}
		p := Config{} // project.Scan.Engines is nil
		m := MergeConfigs(g, p)
		if !reflect.DeepEqual(m.Scan.Engines, gEngines) {
			t.Errorf("trial %d: nil project, merged=%v, want global=%v", i, m.Scan.Engines, gEngines)
		}
	}
}

// TestF3_EmptyNonNilSliceReplaces: an EMPTY but non-nil project slice
// currently replaces global. This is documented as a caveat — an operator
// who writes `engines: []` in .oqs-scanner.yaml will unset global engines.
func TestF3_EmptyNonNilSliceReplaces(t *testing.T) {
	g := Config{Scan: ScanConfig{Engines: []string{"a", "b"}}}
	p := Config{Scan: ScanConfig{Engines: []string{}}} // empty non-nil
	m := MergeConfigs(g, p)
	if len(m.Scan.Engines) != 0 {
		t.Errorf("Engines = %v, want empty (project empty non-nil replaces)", m.Scan.Engines)
	}
	// Verify this matches the yaml parse of `engines: []` which also
	// produces a non-nil empty slice.
	var cfg Config
	// yaml.Unmarshal is not imported here to avoid coupling; rely on
	// round-trip through loadProjectConfig instead.
	dir := t.TempDir()
	writeProjectConfig(t, dir, "scan:\n  engines: []\n")
	cfg, err := loadProjectConfig(dir)
	if err != nil {
		t.Fatalf("loadProjectConfig: %v", err)
	}
	// Note: yaml.v3 parses `engines: []` as a non-nil empty slice.
	if cfg.Scan.Engines == nil {
		t.Logf("yaml parser returned nil for `engines: []` — project would NOT replace global")
	} else {
		t.Logf("yaml parser returned non-nil empty slice for `engines: []` — project WILL replace global")
	}
}

// ── FOCUS 8: path resolution / size / BOM edge cases ───────────────────────

// TestF8_LoadProjectConfig_CandidatePathsCWDLeak: when targetPath is set,
// candidatePaths STILL lists the cwd-relative ".oqs-scanner.yaml" FIRST.
// An attacker who drops a .oqs-scanner.yaml in the scanner's CWD can
// shadow the target's config. This is a behaviour bug that can lead to
// false negatives during CI scans.
func TestF8_LoadProjectConfig_CandidatePathsCWDLeak(t *testing.T) {
	// Create a dummy "target" repo with a benign config.
	targetDir := t.TempDir()
	writeProjectConfig(t, targetDir, "scan:\n  timeout: 42\n")

	// Create a separate "attacker" dir and chdir into it, seeding a different config.
	attackerDir := t.TempDir()
	writeProjectConfig(t, attackerDir, "scan:\n  timeout: 999\n")

	// chdir is the weakness: candidatePaths puts ".oqs-scanner.yaml" (cwd) before
	// filepath.Join(targetPath, ".oqs-scanner.yaml").
	origWD, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.Chdir(origWD) }()
	if err := os.Chdir(attackerDir); err != nil {
		t.Fatal(err)
	}

	cfg, err := loadProjectConfig(targetDir)
	if err != nil {
		t.Fatalf("loadProjectConfig: %v", err)
	}

	// Document observed behaviour: CWD wins because candidatePaths lists
	// ".oqs-scanner.yaml" FIRST and filepath.Join(target, "...") SECOND.
	// This test locks that behaviour in so a future change to fix it
	// (swap ordering / drop CWD lookup when targetPath is set) flips the
	// assertion and is forced to update this test. See F8 in audit report.
	if cfg.Scan.Timeout != 999 {
		t.Fatalf("F8 behaviour changed: CWD config no longer shadows target-dir config "+
			"(got timeout=%d, CWD had 999, target had 42). If this is intentional, "+
			"delete or invert this assertion and close F8.", cfg.Scan.Timeout)
	}
	t.Log("F8 REPRODUCED: CWD .oqs-scanner.yaml shadows target-dir config")
}

// TestF8_CandidatePathsOrdering: confirm the ordering of candidatePaths
// explicitly (documents the behaviour under test).
func TestF8_CandidatePathsOrdering(t *testing.T) {
	paths := candidatePaths("/home/user/myrepo")
	if len(paths) != 2 {
		t.Fatalf("expected 2 paths, got %d: %v", len(paths), paths)
	}
	if paths[0] != ".oqs-scanner.yaml" {
		t.Errorf("paths[0] = %q, want cwd-relative", paths[0])
	}
	if !strings.HasPrefix(paths[1], "/home/user/myrepo") {
		t.Errorf("paths[1] = %q, want targetPath-prefixed", paths[1])
	}
	// F8 root cause: cwd-relative is FIRST, not LAST.
}

// TestF8_Load_GlobalTLSPreservedWhenProjectHasNoTLS: when the global config
// has TLS targets and the PROJECT config has none, the merged result must
// include the global TLS targets. This tests the subtle code path in
// config.go Load() where MergeConfigs does not carry TLS, and the "restore
// global TLS" line only runs when `projectHadTLS == true`.
func TestF8_Load_GlobalTLSPreservedWhenProjectHasNoTLS(t *testing.T) {
	// We can't easily override GlobalConfigPath() without an injected path,
	// so we simulate by constructing the pieces Load() uses directly.
	global := Config{
		TLS: TLSConfig{
			Targets:  []string{"safe.example.com:443"},
			Insecure: false,
			Timeout:  15,
		},
	}
	project := Config{} // no TLS

	// Replicate Load's guard:
	projectHadTLS := len(project.TLS.Targets) > 0 || project.TLS.Insecure || project.TLS.Strict ||
		project.TLS.Timeout != 0 || project.TLS.CACert != ""
	if projectHadTLS {
		t.Fatal("projectHadTLS should be false")
	}
	if projectHadTLS {
		project.TLS = TLSConfig{}
	}
	merged := MergeConfigs(global, project)
	if projectHadTLS {
		merged.TLS = global.TLS
	}

	// BUG CONDITION: MergeConfigs does not carry TLS at all. When project has
	// no TLS, the `merged.TLS = global.TLS` restore line in Load() does not
	// fire (projectHadTLS is false). So merged.TLS ends up whatever MergeConfigs
	// returned — which is `global` (its first line is `merged := global`) so
	// TLS IS preserved via that seed. Verify that invariant.
	if len(merged.TLS.Targets) != 1 || merged.TLS.Targets[0] != "safe.example.com:443" {
		t.Errorf("F8b (HIGH if fails): global TLS lost when project has no TLS: %v",
			merged.TLS.Targets)
	}
	if merged.TLS.Timeout != 15 {
		t.Errorf("F8b: global TLS.Timeout lost: %d", merged.TLS.Timeout)
	}
}

// TestF8_Load_GlobalTLSPreserved_ProjectHadTLS: when BOTH global and project
// have TLS, the guard zeroes project TLS, emits warning, then restores global
// TLS. Verify no project values leak and global is fully preserved.
func TestF8_Load_GlobalTLSPreserved_ProjectHadTLS(t *testing.T) {
	global := Config{
		TLS: TLSConfig{Targets: []string{"api.corp.internal:443"}, Timeout: 20},
	}
	project := Config{
		TLS: TLSConfig{Targets: []string{"evil.example.com:443"}, Insecure: true},
	}

	projectHadTLS := len(project.TLS.Targets) > 0 || project.TLS.Insecure || project.TLS.Strict ||
		project.TLS.Timeout != 0 || project.TLS.CACert != ""
	if !projectHadTLS {
		t.Fatal("projectHadTLS should be true")
	}
	if projectHadTLS {
		project.TLS = TLSConfig{}
	}
	merged := MergeConfigs(global, project)
	if projectHadTLS {
		merged.TLS = global.TLS
	}

	for _, tgt := range merged.TLS.Targets {
		if tgt == "evil.example.com:443" {
			t.Errorf("project TLS target leaked: %v", merged.TLS.Targets)
		}
	}
	if merged.TLS.Insecure {
		t.Error("project TLS.Insecure leaked")
	}
	if merged.TLS.Timeout != 20 {
		t.Errorf("global TLS.Timeout = %d, want 20", merged.TLS.Timeout)
	}
}

// ── utils ───────────────────────────────────────────────────────────────────

func randStrings(rng *rand.Rand, n int) []string {
	out := make([]string, n)
	for i := range out {
		out[i] = fmt.Sprintf("s%d-%d", rng.Intn(1000), i)
	}
	return out
}
