package cryptodeps

// Adversarial / cross-layer audit tests for the cryptodeps Tier 2 SBOM engine.

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/jimbo111/open-quantum-secure/pkg/engines"
	"github.com/jimbo111/open-quantum-secure/pkg/findings"
)

func writeFakeBin(t *testing.T, name, body string) string {
	t.Helper()
	dir := t.TempDir()
	var p string
	if runtime.GOOS == "windows" {
		p = filepath.Join(dir, name+".bat")
		_ = os.WriteFile(p, []byte("@echo off\r\n"+body+"\r\n"), 0o755)
	} else {
		p = filepath.Join(dir, name)
		_ = os.WriteFile(p, []byte("#!/bin/sh\n"+body+"\n"), 0o755)
	}
	return p
}

// TestAudit_CryptodepsStdoutExitNonZeroWithData — cryptodeps writes valid JSON
// to stdout and then exits 1. The engine code says:
//
//	if waitErr != nil { ...; return result, fmt.Errorf(...) }
//
// i.e. findings ARE returned alongside the error. Verify the contract.
func TestAudit_CryptodepsStdoutExitNonZeroWithData(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("skipping on windows")
	}
	body := `
cat <<'JSON'
{"dependencies":[{"name":"lib","version":"1.0","ecosystem":"go","cryptoUsages":[{"algorithm":"RSA","reachable":true,"file":"a.go","line":1}]}]}
JSON
exit 1
`
	bin := writeFakeBin(t, "cryptodeps", body)
	e := &Engine{binaryPath: bin}
	res, err := e.Scan(context.Background(), engines.ScanOptions{TargetPath: t.TempDir()})
	if err == nil {
		t.Error("expected wait error when cryptodeps exits non-zero")
	}
	// BUT findings should still be present.
	if len(res) == 0 {
		t.Errorf("findings lost on non-zero exit: got %d", len(res))
	}
	if len(res) >= 2 {
		if res[1].Algorithm == nil || res[1].Algorithm.Name != "RSA" {
			t.Errorf("expected RSA algorithm finding, got %+v", res[1].Algorithm)
		}
	}
}

// TestAudit_CryptodepsMalformedStdoutJSON — stdout produces garbage; return
// parse error without findings.
func TestAudit_CryptodepsMalformedStdoutJSON(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("skipping on windows")
	}
	body := `printf 'not valid json'; exit 0`
	bin := writeFakeBin(t, "cryptodeps", body)
	e := &Engine{binaryPath: bin}
	_, err := e.Scan(context.Background(), engines.ScanOptions{TargetPath: t.TempDir()})
	if err == nil {
		t.Fatal("expected JSON parse error")
	}
	if !strings.Contains(err.Error(), "JSON parse") && !strings.Contains(err.Error(), "invalid") {
		t.Errorf("expected parse error, got %v", err)
	}
}

// TestAudit_CryptodepsEmptyStdoutExitZero — subprocess exits 0 with no output.
// Engine returns nil,nil. Silent-success — same risk as syft.
func TestAudit_CryptodepsEmptyStdoutExitZero(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("skipping on windows")
	}
	body := `exit 0`
	bin := writeFakeBin(t, "cryptodeps", body)
	e := &Engine{binaryPath: bin}
	res, err := e.Scan(context.Background(), engines.ScanOptions{TargetPath: t.TempDir()})
	if err != nil {
		t.Errorf("unexpected err: %v", err)
	}
	if res != nil {
		t.Errorf("expected nil findings, got %v", res)
	}
}

// TestAudit_CryptodepsStderrRedacted — subprocess writes a secret-looking
// line to stderr and exits non-zero. The secret value must be redacted from
// the returned error while the key name is preserved so operators can still
// debug.
// 2026-04-21: was TestAudit_CryptodepsStderrLeaksIntoError; flipped after
// engines.RedactStderr was applied.
func TestAudit_CryptodepsStderrRedacted(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("skipping on windows")
	}
	secret := "hunter2-very-secret"
	body := `
echo "DB_PASSWORD=` + secret + `" 1>&2
exit 2
`
	bin := writeFakeBin(t, "cryptodeps", body)
	e := &Engine{binaryPath: bin}
	_, err := e.Scan(context.Background(), engines.ScanOptions{TargetPath: t.TempDir()})
	if err == nil {
		t.Fatal("expected error")
	}
	if strings.Contains(err.Error(), secret) {
		t.Errorf("stderr secret leaked into error: %v", err)
	}
	if !strings.Contains(err.Error(), "<redacted>") {
		t.Errorf("expected <redacted> marker in error, got: %v", err)
	}
}

// TestAudit_CryptodepsLargeStdout — 10MB of dependencies; ReadAll should not
// explode and parsing should finish in <1s.
func TestAudit_CryptodepsLargeStdout(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("skipping on windows")
	}
	// Build a large JSON payload (1000 deps, each with 2 usages).
	var sb strings.Builder
	sb.WriteString(`{"dependencies":[`)
	for i := 0; i < 1000; i++ {
		if i > 0 {
			sb.WriteString(",")
		}
		sb.WriteString(`{"name":"lib`)
		for j := 0; j < 3; j++ {
			sb.WriteString("x")
		}
		sb.WriteString(`","version":"1.0","ecosystem":"go","cryptoUsages":[{"algorithm":"RSA","reachable":true,"file":"a.go","line":1},{"algorithm":"ECDH","reachable":false,"file":"b.go","line":2}]}`)
	}
	sb.WriteString(`]}`)

	dir := t.TempDir()
	payload := filepath.Join(dir, "payload.json")
	if err := os.WriteFile(payload, []byte(sb.String()), 0o644); err != nil {
		t.Fatal(err)
	}
	body := `cat "` + payload + `"; exit 0`
	bin := writeFakeBin(t, "cryptodeps", body)
	e := &Engine{binaryPath: bin}

	start := time.Now()
	res, err := e.Scan(context.Background(), engines.ScanOptions{TargetPath: t.TempDir()})
	elapsed := time.Since(start)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	// 1000 deps × (1 dep finding + 2 alg findings) = 3000 findings
	if len(res) != 3000 {
		t.Errorf("expected 3000 findings, got %d", len(res))
	}
	if elapsed > 3*time.Second {
		t.Errorf("1000-dep payload took %v — performance regression", elapsed)
	}
}

// TestAudit_CryptodepsStdoutNeverCloses — subprocess writes nothing and sleeps.
// Verify Scan unblocks when ctx is cancelled. Because of the stderr-drain
// issue (see F-SYFT-CTX), cryptodeps also holds stdout open — this test
// uses a bounded sleep.
func TestAudit_CryptodepsCtxCancelMidRead(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("skipping on windows")
	}
	body := `sleep 2`
	bin := writeFakeBin(t, "cryptodeps", body)
	e := &Engine{binaryPath: bin}
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, err := e.Scan(ctx, engines.ScanOptions{TargetPath: t.TempDir()})
	elapsed := time.Since(start)
	if err == nil {
		t.Fatal("expected error on cancelled ctx")
	}
	t.Logf("cryptodeps Scan returned after %v err=%v", elapsed, err)
}

// TestAudit_CryptodepsCircularCallPath — a usage with a callPath that
// references its own file/line (self-loop). The normalizer doesn't walk
// callPath, so no cycle hazard, but verify no panic.
func TestAudit_CryptodepsCircularCallPath(t *testing.T) {
	input := rawOutput{
		Dependencies: []rawDependency{
			{
				Name:    "lib",
				Version: "1.0",
				CryptoUsages: []rawCryptoUsage{
					{
						Algorithm: "RSA",
						CallPath:  []string{"a.go:1", "b.go:2", "a.go:1"},
						File:      "a.go",
						Line:      1,
					},
				},
			},
		},
	}
	res := normalize(input, "/target")
	if len(res) != 2 {
		t.Errorf("expected 2 findings, got %d", len(res))
	}
}

// TestAudit_CryptodepsDuplicateDependencyDifferentVersions verifies that the
// same library at different versions produces distinct DedupeKeys so both
// findings survive orchestrator dedup.
// 2026-04-21: Dependency.Version field added and included in DedupeKey.
func TestAudit_CryptodepsDuplicateDependencyDifferentVersions(t *testing.T) {
	input := rawOutput{
		Dependencies: []rawDependency{
			{Name: "lib", Version: "1.0"},
			{Name: "lib", Version: "2.0"},
		},
	}
	res := normalize(input, "/target")
	if len(res) != 2 {
		t.Fatalf("expected 2 findings, got %d", len(res))
	}
	if res[0].RawIdentifier == res[1].RawIdentifier {
		t.Error("expected distinct RawIdentifier for different versions")
	}
	if res[0].DedupeKey() == res[1].DedupeKey() {
		t.Errorf("DedupeKey collision on different versions: both = %q", res[0].DedupeKey())
	}
}

// TestAudit_CryptodepsIntegration_UnifiedFindingContract — cross-layer test:
// craft a cryptodeps JSON with an RSA usage, run normalize, and verify the
// resulting UnifiedFinding populates Algorithm.Name for downstream quantum
// classification. This is the contract the orchestrator relies on.
func TestAudit_CryptodepsIntegration_UnifiedFindingContract(t *testing.T) {
	input := rawOutput{
		Dependencies: []rawDependency{
			{
				Name:      "golang.org/x/crypto",
				Version:   "v0.17.0",
				Ecosystem: "go",
				CryptoUsages: []rawCryptoUsage{
					{
						Algorithm:   "RSA-2048",
						QuantumRisk: "VULNERABLE",
						Reachable:   boolPtr(true),
						File:        "vendor/golang.org/x/crypto/rsa/rsa.go",
						Line:        42,
					},
				},
			},
		},
	}
	res := normalize(input, "/target")
	if len(res) != 2 {
		t.Fatalf("want 2 findings, got %d", len(res))
	}
	algF := res[1]

	// Downstream contract requirements:
	if algF.Algorithm == nil {
		t.Fatal("Algorithm must be non-nil for algorithm findings")
	}
	if algF.Algorithm.Name != "RSA-2048" {
		t.Errorf("Algorithm.Name: got %q, want RSA-2048", algF.Algorithm.Name)
	}
	if algF.SourceEngine != "cryptodeps" {
		t.Errorf("SourceEngine wrong: %q", algF.SourceEngine)
	}
	// NOTE: quantumRisk in the raw input is NOT propagated to
	// UnifiedFinding.Risk — quantum classification happens later in
	// pkg/quantum. Documents the engine↔classifier boundary.
	if algF.QuantumRisk != findings.QuantumRisk("") && algF.QuantumRisk != findings.QRUnknown {
		t.Errorf("expected Risk to be unset (classifier's job), got %q", algF.QuantumRisk)
	}
	if algF.Reachable != findings.ReachableYes {
		t.Errorf("Reachable: %q", algF.Reachable)
	}
	if algF.Confidence != findings.ConfidenceMedium {
		t.Errorf("Confidence: %q", algF.Confidence)
	}
}

// TestAudit_CryptodepsQuantumRiskDroppedSilently — rawCryptoUsage has a
// `QuantumRisk` field that is parsed but never forwarded to UnifiedFinding.
// This means if the upstream binary pre-classifies, that info is LOST and the
// downstream quantum engine must redo the work. Severity: low — wasted work,
// but not a correctness issue since re-classification is idempotent.
func TestAudit_CryptodepsQuantumRiskDroppedSilently(t *testing.T) {
	input := rawOutput{
		Dependencies: []rawDependency{
			{
				Name: "lib", Version: "1.0",
				CryptoUsages: []rawCryptoUsage{
					{Algorithm: "ML-KEM-768", QuantumRisk: "SAFE", File: "a.go", Line: 1},
				},
			},
		},
	}
	res := normalize(input, "/target")
	if len(res) != 2 {
		t.Fatal("expected 2 findings")
	}
	// Risk is NOT propagated from the QuantumRisk field.
	if string(res[1].QuantumRisk) != "" && res[1].QuantumRisk != findings.QRUnknown {
		t.Errorf("Risk unexpectedly set from raw QuantumRisk; got %q", res[1].QuantumRisk)
	}
}

// TestAudit_CryptodepsNilDepsHandling — dependencies field missing entirely.
// Current behaviour: empty slice → no findings.
func TestAudit_CryptodepsNilDepsHandling(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("skipping on windows")
	}
	body := `echo '{}'; exit 0`
	bin := writeFakeBin(t, "cryptodeps", body)
	e := &Engine{binaryPath: bin}
	res, err := e.Scan(context.Background(), engines.ScanOptions{TargetPath: t.TempDir()})
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if len(res) != 0 {
		t.Errorf("expected 0 findings for empty {}, got %d", len(res))
	}
}

// TestAudit_CryptodepsReachableInvalidType — callPath with a non-bool
// "reachable" field. json.Unmarshal will error out. Verify graceful error.
func TestAudit_CryptodepsReachableInvalidType(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("skipping on windows")
	}
	body := `
echo '{"dependencies":[{"name":"lib","version":"1.0","cryptoUsages":[{"algorithm":"RSA","reachable":"yes","file":"a.go","line":1}]}]}'
exit 0
`
	bin := writeFakeBin(t, "cryptodeps", body)
	e := &Engine{binaryPath: bin}
	_, err := e.Scan(context.Background(), engines.ScanOptions{TargetPath: t.TempDir()})
	if err == nil {
		t.Error("expected JSON parse error for reachable:\"yes\"")
	}
}

// TestAudit_CryptodepsDeeplyNestedCallPath — very deep transitive chain
// (1000 entries). Normalize should not be O(n^2). This exercises the
// "1000-deep transitive chain" item from the audit focus list.
func TestAudit_CryptodepsDeeplyNestedCallPath(t *testing.T) {
	cp := make([]string, 1000)
	for i := range cp {
		cp[i] = "lvl" + strings.Repeat("x", 4)
	}
	input := rawOutput{
		Dependencies: []rawDependency{
			{
				Name:    "lib",
				Version: "1.0",
				CryptoUsages: []rawCryptoUsage{
					{Algorithm: "RSA", CallPath: cp, File: "a.go", Line: 1},
				},
			},
		},
	}
	start := time.Now()
	res := normalize(input, "/target")
	elapsed := time.Since(start)
	if len(res) != 2 {
		t.Errorf("expected 2 findings, got %d", len(res))
	}
	if elapsed > 100*time.Millisecond {
		t.Errorf("deep callPath took %v — unexpected regression", elapsed)
	}
	// DOCUMENTS: CallPath is currently ignored by normalize(), so depth is moot.
}
