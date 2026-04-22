package cdxgen

// Adversarial / cross-layer audit tests for the cdxgen Tier 2 SBOM engine.

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/jimbo111/open-quantum-secure/pkg/engines"
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

// TestAudit_CdxgenSilentEmptyPath — cdxgen exits 0 but writes no output file.
// 2026-04-21: the engine now surfaces this as an explicit error instead of
// silently returning (nil, nil), so broken installs are visible to operators.
func TestAudit_CdxgenSilentEmptyPath(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("skipping on windows")
	}
	body := `exit 0`
	bin := writeFakeBin(t, "cdxgen", body)
	e := &Engine{binaryPath: bin}
	res, err := e.Scan(context.Background(), engines.ScanOptions{TargetPath: t.TempDir()})
	if err == nil {
		t.Fatal("expected error for exit=0 with empty output, got nil")
	}
	if res != nil {
		t.Errorf("expected nil findings on empty output, got %v", res)
	}
	if !strings.Contains(err.Error(), "no output") {
		t.Errorf("error should mention missing output: %v", err)
	}
}

// TestAudit_CdxgenNonZeroWithValidOutput — cdxgen exits 1 but writes valid
// CycloneDX. The engine is supposed to ignore exit codes when output is present
// (see comment in cdxgen.go:83). Verify this behaviour.
func TestAudit_CdxgenNonZeroWithValidOutput(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("skipping on windows")
	}
	body := `
target=""
while [ $# -gt 0 ]; do
  case "$1" in
    -o) target="$2"; shift 2;;
    *) shift;;
  esac
done
cat > "$target" <<'JSON'
{"bomFormat":"CycloneDX","specVersion":"1.5","components":[{"type":"library","name":"lodash","version":"4.17.21","purl":"pkg:npm/lodash@4.17.21"}]}
JSON
exit 1
`
	bin := writeFakeBin(t, "cdxgen", body)
	e := &Engine{binaryPath: bin}
	res, err := e.Scan(context.Background(), engines.ScanOptions{TargetPath: t.TempDir()})
	if err != nil {
		t.Errorf("unexpected err — cdxgen exit-code should be ignored when output exists: %v", err)
	}
	if len(res) != 1 {
		t.Fatalf("expected 1 finding despite non-zero exit, got %d", len(res))
	}
}

// TestAudit_CdxgenTruncatedJSON — cdxgen emits valid-looking but truncated
// output. Must return a parse error, not silent success.
func TestAudit_CdxgenTruncatedJSON(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("skipping on windows")
	}
	body := `
target=""
while [ $# -gt 0 ]; do
  case "$1" in
    -o) target="$2"; shift 2;;
    *) shift;;
  esac
done
printf '{"components":[{"type":"library","name":"lodash"' > "$target"
exit 0
`
	bin := writeFakeBin(t, "cdxgen", body)
	e := &Engine{binaryPath: bin}
	_, err := e.Scan(context.Background(), engines.ScanOptions{TargetPath: t.TempDir()})
	if err == nil {
		t.Fatal("expected parse error on truncated JSON")
	}
	if !strings.Contains(err.Error(), "parse") && !strings.Contains(err.Error(), "unexpected end") {
		t.Errorf("expected parse error, got %v", err)
	}
}

// TestAudit_CdxgenMissingCryptoProperties — cdxgen emits CycloneDX 1.7
// `cryptoProperties` (the spec'd field) instead of deprecated `cdx:crypto:*`
// properties. The current implementation only reads `properties[]` with
// `cdx:crypto:` prefix, so algorithms advertised via `cryptoProperties` are
// LOST. This is a correctness gap against CycloneDX 1.7.
func TestAudit_CdxgenMissingCryptoProperties(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("skipping on windows")
	}
	body := `
target=""
while [ $# -gt 0 ]; do
  case "$1" in
    -o) target="$2"; shift 2;;
    *) shift;;
  esac
done
cat > "$target" <<'JSON'
{
  "bomFormat":"CycloneDX","specVersion":"1.7",
  "components":[{
    "type":"library","name":"cryptolib","version":"1.0","purl":"pkg:npm/cryptolib@1.0",
    "cryptoProperties":{
      "assetType":"algorithm",
      "algorithmProperties":{
        "primitive":"pke",
        "parameterSetIdentifier":"2048",
        "executionEnvironment":"software-plain-ram",
        "implementationPlatform":"generic",
        "certificationLevel":["none"],
        "mode":"cbc",
        "padding":"pkcs1v15",
        "cryptoFunctions":["encrypt","decrypt"],
        "classicalSecurityLevel":112,
        "nistQuantumSecurityLevel":0
      }
    }
  }]
}
JSON
exit 0
`
	bin := writeFakeBin(t, "cdxgen", body)
	e := &Engine{binaryPath: bin}
	res, err := e.Scan(context.Background(), engines.ScanOptions{TargetPath: t.TempDir()})
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if len(res) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(res))
	}
	// Current behaviour: Algorithm stays nil because cryptoProperties is not parsed.
	if res[0].Algorithm != nil {
		t.Errorf("cryptoProperties is now being parsed — if intentional, update this test. got %+v", res[0].Algorithm)
	}
	// Audit note: this is a documented correctness gap.
}

// TestAudit_CdxgenContextTimeout — slow cdxgen run; ctx cancels at 100ms.
// See F-SYFT-CTX for the stderr-drain-blocks-Wait known issue; use a short
// sleep here so the test completes regardless of which branch is taken.
func TestAudit_CdxgenContextTimeout(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("skipping on windows")
	}
	body := `sleep 2; exit 0`
	bin := writeFakeBin(t, "cdxgen", body)
	e := &Engine{binaryPath: bin}
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	start := time.Now()
	_, err := e.Scan(ctx, engines.ScanOptions{TargetPath: t.TempDir()})
	elapsed := time.Since(start)
	if err == nil {
		t.Fatal("expected context error")
	}
	t.Logf("cdxgen Scan returned after %v — err=%v", elapsed, err)
}

// TestAudit_CdxgenStderrRedacted — cdxgen prints an API-key-looking line to
// stderr while exiting non-zero. The error surfaces the key name for
// debugging but the secret value must be redacted.
// 2026-04-21: was TestAudit_CdxgenStderrSecretLeak; flipped after
// engines.RedactStderr was applied.
func TestAudit_CdxgenStderrRedacted(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("skipping on windows")
	}
	secret := "ghp_secretsecretsecret"
	body := `
echo "GITHUB_TOKEN=` + secret + `" 1>&2
exit 3
`
	bin := writeFakeBin(t, "cdxgen", body)
	e := &Engine{binaryPath: bin}
	_, err := e.Scan(context.Background(), engines.ScanOptions{TargetPath: t.TempDir()})
	if err == nil {
		t.Fatal("expected error for non-zero exit with empty output")
	}
	if strings.Contains(err.Error(), secret) {
		t.Errorf("stderr secret leaked into error: %v", err)
	}
	if !strings.Contains(err.Error(), "<redacted>") {
		t.Errorf("expected <redacted> marker in error, got: %v", err)
	}
}

// TestAudit_CdxgenDuplicateBomRefs — CycloneDX spec requires bom-ref to be
// unique, but cdxgen has been known to emit duplicates. Since the engine does
// NOT parse bom-refs (only components[].{name,version,purl}), duplicate refs
// should be harmless. Verify no panic.
func TestAudit_CdxgenDuplicateBomRefs(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("skipping on windows")
	}
	body := `
target=""
while [ $# -gt 0 ]; do
  case "$1" in
    -o) target="$2"; shift 2;;
    *) shift;;
  esac
done
cat > "$target" <<'JSON'
{"components":[
  {"bom-ref":"X","type":"library","name":"a","version":"1.0","purl":"pkg:npm/a@1.0"},
  {"bom-ref":"X","type":"library","name":"b","version":"2.0","purl":"pkg:npm/b@2.0"}
]}
JSON
exit 0
`
	bin := writeFakeBin(t, "cdxgen", body)
	e := &Engine{binaryPath: bin}
	res, err := e.Scan(context.Background(), engines.ScanOptions{TargetPath: t.TempDir()})
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if len(res) != 2 {
		t.Errorf("expected 2 findings regardless of bom-ref dup, got %d", len(res))
	}
}

// TestAudit_CdxgenCircularDependsOn — the components contain a dependsOn cycle
// A→B→A. Since the engine never walks the dependency graph, no hang/recursion.
func TestAudit_CdxgenCircularDependsOn(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("skipping on windows")
	}
	body := `
target=""
while [ $# -gt 0 ]; do
  case "$1" in
    -o) target="$2"; shift 2;;
    *) shift;;
  esac
done
cat > "$target" <<'JSON'
{"components":[
  {"bom-ref":"A","type":"library","name":"A","version":"1","purl":"pkg:npm/A@1"},
  {"bom-ref":"B","type":"library","name":"B","version":"2","purl":"pkg:npm/B@2"}
],
"dependencies":[
  {"ref":"A","dependsOn":["B"]},
  {"ref":"B","dependsOn":["A"]}
]}
JSON
exit 0
`
	bin := writeFakeBin(t, "cdxgen", body)
	e := &Engine{binaryPath: bin}
	// Must return in bounded time without stack overflow.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	res, err := e.Scan(ctx, engines.ScanOptions{TargetPath: t.TempDir()})
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if len(res) != 2 {
		t.Errorf("expected 2 findings, got %d", len(res))
	}
}

// TestAudit_CdxgenLargeBOMPerformance — parse a BOM with 1000 components;
// verify it completes in <1s to catch accidental O(n^2).
func TestAudit_CdxgenLargeBOMPerformance(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("skipping on windows")
	}
	var sb strings.Builder
	sb.WriteString(`{"components":[`)
	for i := 0; i < 1000; i++ {
		if i > 0 {
			sb.WriteString(",")
		}
		sb.WriteString(`{"type":"library","name":"lib`)
		sb.WriteString(strings.Repeat("x", 5))
		sb.WriteString(`","version":"1.0","purl":"pkg:npm/lib@1.0"}`)
	}
	sb.WriteString(`]}`)
	big := sb.String()

	dir := t.TempDir()
	outFile := filepath.Join(dir, "bom.json")
	if err := os.WriteFile(outFile, []byte(big), 0o644); err != nil {
		t.Fatalf("write bom: %v", err)
	}

	body := `
target=""
while [ $# -gt 0 ]; do
  case "$1" in
    -o) target="$2"; shift 2;;
    *) shift;;
  esac
done
cp "` + outFile + `" "$target"
exit 0
`
	bin := writeFakeBin(t, "cdxgen", body)
	e := &Engine{binaryPath: bin}

	start := time.Now()
	res, err := e.Scan(context.Background(), engines.ScanOptions{TargetPath: t.TempDir()})
	elapsed := time.Since(start)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if len(res) != 1000 {
		t.Errorf("expected 1000 findings, got %d", len(res))
	}
	if elapsed > 1*time.Second {
		t.Errorf("1000-component BOM took %v (>1s) — possible O(n^2) regression", elapsed)
	}
}

// TestAudit_ManifestFileTraversal — can a crafted PURL make manifestFile()
// escape the target path via filepath.Join? Go's filepath.Join normalises
// ".." but does NOT sandbox. Check for traversal attempts.
func TestAudit_ManifestFileTraversal(t *testing.T) {
	got := manifestFile("/safe/target", "pkg:npm/../../../etc/passwd@1.0")
	if !strings.HasPrefix(got, "/safe/target") {
		t.Errorf("manifestFile produced path outside target: %q", got)
	}
	// manifestFile does NOT use the purl name for pathing — it only branches on
	// the ecosystem prefix. So traversal via the package name portion is moot.
}
