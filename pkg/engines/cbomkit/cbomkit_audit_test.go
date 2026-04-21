package cbomkit

// Adversarial / cross-layer audit tests for the cbomkit-theia Tier 2 SBOM engine.

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

// TestAudit_CbomkitHardFailsWithValidOutput — unlike cdxgen, cbomkit-theia
// hard-errors on any non-zero exit even if it produced a usable asset list.
// Real-world cbomkit-theia exits non-zero when some scanners partially fail
// but still emit data. Current behaviour drops the good findings.
// Severity: medium — policy bypass + reduced correctness.
func TestAudit_CbomkitHardFailsWithValidOutput(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("skipping on windows")
	}
	body := `
target=""
# Parse "--output X" pairs
while [ $# -gt 0 ]; do
  case "$1" in
    --output) target="$2"; shift 2;;
    *) shift;;
  esac
done
cat > "$target" <<'JSON'
{"assets":[{"type":"certificate","algorithm":"RSA","keySize":2048,"file":"/etc/ssl/cert.pem","line":0}]}
JSON
exit 1
`
	bin := writeFakeBin(t, "cbomkit-theia", body)
	e := &Engine{binaryPath: bin}
	res, err := e.Scan(context.Background(), engines.ScanOptions{TargetPath: t.TempDir()})
	if err == nil {
		t.Error("current behaviour: cbomkit-theia Scan errors on non-zero exit. Update this test if behaviour changed.")
	}
	if len(res) != 0 {
		t.Errorf("findings were dropped because non-zero exit won: got %d", len(res))
	}
	// DOCUMENTED GAP: cdxgen tolerates exit-non-zero-with-output; cbomkit-theia does not.
}

// TestAudit_CbomkitMalformedJSON — malformed JSON → parse error, not panic.
func TestAudit_CbomkitMalformedJSON(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("skipping on windows")
	}
	body := `
target=""
while [ $# -gt 0 ]; do
  case "$1" in
    --output) target="$2"; shift 2;;
    *) shift;;
  esac
done
printf '{"assets":[{"type":' > "$target"
exit 0
`
	bin := writeFakeBin(t, "cbomkit-theia", body)
	e := &Engine{binaryPath: bin}
	_, err := e.Scan(context.Background(), engines.ScanOptions{TargetPath: t.TempDir()})
	if err == nil {
		t.Fatal("expected JSON parse error")
	}
	if !strings.Contains(err.Error(), "JSON parse") && !strings.Contains(err.Error(), "unexpected") {
		t.Errorf("expected parse error, got %v", err)
	}
}

// TestAudit_CbomkitContextTimeout — slow subprocess; ctx times out.
// See F-SYFT-CTX: Go's os/exec can block on stderr-copy goroutine beyond
// ctx cancel when subprocess has children keeping the stderr pipe open.
// Use a bounded sleep so the test is not flaky.
func TestAudit_CbomkitContextTimeout(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("skipping on windows")
	}
	body := `sleep 2; exit 0`
	bin := writeFakeBin(t, "cbomkit-theia", body)
	e := &Engine{binaryPath: bin}
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	start := time.Now()
	_, err := e.Scan(ctx, engines.ScanOptions{TargetPath: t.TempDir()})
	elapsed := time.Since(start)
	if err == nil {
		t.Fatal("expected context error")
	}
	t.Logf("cbomkit-theia Scan returned after %v — err=%v", elapsed, err)
}

// TestAudit_CbomkitEmptyAssetFileKey — asset with empty File field; the
// resulting UnifiedFinding has Location.File="" which produces DedupeKey
// "|0|alg|RSA". Multiple unrelated assets with empty File collapse into one
// deduped finding → information loss. Severity: medium.
func TestAudit_CbomkitEmptyAssetFileKey(t *testing.T) {
	// 2026-04-21: after fix, empty-File assets use a synthetic "cbom://<type>"
	// path so distinct asset types produce distinct DedupeKeys.
	a1 := normalize(rawAsset{Type: "certificate", Algorithm: "RSA", File: ""})
	a2 := normalize(rawAsset{Type: "private-key", Algorithm: "RSA", File: ""})
	if a1.DedupeKey() == a2.DedupeKey() {
		t.Errorf("DedupeKey collision: cert and private-key with empty File both produced %q",
			a1.DedupeKey())
	}
}

// TestAudit_CbomkitKeySizeZeroInJSON — JSON omits keySize; Algorithm.KeySize
// is zero. `keySize,omitempty` means JSON output hides it; but UnifiedFinding
// carries 0. Verify no panic.
func TestAudit_CbomkitKeySizeZeroInJSON(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("skipping on windows")
	}
	body := `
target=""
while [ $# -gt 0 ]; do
  case "$1" in
    --output) target="$2"; shift 2;;
    *) shift;;
  esac
done
cat > "$target" <<'JSON'
{"assets":[{"type":"config","algorithm":"TLS 1.2","file":"/etc/nginx.conf","line":4}]}
JSON
exit 0
`
	bin := writeFakeBin(t, "cbomkit-theia", body)
	e := &Engine{binaryPath: bin}
	res, err := e.Scan(context.Background(), engines.ScanOptions{TargetPath: t.TempDir()})
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if len(res) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(res))
	}
	if res[0].Algorithm == nil {
		t.Fatal("Algorithm nil")
	}
	if res[0].Algorithm.KeySize != 0 {
		t.Errorf("expected keySize 0 when omitted, got %d", res[0].Algorithm.KeySize)
	}
}

// TestAudit_CbomkitNegativeKeySize — crafted input with negative keySize.
// JSON unmarshal accepts it; Algorithm.KeySize = -1. Downstream policy
// evaluators may be surprised. Check no panic.
func TestAudit_CbomkitNegativeKeySize(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("skipping on windows")
	}
	body := `
target=""
while [ $# -gt 0 ]; do
  case "$1" in
    --output) target="$2"; shift 2;;
    *) shift;;
  esac
done
cat > "$target" <<'JSON'
{"assets":[{"type":"private-key","algorithm":"RSA","keySize":-1,"file":"/key.pem","line":0}]}
JSON
exit 0
`
	bin := writeFakeBin(t, "cbomkit-theia", body)
	e := &Engine{binaryPath: bin}
	res, err := e.Scan(context.Background(), engines.ScanOptions{TargetPath: t.TempDir()})
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if len(res) != 1 || res[0].Algorithm == nil {
		t.Fatal("expected finding")
	}
	if res[0].Algorithm.KeySize != -1 {
		t.Errorf("negative KeySize passed through: got %d", res[0].Algorithm.KeySize)
	}
	// AUDIT NOTE: negative KeySize stays as-is; policy layer may interpret
	// this as "stronger than 4096" if it only checks minimums.
}

// TestAudit_CbomkitLineOverflow — line field with huge int → no panic.
func TestAudit_CbomkitLineOverflow(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("skipping on windows")
	}
	body := `
target=""
while [ $# -gt 0 ]; do
  case "$1" in
    --output) target="$2"; shift 2;;
    *) shift;;
  esac
done
cat > "$target" <<'JSON'
{"assets":[{"type":"certificate","algorithm":"RSA","keySize":2048,"file":"/a.pem","line":9223372036854775807}]}
JSON
exit 0
`
	bin := writeFakeBin(t, "cbomkit-theia", body)
	e := &Engine{binaryPath: bin}
	res, err := e.Scan(context.Background(), engines.ScanOptions{TargetPath: t.TempDir()})
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if len(res) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(res))
	}
	// Document line overflow passed through.
}

// TestAudit_CbomkitDetailsIgnored — the `details` RawMessage is kept but never
// exposed in UnifiedFinding. Downstream engines can't see it. Not a bug, just
// documenting the information-loss boundary.
func TestAudit_CbomkitDetailsIgnored(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("skipping on windows")
	}
	body := `
target=""
while [ $# -gt 0 ]; do
  case "$1" in
    --output) target="$2"; shift 2;;
    *) shift;;
  esac
done
cat > "$target" <<'JSON'
{"assets":[{"type":"certificate","algorithm":"RSA","keySize":2048,"file":"/a.pem","line":1,"details":{"issuer":"CN=foo","notAfter":"2026-01-01"}}]}
JSON
exit 0
`
	bin := writeFakeBin(t, "cbomkit-theia", body)
	e := &Engine{binaryPath: bin}
	res, err := e.Scan(context.Background(), engines.ScanOptions{TargetPath: t.TempDir()})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if len(res) != 1 {
		t.Fatalf("want 1 finding, got %d", len(res))
	}
	// Algorithm should still be set; details is silently dropped.
	if res[0].Algorithm == nil || res[0].Algorithm.Name != "RSA" {
		t.Errorf("unexpected: %+v", res[0].Algorithm)
	}
}

// TestAudit_CbomkitRawIdentifierCollision — two assets of same type+algorithm
// but different files share RawIdentifier ("certificate:RSA"). Downstream
// relies on Location.File to disambiguate; if File is empty for both,
// everything collapses.
func TestAudit_CbomkitRawIdentifierCollision(t *testing.T) {
	a1 := normalize(rawAsset{Type: "certificate", Algorithm: "RSA", File: "/a.pem"})
	a2 := normalize(rawAsset{Type: "certificate", Algorithm: "RSA", File: "/b.pem"})
	if a1.RawIdentifier != a2.RawIdentifier {
		t.Fatalf("RawIdentifier should be identical for same type+algo; got %q vs %q", a1.RawIdentifier, a2.RawIdentifier)
	}
	// RawIdentifier colliding is fine as long as DedupeKey differs:
	if a1.DedupeKey() == a2.DedupeKey() {
		t.Errorf("DedupeKey collision across different files: %q == %q", a1.DedupeKey(), a2.DedupeKey())
	}
}

// TestAudit_CbomkitUnknownAssetTypePrimitiveEmpty — asset type "quantum-gadget"
// → primitiveFromAssetType returns "" → Algorithm.Primitive is empty.
// Downstream quantum classification might rely on Primitive to distinguish
// hash vs. signature. Documents the defaulting behaviour.
func TestAudit_CbomkitUnknownAssetTypePrimitiveEmpty(t *testing.T) {
	uf := normalize(rawAsset{Type: "quantum-gadget", Algorithm: "X", File: "/f", Line: 1})
	if uf.Algorithm == nil {
		t.Fatal("algo nil")
	}
	if uf.Algorithm.Primitive != "" {
		t.Errorf("expected empty primitive for unknown asset type, got %q", uf.Algorithm.Primitive)
	}
}
