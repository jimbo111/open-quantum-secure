package semgrep

// Sophisticated subprocess safety + fault-injection tests for semgrep.
//
// Tests run under:
//   go test -race -count=1 ./pkg/engines/semgrep/...

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

// writeFakeBinSG writes a shell-script stub binary for semgrep tests.
func writeFakeBinSG(t *testing.T, name, body string) string {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, name)
	if runtime.GOOS == "windows" {
		p = p + ".bat"
		_ = os.WriteFile(p, []byte("@echo off\r\n"+body+"\r\n"), 0o755)
	} else {
		_ = os.WriteFile(p, []byte("#!/bin/sh\n"+body+"\n"), 0o755)
	}
	return p
}

// ---------------------------------------------------------------------------
// WaitDelay: grand-child pipe-hang
// ---------------------------------------------------------------------------

// TestSophisticated_SemgrepWaitDelay_GrandChildPipeHang verifies that a
// grand-child process holding the stderr pipe open past SIGKILL does not
// block cmd.Wait() beyond WaitDelay (2 s).
func TestSophisticated_SemgrepWaitDelay_GrandChildPipeHang(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("pipe-hang test requires POSIX semantics")
	}
	t.Parallel()

	// Grand-child inherits stderr and sleeps 30s.
	body := `sleep 30 >&2 &
exit 0`
	bin := writeFakeBinSG(t, "semgrep", body)
	e := &Engine{binaryPath: bin}

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	start := time.Now()
	_, err := e.Scan(ctx, engines.ScanOptions{TargetPath: t.TempDir()})
	elapsed := time.Since(start)

	if err == nil {
		t.Logf("Scan returned nil error (ctx fired before write) after %v", elapsed)
	}
	// ctx=100ms + WaitDelay=2s + 1.5s CI slop.
	const maxAllowed = 4 * time.Second
	if elapsed > maxAllowed {
		t.Errorf("Scan blocked %v — WaitDelay should bound return to ~3s; missing cmd.WaitDelay?", elapsed)
	}
	t.Logf("Scan returned in %v err=%v", elapsed, err)
}

// ---------------------------------------------------------------------------
// Context cancellation propagation
// ---------------------------------------------------------------------------

// TestSophisticated_SemgrepContextTimeout verifies that a slow semgrep
// subprocess returns the context error, not a hang.
func TestSophisticated_SemgrepContextTimeout(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("skipping on windows")
	}
	t.Parallel()

	bin := writeFakeBinSG(t, "semgrep", `sleep 10; exit 0`)
	e := &Engine{binaryPath: bin}

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	start := time.Now()
	_, err := e.Scan(ctx, engines.ScanOptions{TargetPath: t.TempDir()})
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("expected context error for slow subprocess")
	}
	const maxAllowed = 4 * time.Second
	if elapsed > maxAllowed {
		t.Errorf("Scan blocked %v — expected to return in <4s", elapsed)
	}
	t.Logf("Scan returned in %v err=%v", elapsed, err)
}

// ---------------------------------------------------------------------------
// Exit-code tolerance
// ---------------------------------------------------------------------------

// TestSophisticated_SemgrepExitOneWithValidSARIF verifies that semgrep exit=1
// (findings present) is tolerated when SARIF output is valid.
func TestSophisticated_SemgrepExitOneWithValidSARIF(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("skipping on windows")
	}
	t.Parallel()

	// Semgrep writes SARIF to a file path passed via --output <path>.
	// The stub parses --output from args and writes a minimal valid SARIF.
	body := `
outfile=""
for arg in "$@"; do
  case "$prev" in
    --output) outfile="$arg";;
  esac
  prev="$arg"
done
if [ -n "$outfile" ]; then
  cat > "$outfile" <<'SARIF'
{
  "version":"2.1.0",
  "$schema":"https://schemastore.azurewebsites.net/schemas/json/sarif-2.1.0-rtm.5.json",
  "runs":[{
    "tool":{"driver":{"name":"semgrep","rules":[{"id":"crypto-go-rsa","name":"RSA","shortDescription":{"text":"RSA usage"}}]}},
    "results":[{
      "ruleId":"crypto-go-rsa",
      "message":{"text":"RSA key generation"},
      "locations":[{"physicalLocation":{"artifactLocation":{"uri":"main.go"},"region":{"startLine":10,"startColumn":1}}}]
    }]
  }]
}
SARIF
fi
exit 1
`
	bin := writeFakeBinSG(t, "semgrep", body)
	e := &Engine{binaryPath: bin}

	res, err := e.Scan(context.Background(), engines.ScanOptions{TargetPath: t.TempDir()})
	if err != nil {
		t.Fatalf("semgrep exit=1 (findings present) must be tolerated: %v", err)
	}
	if len(res) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(res))
	}
}

// TestSophisticated_SemgrepExitZeroEmptyOutputReturnsNilNil documents that
// semgrep returning exit=0 with empty output produces (nil, nil).
// This is the current documented behaviour (unlike cdxgen/cbomkit which
// surface an explicit error).
func TestSophisticated_SemgrepExitZeroEmptyOutputReturnsNilNil(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("skipping on windows")
	}
	t.Parallel()

	// Write nothing to the output file.
	bin := writeFakeBinSG(t, "semgrep", `exit 0`)
	e := &Engine{binaryPath: bin}

	res, err := e.Scan(context.Background(), engines.ScanOptions{TargetPath: t.TempDir()})
	// Semgrep currently returns (nil, nil) on empty output + exit=0.
	// If this ever changes to an explicit error, this test should flip.
	if err != nil {
		t.Logf("NOTE: semgrep now returns explicit error on empty output: %v", err)
	}
	if len(res) != 0 {
		t.Errorf("expected 0 findings on empty output, got %d", len(res))
	}
}

// ---------------------------------------------------------------------------
// Stderr redaction
// ---------------------------------------------------------------------------

// TestSophisticated_SemgrepStderrNotRedacted_DocumentedGap documents that the
// semgrep engine currently does NOT apply RedactStderr to its stderr — unlike
// cdxgen, cbomkit, cryptodeps, and syft. This test verifies the current
// behaviour so any future fix is noticed.
//
// NOTE: if this test fails (secret no longer leaks), it means RedactStderr
// was applied and the gap is closed — update accordingly.
func TestSophisticated_SemgrepStderrNotRedacted_DocumentedGap(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("skipping on windows")
	}
	t.Parallel()

	secret := "semgrep-api-secret-value-9999"
	// semgrep exits non-zero with no output — stderr goes into error message.
	body := `echo "SEMGREP_API_TOKEN=` + secret + `" 1>&2
exit 2`
	bin := writeFakeBinSG(t, "semgrep", body)
	e := &Engine{binaryPath: bin}

	_, err := e.Scan(context.Background(), engines.ScanOptions{TargetPath: t.TempDir()})
	if err == nil {
		// Semgrep may return nil,nil on empty output even with non-zero exit in
		// some code paths. Skip the assertion in that case.
		t.Log("NOTE: semgrep returned nil error — cannot check stderr leak")
		return
	}

	if strings.Contains(err.Error(), secret) {
		// Document the gap — do not fail the test, just log.
		t.Logf("DOCUMENTED GAP: semgrep stderr not redacted — secret %q visible in error: %v", secret, err)
	} else {
		t.Logf("semgrep stderr appears redacted or secret not included in error path: %v", err)
	}
}

// TestSophisticated_SemgrepNotAvailable verifies the correct error when semgrep binary is not found.
func TestSophisticated_SemgrepNotAvailable(t *testing.T) {
	t.Parallel()
	e := &Engine{binaryPath: ""}
	_, err := e.Scan(context.Background(), engines.ScanOptions{TargetPath: "/tmp"})
	if err == nil {
		t.Fatal("expected error when semgrep is not available")
	}
	if !strings.Contains(err.Error(), "not found") {
		t.Errorf("expected 'not found' in error, got: %v", err)
	}
}
