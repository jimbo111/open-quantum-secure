package cdxgen

// Sophisticated subprocess safety + fault-injection tests for the cdxgen engine.
//
// Tests run under:
//   go test -race -count=1 ./pkg/engines/cdxgen/...
//
// Key goals:
//  1. WaitDelay grand-child pipe-hang: parent must return within ctx+2s even when
//     a grand-child holds the output pipe open past SIGKILL.
//  2. Explicit "no output" error on exit=0 with empty output (regression guard).
//  3. Non-zero exit with valid output is tolerated (regression guard).
//  4. Stderr with embedded secret is redacted (regression guard).

import (
	"context"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/jimbo111/open-quantum-secure/pkg/engines"
)

// TestSophisticated_CdxgenWaitDelay_PipeHangBoundedByCancellation verifies
// that a grand-child process holding the stderr pipe open past SIGKILL of the
// parent shell does NOT block cmd.Wait() beyond WaitDelay (2 s).
//
// Without cmd.WaitDelay the test would hang for 30 s (the sleep duration of
// the detached grand-child). With WaitDelay the test returns within
// 100 ms (ctx timeout) + 2 s (WaitDelay) + 1 s CI slop = 3.1 s.
func TestSophisticated_CdxgenWaitDelay_PipeHangBoundedByCancellation(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("pipe-hang test relies on POSIX fork/exec semantics")
	}
	t.Parallel()

	// The script forks a grand-child that inherits the stderr pipe and sleeps.
	// Without WaitDelay, cmd.Wait() would block until the grand-child exits.
	body := `
# Detach a child that keeps stderr open for 30s.
sleep 30 >&2 &
# The parent shell exits immediately but the grand-child owns the pipe.
exit 0
`
	bin := writeFakeBin(t, "cdxgen", body)
	e := &Engine{binaryPath: bin}

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	start := time.Now()
	_, err := e.Scan(ctx, engines.ScanOptions{TargetPath: t.TempDir()})
	elapsed := time.Since(start)

	// We expect an error (ctx deadline or context cancelled).
	if err == nil {
		t.Fatal("expected an error when context is cancelled")
	}
	// Critical: must complete within WaitDelay (2s) + generous CI slop (1.5s).
	const maxAllowed = 4 * time.Second
	if elapsed > maxAllowed {
		t.Errorf("Scan blocked for %v — WaitDelay should bound return to ~3s (ctx=100ms + WaitDelay=2s); "+
			"missing cmd.WaitDelay?", elapsed)
	}
	t.Logf("Scan returned in %v (ctx=100ms, WaitDelay=2s) err=%v", elapsed, err)
}

// TestSophisticated_CdxgenExitZeroEmptyOutputIsExplicitError is a regression
// guard for the fix that made exit=0 + empty output an explicit error rather
// than a silent (nil, nil).
func TestSophisticated_CdxgenExitZeroEmptyOutputIsExplicitError(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("skipping on windows")
	}
	t.Parallel()
	// Script exits 0 but never writes to the output file.
	bin := writeFakeBin(t, "cdxgen", `exit 0`)
	e := &Engine{binaryPath: bin}

	res, err := e.Scan(context.Background(), engines.ScanOptions{TargetPath: t.TempDir()})
	if err == nil {
		t.Fatal("expected explicit error for exit=0 with empty output, got nil")
	}
	if res != nil {
		t.Errorf("expected nil findings on empty output error, got %v", res)
	}
	if !strings.Contains(err.Error(), "no output") {
		t.Errorf("error should mention 'no output': %v", err)
	}
}

// TestSophisticated_CdxgenNonZeroExitWithValidOutputTolerated is a regression
// guard: non-zero exit + non-empty valid CycloneDX output must succeed.
func TestSophisticated_CdxgenNonZeroExitWithValidOutputTolerated(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("skipping on windows")
	}
	t.Parallel()
	body := `
target=""
while [ $# -gt 0 ]; do
  case "$1" in
    -o) target="$2"; shift 2;;
    *) shift;;
  esac
done
cat > "$target" <<'JSON'
{"bomFormat":"CycloneDX","components":[{"type":"library","name":"openssl","version":"3.0.0","purl":"pkg:gem/openssl@3.0.0"}]}
JSON
exit 2
`
	bin := writeFakeBin(t, "cdxgen", body)
	e := &Engine{binaryPath: bin}

	res, err := e.Scan(context.Background(), engines.ScanOptions{TargetPath: t.TempDir()})
	if err != nil {
		t.Errorf("non-zero exit must be tolerated when valid output exists: %v", err)
	}
	if len(res) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(res))
	}
}

// TestSophisticated_CdxgenStderrSecretRedactedOnNonZeroExitNoOutput verifies
// that a subprocess printing secret-looking values to stderr on exit has those
// values replaced with <redacted> in the returned error, and the key name is
// preserved for debuggability.
func TestSophisticated_CdxgenStderrSecretRedactedOnNonZeroExitNoOutput(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("skipping on windows")
	}
	t.Parallel()
	secret := "super-secret-value-9999"
	body := `echo "STRIPE_SECRET_KEY=` + secret + `" 1>&2
exit 3`
	bin := writeFakeBin(t, "cdxgen", body)
	e := &Engine{binaryPath: bin}

	_, err := e.Scan(context.Background(), engines.ScanOptions{TargetPath: t.TempDir()})
	if err == nil {
		t.Fatal("expected error for non-zero exit with empty output")
	}
	if strings.Contains(err.Error(), secret) {
		t.Errorf("stderr secret leaked into error message: %v", err)
	}
	if !strings.Contains(err.Error(), "<redacted>") {
		t.Errorf("expected <redacted> marker in error, got: %v", err)
	}
	// Key name should be preserved so operators can debug.
	if !strings.Contains(err.Error(), "STRIPE_SECRET_KEY") {
		t.Errorf("key name STRIPE_SECRET_KEY should be preserved in error: %v", err)
	}
}

// TestSophisticated_CdxgenStderrFloodBoundedTo512 verifies that a subprocess
// emitting many KB of stderr does not make the error message unbounded.
func TestSophisticated_CdxgenStderrFloodBoundedTo512(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("skipping on windows")
	}
	t.Parallel()
	// Print 10 000 chars of 'x' to stderr, exit non-zero, write no output.
	body := `python3 -c "import sys; sys.stderr.write('x'*10000)" 2>&2 || printf '%10000s' '' 1>&2
exit 1`
	// Use a simpler approach that works without Python:
	body = `i=0; while [ $i -lt 200 ]; do printf 'xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx' 1>&2; i=$((i+1)); done; exit 1`
	bin := writeFakeBin(t, "cdxgen", body)
	e := &Engine{binaryPath: bin}

	_, err := e.Scan(context.Background(), engines.ScanOptions{TargetPath: t.TempDir()})
	if err == nil {
		t.Fatal("expected error for non-zero exit")
	}
	// Error message must be bounded: cap 512 + " …[truncated]" marker.
	const maxErrLen = 600 // generous allowance for "cdxgen exited with no output: ..." prefix
	if len(err.Error()) > maxErrLen+512 {
		t.Errorf("error message length %d exceeds expected cap: %v", len(err.Error()), err)
	}
}
