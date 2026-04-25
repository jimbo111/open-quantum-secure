package cbomkit

// Sophisticated subprocess safety + fault-injection tests for cbomkit-theia.
//
// Tests run under:
//   go test -race -count=1 ./pkg/engines/cbomkit/...

import (
	"context"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/jimbo111/open-quantum-secure/pkg/engines"
)

// TestSophisticated_CbomkitWaitDelay_GrandChildPipeHang verifies that a
// grand-child process holding the stderr pipe open after SIGKILL does not
// block cmd.Wait() beyond WaitDelay (2 s).
//
// Pattern: shell forks a detached child that sleeps with stderr inherited.
// Without WaitDelay, cmd.Wait() blocks for the full sleep duration.
func TestSophisticated_CbomkitWaitDelay_GrandChildPipeHang(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("pipe-hang test requires POSIX semantics")
	}
	t.Parallel()

	body := `
# Grand-child inherits stderr and sleeps 30s.
sleep 30 >&2 &
exit 0
`
	bin := writeFakeBin(t, "cbomkit-theia", body)
	e := &Engine{binaryPath: bin}

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	start := time.Now()
	_, err := e.Scan(ctx, engines.ScanOptions{TargetPath: t.TempDir()})
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("expected error when context is cancelled")
	}
	// ctx=100ms + WaitDelay=2s + 1.5s CI slop = 3.6s budget.
	const maxAllowed = 4 * time.Second
	if elapsed > maxAllowed {
		t.Errorf("Scan blocked %v — WaitDelay should bound return to ~3s; missing cmd.WaitDelay?", elapsed)
	}
	t.Logf("Scan returned in %v err=%v", elapsed, err)
}

// TestSophisticated_CbomkitExitZeroEmptyOutputIsExplicitError guards the
// explicit-error-on-empty-output contract (F5 fix). Exit=0 with nothing
// written to the output file must return an error, not (nil, nil).
func TestSophisticated_CbomkitExitZeroEmptyOutputIsExplicitError(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("skipping on windows")
	}
	t.Parallel()
	bin := writeFakeBin(t, "cbomkit-theia", `exit 0`)
	e := &Engine{binaryPath: bin}

	res, err := e.Scan(context.Background(), engines.ScanOptions{TargetPath: t.TempDir()})
	if err == nil {
		t.Fatal("expected explicit error for exit=0 with empty output")
	}
	if res != nil {
		t.Errorf("expected nil findings, got %v", res)
	}
	if !strings.Contains(err.Error(), "no output") {
		t.Errorf("error should mention 'no output': %v", err)
	}
}

// TestSophisticated_CbomkitNonZeroExitWithValidOutputTolerated guards the
// exit-code tolerance: cbomkit-theia exits non-zero when partial scanners
// fail; valid on-disk output must still be consumed.
func TestSophisticated_CbomkitNonZeroExitWithValidOutputTolerated(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("skipping on windows")
	}
	t.Parallel()
	body := `
target=""
while [ $# -gt 0 ]; do
  case "$1" in
    --output) target="$2"; shift 2;;
    *) shift;;
  esac
done
cat > "$target" <<'JSON'
{"assets":[{"type":"certificate","algorithm":"RSA","keySize":4096,"file":"/etc/ssl/server.crt","line":0}]}
JSON
exit 1
`
	bin := writeFakeBin(t, "cbomkit-theia", body)
	e := &Engine{binaryPath: bin}

	res, err := e.Scan(context.Background(), engines.ScanOptions{TargetPath: t.TempDir()})
	if err != nil {
		t.Fatalf("non-zero exit must be tolerated when valid output exists: %v", err)
	}
	if len(res) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(res))
	}
	if res[0].Algorithm == nil || res[0].Algorithm.Name != "RSA" {
		t.Errorf("unexpected algorithm: %+v", res[0].Algorithm)
	}
}

// TestSophisticated_CbomkitStderrSecretRedacted verifies that credential-like
// values in cbomkit stderr are scrubbed before appearing in errors.
func TestSophisticated_CbomkitStderrSecretRedacted(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("skipping on windows")
	}
	t.Parallel()
	secret := "cbomkit-api-secret-value"
	body := `echo "API_KEY=` + secret + `" 1>&2
exit 2`
	bin := writeFakeBin(t, "cbomkit-theia", body)
	e := &Engine{binaryPath: bin}

	_, err := e.Scan(context.Background(), engines.ScanOptions{TargetPath: t.TempDir()})
	if err == nil {
		t.Fatal("expected error for non-zero exit with empty output")
	}
	if strings.Contains(err.Error(), secret) {
		t.Errorf("stderr secret leaked: %v", err)
	}
	if !strings.Contains(err.Error(), "<redacted>") {
		t.Errorf("expected <redacted> marker, got: %v", err)
	}
}

// TestSophisticated_CbomkitMultipleAssetsNormalized verifies that a realistic
// multi-asset JSON response (certificate + private-key + config) normalizes to
// 3 distinct findings with correct asset-type → primitive mapping.
func TestSophisticated_CbomkitMultipleAssetsNormalized(t *testing.T) {
	t.Parallel()
	assets := []rawAsset{
		{Type: "certificate", Algorithm: "RSA", KeySize: 2048, File: "/a.crt"},
		{Type: "private-key", Algorithm: "EC", KeySize: 256, Curve: "P-256", File: "/b.pem"},
		{Type: "config", Algorithm: "TLS 1.3", File: "/nginx.conf", Line: 10},
	}
	for _, a := range assets {
		uf := normalize(a)
		if uf.Algorithm == nil {
			t.Errorf("asset %+v produced nil Algorithm", a)
		}
	}
	// Verify distinct primitives.
	rsaUF := normalize(assets[0])
	ecUF := normalize(assets[1])
	tlsUF := normalize(assets[2])
	if rsaUF.Algorithm.Primitive != "asymmetric" {
		t.Errorf("RSA cert: primitive %q, want asymmetric", rsaUF.Algorithm.Primitive)
	}
	if ecUF.Algorithm.Primitive != "asymmetric" {
		t.Errorf("EC key: primitive %q, want asymmetric", ecUF.Algorithm.Primitive)
	}
	if tlsUF.Algorithm.Primitive != "protocol" {
		t.Errorf("TLS config: primitive %q, want protocol", tlsUF.Algorithm.Primitive)
	}
}

// TestSophisticated_CbomkitContextCancelledPreventsStaleParse verifies that
// when the context is cancelled the engine returns the cancellation error and
// does not attempt to parse a stale output file.
func TestSophisticated_CbomkitContextCancelledPreventsStaleParse(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("skipping on windows")
	}
	t.Parallel()
	// The subprocess writes valid JSON then sleeps 2s. Ctx cancels after 50ms.
	// Engine must return ctx.Err(), not the parsed JSON.
	body := `
target=""
while [ $# -gt 0 ]; do
  case "$1" in
    --output) target="$2"; shift 2;;
    *) shift;;
  esac
done
cat > "$target" <<'JSON'
{"assets":[{"type":"certificate","algorithm":"RSA","keySize":2048,"file":"/a.crt","line":0}]}
JSON
sleep 2
exit 0
`
	bin := writeFakeBin(t, "cbomkit-theia", body)
	e := &Engine{binaryPath: bin}

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	_, err := e.Scan(ctx, engines.ScanOptions{TargetPath: t.TempDir()})
	if err == nil {
		t.Fatal("expected ctx error on slow subprocess")
	}
	// Must propagate context cancellation, not silently succeed.
	if !strings.Contains(err.Error(), "context") && !strings.Contains(err.Error(), "deadline") &&
		!strings.Contains(err.Error(), "cbomkit-theia") {
		t.Errorf("unexpected error type: %v", err)
	}
}
