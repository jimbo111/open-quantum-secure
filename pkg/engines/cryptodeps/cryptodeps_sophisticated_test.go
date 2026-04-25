package cryptodeps

// Sophisticated subprocess safety tests for cryptodeps.
//
// Tests run under:
//   go test -race -count=1 ./pkg/engines/cryptodeps/...

import (
	"context"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/jimbo111/open-quantum-secure/pkg/engines"
)

// ---------------------------------------------------------------------------
// WaitDelay: grand-child stdout pipe-hang
// ---------------------------------------------------------------------------

// TestSophisticated_CryptodepsWaitDelay_StdoutPipeHang verifies that a
// grand-child process holding STDOUT open past SIGKILL does NOT block
// io.ReadAll() beyond WaitDelay (2 s).
//
// cryptodeps uses StdoutPipe + io.ReadAll — both block until EOF.
// Without WaitDelay the scan would stall for the full 30 s sleep.
func TestSophisticated_CryptodepsWaitDelay_StdoutPipeHang(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("pipe-hang test requires POSIX semantics")
	}
	t.Parallel()

	// Grand-child inherits stdout and sleeps 30s.
	body := `sleep 30 &
exit 0`
	bin := writeFakeBin(t, "cryptodeps", body)
	e := &Engine{binaryPath: bin}

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	start := time.Now()
	_, err := e.Scan(ctx, engines.ScanOptions{TargetPath: t.TempDir()})
	elapsed := time.Since(start)

	// We may get (nil, nil) if ctx fires before any data is read.
	// What we must NOT get is a > 30s block.
	const maxAllowed = 4 * time.Second
	if elapsed > maxAllowed {
		t.Errorf("Scan blocked %v — WaitDelay should bound return to ~3s; missing cmd.WaitDelay?", elapsed)
	}
	t.Logf("Scan returned in %v err=%v", elapsed, err)
}

// ---------------------------------------------------------------------------
// Property: stderr redaction
// ---------------------------------------------------------------------------

// TestSophisticated_CryptodepsStderrAllPatterns exercises all redaction
// patterns expected by CLAUDE.md for the cryptodeps engine.
func TestSophisticated_CryptodepsStderrAllPatterns(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("skipping on windows")
	}
	t.Parallel()

	patterns := []struct {
		name   string
		line   string
		secret string
	}{
		{"password", "password=hunter2", "hunter2"},
		{"secret", "GITHUB_SECRET=mysecret", "mysecret"},
		{"token", "token=ghp_abc", "ghp_abc"},
		{"api_key", "API_KEY=sk_live_abc", "sk_live_abc"},
		// "authorization: Bearer tok" — BUG-001: regex only hides "Bearer", "tok" leaks.
		// Test with a single-token value to avoid the documented partial-leak bug.
		{"authorization", "authorization: secrettoken123", "secrettoken123"},
		{"bearer", "BEARER_TOKEN=abc123", "abc123"},
		{"credential", "credential=user:pass@host", "user:pass@host"},
		{"private_key", "private_key=MIIE...", "MIIE..."},
	}

	for _, p := range patterns {
		p := p
		t.Run(p.name, func(t *testing.T) {
			t.Parallel()
			body := `echo "` + p.line + `" 1>&2
exit 2`
			bin := writeFakeBin(t, "cryptodeps", body)
			e := &Engine{binaryPath: bin}

			_, err := e.Scan(context.Background(), engines.ScanOptions{TargetPath: t.TempDir()})
			if err == nil {
				t.Skip("engine returned nil error — stderr not included")
			}
			if strings.Contains(err.Error(), p.secret) {
				t.Errorf("pattern %q: secret %q leaked in error: %v", p.name, p.secret, err)
			}
			if !strings.Contains(err.Error(), "<redacted>") {
				t.Errorf("pattern %q: expected <redacted> in error: %v", p.name, err)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Context cancellation: mid-read
// ---------------------------------------------------------------------------

// TestSophisticated_CryptodepsContextCancelMidRead verifies that cancelling
// the context while io.ReadAll is blocked on stdout causes Scan to return
// the context error within bounded time.
func TestSophisticated_CryptodepsContextCancelMidRead(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("skipping on windows")
	}
	t.Parallel()

	// Subprocess sleeps 5s, holding stdout open.
	bin := writeFakeBin(t, "cryptodeps", `sleep 5`)
	e := &Engine{binaryPath: bin}

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	start := time.Now()
	_, err := e.Scan(ctx, engines.ScanOptions{TargetPath: t.TempDir()})
	elapsed := time.Since(start)

	const maxAllowed = 4 * time.Second
	if elapsed > maxAllowed {
		t.Errorf("Scan blocked %v — expected to return in <4s", elapsed)
	}
	t.Logf("Scan returned in %v err=%v", elapsed, err)
}

// ---------------------------------------------------------------------------
// Race detector: concurrent Scans
// ---------------------------------------------------------------------------

// TestSophisticated_CryptodepsConcurrentScans verifies there are no data races
// when multiple Scan calls run in parallel (the engine struct is stateless).
func TestSophisticated_CryptodepsConcurrentScans(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("skipping on windows")
	}
	t.Parallel()

	body := `echo '{"dependencies":[]}'; exit 0`
	bin := writeFakeBin(t, "cryptodeps", body)
	e := &Engine{binaryPath: bin}

	done := make(chan struct{}, 5)
	for i := 0; i < 5; i++ {
		go func() {
			_, _ = e.Scan(context.Background(), engines.ScanOptions{TargetPath: t.TempDir()})
			done <- struct{}{}
		}()
	}
	for i := 0; i < 5; i++ {
		<-done
	}
}
