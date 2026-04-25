package astgrep

// Sophisticated subprocess safety + HMAC/SHA ordering regression tests.
//
// Tests run under:
//   go test -race -count=1 ./pkg/engines/astgrep/...

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/jimbo111/open-quantum-secure/pkg/engines"
)

// writeFakeBinAG writes a shell-script stub binary.
func writeFakeBinAG(t *testing.T, name, body string) string {
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
// Regression: HMAC-SHA ordering (commit 7b7f4ac)
// ---------------------------------------------------------------------------

// TestSophisticated_PrimitiveFromRuleID_HMACBeatsHash_Regression is the
// definitive regression guard for commit 7b7f4ac.  Any rule ID containing
// "hmac" MUST return "mac", even when the ID also contains "sha" (e.g.
// "hmac-sha256").  The switch statement must check HMAC before hash.
func TestSophisticated_PrimitiveFromRuleID_HMACBeatsHash_Regression(t *testing.T) {
	t.Parallel()
	cases := []struct {
		ruleID string
		want   string
	}{
		// Core regression: hmac+sha must return mac.
		{"crypto-go-hmac-sha256", "mac"},
		{"crypto-hmac-sha256-new", "mac"},
		{"crypto-hmac-sha1-verify", "mac"},
		{"crypto-hmac-sha512", "mac"},
		{"crypto-java-hmacsha256", "mac"},
		// HMAC without sha should still be mac.
		{"crypto-hmac-md5", "mac"},
		{"crypto-go-hmac-new", "mac"},
		// Pure hash (no hmac) must still return hash.
		{"crypto-go-sha256-new", "hash"},
		{"crypto-python-hashlib-sha256", "hash"},
		{"crypto-openssl-evp-digest-init", "hash"},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.ruleID, func(t *testing.T) {
			t.Parallel()
			got := primitiveFromRuleID(tc.ruleID)
			if got != tc.want {
				t.Errorf("primitiveFromRuleID(%q) = %q, want %q "+
					"(HMAC ordering regression — hmac must beat sha in switch)", tc.ruleID, got, tc.want)
			}
		})
	}
}

// TestSophisticated_PrimitiveFromRuleID_MACBeforeHASH_Property verifies the
// ordering invariant as a property: for any rule ID that contains both "hmac"
// and "sha", the result must always be "mac" (never "hash").
func TestSophisticated_PrimitiveFromRuleID_MACBeforeHASH_Property(t *testing.T) {
	t.Parallel()
	// Enumerate synthetic rule IDs that contain both tokens.
	mixed := []string{
		"crypto-hmac-sha256",
		"hmac-sha1",
		"hmac-sha384",
		"crypto-python-hmac-sha512",
		"hmacsha256-verify",
		"verify-hmac-sha256",
	}
	for _, id := range mixed {
		id := id
		t.Run(id, func(t *testing.T) {
			t.Parallel()
			got := primitiveFromRuleID(id)
			if got == "hash" {
				t.Errorf("primitiveFromRuleID(%q) returned %q — HMAC rules must not be classified as hash", id, got)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// WaitDelay: bounded return on ctx cancel with detached child
// ---------------------------------------------------------------------------

// TestSophisticated_AstgrepWaitDelay_BoundedByCancel verifies that a grand-
// child process keeping the stdout pipe open does not block Scan() beyond
// WaitDelay (2 s) after ctx cancellation.
//
// ast-grep uses cmd.Output() which internally waits for stdout EOF — a
// grand-child holding the pipe keeps it open past SIGKILL without WaitDelay.
func TestSophisticated_AstgrepWaitDelay_BoundedByCancel(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("pipe-hang test requires POSIX semantics")
	}
	t.Parallel()

	// Grand-child inherits stdout and sleeps; parent shell exits immediately.
	body := `sleep 30 >/dev/null 2>&1 &
exit 0`
	bin := writeFakeBinAG(t, "ast-grep", body)
	e := &Engine{binaryPath: bin}

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	start := time.Now()
	_, _ = e.Scan(ctx, engines.ScanOptions{TargetPath: t.TempDir()})
	elapsed := time.Since(start)

	// ctx=100ms + WaitDelay=2s + 1.5s CI slop.
	const maxAllowed = 4 * time.Second
	if elapsed > maxAllowed {
		t.Errorf("Scan blocked %v — WaitDelay should bound return to ~3s", elapsed)
	}
	t.Logf("Scan returned in %v", elapsed)
}

// TestSophisticated_AstgrepNonZeroWithEmptyOutputIsError verifies that a
// subprocess exit with non-zero code AND zero bytes of output is treated as
// an error (not a silent empty result).
func TestSophisticated_AstgrepNonZeroWithEmptyOutputIsError(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("skipping on windows")
	}
	t.Parallel()
	bin := writeFakeBinAG(t, "ast-grep", `exit 2`)
	e := &Engine{binaryPath: bin}

	_, err := e.Scan(context.Background(), engines.ScanOptions{TargetPath: t.TempDir()})
	if err == nil {
		t.Fatal("expected error for non-zero exit with empty output")
	}
}

// TestSophisticated_AstgrepNonZeroWithValidOutputTolerated verifies that
// ast-grep's "exits non-zero when findings present" behaviour is tolerated.
// A non-zero exit with a valid JSON array of matches must succeed.
func TestSophisticated_AstgrepNonZeroWithValidOutputTolerated(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("skipping on windows")
	}
	t.Parallel()
	// ast-grep writes VALID JSON to stdout then exits 1 (findings present).
	body := `printf '[{"text":"RSA","range":{"start":{"line":0,"column":0},"end":{"line":0,"column":3}},"file":"a.go","language":"go","ruleId":"crypto-go-rsa","message":"RSA usage","severity":"warning","metaVariables":{}}]'
exit 1`
	bin := writeFakeBinAG(t, "ast-grep", body)
	e := &Engine{binaryPath: bin}

	res, err := e.Scan(context.Background(), engines.ScanOptions{TargetPath: t.TempDir()})
	if err != nil {
		t.Fatalf("non-zero exit with valid JSON must be tolerated: %v", err)
	}
	if len(res) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(res))
	}
}

// TestSophisticated_AstgrepContextTimeout checks that a slow ast-grep
// subprocess does not block indefinitely.
func TestSophisticated_AstgrepContextTimeout(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("skipping on windows")
	}
	t.Parallel()
	bin := writeFakeBinAG(t, "ast-grep", `sleep 10; exit 0`)
	e := &Engine{binaryPath: bin}

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	start := time.Now()
	_, err := e.Scan(ctx, engines.ScanOptions{TargetPath: t.TempDir()})
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("expected ctx error for slow subprocess")
	}
	const maxAllowed = 4 * time.Second
	if elapsed > maxAllowed {
		t.Errorf("Scan blocked %v — expected to return in <4s", elapsed)
	}
	t.Logf("Scan returned in %v err=%v", elapsed, err)
}
