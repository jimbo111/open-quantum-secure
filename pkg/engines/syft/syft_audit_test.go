package syft

// Adversarial / cross-layer audit tests for the syft Tier 2 SBOM engine.
// These are added by the 2026-04-20 scanner-layer audit — no behaviour changes.

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

// writeFakeBinary writes a POSIX shell script (or Windows .bat shim) that executes
// the provided body, and returns the path to it. On Windows the body is ignored
// unless it is a valid batch command.
func writeFakeBinary(t *testing.T, name, body string) string {
	t.Helper()
	dir := t.TempDir()
	var path string
	if runtime.GOOS == "windows" {
		path = filepath.Join(dir, name+".bat")
		if err := os.WriteFile(path, []byte("@echo off\r\n"+body+"\r\n"), 0o755); err != nil {
			t.Fatalf("write fake bat: %v", err)
		}
	} else {
		path = filepath.Join(dir, name)
		if err := os.WriteFile(path, []byte("#!/bin/sh\n"+body+"\n"), 0o755); err != nil {
			t.Fatalf("write fake binary: %v", err)
		}
	}
	return path
}

// TestAudit_SyftMalformedJSONReturnsError — syft subprocess returns malformed
// JSON. Expected: Scan returns a parse error, not a silent empty-findings result.
func TestAudit_SyftMalformedJSONReturnsError(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("skipping on windows — shell-script fake binary not portable")
	}
	// syft is called with `-o cyclonedx-json=<tmpPath>`. The shim parses its
	// own args, writes garbage to the target file, exits 0.
	body := `
target=""
for arg in "$@"; do
  case "$arg" in
    cyclonedx-json=*) target="${arg#cyclonedx-json=}" ;;
  esac
done
printf '{"bomFormat": "CycloneDX", "components":' > "$target"
exit 0
`
	bin := writeFakeBinary(t, "syft", body)
	e := &Engine{binaryPath: bin}
	_, err := e.Scan(context.Background(), engines.ScanOptions{TargetPath: t.TempDir()})
	if err == nil {
		t.Fatal("expected JSON parse error for truncated output, got nil")
	}
	if !strings.Contains(err.Error(), "JSON parse") {
		t.Errorf("expected JSON parse error, got %v", err)
	}
}

// TestAudit_SyftExit0EmptyFileReturnsNilNil — syft subprocess exits 0 but writes
// a 0-byte output file. Current behaviour: Scan returns (nil, nil) silently.
// Severity: Low — empty SBOM is semantically valid, but callers have no way to
// distinguish "scanner bug produced nothing" from "project has no deps".
func TestAudit_SyftExit0EmptyFileReturnsNilNil(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("skipping on windows")
	}
	body := `
target=""
for arg in "$@"; do
  case "$arg" in
    cyclonedx-json=*) target="${arg#cyclonedx-json=}" ;;
  esac
done
: > "$target"   # truncate to 0 bytes
exit 0
`
	bin := writeFakeBinary(t, "syft", body)
	e := &Engine{binaryPath: bin}
	res, err := e.Scan(context.Background(), engines.ScanOptions{TargetPath: t.TempDir()})
	if err != nil {
		t.Fatalf("got err: %v", err)
	}
	if len(res) != 0 {
		t.Errorf("expected 0 findings, got %d", len(res))
	}
	// This documents — intentionally — a silent-pass failure mode. No assertion
	// on a warning, because the engine currently doesn't emit one.
}

// TestAudit_SyftStderrRedacted — syft exits non-zero and writes a credential-
// looking line to stderr. engines.RedactStderr must strip the value while
// preserving the key name so operators can still debug.
// 2026-04-21: was TestAudit_SyftNonZeroExitLeaksStderr; flipped after
// engines.RedactStderr was applied in syft.Scan.
func TestAudit_SyftStderrRedacted(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("skipping on windows")
	}
	secret := "abc123-definitely-secret"
	body := `
echo "BEARER_TOKEN=` + secret + `" 1>&2
exit 2
`
	bin := writeFakeBinary(t, "syft", body)
	e := &Engine{binaryPath: bin}
	_, err := e.Scan(context.Background(), engines.ScanOptions{TargetPath: t.TempDir()})
	if err == nil {
		t.Fatal("expected error for non-zero exit")
	}
	if strings.Contains(err.Error(), secret) {
		t.Errorf("stderr secret leaked into error: %v", err)
	}
	if !strings.Contains(err.Error(), "<redacted>") {
		t.Errorf("expected <redacted> marker in error, got: %v", err)
	}
}

// TestAudit_SyftMissingOutputFileOnExit0 — subprocess exits 0 but never writes
// the expected output file. ReadFile returns ENOENT. Current behaviour: error.
func TestAudit_SyftMissingOutputFileOnExit0(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("skipping on windows")
	}
	// The engine creates the temp file, then deletes it right before calling
	// syft — no, actually the file is created first so ReadFile will succeed
	// with 0 bytes. Simulate the tmp file being unlinked by syft.
	body := `
target=""
for arg in "$@"; do
  case "$arg" in
    cyclonedx-json=*) target="${arg#cyclonedx-json=}" ;;
  esac
done
rm -f "$target"
exit 0
`
	bin := writeFakeBinary(t, "syft", body)
	e := &Engine{binaryPath: bin}
	_, err := e.Scan(context.Background(), engines.ScanOptions{TargetPath: t.TempDir()})
	if err == nil {
		t.Fatal("expected read-output error when syft removed the file")
	}
	if !strings.Contains(err.Error(), "read output") && !strings.Contains(err.Error(), "no such") {
		t.Errorf("expected read output error, got %v", err)
	}
}

// TestAudit_SyftSlowSubprocessRespectsContextTimeout — syft hangs; context
// times out at 100ms. Scan must return the context error bounded by
// cmd.WaitDelay (2s) + slop, NOT the full subprocess lifetime.
//
// Background: with cmd.Stderr = &bytes.Buffer, Go's os/exec spawns a goroutine
// that reads the subprocess stderr pipe and won't return from cmd.Wait() until
// the pipe closes. Grand-children that inherit the stderr write-end (e.g.
// `sleep 30 &` double-forks) keep the pipe open past SIGKILL to the parent
// shell. Before the F1 fix this meant Scan blocked for the full subprocess
// lifetime; now cmd.WaitDelay force-closes the pipe 2s after kill.
func TestAudit_SyftSlowSubprocessRespectsContextTimeout(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("skipping on windows — sleep semantics differ")
	}
	// Double-fork a detached child that inherits the stderr pipe and
	// would keep it open past SIGKILL on the shell. Without WaitDelay
	// this blocks Scan for the full sleep 30 duration; with WaitDelay
	// it bounds to ~100ms + 2s.
	body := `sleep 30 &
exec 2>&-
exit 0`
	bin := writeFakeBinary(t, "syft", body)
	e := &Engine{binaryPath: bin}
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	start := time.Now()
	_, err := e.Scan(ctx, engines.ScanOptions{TargetPath: t.TempDir()})
	elapsed := time.Since(start)
	if err == nil {
		t.Fatal("expected an error (context or killed)")
	}
	if !strings.Contains(err.Error(), "deadline") && !strings.Contains(err.Error(), "context") && !strings.Contains(err.Error(), "killed") {
		t.Errorf("expected context/killed-related error, got %v", err)
	}
	// ctx.deadline=100ms + WaitDelay=2s → expect <3s with slop for CI jitter.
	if elapsed > 3*time.Second {
		t.Errorf("Scan blocked %v past ctx deadline of 100ms — WaitDelay should bound this to ~2s", elapsed)
	}
	t.Logf("Scan returned after %v (ctx deadline was 100ms, WaitDelay=2s) — err=%v", elapsed, err)
}

// TestAudit_SyftUnknownCycloneDXFieldsIgnored — syft 1.8 adds a new top-level
// field "evidence" that Go's json.Unmarshal ignores by default. Verify that
// unknown fields do NOT cause parse failures.
func TestAudit_SyftUnknownCycloneDXFieldsIgnored(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("skipping on windows")
	}
	body := `
target=""
for arg in "$@"; do
  case "$arg" in
    cyclonedx-json=*) target="${arg#cyclonedx-json=}" ;;
  esac
done
cat > "$target" <<'JSON'
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.7",
  "serialNumber": "urn:uuid:00000000-0000-0000-0000-000000000000",
  "version": 1,
  "metadata": {"timestamp": "2026-01-01T00:00:00Z", "evidence": {"identity": "strong"}},
  "futureField": {"nested": [1,2,3]},
  "components": [
    {"type":"library","name":"openssl","version":"3.0.0","purl":"pkg:deb/debian/openssl@3.0.0","futureComponentField":"ignoreMe"}
  ],
  "dependencies": [{"ref":"A","dependsOn":["B"]}]
}
JSON
exit 0
`
	bin := writeFakeBinary(t, "syft", body)
	e := &Engine{binaryPath: bin}
	res, err := e.Scan(context.Background(), engines.ScanOptions{TargetPath: t.TempDir()})
	if err != nil {
		t.Fatalf("unknown fields should be ignored, got err: %v", err)
	}
	if len(res) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(res))
	}
	if res[0].Dependency == nil || !strings.HasSuffix(res[0].Dependency.Library, "openssl") {
		t.Errorf("unexpected finding: %+v", res[0])
	}
}

// TestAudit_SyftDuplicateComponentsNotDeduped — two library components with
// identical PURL, name, version emit TWO findings. Documents that syft does not
// dedupe — dedup happens later in the pipeline.
func TestAudit_SyftDuplicateComponentsNotDeduped(t *testing.T) {
	bom := rawBOM{
		BOMFormat: "CycloneDX",
		Components: []rawComponent{
			{Type: "library", Name: "openssl", Version: "3.0.0", PURL: "pkg:deb/debian/openssl@3.0.0"},
			{Type: "library", Name: "openssl", Version: "3.0.0", PURL: "pkg:deb/debian/openssl@3.0.0"},
		},
	}
	res := normalize(bom, "/target")
	if len(res) != 2 {
		t.Fatalf("expected 2 findings (no in-engine dedup), got %d", len(res))
	}
	// DedupeKey must be identical so downstream dedup collapses them.
	if res[0].DedupeKey() != res[1].DedupeKey() {
		t.Errorf("DedupeKey collision expected: %q vs %q", res[0].DedupeKey(), res[1].DedupeKey())
	}
}

// TestAudit_PurlNamespace_MalformedInputs — defensive parsing; no panics on
// malformed PURLs with multiple @'s, trailing slashes, unicode.
func TestAudit_PurlNamespace_MalformedInputs(t *testing.T) {
	cases := []struct {
		purl string
	}{
		{"pkg:deb/"},                         // no component
		{"pkg:maven/g/a@1.0@extra"},          // double @
		{"pkg:maven//a@1.0"},                 // empty namespace
		{"pkg:maven/g/a/extra@1.0"},          // 3 path segments
		{"pkg:\x00bad/ns/a@1.0"},             // nul byte
		{"pkg:maven/g/a@1.0?qualifier=val"},  // qualifiers
		{strings.Repeat("a", 10_000)},        // very long string
		{"////@/"},                           // all slashes
	}
	for _, tc := range cases {
		t.Run(tc.purl, func(t *testing.T) {
			// Must not panic
			_ = purlNamespace(tc.purl)
		})
	}
}

// TestAudit_SyftNilContextPanics — passing a nil context to Scan when the
// engine IS available is currently undefined. Without a binary, Scan returns
// early with "not found". This documents that path.
func TestAudit_SyftNilContextGuarded(t *testing.T) {
	e := &Engine{binaryPath: ""} // not available
	// Must not panic even with nil ctx.
	_, err := e.Scan(nil, engines.ScanOptions{TargetPath: "/tmp"})
	if err == nil {
		t.Fatal("expected error for not-available engine")
	}
}
