package engines

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// TestProbeVersion_StripsANSI covers the cdxgen case: --version stdout starts
// with `\x1b[1m...\x1b[0m`, and the raw escape bytes must not leak into engine
// listings.
func TestProbeVersion_StripsANSI(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell-script fake binary not portable to Windows")
	}
	dir := t.TempDir()
	bin := filepath.Join(dir, "fake")
	// Echo a payload containing ANSI bold + reset codes.
	script := "#!/bin/sh\nprintf '\\033[1mFakeTool 9.9.9\\033[0m\\n'\n"
	if err := os.WriteFile(bin, []byte(script), 0755); err != nil {
		t.Fatalf("write fake bin: %v", err)
	}

	got := ProbeVersion(bin)
	want := "FakeTool 9.9.9"
	if got != want {
		t.Errorf("ProbeVersion stripped ANSI = %q; want %q", got, want)
	}
}

// TestProbeVersion_EmptyPath returns "unknown" without invoking exec.
func TestProbeVersion_EmptyPath(t *testing.T) {
	if got := ProbeVersion(""); got != "unknown" {
		t.Errorf("ProbeVersion(\"\") = %q; want \"unknown\"", got)
	}
}

// TestProbeVersion_FirstLineOnly trims to the first newline-delimited line
// (cdxgen also prints "Runtime: Node.js, ..." on line 2).
func TestProbeVersion_FirstLineOnly(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell-script fake binary not portable to Windows")
	}
	dir := t.TempDir()
	bin := filepath.Join(dir, "multiline")
	script := "#!/bin/sh\necho 'first 1.0'\necho 'second line'\n"
	if err := os.WriteFile(bin, []byte(script), 0755); err != nil {
		t.Fatalf("write fake bin: %v", err)
	}
	got := ProbeVersion(bin)
	if got != "first 1.0" {
		t.Errorf("ProbeVersion first-line = %q; want %q", got, "first 1.0")
	}
}

// TestProbeVersionCombined_ReadsStderr: enginemgr's listing probe counts
// stderr toward the banner; the scan-time probe must not.
func TestProbeVersionCombined_ReadsStderr(t *testing.T) {
	bin := writeFakeBin(t, "#!/bin/sh\nprintf 'StderrTool 1.2.3\\n' >&2\n")
	if got := ProbeVersionCombined(context.Background(), bin); got != "StderrTool 1.2.3" {
		t.Errorf("ProbeVersionCombined = %q; want %q", got, "StderrTool 1.2.3")
	}
	if got := ProbeVersion(bin); got != "unknown" {
		t.Errorf("ProbeVersion (stdout-only, empty stdout) = %q; want \"unknown\"", got)
	}
}

// TestProbeVersionCombined_EmptyPath short-circuits like ProbeVersion.
func TestProbeVersionCombined_EmptyPath(t *testing.T) {
	if got := ProbeVersionCombined(context.Background(), ""); got != "unknown" {
		t.Errorf("ProbeVersionCombined(\"\") = %q; want \"unknown\"", got)
	}
}

// TestProbeVersion_EmptyOutputIsUnknown pins the contract alignment: empty
// probe output reports "unknown", never "".
func TestProbeVersion_EmptyOutputIsUnknown(t *testing.T) {
	bin := writeFakeBin(t, "#!/bin/sh\nexit 0\n")
	if got := ProbeVersion(bin); got != "unknown" {
		t.Errorf("ProbeVersion(empty output) = %q; want \"unknown\"", got)
	}
}
