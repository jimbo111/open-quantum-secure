package engines

// Tests for the line-truncation pass in RedactStderr: subprocess failures
// that dump their entire --help text must collapse to the first
// maxStderrLines non-empty lines + a "…[+N more lines]" marker, applied
// BEFORE the 512-byte cap and AFTER redaction.

import (
	"strings"
	"testing"
)

func TestRedactStderr_LineTruncation_HelpDump(t *testing.T) {
	t.Parallel()
	helpDump := strings.Join([]string{
		"error: unknown flag --frobnicate",
		"Usage: some-engine [OPTIONS] PATH",
		"",
		"Options:",
		"  -h, --help     Show this message",
		"  -v, --version  Print version",
		"  -o FILE        Output file",
	}, "\n")

	out := RedactStderr(helpDump)

	// First 3 non-empty lines survive.
	for _, want := range []string{
		"error: unknown flag --frobnicate",
		"Usage: some-engine [OPTIONS] PATH",
		"Options:",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("expected line %q to survive, got:\n%s", want, out)
		}
	}
	// The rest of the help dump is dropped.
	for _, dropped := range []string{"--help", "--version", "-o FILE"} {
		if strings.Contains(out, dropped) {
			t.Errorf("line %q should have been truncated away, got:\n%s", dropped, out)
		}
	}
	// Marker names how many lines were dropped (6 non-empty - 3 kept = 3).
	if !strings.Contains(out, "…[+3 more lines]") {
		t.Errorf("expected …[+3 more lines] marker, got:\n%s", out)
	}
	// Kept output has exactly maxStderrLines lines.
	if got := len(strings.Split(out, "\n")); got != maxStderrLines {
		t.Errorf("expected %d lines, got %d:\n%s", maxStderrLines, got, out)
	}
}

func TestRedactStderr_LineTruncation_ThreeOrFewerLinesUnchanged(t *testing.T) {
	t.Parallel()
	cases := []string{
		"single line",
		"line one\nline two",
		"line one\nline two\nline three",
		"line one\n\nline two", // blank line between two non-empty lines preserved
	}
	for _, in := range cases {
		in := in
		t.Run(in, func(t *testing.T) {
			t.Parallel()
			if out := RedactStderr(in); out != in {
				t.Errorf("RedactStderr(%q) = %q, want unchanged", in, out)
			}
		})
	}
}

func TestRedactStderr_LineTruncation_SkipsBlankLines(t *testing.T) {
	t.Parallel()
	// 4 non-empty lines separated by blanks: only line4 is dropped.
	in := "line1\n\nline2\n\n\nline3\nline4"
	out := RedactStderr(in)
	if !strings.Contains(out, "line3") {
		t.Errorf("blank lines must not count toward the cap, got:\n%s", out)
	}
	if strings.Contains(out, "line4") {
		t.Errorf("4th non-empty line must be dropped, got:\n%s", out)
	}
	if !strings.Contains(out, "…[+1 more lines]") {
		t.Errorf("expected +1 marker, got:\n%s", out)
	}
}

func TestRedactStderr_LineTruncation_Idempotent(t *testing.T) {
	t.Parallel()
	in := "a\nb\nc\nd\ne\nf"
	once := RedactStderr(in)
	twice := RedactStderr(once)
	if once != twice {
		t.Errorf("line truncation must be idempotent:\n once: %q\ntwice: %q", once, twice)
	}
}

func TestRedactStderr_LineTruncation_RedactionStillApplies(t *testing.T) {
	t.Parallel()
	// Credential on line 1 must be redacted even when later lines are dropped;
	// a credential on a dropped line must not appear at all.
	in := "GITHUB_TOKEN=ghp_topsecret\nusage line\nmore usage\npassword=alsosecret\ntrailer"
	out := RedactStderr(in)
	if strings.Contains(out, "ghp_topsecret") {
		t.Errorf("kept-line credential leaked: %q", out)
	}
	if !strings.Contains(out, "GITHUB_TOKEN=<redacted>") {
		t.Errorf("expected redacted kept line, got %q", out)
	}
	if strings.Contains(out, "alsosecret") {
		t.Errorf("dropped-line credential leaked: %q", out)
	}
}

func TestRedactStderr_LineTruncation_ByteCapStillEnforced(t *testing.T) {
	t.Parallel()
	// 3 long lines: line truncation keeps all 3, byte cap must still fire.
	in := strings.Repeat("x", 300) + "\n" + strings.Repeat("y", 300) + "\n" + strings.Repeat("z", 300)
	out := RedactStderr(in)
	if len(out) > maxStderrInError+len(" …[truncated]") {
		t.Errorf("output length %d exceeds byte cap", len(out))
	}
	if !strings.HasSuffix(out, "…[truncated]") {
		t.Errorf("expected byte-cap marker, got suffix %q", out[len(out)-20:])
	}
}
