package engines

import (
	"fmt"
	"regexp"
	"strings"
)

// maxStderrLines caps how many non-empty stderr lines survive into an error
// message. Subprocess failures frequently dump their entire --help text to
// stderr; embedding that wall of text in a WARNING makes scan logs unreadable.
// The first few lines carry the actual error ("unknown flag …", "Cannot read
// rule …"); the rest is noise. Applied BEFORE the byte cap.
const maxStderrLines = 3

// maxStderrInError caps how much subprocess stderr ends up in a returned
// error message. Engines reap stderr to give operators context when a
// subprocess fails, but unbounded stderr in errors (a) bloats JSON scan
// reports and (b) can leak sensitive values (env vars printed on crash,
// credential-bearing connection strings). 512 bytes is enough for "exit 2:
// permission denied" + a couple of lines, and truncation is signalled with
// "…[truncated]".
const maxStderrInError = 512

// credentialPatterns matches common ways credentials appear in subprocess
// stderr — environment-style KEY=value lines (including compound names like
// GITHUB_TOKEN=… or DB_PASSWORD=…) and HTTP Authorization-header style
// key:value pairs. The matcher is deliberately loose: false positives just
// redact harmless content; false negatives allow leaks.
var credentialPatterns = regexp.MustCompile(
	`(?i)[\w-]*(?:password|passwd|secret|token|api[_-]?key|authorization|bearer|credential|private[_-]?key)[\w-]*\s*[=:]\s*\S+`,
)

// bearerPattern matches HTTP `Authorization: Bearer <token>` form where the
// token is whitespace-separated from the `Bearer` scheme keyword. The
// credentialPatterns regex above stops at the first whitespace via `\S+`, so
// the actual token after `Bearer ` would otherwise leak. Apply this BEFORE
// credentialPatterns so the env-var matcher never sees the raw token.
var bearerPattern = regexp.MustCompile(`(?i)\bbearer\s+\S+`)

// RedactStderr returns a safe representation of subprocess stderr for
// inclusion in an error message:
//   - credential-looking key=value / key:value tokens are masked with
//     "<name>=<redacted>"
//   - output is trimmed to the first maxStderrLines non-empty lines with a
//     " …[+N more lines]" marker (child --help dumps otherwise flood scan
//     logs) BEFORE the byte cap
//   - total output is capped to maxStderrInError bytes and suffixed
//     with " …[truncated]" when trimmed
//   - trailing whitespace is stripped
//
// The caller is responsible for deciding whether stderr belongs in the
// error at all; this function only makes inclusion safer.
func RedactStderr(stderr string) string {
	s := strings.TrimSpace(stderr)
	if s == "" {
		return ""
	}
	// Redaction MUST run in this order: bearerPattern first, then
	// credentialPatterns (see the pattern comments above — reversing leaks
	// Bearer tokens). Line truncation runs after redaction so the marker is
	// never mistaken for content, and before the byte cap so the cap applies
	// to the already-shortened text.
	s = bearerPattern.ReplaceAllString(s, "<redacted>")
	s = credentialPatterns.ReplaceAllStringFunc(s, func(match string) string {
		// Find the separator (= or :) and replace the value portion only.
		sepIdx := strings.IndexAny(match, "=:")
		if sepIdx < 0 {
			return "<redacted>"
		}
		return match[:sepIdx+1] + "<redacted>"
	})
	s = truncateLines(s, maxStderrLines)
	if len(s) > maxStderrInError {
		// Drop split-rune bytes at the truncation boundary so the result is
		// always valid UTF-8 — multi-byte runes straddling byte 512 would
		// otherwise leave a lone leading byte (e.g. 0xC2 from `©`).
		s = strings.ToValidUTF8(s[:maxStderrInError], "") + " …[truncated]"
	}
	return s
}

// truncateLines keeps only the first max non-empty lines of s. When lines are
// dropped, a " …[+N more lines]" marker is appended to the LAST kept line
// (not emitted as its own line) so a second RedactStderr pass over the result
// still counts ≤ max non-empty lines — keeping the function idempotent.
// Inputs with ≤ max non-empty lines are returned unchanged.
func truncateLines(s string, max int) string {
	lines := strings.Split(s, "\n")
	nonEmpty := 0
	for _, ln := range lines {
		if strings.TrimSpace(ln) != "" {
			nonEmpty++
		}
	}
	if nonEmpty <= max {
		return s
	}
	kept := make([]string, 0, max)
	for _, ln := range lines {
		if strings.TrimSpace(ln) == "" {
			continue
		}
		kept = append(kept, strings.TrimRight(ln, " \t"))
		if len(kept) == max {
			break
		}
	}
	kept[len(kept)-1] += fmt.Sprintf(" …[+%d more lines]", nonEmpty-max)
	return strings.Join(kept, "\n")
}
