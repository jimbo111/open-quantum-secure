package engines

import (
	"regexp"
	"strings"
)

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
	s = bearerPattern.ReplaceAllString(s, "<redacted>")
	s = credentialPatterns.ReplaceAllStringFunc(s, func(match string) string {
		// Find the separator (= or :) and replace the value portion only.
		sepIdx := strings.IndexAny(match, "=:")
		if sepIdx < 0 {
			return "<redacted>"
		}
		return match[:sepIdx+1] + "<redacted>"
	})
	if len(s) > maxStderrInError {
		// Drop split-rune bytes at the truncation boundary so the result is
		// always valid UTF-8 — multi-byte runes straddling byte 512 would
		// otherwise leave a lone leading byte (e.g. 0xC2 from `©`).
		s = strings.ToValidUTF8(s[:maxStderrInError], "") + " …[truncated]"
	}
	return s
}
