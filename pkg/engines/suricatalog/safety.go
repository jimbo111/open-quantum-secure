package suricatalog

import (
	"regexp"
	"strings"
)

// ja3Pattern matches a valid lowercase 32-character MD5 hex string.
// Suricata always emits lowercase hex; uppercase or non-hex are rejected.
var ja3Pattern = regexp.MustCompile(`^[0-9a-f]{32}$`)

// validateJA3Hash sanitizes and validates a JA3/JA3S hash from an eve.json event.
// Returns the hash unchanged if valid, or "" if invalid or malformed.
func validateJA3Hash(s string) string {
	s = sanitizeField(s)
	if s == "" {
		return ""
	}
	if !ja3Pattern.MatchString(s) {
		return ""
	}
	return s
}

// sanitizeField strips control characters (< 0x20, DEL 0x7F) from
// attacker-controlled Suricata field values before they flow into UnifiedFinding.
// Prevents ANSI injection in table output and control-char smuggling in SARIF/CBOM.
func sanitizeField(s string) string {
	if s == "" {
		return ""
	}
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		if r >= 0x20 && r != 0x7F {
			b.WriteRune(r)
		}
	}
	return b.String()
}

// sanitizeTarget sanitizes a suricata-log target string used as a URI path component.
// In addition to control-char stripping, removes '/', '?', '#' which would
// fragment the "(suricata-log)/<target>#<alg>" filePath format in UnifiedFinding.
func sanitizeTarget(s string) string {
	if s == "" {
		return ""
	}
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		if r < 0x20 || r == 0x7F || r == '/' || r == '?' || r == '#' {
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}
