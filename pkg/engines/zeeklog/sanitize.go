package zeeklog

import "strings"

// sanitizeZeekField strips control characters (< 0x20, DEL 0x7F) from
// attacker-controlled Zeek field values before they flow into UnifiedFinding.
// Prevents ANSI injection in table output and control-char smuggling in SARIF/CBOM.
func sanitizeZeekField(s string) string {
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

// sanitizeTarget sanitizes a zeek-log target string used as a URI path component.
// In addition to control-char stripping, removes '/', '?', '#' which would
// fragment the "(zeek-log)/<target>#<alg>" filePath format in UnifiedFinding.
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
