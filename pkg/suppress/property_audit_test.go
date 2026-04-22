// Package suppress — property-based audit tests.
//
// Uses testing/quick to probe invariants of the suppression engine. These
// tests were added as part of the 2026-04-20 scanner-layer audit.
package suppress

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"testing/quick"
)

// Property: IsSuppressed is a pure function of (filePath, line, algorithm) —
// idempotent. Calling twice returns the same value.
func TestProp_IsSuppressed_Idempotent(t *testing.T) {
	dir := t.TempDir()
	content := "package main\n// oqs:ignore\nrsa.GenerateKey()\n"
	fp := filepath.Join(dir, "p.go")
	os.WriteFile(fp, []byte(content), 0644)

	s, _ := NewScanner(dir)

	f := func(line uint16, algoChar byte) bool {
		algo := strings.ToUpper(string(rune('A' + algoChar%26)))
		a := s.IsSuppressed(fp, int(line)%20, algo)
		b := s.IsSuppressed(fp, int(line)%20, algo)
		return a == b
	}
	if err := quick.Check(f, &quick.Config{MaxCount: 500}); err != nil {
		t.Error(err)
	}
}

// Property: MatchesIgnorePattern is deterministic for a given pattern set.
func TestProp_MatchesIgnorePattern_Deterministic(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, ".oqs-ignore"),
		[]byte("vendor/**\n*.test.go\ntestdata/**\n"), 0644)
	s, _ := NewScanner(dir)

	f := func(pathInts []byte) bool {
		// Build a random-ish path from the bytes.
		var parts []string
		for i := 0; i < len(pathInts); i++ {
			c := rune('a' + pathInts[i]%26)
			parts = append(parts, string(c))
		}
		p := filepath.Join(dir, filepath.Join(parts...))
		a := s.MatchesIgnorePattern(p)
		b := s.MatchesIgnorePattern(p)
		return a == b
	}
	if err := quick.Check(f, &quick.Config{MaxCount: 500}); err != nil {
		t.Error(err)
	}
}

// Property: scanContent returns suppressions whose Line is within the file's
// line range [1, len(strings.Split(content, "\n"))].
func TestProp_ScanContent_LineNumbersInRange(t *testing.T) {
	s := &Scanner{suppressMap: make(map[string][]Suppression)}

	f := func(blob []byte) bool {
		content := string(blob)
		sups := s.scanContent("prop.go", content)
		maxLine := len(strings.Split(content, "\n"))
		for _, sup := range sups {
			if sup.Line < 1 || sup.Line > maxLine {
				return false
			}
		}
		return true
	}
	if err := quick.Check(f, &quick.Config{MaxCount: 500}); err != nil {
		t.Error(err)
	}
}

// Property: parseIgnoreFile never returns a pattern containing only whitespace.
func TestProp_ParseIgnore_NoWhitespacePatterns(t *testing.T) {
	f := func(blob []byte) bool {
		pats := parseIgnoreFile(string(blob))
		for _, p := range pats {
			if strings.TrimSpace(p) == "" {
				return false
			}
		}
		return true
	}
	if err := quick.Check(f, &quick.Config{MaxCount: 500}); err != nil {
		t.Error(err)
	}
}
