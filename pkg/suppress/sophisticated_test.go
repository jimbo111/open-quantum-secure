// Package suppress — sophisticated tests for inline directives, .oqs-ignore
// glob patterns, and gitignore-style negation.
package suppress

import (
	"os"
	"path/filepath"
	"testing"
)

// ---------------------------------------------------------------------------
// Helper: create a temp directory with the given files
// ---------------------------------------------------------------------------

func setupDir(t *testing.T, files map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	for name, content := range files {
		full := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(full), 0755); err != nil {
			t.Fatalf("mkdir: %v", err)
		}
		if err := os.WriteFile(full, []byte(content), 0644); err != nil {
			t.Fatalf("write file %s: %v", name, err)
		}
	}
	return dir
}

// ---------------------------------------------------------------------------
// 1. Inline // oqs:ignore suppresses the next line
// ---------------------------------------------------------------------------

func TestInlineDirective_SuppressesNextLine(t *testing.T) {
	dir := setupDir(t, map[string]string{
		"crypto.go": `package main
// oqs:ignore
var key = rsa.NewKey(2048)
`,
	})

	s, err := NewScanner(dir)
	if err != nil {
		t.Fatalf("NewScanner: %v", err)
	}

	filePath := filepath.Join(dir, "crypto.go")
	// Line 2 is the directive; line 3 is the finding — should be suppressed.
	if !s.IsSuppressed(filePath, 3, "RSA") {
		t.Error("finding on line 3 should be suppressed by // oqs:ignore on line 2")
	}
}

// ---------------------------------------------------------------------------
// 2. Inline directive does NOT suppress two lines away
// ---------------------------------------------------------------------------

func TestInlineDirective_DoesNotSuppressTwoLinesAway(t *testing.T) {
	dir := setupDir(t, map[string]string{
		"crypto.go": `package main
// oqs:ignore
// some other comment
var key = rsa.NewKey(2048)
`,
	})

	s, err := NewScanner(dir)
	if err != nil {
		t.Fatalf("NewScanner: %v", err)
	}

	filePath := filepath.Join(dir, "crypto.go")
	// Directive is line 2; finding is line 4 — too far.
	if s.IsSuppressed(filePath, 4, "RSA") {
		t.Error("finding on line 4 should NOT be suppressed by // oqs:ignore on line 2")
	}
}

// ---------------------------------------------------------------------------
// 3. Algorithm-specific suppression: oqs:ignore[RSA] suppresses RSA only
// ---------------------------------------------------------------------------

func TestInlineDirective_AlgorithmSpecific(t *testing.T) {
	dir := setupDir(t, map[string]string{
		"crypto.go": `package main
// oqs:ignore[RSA]
var key = rsa.NewKey(2048)
`,
	})

	s, err := NewScanner(dir)
	if err != nil {
		t.Fatalf("NewScanner: %v", err)
	}

	filePath := filepath.Join(dir, "crypto.go")
	if !s.IsSuppressed(filePath, 3, "RSA") {
		t.Error("RSA should be suppressed by oqs:ignore[RSA]")
	}
	if s.IsSuppressed(filePath, 3, "ECDSA") {
		t.Error("ECDSA should NOT be suppressed by oqs:ignore[RSA]")
	}
}

// ---------------------------------------------------------------------------
// 4. Algorithm suppression is case-insensitive
// ---------------------------------------------------------------------------

func TestInlineDirective_CaseInsensitiveAlgorithm(t *testing.T) {
	dir := setupDir(t, map[string]string{
		"crypto.go": `package main
// oqs:ignore[rsa]
var key = rsa.NewKey(2048)
`,
	})

	s, err := NewScanner(dir)
	if err != nil {
		t.Fatalf("NewScanner: %v", err)
	}

	filePath := filepath.Join(dir, "crypto.go")
	if !s.IsSuppressed(filePath, 3, "RSA") {
		t.Error("RSA (uppercase) should be suppressed by oqs:ignore[rsa] (lowercase)")
	}
}

// ---------------------------------------------------------------------------
// 5. .oqs-ignore glob: vendor/** matches nested vendor files
// ---------------------------------------------------------------------------

func TestOQSIgnore_VendorGlob(t *testing.T) {
	dir := setupDir(t, map[string]string{
		".oqs-ignore": "vendor/**\n",
		"main.go":     "package main",
		"vendor/lib/rsa.go": "package lib",
	})

	s, err := NewScanner(dir)
	if err != nil {
		t.Fatalf("NewScanner: %v", err)
	}

	vendorFile := filepath.Join(dir, "vendor", "lib", "rsa.go")
	if !s.MatchesIgnorePattern(vendorFile) {
		t.Errorf("vendor/lib/rsa.go should match vendor/** pattern")
	}

	mainFile := filepath.Join(dir, "main.go")
	if s.MatchesIgnorePattern(mainFile) {
		t.Error("main.go must NOT match vendor/** pattern")
	}
}

// ---------------------------------------------------------------------------
// 6. Negation: !important.go re-includes a file (gitignore-style, fix bbfdec0)
// ---------------------------------------------------------------------------

func TestOQSIgnore_NegationReIncludes(t *testing.T) {
	dir := setupDir(t, map[string]string{
		".oqs-ignore": "*.go\n!important.go\n",
		"auth.go":     "package auth",
		"important.go": "package important",
	})

	s, err := NewScanner(dir)
	if err != nil {
		t.Fatalf("NewScanner: %v", err)
	}

	authFile := filepath.Join(dir, "auth.go")
	if !s.MatchesIgnorePattern(authFile) {
		t.Error("auth.go should be ignored by *.go pattern")
	}

	importantFile := filepath.Join(dir, "important.go")
	if s.MatchesIgnorePattern(importantFile) {
		t.Error("important.go should be RE-INCLUDED by !important.go negation")
	}
}

// ---------------------------------------------------------------------------
// 7. Negation only fires when file was previously matched
// ---------------------------------------------------------------------------

func TestOQSIgnore_NegationNoEffect_WhenNotPreviouslyMatched(t *testing.T) {
	dir := setupDir(t, map[string]string{
		// No positive pattern for *.py — negation on a Go file should do nothing.
		".oqs-ignore": "!main.go\n",
		"main.go":     "package main",
	})

	s, err := NewScanner(dir)
	if err != nil {
		t.Fatalf("NewScanner: %v", err)
	}

	mainFile := filepath.Join(dir, "main.go")
	// Negation without a prior positive match must not accidentally suppress.
	if s.MatchesIgnorePattern(mainFile) {
		t.Error("main.go should NOT be ignored — negation without a prior match has no effect")
	}
}

// ---------------------------------------------------------------------------
// 8. Multiple algorithm list: oqs:ignore[RSA,ECDSA]
// ---------------------------------------------------------------------------

func TestInlineDirective_MultipleAlgorithms(t *testing.T) {
	dir := setupDir(t, map[string]string{
		"crypto.go": `package main
// oqs:ignore[RSA,ECDSA]
var key interface{}
`,
	})

	s, err := NewScanner(dir)
	if err != nil {
		t.Fatalf("NewScanner: %v", err)
	}

	filePath := filepath.Join(dir, "crypto.go")
	for _, alg := range []string{"RSA", "ECDSA"} {
		if !s.IsSuppressed(filePath, 3, alg) {
			t.Errorf("%s should be suppressed by oqs:ignore[RSA,ECDSA]", alg)
		}
	}
	if s.IsSuppressed(filePath, 3, "AES") {
		t.Error("AES should NOT be suppressed by oqs:ignore[RSA,ECDSA]")
	}
}

// ---------------------------------------------------------------------------
// 9. Directive inside string literal must NOT suppress
// ---------------------------------------------------------------------------

func TestInlineDirective_InsideStringLiteral_IsIgnored(t *testing.T) {
	dir := setupDir(t, map[string]string{
		"crypto.go": `package main
var s = "// oqs:ignore"
var key = rsa.NewKey(2048)
`,
	})

	s, err := NewScanner(dir)
	if err != nil {
		t.Fatalf("NewScanner: %v", err)
	}

	filePath := filepath.Join(dir, "crypto.go")
	// Line 3 is the rsa call; the directive is inside a string on line 2.
	if s.IsSuppressed(filePath, 3, "RSA") {
		t.Error("directive inside string literal must not suppress line 3")
	}
}

// ---------------------------------------------------------------------------
// 10. .oqs-ignore: comment lines and blank lines ignored
// ---------------------------------------------------------------------------

func TestOQSIgnore_CommentAndBlankLinesIgnored(t *testing.T) {
	dir := setupDir(t, map[string]string{
		".oqs-ignore": `# This is a comment
# Another comment

*.min.js
`,
		"script.min.js": "minified",
		"main.go":       "package main",
	})

	s, err := NewScanner(dir)
	if err != nil {
		t.Fatalf("NewScanner: %v", err)
	}

	jsFile := filepath.Join(dir, "script.min.js")
	if !s.MatchesIgnorePattern(jsFile) {
		t.Error("script.min.js should match *.min.js pattern")
	}
}

// ---------------------------------------------------------------------------
// 11. Empty .oqs-ignore — nothing suppressed
// ---------------------------------------------------------------------------

func TestOQSIgnore_Empty_NothingSuppressed(t *testing.T) {
	dir := setupDir(t, map[string]string{
		".oqs-ignore": "",
		"main.go":     "package main",
	})

	s, err := NewScanner(dir)
	if err != nil {
		t.Fatalf("NewScanner: %v", err)
	}

	if s.MatchesIgnorePattern(filepath.Join(dir, "main.go")) {
		t.Error("empty .oqs-ignore should not suppress anything")
	}
}

// ---------------------------------------------------------------------------
// 12. PreloadFile is idempotent — calling twice doesn't double-count directives
// ---------------------------------------------------------------------------

func TestPreloadFile_Idempotent(t *testing.T) {
	dir := setupDir(t, map[string]string{
		"crypto.go": `package main
// oqs:ignore
var key = rsa.NewKey()
`,
	})

	s, err := NewScanner(dir)
	if err != nil {
		t.Fatalf("NewScanner: %v", err)
	}

	filePath := filepath.Join(dir, "crypto.go")
	s.PreloadFile(filePath)
	s.PreloadFile(filePath) // second call should be no-op

	stats := s.Stats()
	if stats.TotalDirectives != 1 {
		t.Errorf("TotalDirectives = %d after double PreloadFile; want 1", stats.TotalDirectives)
	}
}
