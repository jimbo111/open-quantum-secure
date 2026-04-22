// Package suppress — adversarial audit fixtures.
//
// These tests were added as part of the 2026-04-20 scanner-layer audit to probe
// the suppression engine for false-negative (suppressing findings that SHOULD
// NOT be suppressed) and false-positive (failing to suppress findings that
// should be) behaviour.
//
// Each test is self-contained and documents the adversarial input it probes.
// Some tests are EXPECTED TO FAIL — they document bugs with t.Errorf /
// t.Logf. When a bug is found the test is kept so we can track regressions.
package suppress

import (
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// ---------------------------------------------------------------------------
// FALSE POSITIVE: directive inside a string literal is currently matched
// ---------------------------------------------------------------------------

// Audit_StringLiteral_SuppressesErroneously probes whether an oqs:ignore
// inside a double-quoted string literal incorrectly suppresses a genuine
// finding on that line.
//
// Adversarial input: `msg := "// oqs:ignore — exploit"`
// Expected: no suppression — the directive is inside string data, not a comment.
// Actual (documented below): the regex has no comment-context awareness and
// will match the substring, producing a spurious suppression.
func TestAudit_F1_StringLiteral_InsideDoubleQuotes(t *testing.T) {
	content := `package main
var msg = "// oqs:ignore — attacker bypass"
key, _ := rsa.GenerateKey(rand.Reader, 2048)
`
	s := &Scanner{suppressMap: make(map[string][]Suppression)}
	sups := s.scanContent("main.go", content)

	// A correct implementation returns 0 suppressions because the directive
	// is inside a string literal, not a comment. Flipped from t.Logf to
	// t.Errorf on 2026-04-20 as part of fixing F1.
	if len(sups) != 0 {
		t.Errorf("directive inside \" \" string literal produced %d suppression(s), want 0. Content: %q",
			len(sups), content)
	}
}

// Audit_StringLiteral_BacktickRawString probes Go raw string literals.
func TestAudit_F1_StringLiteral_BacktickRawString(t *testing.T) {
	content := "package main\n" +
		"var msg = `// oqs:ignore — attacker bypass via backticks`\n" +
		"key, _ := rsa.GenerateKey(rand.Reader, 2048)\n"

	s := &Scanner{suppressMap: make(map[string][]Suppression)}
	sups := s.scanContent("main.go", content)
	if len(sups) != 0 {
		t.Errorf("directive inside backtick raw string literal produced %d suppression(s), want 0",
			len(sups))
	}
}

// Audit_StringLiteral_Python probes a Python single-quoted string with the
// directive inside it. The Python code should NOT be suppressed.
func TestAudit_F1_StringLiteral_PythonSingleQuote(t *testing.T) {
	content := `msg = '# oqs:ignore — exploit attempt'
key = Crypto.PublicKey.RSA.generate(2048)
`
	s := &Scanner{suppressMap: make(map[string][]Suppression)}
	sups := s.scanContent("main.py", content)
	if len(sups) != 0 {
		t.Errorf("Python string literal containing '# oqs:ignore' produced %d suppression(s), want 0",
			len(sups))
	}
}

// ---------------------------------------------------------------------------
// FALSE POSITIVE: code AFTER the directive on same line
// ---------------------------------------------------------------------------

// Audit_DirectiveBeforeCode verifies that `/* oqs:ignore */ key := rsa.Gen()`
// (directive FIRST, code AFTER on the same line) triggers suppression — but
// the `$` anchor plus optional closing `*/` in the pattern may or may not
// handle this case. A more subtle case: `// oqs:ignore\nnext line`.
func TestAudit_F2_DirectiveBeforeCodeSameLine(t *testing.T) {
	// `/* oqs:ignore */ rsa.GenerateKey(...)` — directive in prefix comment.
	// The regex ends with `\s*\*/\s*$` — but there's non-whitespace AFTER the
	// `*/`. So this should NOT match.
	content := `/* oqs:ignore */ key, _ := rsa.GenerateKey(rand.Reader, 2048)
`
	s := &Scanner{suppressMap: make(map[string][]Suppression)}
	sups := s.scanContent("main.go", content)
	if len(sups) != 0 {
		t.Logf("DOCUMENT: /* oqs:ignore */ code-after triggers suppression (count=%d). This is ambiguous —"+
			" a user might intend it to suppress, but the regex pattern advertises end-of-line suppression.",
			len(sups))
	}
}

// ---------------------------------------------------------------------------
// REGEX ANCHOR / DIRECTIVE DETECTION
// ---------------------------------------------------------------------------

// Audit_F3_DirectiveWithCRLF verifies that \r\n line endings don't break
// parsing (bufio-split-by-newline may leave \r at end; the regex has `$` anchor).
func TestAudit_F3_CRLFLineEndings(t *testing.T) {
	content := "package main\r\n// oqs:ignore\r\nkey := rsa.Generate()\r\n"
	s := &Scanner{suppressMap: make(map[string][]Suppression)}
	sups := s.scanContent("main.go", content)
	if len(sups) != 1 {
		t.Errorf("CRLF file: expected 1 suppression, got %d — the \\r byte after the directive may defeat the $ anchor",
			len(sups))
	}
}

// Audit_F3b_DoubleSpaceAfterMarker verifies the common typo `//  oqs:ignore`
// (two spaces) still works — the regex uses `\s*` so it should.
func TestAudit_F3b_DoubleSpaceAfterMarker(t *testing.T) {
	content := `//  oqs:ignore
key := rsa.Generate()
`
	s := &Scanner{suppressMap: make(map[string][]Suppression)}
	sups := s.scanContent("main.go", content)
	if len(sups) != 1 {
		t.Errorf("double-space after // should match: got %d", len(sups))
	}
}

// ---------------------------------------------------------------------------
// GLOB / .oqs-ignore edge cases
// ---------------------------------------------------------------------------

// Audit_F4_NegationPattern checks gitignore-style negation (`!pattern`).
// gitignore supports "exclude this even if a prior rule included it". This
// implementation is gitignore-compatible-ish per CLAUDE.md, but negation is
// undocumented. This test documents actual behaviour.
func TestAudit_F4_NegationPatternSemantics(t *testing.T) {
	dir := t.TempDir()
	ignore := "vendor/**\n!vendor/trusted/**\n"
	if err := os.WriteFile(filepath.Join(dir, ".oqs-ignore"), []byte(ignore), 0644); err != nil {
		t.Fatal(err)
	}
	s, _ := NewScanner(dir)

	// vendor/trusted should NOT be ignored (negation). vendor/untrusted SHOULD.
	trusted := filepath.Join(dir, "vendor/trusted/crypto.go")
	untrusted := filepath.Join(dir, "vendor/untrusted/crypto.go")

	// 2026-04-21: flipped after negation support fix. vendor/trusted must
	// be re-included by `!vendor/trusted/**` even though `vendor/**` would
	// match it.
	if s.MatchesIgnorePattern(trusted) {
		t.Errorf("vendor/trusted should be UN-ignored by `!vendor/trusted/**` negation")
	}
	if !s.MatchesIgnorePattern(untrusted) {
		t.Errorf("vendor/untrusted should still be ignored by `vendor/**`")
	}
}

// Audit_F5_LeadingSlashAnchored checks gitignore-style leading-slash anchoring
// (`/pattern` = anchor to repo root). Our glob treats the leading `/` as a
// literal segment separator, so `/vendor/**` might or might not work.
func TestAudit_F5_LeadingSlashAnchoring(t *testing.T) {
	dir := t.TempDir()
	ignore := "/vendor/**\n" // gitignore: "vendor at repo root ONLY"
	if err := os.WriteFile(filepath.Join(dir, ".oqs-ignore"), []byte(ignore), 0644); err != nil {
		t.Fatal(err)
	}
	s, _ := NewScanner(dir)

	rootVendor := filepath.Join(dir, "vendor/crypto.go")
	nestedVendor := filepath.Join(dir, "subpkg/vendor/crypto.go")

	rootMatch := s.MatchesIgnorePattern(rootVendor)
	nestedMatch := s.MatchesIgnorePattern(nestedVendor)

	t.Logf("leading-slash documented: rootVendor matches=%v (gitignore=true), nestedVendor matches=%v (gitignore=false)",
		rootMatch, nestedMatch)

	// In gitignore: nestedVendor should NOT match. If our code treats `/vendor/**`
	// like `vendor/**` anywhere, nested match will be true — diverges.
	if nestedMatch {
		t.Errorf("LEADING-SLASH NOT ANCHORED: `/vendor/**` matched nested path %q (gitignore would NOT match)",
			nestedVendor)
	}
}

// Audit_F6_TrailingSlashDirOnly verifies gitignore semantics:
// `vendor/` = directory only, NOT file. Our code doesn't distinguish.
func TestAudit_F6_TrailingSlashDirOnly(t *testing.T) {
	dir := t.TempDir()
	ignore := "crypto/\n" // gitignore: match directory only
	if err := os.WriteFile(filepath.Join(dir, ".oqs-ignore"), []byte(ignore), 0644); err != nil {
		t.Fatal(err)
	}
	s, _ := NewScanner(dir)

	filePath := filepath.Join(dir, "crypto") // regular file named "crypto"
	if err := os.WriteFile(filePath, []byte("x"), 0644); err != nil {
		t.Fatal(err)
	}

	matches := s.MatchesIgnorePattern(filePath)
	t.Logf("pattern 'crypto/' against file 'crypto' matches=%v (gitignore would be false)", matches)
}

// Audit_F7_EmptyPattern — line with just whitespace in .oqs-ignore.
func TestAudit_F7_EmptyPatternLine(t *testing.T) {
	// Empty lines are already skipped — verify behaviour doesn't crash on
	// lines that are just whitespace (they become non-empty after Scanner
	// reads but are empty after TrimSpace).
	pats := parseIgnoreFile("   \n\t\n# comment\nvendor/**\n")
	if len(pats) != 1 || pats[0] != "vendor/**" {
		t.Errorf("whitespace-only lines should be skipped, got patterns=%v", pats)
	}
}

// Audit_F8_EscapedLiteralChars probes gitignore-style escape `\*` (literal *).
// gitignore supports escaping; Go's filepath.Match has its own escape syntax
// (`\\*` = literal *). Verify behaviour.
func TestAudit_F8_EscapedLiteralStar(t *testing.T) {
	dir := t.TempDir()
	// File with a literal `*` in name — rare but legal.
	// `\*.go` in gitignore means "file literally named *.go".
	ignore := "\\*.go\n"
	if err := os.WriteFile(filepath.Join(dir, ".oqs-ignore"), []byte(ignore), 0644); err != nil {
		t.Fatal(err)
	}
	s, _ := NewScanner(dir)

	literalStarFile := filepath.Join(dir, "*.go") // filename literally "*.go"
	regularFile := filepath.Join(dir, "main.go")

	starMatch := s.MatchesIgnorePattern(literalStarFile)
	regularMatch := s.MatchesIgnorePattern(regularFile)

	t.Logf("escaped `\\*.go`: literal-star-file matches=%v (gitignore=true), main.go matches=%v (gitignore=false)",
		starMatch, regularMatch)

	// Divergence: filepath.Match `\*.go` may treat `\` as escape, meaning literal `*`,
	// so regularMatch should be false (pass). If regularMatch is true, escape semantics
	// silently differ.
	if regularMatch {
		t.Errorf("ESCAPE BEHAVIOUR DIVERGES: backslash-star in .oqs-ignore matched a non-literal-star filename")
	}
}

// Audit_F9_AbsolutePathInIgnore checks what happens when a user puts an
// absolute path in .oqs-ignore (common mistake).
func TestAudit_F9_AbsolutePathInIgnore(t *testing.T) {
	dir := t.TempDir()
	absPath := filepath.Join(dir, "sensitive/crypto.go")
	// User mistakenly writes full absolute path — our code calls filepath.Rel
	// so the pattern stays absolute, and target relpath is "sensitive/crypto.go".
	ignore := absPath + "\n"
	if err := os.WriteFile(filepath.Join(dir, ".oqs-ignore"), []byte(ignore), 0644); err != nil {
		t.Fatal(err)
	}
	s, _ := NewScanner(dir)

	matches := s.MatchesIgnorePattern(absPath)
	t.Logf("absolute path in .oqs-ignore: matches=%v (documented behaviour; user-hostile if false)",
		matches)
}

// ---------------------------------------------------------------------------
// LINE-NUMBERING EDGE CASES
// ---------------------------------------------------------------------------

// Audit_F10_MultiLineCommentSpansLines — C-style /* ... oqs:ignore ... */
// across multiple lines. Our scanner is line-based, so the middle of a
// multi-line block comment would not match the regex (lines don't start with /*).
func TestAudit_F10_MultiLineCommentWithIgnoreInMiddle(t *testing.T) {
	content := `/*
 * oqs:ignore — this is inside a multi-line C comment
 */
key, _ := rsa.GenerateKey(rand.Reader, 2048)
`
	s := &Scanner{suppressMap: make(map[string][]Suppression)}
	sups := s.scanContent("main.c", content)
	t.Logf("multi-line /* */ with 'oqs:ignore' on an inner line: suppression count=%d (lines: %v)",
		len(sups), sups)
	// Currently a middle-line like " * oqs:ignore — ..." doesn't match the
	// regex (must start with //, #, /*, or <!--). Document.
}

// Audit_F11_DirectiveOnLineContinuation — backslash line continuation (C/shell).
func TestAudit_F11_LineContinuation(t *testing.T) {
	// In C: `\\\n` joins lines. Our line-based scanner treats them separately.
	content := "// oqs:\\\nignore\nkey := rsa.Gen()\n"
	s := &Scanner{suppressMap: make(map[string][]Suppression)}
	sups := s.scanContent("main.c", content)
	t.Logf("line continuation through oqs:\\<newline>ignore: count=%d (documented non-support)", len(sups))
}

// ---------------------------------------------------------------------------
// IsSuppressed concurrency: two goroutines loading same file concurrently
// with different ScanFile return values (shouldn't happen, but race test)
// ---------------------------------------------------------------------------

// Audit_F12_ConcurrentIsSuppressedStress hammers IsSuppressed with many
// concurrent calls over multiple files to surface races.
func TestAudit_F12_ConcurrentIsSuppressedStress(t *testing.T) {
	dir := t.TempDir()
	filePaths := make([]string, 20)
	for i := 0; i < 20; i++ {
		p := filepath.Join(dir, "f"+string(rune('A'+i))+".go")
		content := "// oqs:ignore\nrsa.GenerateKey()\n"
		os.WriteFile(p, []byte(content), 0644)
		filePaths[i] = p
	}

	s, _ := NewScanner(dir)

	var wg sync.WaitGroup
	for worker := 0; worker < 10; worker++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 100; i++ {
				fp := filePaths[i%len(filePaths)]
				_ = s.IsSuppressed(fp, 2, "RSA")
				_ = s.MatchesIgnorePattern(fp)
				_ = s.Stats()
				s.PreloadFile(fp)
			}
		}()
	}
	wg.Wait()

	// All files loaded: TotalDirectives should equal number of files (each has 1).
	st := s.Stats()
	if st.TotalDirectives != 20 {
		t.Errorf("TotalDirectives = %d, expected 20 (one per file, loaded exactly once). "+
			"Double-loading indicates race in PreloadFile/IsSuppressed interleaving.", st.TotalDirectives)
	}
}

// Audit_F13_OqsInName — a variable named `oqsIgnore` or `my_oqs:ignore_handler`.
// The regex looks for "oqs:ignore" after a comment marker — something like
// `someFn(oqs:ignoreArg)` is NOT a comment, so should not match.
func TestAudit_F13_VariableNameContainsOqsIgnore(t *testing.T) {
	content := `
x := oqsIgnore()  // just a function call, not a directive
rsa.GenerateKey()
`
	s := &Scanner{suppressMap: make(map[string][]Suppression)}
	sups := s.scanContent("main.go", content)
	if len(sups) != 0 {
		t.Errorf("variable/function name 'oqsIgnore' should not trigger suppression; got %d", len(sups))
	}
}

// Audit_F14_MatchesIgnore_RelPathOutsideRoot verifies that when filePath is
// OUTSIDE rootPath, filepath.Rel produces "../..." and pattern matching
// behaves predictably. The code does not short-circuit on this edge case.
func TestAudit_F14_MatchesIgnorePatternOutsideRoot(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, ".oqs-ignore"), []byte("vendor/**\n"), 0644); err != nil {
		t.Fatal(err)
	}
	s, _ := NewScanner(dir)

	// File is in a DIFFERENT temp dir — outside rootPath.
	other := t.TempDir()
	outsidePath := filepath.Join(other, "vendor/crypto.go")

	// Expect: either doesn't match (safest), or matches based on suffix.
	// Document behaviour; we don't know what's correct.
	matches := s.MatchesIgnorePattern(outsidePath)
	t.Logf("file outside rootPath (relpath starts with ../), matches=%v", matches)
	// If outside-root files match vendor/**, that's a potential false positive
	// because the user probably didn't intend patterns to apply beyond the
	// repo root. Document.
}

// Audit_F15_MatchesIgnorePattern_OnSymlinkedRoot probes how symlinks in the
// rootPath are resolved.
func TestAudit_F15_IgnorePatternSymlinkRoot(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, ".oqs-ignore"), []byte("secret/**\n"), 0644)
	os.MkdirAll(filepath.Join(dir, "secret"), 0755)

	linkDir := t.TempDir()
	linkPath := filepath.Join(linkDir, "linkedroot")
	if err := os.Symlink(dir, linkPath); err != nil {
		t.Skipf("symlink creation failed: %v", err)
	}

	// Scanner initialized with linked path. File path uses symlink.
	s, _ := NewScanner(linkPath)
	if s == nil {
		t.Fatal("scanner creation failed")
	}
	filePath := filepath.Join(linkPath, "secret/x.go")
	if !s.MatchesIgnorePattern(filePath) {
		t.Errorf("pattern should match secret/** through symlinked root; got false")
	}
}

// ---------------------------------------------------------------------------
// Regex token variations
// ---------------------------------------------------------------------------

// Audit_F16_ReasonOnSameLineWithNoSeparator verifies that text after the
// directive without the expected separator `-` / `:` / `—` doesn't produce
// a bogus match. Example: `// oqs:ignore IS BOGUS` — the regex requires a
// separator before the reason.
func TestAudit_F16_ReasonSeparatorRequired(t *testing.T) {
	content := `// oqs:ignore IS THIS A REASON?
key := rsa.Gen()
`
	s := &Scanner{suppressMap: make(map[string][]Suppression)}
	sups := s.scanContent("main.go", content)
	// Expected: regex does NOT match because there's non-whitespace after
	// oqs:ignore without the separator.
	if len(sups) != 0 {
		t.Logf("DOCUMENT: `// oqs:ignore IS THIS A REASON?` produced %d suppression(s). "+
			"Sups=%+v. Caller should validate the reason-separator requirement.",
			len(sups), sups)
	}

	// Sanity: this content should NOT suppress line 2 anyway
	// If it did, that'd be a false positive.
	if strings.Contains(content, "// oqs:ignore") && len(sups) == 1 {
		t.Errorf("IMPROPERLY RELAXED REGEX: matched despite garbage-after-directive (no separator). "+
			"Got reason=%q", sups[0].Reason)
	}
}
