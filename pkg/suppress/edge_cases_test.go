package suppress

import (
	"os"
	"path/filepath"
	"sync"
	"testing"
)

func TestPreloadFile_DoesNotDoubleCount(t *testing.T) {
	dir := t.TempDir()
	content := `// oqs:ignore
key := rsa.GenerateKey()
// oqs:ignore[DES]
des := cipher("DES")
`
	filePath := filepath.Join(dir, "main.go")
	os.WriteFile(filePath, []byte(content), 0644)

	s, _ := NewScanner(dir)

	// Preload twice — stats should only count once
	s.PreloadFile(filePath)
	s.PreloadFile(filePath)

	stats := s.Stats()
	if stats.TotalDirectives != 2 {
		t.Errorf("TotalDirectives should be 2 (not double-counted), got %d", stats.TotalDirectives)
	}
}

func TestPreloadFile_ConcurrentSameFile(t *testing.T) {
	dir := t.TempDir()
	content := `// oqs:ignore
key := rsa.GenerateKey()
`
	filePath := filepath.Join(dir, "main.go")
	os.WriteFile(filePath, []byte(content), 0644)

	s, _ := NewScanner(dir)

	// Concurrent preloads of same file
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			s.PreloadFile(filePath)
		}()
	}
	wg.Wait()

	stats := s.Stats()
	if stats.TotalDirectives != 1 {
		t.Errorf("concurrent preload should count 1 directive, got %d", stats.TotalDirectives)
	}
}

func TestIsSuppressed_LineZero(t *testing.T) {
	dir := t.TempDir()
	content := `// oqs:ignore
key := rsa.GenerateKey()
`
	filePath := filepath.Join(dir, "main.go")
	os.WriteFile(filePath, []byte(content), 0644)

	s, _ := NewScanner(dir)

	// Line 0 should not crash and should not match line 1's directive
	if s.IsSuppressed(filePath, 0, "RSA") {
		t.Error("line 0 should not be suppressed (directives start at line 1)")
	}
}

func TestIsSuppressed_NegativeLine(t *testing.T) {
	dir := t.TempDir()
	content := `// oqs:ignore
`
	filePath := filepath.Join(dir, "main.go")
	os.WriteFile(filePath, []byte(content), 0644)

	s, _ := NewScanner(dir)

	// Negative line should not crash
	if s.IsSuppressed(filePath, -1, "RSA") {
		t.Error("negative line should not be suppressed")
	}
}

func TestIsSuppressed_WhitespaceOnlyFile(t *testing.T) {
	dir := t.TempDir()
	filePath := filepath.Join(dir, "empty.go")
	os.WriteFile(filePath, []byte("   \n\n   \n"), 0644)

	s, _ := NewScanner(dir)

	if s.IsSuppressed(filePath, 1, "RSA") {
		t.Error("whitespace-only file should not have suppressions")
	}
}

func TestScanContent_ReasonWithColon(t *testing.T) {
	content := `// oqs:ignore: backward compat required
`
	s := &Scanner{suppressMap: make(map[string][]Suppression)}
	sups := s.scanContent("main.go", content)
	if len(sups) != 1 {
		t.Fatalf("expected 1 suppression with colon reason, got %d", len(sups))
	}
}

func TestMatchesIgnorePattern_LargePatternSet(t *testing.T) {
	dir := t.TempDir()
	// Create .oqs-ignore with many patterns
	var patterns string
	for i := 0; i < 100; i++ {
		patterns += "vendor" + string(rune('A'+i%26)) + "/**\n"
	}
	patterns += "actual_vendor/**\n"
	os.WriteFile(filepath.Join(dir, ".oqs-ignore"), []byte(patterns), 0644)

	s, _ := NewScanner(dir)

	// Should match the specific pattern
	if !s.MatchesIgnorePattern(filepath.Join(dir, "actual_vendor/crypto.go")) {
		t.Error("should match actual_vendor pattern")
	}

	// Should not match unrelated paths
	if s.MatchesIgnorePattern(filepath.Join(dir, "src/main.go")) {
		t.Error("should not match src/main.go")
	}
}

func TestIsSuppressed_IgnorePatternTakesPrecedence(t *testing.T) {
	dir := t.TempDir()
	// File is in vendor (matched by .oqs-ignore) AND has inline directive
	ignoreContent := "vendor/**\n"
	os.WriteFile(filepath.Join(dir, ".oqs-ignore"), []byte(ignoreContent), 0644)

	vendorDir := filepath.Join(dir, "vendor")
	os.MkdirAll(vendorDir, 0755)
	filePath := filepath.Join(vendorDir, "crypto.go")
	os.WriteFile(filePath, []byte("// no oqs:ignore here\nkey := rsa.Gen()\n"), 0644)

	s, _ := NewScanner(dir)

	// Should be suppressed by .oqs-ignore pattern (even without inline directive)
	if !s.IsSuppressed(filePath, 2, "RSA") {
		t.Error("vendor file should be suppressed by .oqs-ignore pattern")
	}

	stats := s.Stats()
	if stats.SuppressedByIgnore != 1 {
		t.Errorf("expected 1 ignore suppression, got %d", stats.SuppressedByIgnore)
	}
}

// ---------------------------------------------------------------------------
// NEW edge cases below (not duplicated from existing tests)
// ---------------------------------------------------------------------------

// TestScanContent_NoAlgorithmList_SuppressesAll verifies that an oqs:ignore
// directive with no algorithm list (empty brackets omitted) suppresses any
// algorithm on that line — i.e., Algorithms slice is nil/empty.
func TestScanContent_NoAlgorithmList_SuppressesAllAlgorithms(t *testing.T) {
	content := `// oqs:ignore
rsa.GenerateKey(rand.Reader, 2048)
`
	s := &Scanner{suppressMap: make(map[string][]Suppression)}
	sups := s.scanContent("main.go", content)
	if len(sups) != 1 {
		t.Fatalf("expected 1 suppression, got %d", len(sups))
	}
	if len(sups[0].Algorithms) != 0 {
		t.Errorf("no algorithm list should produce empty Algorithms (suppress all), got %v", sups[0].Algorithms)
	}
}

// TestIsSuppressed_NoAlgorithmList_SuppressesAnyAlgorithm verifies that an
// empty Algorithms list in a suppression directive matches any algorithm string.
func TestIsSuppressed_NoAlgorithmList_MatchesAny(t *testing.T) {
	dir := t.TempDir()
	content := `// oqs:ignore
key, _ := rsa.GenerateKey(rand.Reader, 2048)
`
	fp := filepath.Join(dir, "main.go")
	os.WriteFile(fp, []byte(content), 0644)

	s, _ := NewScanner(dir)

	// Any algorithm on line 2 should be suppressed
	for _, alg := range []string{"RSA", "AES", "MD5", "ECDH"} {
		if !s.IsSuppressed(fp, 2, alg) {
			t.Errorf("algorithm %q should be suppressed by no-list directive", alg)
		}
	}
}

// TestScanContent_NarrowAlgorithmList_DoesNotSuppressOthers verifies that a
// directive with a specific algorithm list only suppresses listed algorithms.
func TestScanContent_NarrowAlgorithmList_Narrow(t *testing.T) {
	content := `// oqs:ignore[RSA]
key := genKey()
md5 := doHash()
`
	s := &Scanner{suppressMap: make(map[string][]Suppression)}
	sups := s.scanContent("main.go", content)
	if len(sups) != 1 {
		t.Fatalf("expected 1 suppression, got %d", len(sups))
	}
	if len(sups[0].Algorithms) != 1 || sups[0].Algorithms[0] != "RSA" {
		t.Errorf("expected [RSA], got %v", sups[0].Algorithms)
	}
}

// TestMatchesIgnorePattern_DoubleStarGlob verifies the ** recursive glob
// expansion only matches files actually matching the suffix pattern.
// Regression: earlier behavior used strings.HasPrefix with an empty prefix
// extracted from "**/..." and thus matched every path.
func TestMatchesIgnorePattern_DoubleStarGlob(t *testing.T) {
	dir := t.TempDir()
	ignoreContent := "**/*.test.go\n"
	os.WriteFile(filepath.Join(dir, ".oqs-ignore"), []byte(ignoreContent), 0644)

	s, _ := NewScanner(dir)

	shouldMatch := []string{
		filepath.Join(dir, "pkg/crypto/aes.test.go"),
		filepath.Join(dir, "auth.test.go"),
		filepath.Join(dir, "a/b/c/d/deep.test.go"),
	}
	for _, p := range shouldMatch {
		if !s.MatchesIgnorePattern(p) {
			t.Errorf("MatchesIgnorePattern(%q) = false, want true", p)
		}
	}

	shouldNotMatch := []string{
		filepath.Join(dir, "pkg/crypto/aes.go"),
		filepath.Join(dir, "main.go"),
		filepath.Join(dir, "notes.md"),
	}
	for _, p := range shouldNotMatch {
		if s.MatchesIgnorePattern(p) {
			t.Errorf("MatchesIgnorePattern(%q) = true, want false", p)
		}
	}
}

// TestMatchesIgnorePattern_DoubleStarMiddle verifies ** in the middle of a
// pattern matches zero or more intermediate path segments.
func TestMatchesIgnorePattern_DoubleStarMiddle(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, ".oqs-ignore"), []byte("vendor/**/cache/*.go\n"), 0644)
	s, _ := NewScanner(dir)

	shouldMatch := []string{
		filepath.Join(dir, "vendor/cache/x.go"),
		filepath.Join(dir, "vendor/a/cache/x.go"),
		filepath.Join(dir, "vendor/a/b/c/cache/x.go"),
	}
	for _, p := range shouldMatch {
		if !s.MatchesIgnorePattern(p) {
			t.Errorf("MatchesIgnorePattern(%q) = false, want true", p)
		}
	}
	if s.MatchesIgnorePattern(filepath.Join(dir, "vendor/a/b/other/x.go")) {
		t.Error("non-cache path should not match")
	}
}

// TestScanContent_HashStyleComment_WithAlgorithmList verifies Python/YAML-style
// hash (#) comment suppression with an algorithm list.
func TestScanContent_HashStyleComment_WithAlgorithmList(t *testing.T) {
	content := `# oqs:ignore[AES-128]
cipher = AES128.new(key)
`
	s := &Scanner{suppressMap: make(map[string][]Suppression)}
	sups := s.scanContent("config.py", content)
	if len(sups) != 1 {
		t.Fatalf("expected 1 suppression, got %d", len(sups))
	}
	if len(sups[0].Algorithms) != 1 || sups[0].Algorithms[0] != "AES-128" {
		t.Errorf("expected [AES-128], got %v", sups[0].Algorithms)
	}
}

// TestScanContent_BlockComment_WithAlgorithmAndReason verifies C-style block
// comment /* */ with both an algorithm list and a reason.
func TestScanContent_BlockComment_WithAlgorithmAndReason(t *testing.T) {
	content := `/* oqs:ignore[DES] — legacy HSM constraint */
des_encrypt(data, key);
`
	s := &Scanner{suppressMap: make(map[string][]Suppression)}
	sups := s.scanContent("legacy.c", content)
	if len(sups) != 1 {
		t.Fatalf("expected 1 suppression, got %d", len(sups))
	}
	if len(sups[0].Algorithms) != 1 || sups[0].Algorithms[0] != "DES" {
		t.Errorf("expected [DES], got %v", sups[0].Algorithms)
	}
	if sups[0].Reason == "" {
		t.Error("expected reason to be parsed from block comment")
	}
}

// TestScanContent_XMLComment_WithAlgorithmList verifies HTML/XML comment
// <!-- --> with an algorithm list parses correctly.
func TestScanContent_XMLComment_WithAlgorithmList(t *testing.T) {
	content := `<config>
  <cipher>DES</cipher> <!-- oqs:ignore[DES] -->
</config>
`
	s := &Scanner{suppressMap: make(map[string][]Suppression)}
	sups := s.scanContent("config.xml", content)
	if len(sups) != 1 {
		t.Fatalf("expected 1 XML comment suppression with algorithm list, got %d", len(sups))
	}
	if len(sups[0].Algorithms) != 1 || sups[0].Algorithms[0] != "DES" {
		t.Errorf("expected [DES] from XML comment, got %v", sups[0].Algorithms)
	}
}

// TestScanContent_DirectiveOnLastLineNoNewline verifies a directive on the
// very last line (no trailing newline) is still parsed.
func TestScanContent_DirectiveAtEOF_NoNewline(t *testing.T) {
	content := "cipher := aes128() // oqs:ignore[AES-128]"
	s := &Scanner{suppressMap: make(map[string][]Suppression)}
	sups := s.scanContent("main.go", content)
	if len(sups) != 1 {
		t.Fatalf("expected 1 suppression at EOF without newline, got %d", len(sups))
	}
	if len(sups[0].Algorithms) != 1 || sups[0].Algorithms[0] != "AES-128" {
		t.Errorf("expected [AES-128], got %v", sups[0].Algorithms)
	}
}

// TestIsSuppressed_BothLineAndFileMatch_CountsAsIgnore verifies that when a
// finding matches BOTH the .oqs-ignore pattern AND an inline directive, the
// suppression counter uses SuppressedByIgnore (pattern check runs first).
func TestIsSuppressed_FileAndInlineMatch_IgnoreCountsFirst(t *testing.T) {
	dir := t.TempDir()
	ignoreContent := "testdata/**\n"
	os.WriteFile(filepath.Join(dir, ".oqs-ignore"), []byte(ignoreContent), 0644)

	testDir := filepath.Join(dir, "testdata")
	os.MkdirAll(testDir, 0755)
	fp := filepath.Join(testDir, "sample.go")
	// File also has an inline directive
	os.WriteFile(fp, []byte("// oqs:ignore\nrsa.GenerateKey()\n"), 0644)

	s, _ := NewScanner(dir)
	if !s.IsSuppressed(fp, 2, "RSA") {
		t.Error("should be suppressed (both pattern and inline directive match)")
	}
	stats := s.Stats()
	// Pattern takes precedence — should count as ignore, not inline
	if stats.SuppressedByIgnore != 1 {
		t.Errorf("expected 1 SuppressedByIgnore (pattern runs first), got %d", stats.SuppressedByIgnore)
	}
}
