package suppress

import (
	"os"
	"path/filepath"
	"sync"
	"testing"
)

func TestScanContent_GoStyleIgnore(t *testing.T) {
	content := `package main
import "crypto/rsa"
// oqs:ignore
key, _ := rsa.GenerateKey(rand.Reader, 2048)
`
	s := &Scanner{suppressMap: make(map[string][]Suppression)}
	sups := s.scanContent("main.go", content)
	if len(sups) != 1 {
		t.Fatalf("expected 1 suppression, got %d", len(sups))
	}
	if sups[0].Line != 3 {
		t.Errorf("expected line 3, got %d", sups[0].Line)
	}
	if len(sups[0].Algorithms) != 0 {
		t.Errorf("expected empty algorithm list, got %v", sups[0].Algorithms)
	}
}

func TestScanContent_PythonStyleIgnore(t *testing.T) {
	content := `import hashlib
# oqs:ignore
md5 = hashlib.md5(data)
`
	s := &Scanner{suppressMap: make(map[string][]Suppression)}
	sups := s.scanContent("hash.py", content)
	if len(sups) != 1 {
		t.Fatalf("expected 1 suppression, got %d", len(sups))
	}
	if sups[0].Line != 2 {
		t.Errorf("expected line 2, got %d", sups[0].Line)
	}
}

func TestScanContent_BlockCommentIgnore(t *testing.T) {
	content := `Cipher c = Cipher.getInstance("DES");  /* oqs:ignore */
`
	s := &Scanner{suppressMap: make(map[string][]Suppression)}
	sups := s.scanContent("Crypto.java", content)
	if len(sups) != 1 {
		t.Fatalf("expected 1 suppression, got %d", len(sups))
	}
}

func TestScanContent_AlgorithmSpecific(t *testing.T) {
	content := `// oqs:ignore[RSA]
key, _ := rsa.GenerateKey(rand.Reader, 2048)
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

func TestScanContent_MultiAlgorithm(t *testing.T) {
	content := `// oqs:ignore[RSA,DES,MD5]
`
	s := &Scanner{suppressMap: make(map[string][]Suppression)}
	sups := s.scanContent("main.go", content)
	if len(sups) != 1 {
		t.Fatalf("expected 1 suppression, got %d", len(sups))
	}
	if len(sups[0].Algorithms) != 3 {
		t.Errorf("expected 3 algorithms, got %d", len(sups[0].Algorithms))
	}
}

func TestScanContent_WithReason(t *testing.T) {
	content := `// oqs:ignore — this is intentional for backward compatibility
`
	s := &Scanner{suppressMap: make(map[string][]Suppression)}
	sups := s.scanContent("main.go", content)
	if len(sups) != 1 {
		t.Fatalf("expected 1 suppression, got %d", len(sups))
	}
	if sups[0].Reason == "" {
		t.Error("expected reason to be parsed")
	}
}

func TestScanContent_EmptyFile(t *testing.T) {
	s := &Scanner{suppressMap: make(map[string][]Suppression)}
	sups := s.scanContent("empty.go", "")
	if len(sups) != 0 {
		t.Errorf("expected 0 suppressions for empty file, got %d", len(sups))
	}
}

func TestScanContent_NoDirectives(t *testing.T) {
	content := `package main
// This is a normal comment about oqs
func main() {}
`
	s := &Scanner{suppressMap: make(map[string][]Suppression)}
	sups := s.scanContent("main.go", content)
	if len(sups) != 0 {
		t.Errorf("expected 0 suppressions, got %d", len(sups))
	}
}

func TestScanContent_MalformedDirective(t *testing.T) {
	content := `// oqs:ignor  (typo — should not match)
// oqsignore   (no colon — should not match)
`
	s := &Scanner{suppressMap: make(map[string][]Suppression)}
	sups := s.scanContent("main.go", content)
	if len(sups) != 0 {
		t.Errorf("malformed directives should not match, got %d", len(sups))
	}
}

func TestIsSuppressed_SameLine(t *testing.T) {
	dir := t.TempDir()
	// Create a file with inline suppression on line 3
	content := `package main
import "crypto/rsa"
key, _ := rsa.GenerateKey(rand.Reader, 2048) // oqs:ignore
`
	filePath := filepath.Join(dir, "main.go")
	os.WriteFile(filePath, []byte(content), 0644)

	s, err := NewScanner(dir)
	if err != nil {
		t.Fatal(err)
	}

	// Line 3 has the directive AND the finding → suppressed
	if !s.IsSuppressed(filePath, 3, "RSA") {
		t.Error("same-line suppression should match")
	}
}

func TestIsSuppressed_NextLine(t *testing.T) {
	dir := t.TempDir()
	content := `package main
// oqs:ignore
key, _ := rsa.GenerateKey(rand.Reader, 2048)
`
	filePath := filepath.Join(dir, "main.go")
	os.WriteFile(filePath, []byte(content), 0644)

	s, err := NewScanner(dir)
	if err != nil {
		t.Fatal(err)
	}

	// Directive on line 2, finding on line 3 → suppressed
	if !s.IsSuppressed(filePath, 3, "RSA") {
		t.Error("next-line suppression should match")
	}

	// Finding on line 4 → NOT suppressed
	if s.IsSuppressed(filePath, 4, "RSA") {
		t.Error("line 4 should not be suppressed")
	}
}

func TestIsSuppressed_AlgorithmMatch(t *testing.T) {
	dir := t.TempDir()
	content := `// oqs:ignore[RSA]
key, _ := rsa.GenerateKey(rand.Reader, 2048)
md5 := hashlib.md5(data)
`
	filePath := filepath.Join(dir, "main.go")
	os.WriteFile(filePath, []byte(content), 0644)

	s, err := NewScanner(dir)
	if err != nil {
		t.Fatal(err)
	}

	// RSA on next line → suppressed
	if !s.IsSuppressed(filePath, 2, "RSA") {
		t.Error("RSA should be suppressed")
	}

	// MD5 on next line → NOT suppressed (not in algorithm list)
	if s.IsSuppressed(filePath, 2, "MD5") {
		t.Error("MD5 should not be suppressed by RSA-only directive")
	}
}

func TestIsSuppressed_CaseInsensitive(t *testing.T) {
	dir := t.TempDir()
	content := `// oqs:ignore[rsa]
`
	filePath := filepath.Join(dir, "main.go")
	os.WriteFile(filePath, []byte(content), 0644)

	s, err := NewScanner(dir)
	if err != nil {
		t.Fatal(err)
	}

	if !s.IsSuppressed(filePath, 2, "RSA") {
		t.Error("case-insensitive algorithm match should work")
	}
}

func TestMatchesIgnorePattern(t *testing.T) {
	dir := t.TempDir()
	ignoreContent := `vendor/**
node_modules/**
*_test.go
*.test.js
testdata/**
legacy/old_crypto.py
`
	os.WriteFile(filepath.Join(dir, ".oqs-ignore"), []byte(ignoreContent), 0644)

	s, err := NewScanner(dir)
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		path     string
		expected bool
	}{
		{filepath.Join(dir, "vendor/crypto/aes.go"), true},
		{filepath.Join(dir, "node_modules/crypto-js/aes.js"), true},
		{filepath.Join(dir, "src/auth_test.go"), true},
		{filepath.Join(dir, "src/crypto.test.js"), true},
		{filepath.Join(dir, "testdata/samples.go"), true},
		{filepath.Join(dir, "legacy/old_crypto.py"), true},
		// Should NOT match
		{filepath.Join(dir, "src/auth.go"), false},
		{filepath.Join(dir, "pkg/crypto/aes.go"), false},
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			if got := s.MatchesIgnorePattern(tt.path); got != tt.expected {
				t.Errorf("MatchesIgnorePattern(%q) = %v, want %v", tt.path, got, tt.expected)
			}
		})
	}
}

func TestMatchesIgnorePattern_EmptyPatterns(t *testing.T) {
	s := &Scanner{ignorePatterns: nil, suppressMap: make(map[string][]Suppression)}
	if s.MatchesIgnorePattern("/some/path.go") {
		t.Error("empty patterns should never match")
	}
}

func TestStats(t *testing.T) {
	dir := t.TempDir()
	content := `// oqs:ignore
key, _ := rsa.GenerateKey(rand.Reader, 2048)
`
	filePath := filepath.Join(dir, "main.go")
	os.WriteFile(filePath, []byte(content), 0644)

	ignoreContent := `vendor/**
`
	os.WriteFile(filepath.Join(dir, ".oqs-ignore"), []byte(ignoreContent), 0644)

	s, err := NewScanner(dir)
	if err != nil {
		t.Fatal(err)
	}

	// Trigger inline suppression
	s.IsSuppressed(filePath, 2, "RSA")

	// Trigger ignore pattern suppression
	s.IsSuppressed(filepath.Join(dir, "vendor/crypto.go"), 1, "AES")

	stats := s.Stats()
	if stats.SuppressedByInline != 1 {
		t.Errorf("expected 1 inline suppression, got %d", stats.SuppressedByInline)
	}
	if stats.SuppressedByIgnore != 1 {
		t.Errorf("expected 1 ignore suppression, got %d", stats.SuppressedByIgnore)
	}
}

func TestIsSuppressed_MissingFile(t *testing.T) {
	s := &Scanner{suppressMap: make(map[string][]Suppression)}
	// Should not crash on missing file
	if s.IsSuppressed("/nonexistent/file.go", 1, "RSA") {
		t.Error("missing file should not be suppressed")
	}
}

func TestIsSuppressed_ConcurrentAccess(t *testing.T) {
	dir := t.TempDir()
	content := `// oqs:ignore
key, _ := rsa.GenerateKey(rand.Reader, 2048)
`
	filePath := filepath.Join(dir, "main.go")
	os.WriteFile(filePath, []byte(content), 0644)

	s, err := NewScanner(dir)
	if err != nil {
		t.Fatal(err)
	}

	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			s.IsSuppressed(filePath, 2, "RSA")
		}()
	}
	wg.Wait()
}

func TestParseIgnoreFile(t *testing.T) {
	content := `# Comment line
vendor/**
node_modules/**

# Another comment
*.min.js

`
	patterns := parseIgnoreFile(content)
	if len(patterns) != 3 {
		t.Errorf("expected 3 patterns, got %d: %v", len(patterns), patterns)
	}
}

func TestNewScanner_NoIgnoreFile(t *testing.T) {
	dir := t.TempDir()
	s, err := NewScanner(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(s.ignorePatterns) != 0 {
		t.Error("expected no patterns when .oqs-ignore doesn't exist")
	}
}

func TestScanContent_XMLComment(t *testing.T) {
	content := `<config>
  <cipher>DES</cipher> <!-- oqs:ignore -->
</config>
`
	s := &Scanner{suppressMap: make(map[string][]Suppression)}
	sups := s.scanContent("config.xml", content)
	if len(sups) != 1 {
		t.Fatalf("expected 1 suppression from XML comment, got %d", len(sups))
	}
}

func TestScanContent_MultipleDirectives(t *testing.T) {
	content := `// oqs:ignore[RSA]
key := genRSA()
// oqs:ignore[MD5]
hash := md5sum()
`
	s := &Scanner{suppressMap: make(map[string][]Suppression)}
	sups := s.scanContent("main.go", content)
	if len(sups) != 2 {
		t.Fatalf("expected 2 suppressions, got %d", len(sups))
	}
}

func TestScanContent_SuppressionAtEOF(t *testing.T) {
	content := `package main
// oqs:ignore`
	s := &Scanner{suppressMap: make(map[string][]Suppression)}
	sups := s.scanContent("main.go", content)
	if len(sups) != 1 {
		t.Fatalf("expected 1 suppression at EOF, got %d", len(sups))
	}
}
