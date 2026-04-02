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
