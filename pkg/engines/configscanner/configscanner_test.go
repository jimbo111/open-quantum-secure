package configscanner

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/jimbo111/open-quantum-secure/pkg/engines"
	"github.com/jimbo111/open-quantum-secure/pkg/findings"
)

func TestEngineMetadata(t *testing.T) {
	e := New()
	if e.Name() != "config-scanner" {
		t.Errorf("Name() = %q, want %q", e.Name(), "config-scanner")
	}
	if e.Tier() != engines.Tier1Pattern {
		t.Errorf("Tier() = %v, want Tier1Pattern", e.Tier())
	}
	if !e.Available() {
		t.Error("Available() = false, want true")
	}
	langs := e.SupportedLanguages()
	if len(langs) == 0 {
		t.Error("SupportedLanguages() returned empty slice")
	}
}

// writeFile creates a file inside dir with the given content.
func writeFile(t *testing.T, dir, name, content string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatalf("writeFile %s: %v", name, err)
	}
	return path
}

func TestScanYAMLConfig(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "application.yml", `
spring:
  security:
    algorithm: AES
    keySize: 256
`)
	e := New()
	fds, err := e.Scan(context.Background(), engines.ScanOptions{TargetPath: dir})
	if err != nil {
		t.Fatalf("Scan error: %v", err)
	}
	if len(fds) == 0 {
		t.Fatal("expected findings, got none")
	}
	assertContainsAlgorithm(t, fds, "AES")
}

func TestScanJSONConfig(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "appsettings.json", `{
  "security": {
    "algorithm": "RSA",
    "hash": "SHA-256"
  }
}`)
	e := New()
	fds, err := e.Scan(context.Background(), engines.ScanOptions{TargetPath: dir})
	if err != nil {
		t.Fatalf("Scan error: %v", err)
	}
	assertContainsAlgorithm(t, fds, "RSA")
	assertContainsAlgorithm(t, fds, "SHA-256")
}

func TestScanPropertiesConfig(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "application.properties", "algorithm=DES\ncipher=AES-256-GCM\n")
	e := New()
	fds, err := e.Scan(context.Background(), engines.ScanOptions{TargetPath: dir})
	if err != nil {
		t.Fatalf("Scan error: %v", err)
	}
	assertContainsAlgorithm(t, fds, "DES")
	assertContainsAlgorithm(t, fds, "AES")
}

func TestScanEnvFile(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, ".env", "CIPHER=\"AES-256-GCM\"\nHASH=SHA-256\n")
	e := New()
	fds, err := e.Scan(context.Background(), engines.ScanOptions{TargetPath: dir})
	if err != nil {
		t.Fatalf("Scan error: %v", err)
	}
	assertContainsAlgorithm(t, fds, "AES")
	assertContainsAlgorithm(t, fds, "SHA-256")
}

func TestScanSkipsVendorAndNodeModules(t *testing.T) {
	dir := t.TempDir()

	// Write findings-worthy config in ignored directories.
	vendorDir := filepath.Join(dir, "vendor")
	nmDir := filepath.Join(dir, "node_modules")
	gitDir := filepath.Join(dir, ".git")
	for _, d := range []string{vendorDir, nmDir, gitDir} {
		if err := os.MkdirAll(d, 0755); err != nil {
			t.Fatal(err)
		}
		writeFile(t, d, "application.yml", "algorithm: DES\n")
	}
	// Also write a real file in the root.
	writeFile(t, dir, "application.yml", "algorithm: AES\n")

	e := New()
	fds, err := e.Scan(context.Background(), engines.ScanOptions{TargetPath: dir})
	if err != nil {
		t.Fatalf("Scan error: %v", err)
	}
	for _, f := range fds {
		for _, skip := range []string{"vendor", "node_modules", ".git"} {
			if containsPathSegment(f.Location.File, skip) {
				t.Errorf("finding from skipped dir %q: %s", skip, f.Location.File)
			}
		}
	}
	assertContainsAlgorithm(t, fds, "AES")
}

func TestScanContextCancellation(t *testing.T) {
	dir := t.TempDir()
	for i := 0; i < 20; i++ {
		writeFile(t, dir, filepath.Join("application.yml"), "algorithm: AES\n")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Nanosecond)
	defer cancel()
	time.Sleep(1 * time.Millisecond) // ensure context is cancelled

	e := New()
	_, err := e.Scan(ctx, engines.ScanOptions{TargetPath: dir})
	// We expect either context.Canceled or context.DeadlineExceeded.
	if err != nil && err != context.Canceled && err != context.DeadlineExceeded {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestScanEmptyDirectory(t *testing.T) {
	dir := t.TempDir()
	e := New()
	fds, err := e.Scan(context.Background(), engines.ScanOptions{TargetPath: dir})
	if err != nil {
		t.Fatalf("Scan error: %v", err)
	}
	if len(fds) != 0 {
		t.Errorf("expected no findings, got %d", len(fds))
	}
}

func TestScanNonConfigFilesIgnored(t *testing.T) {
	dir := t.TempDir()
	// These files should not be scanned.
	writeFile(t, dir, "main.go", "// algorithm = AES\n")
	writeFile(t, dir, "README.md", "algorithm: AES\n")
	writeFile(t, dir, "Makefile", "CIPHER=AES-256-GCM\n")

	e := New()
	fds, err := e.Scan(context.Background(), engines.ScanOptions{TargetPath: dir})
	if err != nil {
		t.Fatalf("Scan error: %v", err)
	}
	if len(fds) != 0 {
		t.Errorf("expected 0 findings for non-config files, got %d: %+v", len(fds), fds)
	}
}

func TestScanFindingFields(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "config.yml", "algorithm: RSA\n")

	e := New()
	fds, err := e.Scan(context.Background(), engines.ScanOptions{TargetPath: dir})
	if err != nil {
		t.Fatalf("Scan error: %v", err)
	}
	if len(fds) == 0 {
		t.Fatal("expected findings, got none")
	}
	f := fds[0]
	if f.SourceEngine != "config-scanner" {
		t.Errorf("SourceEngine = %q, want %q", f.SourceEngine, "config-scanner")
	}
	if f.Confidence != findings.ConfidenceMedium {
		t.Errorf("Confidence = %q, want medium", f.Confidence)
	}
	if f.Reachable != findings.ReachableUnknown {
		t.Errorf("Reachable = %q, want unknown", f.Reachable)
	}
	if f.Algorithm == nil {
		t.Fatal("Algorithm is nil")
	}
	if f.Location.File == "" {
		t.Error("Location.File is empty")
	}
	if f.Location.Line == 0 {
		t.Error("Location.Line is 0")
	}
}

func TestScanCryptoDirectory(t *testing.T) {
	// Files in a directory named "config" should be scanned.
	dir := t.TempDir()
	configDir := filepath.Join(dir, "config")
	if err := os.MkdirAll(configDir, 0755); err != nil {
		t.Fatal(err)
	}
	writeFile(t, configDir, "app.yml", "cipher: AES-128-GCM\n")

	e := New()
	fds, err := e.Scan(context.Background(), engines.ScanOptions{TargetPath: dir})
	if err != nil {
		t.Fatalf("Scan error: %v", err)
	}
	assertContainsAlgorithm(t, fds, "AES")
}

func TestScanOversizedFileSkipped(t *testing.T) {
	dir := t.TempDir()
	// Create a file with a size that exceeds maxConfigFileSize by using a
	// sparse file trick — we write only the last byte to set a large size.
	path := filepath.Join(dir, "application.yml")
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	// Seek past the 10 MB limit and write one byte.
	if _, err := f.WriteAt([]byte("x"), maxConfigFileSize+1); err != nil {
		f.Close()
		t.Fatal(err)
	}
	f.Close()

	e := New()
	fds, scanErr := e.Scan(context.Background(), engines.ScanOptions{TargetPath: dir})
	if scanErr != nil {
		t.Fatalf("Scan error: %v", scanErr)
	}
	// The oversized file should produce no findings.
	if len(fds) != 0 {
		t.Errorf("expected 0 findings for oversized file, got %d", len(fds))
	}
}

// --- helpers ---

func assertContainsAlgorithm(t *testing.T, fds []findings.UnifiedFinding, alg string) {
	t.Helper()
	for _, f := range fds {
		if f.Algorithm != nil && f.Algorithm.Name == alg {
			return
		}
	}
	t.Errorf("no finding with Algorithm.Name=%q in %d findings", alg, len(fds))
}

func containsPathSegment(path, segment string) bool {
	for _, part := range filepath.SplitList(path) {
		if part == segment {
			return true
		}
	}
	// Simpler check for forward-slash paths.
	for _, part := range splitPath(path) {
		if part == segment {
			return true
		}
	}
	return false
}

func splitPath(path string) []string {
	var parts []string
	for {
		dir, base := filepath.Split(filepath.Clean(path))
		if base == "" || base == "." {
			break
		}
		parts = append(parts, base)
		path = dir
	}
	return parts
}
