package configscanner

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/jimbo111/open-quantum-secure/pkg/engines"
)

// TestIntegration_SpringBootConfig tests scanning a Spring Boot application.yml
// with typical crypto parameters.
func TestIntegration_SpringBootConfig(t *testing.T) {
	dir := t.TempDir()

	content := `server:
  ssl:
    key-store-type: PKCS12
    enabled-protocols: TLSv1.2,TLSv1.3

spring:
  security:
    encryption:
      algorithm: AES
      key-size: 256
`
	if err := os.WriteFile(filepath.Join(dir, "application.yml"), []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	e := New()
	opts := engines.ScanOptions{
		TargetPath: dir,
		Mode:       engines.ModeFull,
	}

	findings, err := e.Scan(context.Background(), opts)
	if err != nil {
		t.Fatalf("Scan error: %v", err)
	}

	if len(findings) == 0 {
		t.Fatal("expected findings from Spring Boot config, got none")
	}

	// Should detect AES with key size 256
	found := false
	for _, f := range findings {
		if f.Algorithm != nil && f.Algorithm.Name == "AES" && f.Algorithm.KeySize == 256 {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected to find AES-256 in Spring Boot config")
	}
}

// TestIntegration_EnvFileConfig tests scanning a .env file with crypto settings.
func TestIntegration_EnvFileConfig(t *testing.T) {
	dir := t.TempDir()

	content := `# Crypto settings
ENCRYPTION_ALGORITHM=AES
ENCRYPTION_KEY_SIZE=128
HASH_ALGORITHM=SHA256
`
	if err := os.WriteFile(filepath.Join(dir, ".env"), []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	e := New()
	opts := engines.ScanOptions{
		TargetPath: dir,
		Mode:       engines.ModeFull,
	}

	findings, err := e.Scan(context.Background(), opts)
	if err != nil {
		t.Fatalf("Scan error: %v", err)
	}

	if len(findings) == 0 {
		t.Fatal("expected findings from .env file, got none")
	}

	// Check all findings have correct source engine
	for _, f := range findings {
		if f.SourceEngine != "config-scanner" {
			t.Errorf("finding has SourceEngine=%q, want config-scanner", f.SourceEngine)
		}
	}
}

// TestIntegration_PropertiesFile tests scanning a Java .properties file.
func TestIntegration_PropertiesFile(t *testing.T) {
	dir := t.TempDir()

	content := `# Application crypto config
encryption.algorithm=DES
encryption.key.size=56
ssl.protocol=TLSv1.0
`
	if err := os.WriteFile(filepath.Join(dir, "crypto.properties"), []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	e := New()
	opts := engines.ScanOptions{
		TargetPath: dir,
		Mode:       engines.ModeFull,
	}

	findings, err := e.Scan(context.Background(), opts)
	if err != nil {
		t.Fatalf("Scan error: %v", err)
	}

	if len(findings) == 0 {
		t.Fatal("expected findings from .properties file, got none")
	}
}

// TestIntegration_JSONConfig tests scanning a JSON config file.
func TestIntegration_JSONConfig(t *testing.T) {
	dir := t.TempDir()

	content := `{
  "crypto": {
    "algorithm": "RSA",
    "keySize": 2048
  },
  "tls": {
    "cipherSuites": ["TLS_AES_256_GCM_SHA384"]
  }
}
`
	if err := os.WriteFile(filepath.Join(dir, "crypto-config.json"), []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	e := New()
	opts := engines.ScanOptions{
		TargetPath: dir,
		Mode:       engines.ModeFull,
	}

	findings, err := e.Scan(context.Background(), opts)
	if err != nil {
		t.Fatalf("Scan error: %v", err)
	}

	if len(findings) == 0 {
		t.Fatal("expected findings from JSON config, got none")
	}
}

// TestIntegration_EngineInterface verifies the engine satisfies the Engine interface contract.
func TestIntegration_EngineInterface(t *testing.T) {
	e := New()

	if e.Name() != "config-scanner" {
		t.Errorf("Name() = %q, want config-scanner", e.Name())
	}
	if e.Tier() != engines.Tier1Pattern {
		t.Errorf("Tier() = %v, want Tier1Pattern", e.Tier())
	}
	if !e.Available() {
		t.Error("Available() should be true for embedded engine")
	}
	if len(e.SupportedLanguages()) == 0 {
		t.Error("SupportedLanguages() should not be empty")
	}
}

// TestIntegration_SkipsVendor verifies that vendor directories are skipped.
func TestIntegration_SkipsVendor(t *testing.T) {
	dir := t.TempDir()

	// Create a config inside vendor/ — should be skipped
	vendorDir := filepath.Join(dir, "vendor", "lib")
	if err := os.MkdirAll(vendorDir, 0755); err != nil {
		t.Fatal(err)
	}
	content := `encryption.algorithm=AES
encryption.key.size=256
`
	if err := os.WriteFile(filepath.Join(vendorDir, "config.properties"), []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	e := New()
	opts := engines.ScanOptions{
		TargetPath: dir,
		Mode:       engines.ModeFull,
	}

	findings, err := e.Scan(context.Background(), opts)
	if err != nil {
		t.Fatalf("Scan error: %v", err)
	}

	if len(findings) != 0 {
		t.Errorf("expected 0 findings from vendor dir, got %d", len(findings))
	}
}
