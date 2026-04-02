package binaryscanner

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"

	"github.com/jimbo111/open-quantum-secure/pkg/engines"
	"github.com/jimbo111/open-quantum-secure/pkg/findings"
)

// TestIntegration_JAREndToEnd creates a minimal JAR with multiple crypto
// algorithms and verifies the full engine pipeline produces correct findings.
func TestIntegration_JAREndToEnd(t *testing.T) {
	dir := t.TempDir()

	// Create a JAR with two crypto classes.
	jarPath := filepath.Join(dir, "crypto-app.jar")
	jarData := buildMultiClassJar(t, map[string]string{
		"com/example/EncryptService.class": "AES/GCM/NoPadding",
		"com/example/SignService.class":    "SHA256withRSA",
	})
	if err := os.WriteFile(jarPath, jarData, 0644); err != nil {
		t.Fatalf("write jar: %v", err)
	}

	e := New()
	opts := engines.ScanOptions{
		TargetPath:  dir,
		BinaryPaths: []string{jarPath},
	}

	fds, err := e.Scan(context.Background(), opts)
	if err != nil {
		t.Fatalf("Scan error: %v", err)
	}

	// Verify findings structure.
	if len(fds) == 0 {
		t.Fatal("expected at least one finding")
	}
	for _, f := range fds {
		if f.SourceEngine != "binary-scanner" {
			t.Errorf("SourceEngine = %q, want %q", f.SourceEngine, "binary-scanner")
		}
		if f.Location.File != jarPath {
			t.Errorf("Location.File = %q, want %q", f.Location.File, jarPath)
		}
		if f.Location.ArtifactType == "" {
			t.Error("Location.ArtifactType should be set for binary findings")
		}
	}

	// Check that at least one AES finding exists.
	foundAES := false
	for _, f := range fds {
		if f.Algorithm != nil && f.Algorithm.Name == "AES" {
			foundAES = true
			break
		}
	}
	if !foundAES {
		t.Error("expected AES finding from JAR with AES/GCM/NoPadding")
	}
}

// TestIntegration_AutoDiscoveryMixedArtifacts creates a directory with both
// binary and non-binary files, verifying that walkAndScan only picks up JAR files.
func TestIntegration_AutoDiscoveryMixedArtifacts(t *testing.T) {
	dir := t.TempDir()

	// Binary artifact — should be scanned.
	jarData := buildMinimalJar("RSA/ECB/PKCS1Padding")
	if err := os.WriteFile(filepath.Join(dir, "app.jar"), jarData, 0644); err != nil {
		t.Fatalf("write jar: %v", err)
	}

	// Non-binary files — should be ignored.
	if err := os.WriteFile(filepath.Join(dir, "README.md"), []byte("# README"), 0644); err != nil {
		t.Fatalf("write readme: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "main.go"), []byte("package main\nfunc main() {}"), 0644); err != nil {
		t.Fatalf("write go file: %v", err)
	}

	e := New()
	fds, err := e.Scan(context.Background(), engines.ScanOptions{TargetPath: dir})
	if err != nil {
		t.Fatalf("Scan error: %v", err)
	}

	if len(fds) == 0 {
		t.Fatal("expected findings from auto-discovered JAR")
	}
	for _, f := range fds {
		if f.SourceEngine != "binary-scanner" {
			t.Errorf("unexpected engine: %s", f.SourceEngine)
		}
	}
}

// TestIntegration_CrossTierDedup verifies that when the same algorithm is detected
// by both Tier 1 (source) and Tier 4 (binary), the dedup key differentiates them
// properly when the binary finding has an InnerPath.
func TestIntegration_CrossTierDedup(t *testing.T) {
	// Tier 1 source finding (no InnerPath).
	source := findings.UnifiedFinding{
		Location:     findings.Location{File: "/src/main.go", Line: 42},
		Algorithm:    &findings.Algorithm{Name: "AES"},
		SourceEngine: "cipherscope",
	}

	// Tier 4 binary finding (with InnerPath).
	binary := findings.UnifiedFinding{
		Location:     findings.Location{File: "app.jar", InnerPath: "com/example/Crypto.class"},
		Algorithm:    &findings.Algorithm{Name: "AES"},
		SourceEngine: "binary-scanner",
	}

	// Different files + InnerPath → different dedup keys.
	if source.DedupeKey() == binary.DedupeKey() {
		t.Errorf("source and binary findings should have different dedup keys:\n  source: %q\n  binary: %q",
			source.DedupeKey(), binary.DedupeKey())
	}
}

// TestIntegration_FindingFieldsComplete verifies that all required fields are
// set on findings produced by the binary scanner.
func TestIntegration_FindingFieldsComplete(t *testing.T) {
	jarData := buildMinimalJar("PBKDF2WithHmacSHA256")
	path := writeTempFile(t, jarData, ".jar")

	e := New()
	fds, err := e.Scan(context.Background(), engines.ScanOptions{BinaryPaths: []string{path}})
	if err != nil {
		t.Fatalf("Scan error: %v", err)
	}

	for _, f := range fds {
		// Verify required fields.
		if f.SourceEngine == "" {
			t.Error("SourceEngine should not be empty")
		}
		if f.Location.File == "" {
			t.Error("Location.File should not be empty")
		}
		if f.Confidence == "" {
			t.Error("Confidence should not be empty")
		}
		if f.Reachable == "" {
			t.Error("Reachable should not be empty")
		}
		// At least one of Algorithm or Dependency should be set.
		if f.Algorithm == nil && f.Dependency == nil {
			t.Error("expected either Algorithm or Dependency to be set")
		}
	}
}

// buildMultiClassJar creates a JAR with multiple class files, each containing
// the specified UTF-8 constant string.
func buildMultiClassJar(t *testing.T, entries map[string]string) []byte {
	t.Helper()
	var buf bytes.Buffer
	w := zip.NewWriter(&buf)
	for path, constant := range entries {
		f, err := w.Create(path)
		if err != nil {
			t.Fatalf("create zip entry: %v", err)
		}
		classData := buildIntegrationClassBytes(constant)
		if _, err := f.Write(classData); err != nil {
			t.Fatalf("write class data: %v", err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatalf("close zip: %v", err)
	}
	return buf.Bytes()
}

// buildIntegrationClassBytes builds a minimal valid Java class file with one Utf8 constant.
func buildIntegrationClassBytes(utf8Constant string) []byte {
	var buf bytes.Buffer
	writeU32 := func(v uint32) { _ = binary.Write(&buf, binary.BigEndian, v) }
	writeU16 := func(v uint16) { _ = binary.Write(&buf, binary.BigEndian, v) }
	writeU8 := func(v uint8) { buf.WriteByte(v) }

	writeU32(0xCAFEBABE) // magic
	writeU16(0)           // minor
	writeU16(61)          // major (Java 17)

	// cpCount=2: slot1=Utf8(utf8Constant)
	writeU16(2)
	writeU8(1) // tagUtf8
	writeU16(uint16(len(utf8Constant)))
	buf.WriteString(utf8Constant)
	return buf.Bytes()
}
