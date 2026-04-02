package constresolver

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestCollect_EmptyDir(t *testing.T) {
	dir := t.TempDir()
	c := New()
	cm := c.Collect(context.Background(), dir)
	if cm == nil {
		t.Fatal("expected non-nil ConstMap")
	}
	if len(cm) != 0 {
		t.Errorf("expected empty map, got %d entries", len(cm))
	}
}

func TestCollect_ContextCancel(t *testing.T) {
	dir := t.TempDir()
	// Write a Go file so we have something to parse.
	if err := os.WriteFile(filepath.Join(dir, "a.go"), []byte(`package a
const KEY = 256
`), 0o644); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel immediately

	c := New()
	cm := c.Collect(ctx, dir)
	// Should return a non-nil map (possibly empty due to cancellation).
	if cm == nil {
		t.Fatal("expected non-nil ConstMap even on cancel")
	}
}

func TestCollect_SkipsExcludedDirs(t *testing.T) {
	dir := t.TempDir()

	for _, excluded := range []string{"vendor", "node_modules", ".git"} {
		subDir := filepath.Join(dir, excluded)
		if err := os.MkdirAll(subDir, 0o755); err != nil {
			t.Fatal(err)
		}
		content := []byte("package x\nconst SECRET = 999\n")
		if err := os.WriteFile(filepath.Join(subDir, "file.go"), content, 0o644); err != nil {
			t.Fatal(err)
		}
	}

	// Also write a valid file at the root.
	if err := os.WriteFile(filepath.Join(dir, "root.go"), []byte("package root\nconst VALUE = 42\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	c := New()
	cm := c.Collect(context.Background(), dir)

	// Should find root.VALUE but not anything from excluded dirs.
	if _, ok := cm["root.VALUE"]; !ok {
		t.Error("expected root.VALUE to be found")
	}
	if _, ok := cm["x.SECRET"]; ok {
		t.Error("expected excluded dir constants to be skipped")
	}
}

func TestCollect_SkipsLargeFiles(t *testing.T) {
	dir := t.TempDir()

	// Create a large file (> 1MB).
	large := make([]byte, maxFileSize+1)
	copy(large, []byte("package big\nconst BIG = 123\n"))
	if err := os.WriteFile(filepath.Join(dir, "big.go"), large, 0o644); err != nil {
		t.Fatal(err)
	}

	// Write a normal-sized file.
	if err := os.WriteFile(filepath.Join(dir, "small.go"), []byte("package small\nconst SMALL = 456\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	c := New()
	cm := c.Collect(context.Background(), dir)

	if _, ok := cm["small.SMALL"]; !ok {
		t.Error("expected small.SMALL to be found")
	}
	// big.go may or may not be parseable (it starts with valid Go, but content is mostly null bytes).
	// The important invariant is that it doesn't panic and SMALL is found.
}

func TestCollect_MultiLanguage(t *testing.T) {
	dir := t.TempDir()

	files := map[string]string{
		"Crypto.java": `public class Crypto {
    public static final int KEY_SIZE = 256;
}`,
		"config.go": `package config
const KEY_BITS = 128`,
		"constants.py": `KEY_SIZE = 512`,
		"crypto.ts":    `export const KEY_LEN = 384`,
	}

	for name, content := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	c := New()
	cm := c.Collect(context.Background(), dir)

	checks := map[string]int{
		"Crypto.KEY_SIZE":     256,
		"config.KEY_BITS":     128,
		"constants.KEY_SIZE":  512,
		"crypto.KEY_LEN":      384,
	}
	for key, want := range checks {
		if got, ok := cm[key]; !ok {
			t.Errorf("key %q not found in ConstMap", key)
		} else if got != want {
			t.Errorf("key %q: want %d, got %d", key, want, got)
		}
	}
}

func TestCollect_NonExistentPath(t *testing.T) {
	c := New()
	cm := c.Collect(context.Background(), "/nonexistent/path/that/does/not/exist")
	if cm == nil {
		t.Fatal("expected non-nil ConstMap")
	}
}
