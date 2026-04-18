package suricatalog

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/jimbo111/open-quantum-secure/pkg/engines"
)

func TestRejectSymlink(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink creation requires elevated privileges on Windows")
	}
	dir := t.TempDir()
	target := filepath.Join(dir, "target.json")
	if err := os.WriteFile(target, []byte(`{"event_type":"tls","dest_ip":"1.2.3.4","dest_port":443,"tls":{"version":"TLSv1.3","cipher_suite":"TLS_AES_128_GCM_SHA256"}}`+"\n"), 0600); err != nil {
		t.Fatalf("write target: %v", err)
	}
	link := filepath.Join(dir, "eve.json")
	if err := os.Symlink(target, link); err != nil {
		t.Fatalf("symlink: %v", err)
	}
	_, err := openLogFile(link)
	if err == nil {
		t.Fatal("openLogFile should reject symlinks")
	}
}

func TestRejectNonRegularFile(t *testing.T) {
	// Use the temp directory itself (a directory, not a regular file).
	dir := t.TempDir()
	_, err := openLogFile(dir)
	if err == nil {
		t.Fatal("openLogFile should reject directories")
	}
}

func TestRejectNullBytePath(t *testing.T) {
	e := New()
	_, err := e.Scan(context.Background(), engines.ScanOptions{
		SuricataEvePath: "/tmp/eve\x00json",
	})
	// The OS itself will reject this path; we just need no panic and an error.
	if err == nil {
		t.Fatal("expected error for null-byte path")
	}
}

func TestSanitizeFieldControlChars(t *testing.T) {
	cases := []struct {
		input string
		want  string
	}{
		{"normal", "normal"},
		{"with\x00null", "withnull"},
		{"with\x1bESC", "withESC"},
		{"with\x7fDEL", "withDEL"}, // DEL control char stripped; literal letters remain
		{"clean ASCII!", "clean ASCII!"},
	}
	for _, c := range cases {
		got := sanitizeField(c.input)
		if got != c.want {
			t.Errorf("sanitizeField(%q) = %q, want %q", c.input, got, c.want)
		}
	}
}

func TestSanitizeTargetPathChars(t *testing.T) {
	cases := []struct {
		input string
		want  string
	}{
		{"example.com", "example.com"},
		{"bad/path", "badpath"},
		{"has#fragment", "hasfragment"},
		{"has?query", "hasquery"},
		{"with\x1bESC", "withESC"},
	}
	for _, c := range cases {
		got := sanitizeTarget(c.input)
		if got != c.want {
			t.Errorf("sanitizeTarget(%q) = %q, want %q", c.input, got, c.want)
		}
	}
}
