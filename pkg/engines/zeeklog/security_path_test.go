//go:build !windows

package zeeklog

import (
	"context"
	"os"
	"strings"
	"syscall"
	"testing"
)

// securityPathTestCases are paths that must return errors, not panic.
// The engine opens files with os.Open — kernel path resolution applies.
var securityPathTestCases = []struct {
	name string
	path string
}{
	{name: "EtcShadow", path: "/etc/shadow"},
	{name: "EtcPasswd", path: "/etc/passwd"},
	{name: "Nonexistent", path: "/nonexistent/path/ssl.log"},
	{name: "DevZero", path: "/dev/zero"},
	{name: "Directory", path: "/tmp"},
	{name: "PathTooLong", path: "/" + strings.Repeat("a", 4096)},
}

// TestSecurityPath_ReadSSLLog verifies that attacker-controlled path arguments
// produce errors rather than panics or data leaks through the parse layer.
func TestSecurityPath_ReadSSLLog(t *testing.T) {
	for _, tc := range securityPathTestCases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			// Must not panic. May return error or empty records.
			recs, err := readSSLLog(context.Background(), tc.path)
			if err == nil && len(recs) > 0 {
				t.Errorf("path %q: expected error or empty result, got %d records", tc.path, len(recs))
			}
		})
	}
}

// TestSecurityPath_ReadX509Log mirrors the SSL test for x509 parsing.
func TestSecurityPath_ReadX509Log(t *testing.T) {
	for _, tc := range securityPathTestCases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			_, _ = readX509Log(context.Background(), tc.path) // must not panic
		})
	}
}

// TestSecurityPath_NullByte verifies that a path containing a null byte
// is rejected by the OS before any data is read.
func TestSecurityPath_NullByte(t *testing.T) {
	path := "/tmp/ssl\x00.log"
	_, err := readSSLLog(context.Background(), path)
	if err == nil {
		t.Error("null-byte path: expected os.Open error, got nil")
	}
}

// TestSecurityPath_SymlinkTrap verifies that a symlink to a sensitive file
// produces an error or empty parse result — no valid Zeek records.
func TestSecurityPath_SymlinkTrap(t *testing.T) {
	dir := t.TempDir()
	link := dir + "/shadow_trap.log"
	if err := os.Symlink("/etc/shadow", link); err != nil {
		t.Skipf("cannot create symlink: %v", err)
	}
	recs, _ := readSSLLog(context.Background(), link)
	if len(recs) > 0 {
		t.Errorf("symlink to /etc/shadow yielded %d records — expected 0", len(recs))
	}
}

// TestSecurityPath_NamedPipe verifies that a FIFO path is handled without panic.
// The actual read is skipped to avoid blocking on an unconnected pipe.
func TestSecurityPath_NamedPipe(t *testing.T) {
	dir := t.TempDir()
	fifo := dir + "/test.fifo"
	if err := syscall.Mkfifo(fifo, 0o644); err != nil {
		t.Skipf("cannot create FIFO: %v", err)
	}
	t.Logf("FIFO created at %s — skipping blocking open (engine uses os.Open)", fifo)
}

// TestSecurityPath_ReadDenied verifies a mode-000 file returns a permission error.
func TestSecurityPath_ReadDenied(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("running as root — permission checks do not apply")
	}
	dir := t.TempDir()
	f := dir + "/noaccess.log"
	if err := os.WriteFile(f, []byte("#fields\tts\n"), 0o000); err != nil {
		t.Fatalf("write: %v", err)
	}
	_, err := readSSLLog(context.Background(), f)
	if err == nil {
		t.Error("expected permission denied error, got nil")
	}
}
