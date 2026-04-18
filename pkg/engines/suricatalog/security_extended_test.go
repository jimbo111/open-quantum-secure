//go:build !windows

package suricatalog

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

// TestRejectSymlinkToSensitiveFile verifies that a symlink pointing to a sensitive
// system file (/etc/passwd as a widely-available proxy for /etc/shadow) is rejected.
func TestRejectSymlinkToSensitiveFile(t *testing.T) {
	target := "/etc/passwd"
	if _, err := os.Stat(target); err != nil {
		t.Skipf("skipping: %s not accessible: %v", target, err)
	}
	dir := t.TempDir()
	link := filepath.Join(dir, "evil.json")
	if err := os.Symlink(target, link); err != nil {
		t.Fatalf("symlink: %v", err)
	}
	_, err := openLogFile(link)
	if err == nil {
		t.Fatal("openLogFile must reject symlink to sensitive file")
	}
}

// TestRejectSymlinkTrap verifies that a symlink chain (link → tempfile) is rejected.
func TestRejectSymlinkTrap(t *testing.T) {
	dir := t.TempDir()
	// Create a legitimate target file.
	target := filepath.Join(dir, "real.json")
	if err := os.WriteFile(target, []byte("{}\n"), 0600); err != nil {
		t.Fatalf("write target: %v", err)
	}
	// Symlink to it.
	link := filepath.Join(dir, "trap.json")
	if err := os.Symlink(target, link); err != nil {
		t.Fatalf("symlink: %v", err)
	}
	_, err := openLogFile(link)
	if err == nil {
		t.Fatal("openLogFile must reject any symlink regardless of target")
	}
}

// TestRejectPermissionDenied verifies that a mode-000 file returns an error.
func TestRejectPermissionDenied(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("running as root — mode 000 is readable by root")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "noaccess.json")
	if err := os.WriteFile(path, []byte("{}\n"), 0600); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := os.Chmod(path, 0000); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(path, 0600) })

	_, err := openLogFile(path)
	if err == nil {
		t.Fatal("openLogFile must return error for mode-000 file")
	}
}

// TestRejectDevZero verifies that /dev/zero (a character device) is rejected as
// non-regular. Without this guard, reads from /dev/zero never terminate.
func TestRejectDevZero(t *testing.T) {
	if _, err := os.Stat("/dev/zero"); err != nil {
		t.Skip("/dev/zero not available on this system")
	}
	_, err := openLogFile("/dev/zero")
	if err == nil {
		t.Fatal("openLogFile must reject /dev/zero (character device, not a regular file)")
	}
}

// TestRejectNamedPipe verifies that a named pipe (FIFO) is rejected as non-regular.
func TestRejectNamedPipe(t *testing.T) {
	dir := t.TempDir()
	pipe := filepath.Join(dir, "test.fifo")
	if err := syscall.Mkfifo(pipe, 0600); err != nil {
		t.Skipf("mkfifo not available: %v", err)
	}
	_, err := openLogFile(pipe)
	if err == nil {
		t.Fatal("openLogFile must reject named pipe (FIFO, not a regular file)")
	}
}

// TestRejectDirectory verifies that a directory path is rejected as non-regular.
func TestRejectDirectory(t *testing.T) {
	dir := t.TempDir()
	_, err := openLogFile(dir)
	if err == nil {
		t.Fatal("openLogFile must reject a directory")
	}
}

// TestNullByteInPath verifies that a path containing an embedded NUL byte is rejected.
// The OS syscall itself rejects NUL bytes in paths — openLogFile must propagate the error.
func TestNullByteInPath(t *testing.T) {
	_, err := openLogFile("/tmp/eve\x00.json")
	if err == nil {
		t.Fatal("openLogFile must return error for null-byte path (OS rejects it)")
	}
}

// TestVeryLongFilename verifies that a path with a filename near or over NAME_MAX (255)
// does not panic — the OS returns an appropriate error.
func TestVeryLongFilename(t *testing.T) {
	dir := t.TempDir()
	// 256-byte filename (1 over typical NAME_MAX of 255).
	name := make([]byte, 256)
	for i := range name {
		name[i] = 'a'
	}
	name[252] = '.'
	name[253] = 'j'
	name[254] = 's'
	name[255] = 'n'
	path := filepath.Join(dir, string(name))
	// Must not panic; OS will return an error for the oversized name.
	_, _ = openLogFile(path)
}
