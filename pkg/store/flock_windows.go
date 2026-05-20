//go:build windows

package store

// acquireFileLock is a no-op stub on Windows. Cross-process serialisation of
// SaveScan would require LockFileEx via golang.org/x/sys/windows, which the
// scanner does not depend on today. The in-process sync.Mutex inside
// LocalStore still serialises concurrent goroutines within a single
// oqs-scanner run; two SEPARATE oqs-scanner processes writing to the same
// ~/.oqs/history directory on Windows remain susceptible to the
// read-append-rename race documented in the lockfile_unix.go file.
//
// Tracked as a follow-up. Document the limitation in CLAUDE.md when this
// stub is replaced.
func acquireFileLock(_ string) (release func() error, err error) {
	return func() error { return nil }, nil
}
