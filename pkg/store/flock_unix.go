//go:build !windows

package store

import (
	"fmt"
	"os"
	"syscall"
)

// acquireFileLock opens (creating if absent) lockPath and takes an exclusive
// advisory flock(2). Returns a release function that unlocks and closes the
// fd. Holding the lock blocks other processes calling acquireFileLock on the
// same path until release is invoked.
//
// The lock is advisory: only cooperating processes (i.e. other oqs-scanner
// runs) honour it. Other tools writing to the same file ignore it.
func acquireFileLock(lockPath string) (release func() error, err error) {
	// O_RDWR is needed for some kernels' flock semantics; O_CREATE so the
	// first SaveScan after a fresh ~/.oqs/history/ creates the lock file.
	// Mode 0600 mirrors the history-file permissions.
	f, err := os.OpenFile(lockPath, os.O_RDWR|os.O_CREATE, 0600)
	if err != nil {
		return nil, fmt.Errorf("store: open lock file %s: %w", lockPath, err)
	}

	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX); err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("store: flock %s: %w", lockPath, err)
	}

	return func() error {
		// Unlock first, then close. If unlock fails the close will still
		// release the fd (and with it the kernel lock), so we report the
		// unlock error but continue to close.
		unlockErr := syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
		closeErr := f.Close()
		if unlockErr != nil {
			return fmt.Errorf("store: flock unlock %s: %w", lockPath, unlockErr)
		}
		return closeErr
	}, nil
}
