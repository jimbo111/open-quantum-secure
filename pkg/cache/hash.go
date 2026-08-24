package cache

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"runtime"
	"sort"
	"sync"
)

// ErrFileTooLarge is returned by HashFileWithLimit when the file exceeds the
// given size limit. Callers should treat such files as "always changed"
// (never cached) rather than reading them in full.
var ErrFileTooLarge = errors.New("file exceeds hash size limit")

// HashFile returns the SHA-256 hex digest of the file at path.
func HashFile(path string) (string, error) {
	return HashFileWithLimit(path, 0)
}

// HashFileWithLimit returns the SHA-256 hex digest of the file at path.
// When maxBytes > 0 and the file is larger than maxBytes, it returns
// ErrFileTooLarge WITHOUT reading the file contents — this bounds the I/O
// cost of pre-scan hashing on repos containing large artifacts.
func HashFileWithLimit(path string, maxBytes int64) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", fmt.Errorf("open file for hashing: %w", err)
	}
	defer f.Close()

	if maxBytes > 0 {
		info, err := f.Stat()
		if err != nil {
			return "", fmt.Errorf("stat file for hashing: %w", err)
		}
		if info.Size() > maxBytes {
			return "", fmt.Errorf("%s (%d bytes > %d): %w", path, info.Size(), maxBytes, ErrFileTooLarge)
		}
	}

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", fmt.Errorf("hash file: %w", err)
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// HashFiles computes SHA-256 hashes for all given paths in parallel with no
// size limit. See HashFilesWithLimit.
func HashFiles(paths []string) (map[string]string, error) {
	hashes, _, err := HashFilesWithLimit(paths, 0)
	return hashes, err
}

// HashFilesWithLimit computes SHA-256 hashes for all given paths in parallel.
// Returns a map from path to hex hash plus the sorted list of paths skipped
// because they exceed maxBytes (0 = no limit). Skipped-for-size files are NOT
// errors — callers should treat them as always-changed and never cache them.
// Other per-file errors are collected and returned as a combined error;
// successfully hashed files are still included in the map.
func HashFilesWithLimit(paths []string, maxBytes int64) (map[string]string, []string, error) {
	type result struct {
		path    string
		hash    string
		skipped bool
		err     error
	}

	results := make(chan result, len(paths))
	var wg sync.WaitGroup

	// Limit concurrency to avoid exhausting file descriptors on large repos.
	sem := make(chan struct{}, runtime.NumCPU()*4)

	for _, p := range paths {
		p := p
		wg.Add(1)
		go func() {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			defer func() {
				if r := recover(); r != nil {
					results <- result{path: p, err: fmt.Errorf("panic hashing %s: %v", p, r)}
				}
			}()
			h, err := HashFileWithLimit(p, maxBytes)
			if errors.Is(err, ErrFileTooLarge) {
				results <- result{path: p, skipped: true}
				return
			}
			results <- result{path: p, hash: h, err: err}
		}()
	}

	wg.Wait()
	close(results)

	hashes := make(map[string]string, len(paths))
	var skipped []string
	var errs []error
	for r := range results {
		if r.skipped {
			skipped = append(skipped, r.path)
			continue
		}
		if r.err != nil {
			errs = append(errs, r.err)
			continue
		}
		hashes[r.path] = r.hash
	}
	sort.Strings(skipped)

	if len(errs) > 0 {
		return hashes, skipped, fmt.Errorf("hash errors: %v", errs)
	}
	return hashes, skipped, nil
}
