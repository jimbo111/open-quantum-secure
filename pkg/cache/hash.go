package cache

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"runtime"
	"sync"
)

// HashFile returns the SHA-256 hex digest of the file at path.
func HashFile(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", fmt.Errorf("open file for hashing: %w", err)
	}
	defer f.Close()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", fmt.Errorf("hash file: %w", err)
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// HashFiles computes SHA-256 hashes for all given paths in parallel.
// Returns a map from path to hex hash. Errors from individual files are
// collected and returned as a combined error; successfully hashed files
// are still included in the map.
func HashFiles(paths []string) (map[string]string, error) {
	type result struct {
		path string
		hash string
		err  error
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
			h, err := HashFile(p)
			results <- result{path: p, hash: h, err: err}
		}()
	}

	wg.Wait()
	close(results)

	hashes := make(map[string]string, len(paths))
	var errs []error
	for r := range results {
		if r.err != nil {
			errs = append(errs, r.err)
			continue
		}
		hashes[r.path] = r.hash
	}

	if len(errs) > 0 {
		return hashes, fmt.Errorf("hash errors: %v", errs)
	}
	return hashes, nil
}
