package enginemgr

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

// maxParallelDownloads limits concurrent engine binary downloads to prevent
// FD exhaustion (same pattern as HashFiles semaphore in pkg/cache).
const maxParallelDownloads = 4

// Retry constants — mirrors pkg/api/retry.go values.
const (
	maxDownloadRetries = 3
	initialBackoff     = 1 * time.Second
	maxBackoff         = 4 * time.Second
)

// maxEngineSize is the maximum allowed download size for a single engine binary (500 MB).
const maxEngineSize = 500 << 20

// DownloadResult holds the outcome of a single engine download attempt.
type DownloadResult struct {
	Name      string `json:"name"`
	Version   string `json:"version"`
	BytesRead int64  `json:"bytesRead,omitempty"`
	Skipped   bool   `json:"skipped,omitempty"`
	WarnMsg   string `json:"warning,omitempty"`
	Err       error  `json:"-"`
	ErrMsg    string `json:"error,omitempty"`
}

// setErr sets both Err and ErrMsg in a DownloadResult.
func (r *DownloadResult) setErr(err error) {
	r.Err = err
	r.ErrMsg = err.Error()
}

// DownloadOptions configures the engine download behavior.
type DownloadOptions struct {
	InstallDir string
	Force      bool
	HTTPClient *http.Client
	// ProgressFunc is called with the engine name and cumulative bytes downloaded.
	// When used with DownloadEngines, this function is called concurrently from
	// multiple goroutines — implementations must be goroutine-safe.
	ProgressFunc func(engine string, bytesRead int64)
}

// downloadOne downloads a single engine binary using atomic write + SHA-256 verification.
func downloadOne(ctx context.Context, info EngineInfo, entry ManifestEngine, opts DownloadOptions) DownloadResult {
	result := DownloadResult{
		Name:    info.Name,
		Version: entry.Version,
	}

	// Resolve binary name: manifest override, then registry BinaryName.
	binaryName := info.BinaryName
	if entry.BinaryOverride != "" {
		binaryName = entry.BinaryOverride
	}
	if binaryName == "" {
		result.setErr(fmt.Errorf("engine %q has no binary name", info.Name))
		return result
	}

	// Path traversal guard: reject names containing path separators or ".." sequences.
	if binaryName != filepath.Base(binaryName) {
		result.setErr(fmt.Errorf("invalid binary name %q: contains path separator", binaryName))
		return result
	}

	// Append .exe on Windows.
	if runtime.GOOS == "windows" && !strings.HasSuffix(binaryName, ".exe") {
		binaryName += ".exe"
	}

	destPath := filepath.Join(opts.InstallDir, binaryName)

	// Belt-and-suspenders: verify destPath is within InstallDir after resolution.
	cleanDest := filepath.Clean(destPath)
	cleanDir := filepath.Clean(opts.InstallDir)
	if !strings.HasPrefix(cleanDest, cleanDir+string(os.PathSeparator)) && cleanDest != cleanDir {
		result.setErr(fmt.Errorf("path traversal detected: %q escapes install dir", binaryName))
		return result
	}

	// Skip if already exists and not forced.
	if !opts.Force {
		if _, err := os.Lstat(destPath); err == nil {
			result.Skipped = true
			return result
		}
	}

	// Lookup platform entry.
	platKey := PlatformKey()
	plat, ok := entry.Platforms[platKey]
	if !ok {
		result.setErr(fmt.Errorf("engine %q: no binary for platform %s", info.Name, platKey))
		return result
	}

	// Validate download URL: must be HTTPS.
	if err := validateDownloadURL(plat.URL); err != nil {
		result.setErr(fmt.Errorf("engine %q: %w", info.Name, err))
		return result
	}

	// Create install directory with restrictive permissions.
	if err := os.MkdirAll(opts.InstallDir, 0700); err != nil {
		result.setErr(fmt.Errorf("create install dir: %w", err))
		return result
	}

	// Download with retry.
	client := opts.HTTPClient
	if client == nil {
		client = SecureHTTPClient(5 * time.Minute)
	}

	var lastErr error
	backoff := initialBackoff
	for attempt := 0; attempt < maxDownloadRetries; attempt++ {
		if attempt > 0 {
			select {
			case <-ctx.Done():
				result.setErr(ctx.Err())
				return result
			case <-time.After(backoff):
			}
			backoff *= 2
			if backoff > maxBackoff {
				backoff = maxBackoff
			}
		}

		n, err := downloadAtomicVerify(ctx, client, plat.URL, plat.SHA256, destPath, info.Name, opts.ProgressFunc)
		if err == nil {
			result.BytesRead = n
			if plat.SHA256 == "" || plat.SHA256 == "placeholder" {
				result.WarnMsg = fmt.Sprintf("engine %q: integrity not verified (SHA-256 is %q); do not use in production", info.Name, plat.SHA256)
			}
			return result
		}

		// Only retry on transient HTTP errors (429, 503, 504).
		if isTransientErr(err) {
			lastErr = err
			continue
		}
		// Non-transient error — fail immediately.
		result.setErr(err)
		return result
	}

	result.setErr(fmt.Errorf("engine %q: download failed after %d retries: %w", info.Name, maxDownloadRetries, lastErr))
	return result
}

// validateDownloadURL checks that the URL is well-formed, uses HTTPS, and has a host.
func validateDownloadURL(rawURL string) error {
	if rawURL == "" {
		return fmt.Errorf("empty download URL")
	}
	u, err := url.Parse(rawURL)
	if err != nil {
		return fmt.Errorf("invalid download URL: %w", err)
	}
	if u.Scheme != "https" {
		return fmt.Errorf("refusing non-HTTPS download URL: %s", rawURL)
	}
	if u.Host == "" {
		return fmt.Errorf("download URL has no host: %s", rawURL)
	}
	return nil
}

// httpsOnlyRedirectPolicy rejects any redirect that leaves HTTPS.
func httpsOnlyRedirectPolicy(req *http.Request, via []*http.Request) error {
	if req.URL.Scheme != "https" {
		return fmt.Errorf("refusing redirect to non-HTTPS URL: %s", req.URL)
	}
	if len(via) >= 10 {
		return fmt.Errorf("too many redirects")
	}
	return nil
}

// SecureHTTPClient returns an *http.Client with HTTPS redirect enforcement
// and the given timeout. Use this for all engine binary downloads.
func SecureHTTPClient(timeout time.Duration) *http.Client {
	return &http.Client{
		Timeout:       timeout,
		CheckRedirect: httpsOnlyRedirectPolicy,
	}
}

// downloadAtomicVerify performs the actual HTTP download, SHA-256 verification, and atomic rename.
func downloadAtomicVerify(ctx context.Context, client *http.Client, dlURL, expectedSHA256, destPath, engineName string, progressFn func(string, int64)) (int64, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, dlURL, nil)
	if err != nil {
		return 0, err
	}

	resp, err := client.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusTooManyRequests ||
		resp.StatusCode == http.StatusServiceUnavailable ||
		resp.StatusCode == http.StatusGatewayTimeout {
		// Drain body to allow HTTP connection reuse on retry.
		io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
		return 0, &transientError{StatusCode: resp.StatusCode}
	}
	if resp.StatusCode != http.StatusOK {
		return 0, fmt.Errorf("HTTP %d from %s", resp.StatusCode, dlURL)
	}

	// Atomic write: temp file → chmod → write+hash → verify → rename.
	dir := filepath.Dir(destPath)
	tmp, err := os.CreateTemp(dir, ".engine-download-*.tmp")
	if err != nil {
		return 0, fmt.Errorf("create temp file: %w", err)
	}
	tmpPath := tmp.Name()
	tmpClosed := false
	defer func() {
		// Clean up temp file on any failure.
		if !tmpClosed {
			tmp.Close()
		}
		if tmpPath != "" {
			os.Remove(tmpPath)
		}
	}()

	if err := tmp.Chmod(0755); err != nil && runtime.GOOS != "windows" {
		// On Windows, Chmod does not meaningfully set execute permission (executability
		// is determined by file extension). Treat chmod errors as non-fatal on Windows.
		return 0, fmt.Errorf("chmod temp file: %w", err)
	}

	hasher := sha256.New()
	var reader io.Reader = io.LimitReader(resp.Body, maxEngineSize+1)
	if progressFn != nil {
		reader = &progressReader{r: reader, engine: engineName, fn: progressFn}
	}

	n, err := io.Copy(io.MultiWriter(tmp, hasher), reader)
	if err != nil {
		return 0, fmt.Errorf("download %s: %w", engineName, err)
	}
	if n > maxEngineSize {
		return 0, fmt.Errorf("download %s: exceeds maximum size (%d bytes)", engineName, maxEngineSize)
	}
	if n == 0 {
		return 0, fmt.Errorf("download %s: empty response (0 bytes)", engineName)
	}

	if err := tmp.Close(); err != nil {
		return 0, fmt.Errorf("close temp file: %w", err)
	}
	tmpClosed = true

	// Verify SHA-256. The "placeholder" sentinel is only accepted during development;
	// a CI gate should reject manifest entries with placeholder hashes before release.
	if expectedSHA256 == "" || expectedSHA256 == "placeholder" {
		// Skip verification but log intent — this is a pre-release state.
	} else {
		gotHash := hex.EncodeToString(hasher.Sum(nil))
		if gotHash != expectedSHA256 {
			return 0, fmt.Errorf("SHA-256 mismatch for %s: expected %s, got %s", engineName, expectedSHA256, gotHash)
		}
	}

	// Reject symlinks at destination to prevent symlink-following attacks.
	if fi, lstatErr := os.Lstat(destPath); lstatErr == nil && fi.Mode()&os.ModeSymlink != 0 {
		return 0, fmt.Errorf("refusing to overwrite symlink at %s", destPath)
	}

	// On Windows, os.Rename fails if destination exists. Remove first.
	if runtime.GOOS == "windows" {
		os.Remove(destPath)
	}

	// Atomic rename.
	if err := os.Rename(tmpPath, destPath); err != nil {
		return 0, fmt.Errorf("rename %s: %w", engineName, err)
	}
	tmpPath = "" // prevent deferred cleanup

	return n, nil
}

// DownloadEngines downloads multiple engines in parallel with bounded concurrency.
// Returns one DownloadResult per engine in the same order as the input slice.
func DownloadEngines(ctx context.Context, engines []EngineInfo, manifest *Manifest, opts DownloadOptions) []DownloadResult {
	results := make([]DownloadResult, len(engines))

	if manifest == nil {
		for i, info := range engines {
			results[i] = DownloadResult{
				Name:   info.Name,
				Err:    fmt.Errorf("manifest is nil"),
				ErrMsg: "manifest is nil",
			}
		}
		return results
	}

	type indexedResult struct {
		idx    int
		result DownloadResult
	}
	ch := make(chan indexedResult, len(engines))

	// Semaphore limits concurrent downloads to prevent FD exhaustion.
	sem := make(chan struct{}, maxParallelDownloads)

	for i, info := range engines {
		i, info := i, info
		go func() {
			// Panic recovery must be registered before semaphore acquire to
			// prevent deadlock if a panic occurs between acquire and registration.
			defer func() {
				if r := recover(); r != nil {
					ch <- indexedResult{idx: i, result: DownloadResult{
						Name:   info.Name,
						Err:    fmt.Errorf("panic: %v", r),
						ErrMsg: fmt.Sprintf("panic: %v", r),
					}}
				}
			}()
			// Acquire semaphore slot.
			select {
			case sem <- struct{}{}:
				defer func() { <-sem }()
			case <-ctx.Done():
				ch <- indexedResult{idx: i, result: DownloadResult{
					Name:   info.Name,
					Err:    ctx.Err(),
					ErrMsg: ctx.Err().Error(),
				}}
				return
			}
			entry, ok := manifest.Engines[info.Name]
			if !ok {
				ch <- indexedResult{idx: i, result: DownloadResult{
					Name:   info.Name,
					Err:    fmt.Errorf("engine %q not in manifest", info.Name),
					ErrMsg: fmt.Sprintf("engine %q not in manifest", info.Name),
				}}
				return
			}
			ch <- indexedResult{idx: i, result: downloadOne(ctx, info, entry, opts)}
		}()
	}

	for range engines {
		r := <-ch
		results[r.idx] = r.result
	}
	return results
}

// transientError marks an HTTP error as retryable.
type transientError struct {
	StatusCode int
}

func (e *transientError) Error() string {
	return fmt.Sprintf("transient HTTP %d", e.StatusCode)
}

// isTransientErr checks if an error is a transient HTTP error.
// Uses errors.As to handle wrapped errors.
func isTransientErr(err error) bool {
	var te *transientError
	return errors.As(err, &te)
}

// progressReader wraps an io.Reader and calls a progress function after each Read.
type progressReader struct {
	r      io.Reader
	engine string
	fn     func(string, int64)
	total  int64
}

func (pr *progressReader) Read(p []byte) (int, error) {
	n, err := pr.r.Read(p)
	pr.total += int64(n)
	if n > 0 {
		pr.fn(pr.engine, pr.total)
	}
	return n, err
}
