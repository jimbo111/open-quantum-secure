// Package cache provides an incremental scan cache that stores per-file
// findings keyed by content hash so that unchanged files are not re-scanned.
package cache

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/jimbo111/open-quantum-secure/pkg/findings"
)

const cacheFormatVersion = "2"

// ScanCache is the top-level cache structure persisted to disk as JSON.
//
// V2 adds per-engine entries (EngineEntries) so that engine version changes
// only invalidate that engine's cache, not the entire cache. The flat Entries
// map is kept for backward compatibility during the transition.
type ScanCache struct {
	// mu guards every map field below. All public methods acquire mu; callers
	// that read or write map fields directly must synchronise externally.
	mu sync.RWMutex `json:"-"`

	// Version is the cache format version (bumped when the schema changes).
	Version string `json:"version"`

	// ScannerVersion is the oqs-scanner binary version that created this cache.
	ScannerVersion string `json:"scannerVersion"`

	// EngineVersions maps engine name → version string (e.g. "cipherscope" → "0.3.1").
	// Used by IsValidForEngine to detect per-engine version changes.
	EngineVersions map[string]string `json:"engineVersions"`

	// EngineEntries maps engine name → file path → cached scan result.
	// This is the V2 per-engine cache structure. Each engine's entries are
	// independent so that upgrading one engine only invalidates its cache.
	EngineEntries map[string]map[string]*CacheEntry `json:"engineEntries,omitempty"`

	// Entries maps absolute file path → cached scan result for that file.
	// This is the V1 flat cache structure, kept for backward compatibility
	// during the transition to per-engine entries.
	Entries map[string]*CacheEntry `json:"entries,omitempty"`
}

// CacheEntry holds the cached findings for a single source file.
type CacheEntry struct {
	// ContentHash is the SHA-256 hex digest of the file contents at scan time.
	ContentHash string `json:"contentHash"`

	// ModTime is the file modification time at scan time, used as a fast
	// pre-check before computing the full SHA-256 hash.
	ModTime time.Time `json:"modTime"`

	// Findings are the deduplicated, classified findings for this file.
	Findings []findings.UnifiedFinding `json:"findings"`

	// ScannedAt records when this entry was created.
	ScannedAt time.Time `json:"scannedAt"`
}

// New returns an empty ScanCache with the current format version.
func New() *ScanCache {
	return &ScanCache{
		Version:        cacheFormatVersion,
		EngineVersions: make(map[string]string),
		EngineEntries:  make(map[string]map[string]*CacheEntry),
		Entries:        make(map[string]*CacheEntry),
	}
}

// Load reads a ScanCache from the JSON file at path.
// If the file does not exist or cannot be parsed, an empty (but valid) cache
// is returned — the caller should treat this as a cache miss, not an error.
func Load(path string) (*ScanCache, error) {
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return New(), nil
	}
	if err != nil {
		// Unreadable — return empty cache, not a hard error.
		return New(), nil
	}

	var sc ScanCache
	if err := json.Unmarshal(data, &sc); err != nil {
		// Corrupt JSON — treat as cache miss.
		return New(), nil
	}

	// Ensure maps are non-nil even if the JSON contained null.
	if sc.EngineVersions == nil {
		sc.EngineVersions = make(map[string]string)
	}
	if sc.EngineEntries == nil {
		sc.EngineEntries = make(map[string]map[string]*CacheEntry)
	}
	if sc.Entries == nil {
		sc.Entries = make(map[string]*CacheEntry)
	}

	return &sc, nil
}

// Save persists the cache to path using an atomic temp-rename write so that
// a crash mid-write never leaves a corrupt file.
func (sc *ScanCache) Save(path string) error {
	sc.mu.RLock()
	data, err := json.MarshalIndent(sc, "", "  ")
	sc.mu.RUnlock()
	if err != nil {
		return fmt.Errorf("marshal cache: %w", err)
	}

	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".oqs-cache-*.tmp")
	if err != nil {
		return fmt.Errorf("create temp cache file: %w", err)
	}
	tmpPath := tmp.Name()

	// Clean up temp file on any error path.
	success := false
	defer func() {
		if !success {
			os.Remove(tmpPath)
		}
	}()

	if err := tmp.Chmod(0600); err != nil {
		tmp.Close()
		return fmt.Errorf("chmod cache file: %w", err)
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return fmt.Errorf("write cache: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return fmt.Errorf("sync cache file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close cache file: %w", err)
	}

	// Guard against symlink attacks: refuse to overwrite if destination is a symlink.
	if fi, err := os.Lstat(path); err == nil && fi.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("cache path is a symlink (possible attack): %s", path)
	}
	if err := os.Rename(tmpPath, path); err != nil {
		return fmt.Errorf("rename cache file: %w", err)
	}
	success = true
	return nil
}

// IsValid reports whether the cache was produced by the same scanner version
// and engine versions. A version mismatch means all entries are stale.
func (sc *ScanCache) IsValid(currentScannerVersion string, currentEngineVersions map[string]string) bool {
	sc.mu.RLock()
	defer sc.mu.RUnlock()
	if sc.Version != cacheFormatVersion {
		return false
	}
	if sc.ScannerVersion != currentScannerVersion {
		return false
	}
	if len(sc.EngineVersions) != len(currentEngineVersions) {
		return false
	}
	for name, ver := range currentEngineVersions {
		if sc.EngineVersions[name] != ver {
			return false
		}
	}
	return true
}

// GetUnchangedFindings compares the on-disk state of targetDir against the
// cache.  It returns:
//   - cachedFindings: all findings from files that have not changed
//   - changedPaths:   absolute paths of files that are new or have changed
//
// currentScannerVersion guards against stale findings surviving a scanner
// upgrade: when the stored ScannerVersion or cache format version does not
// match, every path is reported as changed (forcing a fresh scan) and no
// cached findings are returned.
//
// Files that exist in the cache but are no longer on disk are silently dropped
// (their findings are not included).
//
// allFileHashes is a map of absolute path → SHA-256 hash for every file
// currently on disk in the target directory. Callers should compute this
// with HashFiles before calling GetUnchangedFindings.
func (sc *ScanCache) GetUnchangedFindings(currentScannerVersion string, allFileHashes map[string]string) (cachedFindings []findings.UnifiedFinding, changedPaths []string) {
	sc.mu.RLock()
	defer sc.mu.RUnlock()
	// Version guard: if the cache format or scanner version doesn't match,
	// every file is stale from this caller's perspective.
	if sc.Version != cacheFormatVersion || sc.ScannerVersion != currentScannerVersion {
		changedPaths = make([]string, 0, len(allFileHashes))
		for path := range allFileHashes {
			changedPaths = append(changedPaths, path)
		}
		return nil, changedPaths
	}
	for path, hash := range allFileHashes {
		entry, ok := sc.Entries[path]
		if !ok || entry.ContentHash != hash {
			changedPaths = append(changedPaths, path)
			continue
		}
		// File is unchanged — use cached findings.
		cachedFindings = append(cachedFindings, entry.Findings...)
	}
	return cachedFindings, changedPaths
}

// Update incorporates new scan results into the cache and removes entries for
// files that no longer exist on disk.
//
//   - changedFindings: maps absolute file path → new findings for that file
//   - allFileHashes:   maps absolute file path → current content hash
//     (used to record hashes and prune deleted files)
func (sc *ScanCache) Update(changedFindings map[string][]findings.UnifiedFinding, allFileHashes map[string]string) {
	sc.mu.Lock()
	defer sc.mu.Unlock()
	now := time.Now()

	// Update entries for changed/new files.
	for path, ff := range changedFindings {
		hash, ok := allFileHashes[path]
		if !ok {
			// File was scanned but no longer on disk — skip.
			continue
		}
		modTime := fileModTime(path)
		sc.Entries[path] = &CacheEntry{
			ContentHash: hash,
			ModTime:     modTime,
			Findings:    ff,
			ScannedAt:   now,
		}
	}

	// Prune entries for files no longer on disk.
	for path := range sc.Entries {
		if _, exists := allFileHashes[path]; !exists {
			delete(sc.Entries, path)
		}
	}
}

// IsValidForEngine reports whether the cache has a valid entry set for the
// named engine at the given version. Returns false if the cache format is
// wrong, the engine is not in the cache, or its version doesn't match.
func (sc *ScanCache) IsValidForEngine(engineName, currentVersion string) bool {
	sc.mu.RLock()
	defer sc.mu.RUnlock()
	if sc.Version != cacheFormatVersion {
		return false
	}
	cachedVer, ok := sc.EngineVersions[engineName]
	if !ok {
		return false
	}
	return cachedVer == currentVersion
}

// GetUnchangedFindingsForEngine is the per-engine variant of GetUnchangedFindings.
// It checks only the entries belonging to engineName in EngineEntries.
//
// currentVersion guards against stale findings surviving an engine upgrade:
// when the recorded EngineVersions[engineName] or cache format version does
// not match, every path is reported as changed (forcing a fresh scan) and no
// cached findings are returned.
//
// Returns:
//   - cachedFindings: findings from files whose content hash has not changed
//   - changedPaths: absolute paths of files that are new or have changed
//
// Files in the engine's cache that are not in allFileHashes (deleted or no
// longer relevant) are silently dropped.
func (sc *ScanCache) GetUnchangedFindingsForEngine(engineName, currentVersion string, allFileHashes map[string]string) (cachedFindings []findings.UnifiedFinding, changedPaths []string) {
	sc.mu.RLock()
	defer sc.mu.RUnlock()
	// Version guard: cache format or engine version mismatch → all paths changed.
	if sc.Version != cacheFormatVersion || sc.EngineVersions[engineName] != currentVersion {
		changedPaths = make([]string, 0, len(allFileHashes))
		for path := range allFileHashes {
			changedPaths = append(changedPaths, path)
		}
		return nil, changedPaths
	}
	engineFiles := sc.EngineEntries[engineName]
	for path, hash := range allFileHashes {
		if engineFiles == nil {
			changedPaths = append(changedPaths, path)
			continue
		}
		entry, ok := engineFiles[path]
		if !ok || entry.ContentHash != hash {
			changedPaths = append(changedPaths, path)
			continue
		}
		cachedFindings = append(cachedFindings, entry.Findings...)
	}
	return cachedFindings, changedPaths
}

// UpdateEngine incorporates scan results for a single engine into EngineEntries.
// It creates or updates the engine's entries for changed files and optionally
// prunes entries for files not in allFileHashes (deleted or no longer relevant).
//
// When pruneDeleted is true, entries for files absent from allFileHashes are
// removed. This should only be set when allFileHashes represents the complete
// set of relevant files (full mode). In diff mode, allFileHashes contains only
// the changed files — pruning would destroy valid cached entries for unchanged
// files.
func (sc *ScanCache) UpdateEngine(engineName string, changedFindings map[string][]findings.UnifiedFinding, allFileHashes map[string]string, pruneDeleted bool) {
	sc.mu.Lock()
	defer sc.mu.Unlock()
	engineFiles, ok := sc.EngineEntries[engineName]
	if !ok {
		engineFiles = make(map[string]*CacheEntry)
		sc.EngineEntries[engineName] = engineFiles
	}

	now := time.Now()
	for path, ff := range changedFindings {
		hash, ok := allFileHashes[path]
		if !ok {
			continue // file was scanned but no longer on disk
		}
		engineFiles[path] = &CacheEntry{
			ContentHash: hash,
			ModTime:     fileModTime(path),
			Findings:    ff,
			ScannedAt:   now,
		}
	}

	// Prune entries for files no longer in the hash set. Only safe when
	// allFileHashes is the complete file set (full mode), not a partial
	// subset (diff mode).
	if pruneDeleted {
		for path := range engineFiles {
			if _, exists := allFileHashes[path]; !exists {
				delete(engineFiles, path)
			}
		}
	}
}

// EnsureEngineEntry ensures that EngineEntries[engineName] is a non-nil map.
// It is safe to call concurrently. Used by callers (e.g. orchestrator) that
// want to pre-populate engine keys so later goroutine writes into the inner
// map don't need to take the outer lock.
func (sc *ScanCache) EnsureEngineEntry(engineName string) {
	sc.mu.Lock()
	defer sc.mu.Unlock()
	if sc.EngineEntries[engineName] == nil {
		sc.EngineEntries[engineName] = make(map[string]*CacheEntry)
	}
}

// SetEngineVersion records the version string for a named engine. Safe for
// concurrent use.
func (sc *ScanCache) SetEngineVersion(engineName, version string) {
	sc.mu.Lock()
	defer sc.mu.Unlock()
	if sc.EngineVersions == nil {
		sc.EngineVersions = make(map[string]string)
	}
	sc.EngineVersions[engineName] = version
}

// PruneDeletedFiles removes entries for files that no longer exist on disk,
// across both the flat Entries map and all EngineEntries. allFileHashes should
// contain every file currently on disk.
func (sc *ScanCache) PruneDeletedFiles(allFileHashes map[string]string) {
	sc.mu.Lock()
	defer sc.mu.Unlock()
	for path := range sc.Entries {
		if _, exists := allFileHashes[path]; !exists {
			delete(sc.Entries, path)
		}
	}
	for _, engineFiles := range sc.EngineEntries {
		for path := range engineFiles {
			if _, exists := allFileHashes[path]; !exists {
				delete(engineFiles, path)
			}
		}
	}
}

// MarshalGzip serializes the cache to gzip-compressed JSON bytes.
// It is the inverse of UnmarshalGzip.
func (sc *ScanCache) MarshalGzip() ([]byte, error) {
	sc.mu.RLock()
	data, err := json.Marshal(sc)
	sc.mu.RUnlock()
	if err != nil {
		return nil, fmt.Errorf("cache: marshal: %w", err)
	}

	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	if _, err := gz.Write(data); err != nil {
		return nil, fmt.Errorf("cache: gzip write: %w", err)
	}
	if err := gz.Close(); err != nil {
		return nil, fmt.Errorf("cache: gzip close: %w", err)
	}
	return buf.Bytes(), nil
}

// UnmarshalGzip deserializes a ScanCache from gzip-compressed JSON bytes.
// Returns an error for non-gzip input or malformed JSON.
func UnmarshalGzip(data []byte) (*ScanCache, error) {
	gr, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("cache: gzip open: %w", err)
	}
	defer gr.Close()

	// Limit decompressed size to prevent decompression bombs.
	const maxDecompressedCacheBytes = 500 * 1024 * 1024 // 500 MB
	raw, err := io.ReadAll(io.LimitReader(gr, maxDecompressedCacheBytes+1))
	if err != nil {
		return nil, fmt.Errorf("cache: gzip read: %w", err)
	}
	if int64(len(raw)) > maxDecompressedCacheBytes {
		return nil, fmt.Errorf("cache: decompressed size exceeds %d bytes", maxDecompressedCacheBytes)
	}

	var sc ScanCache
	if err := json.Unmarshal(raw, &sc); err != nil {
		return nil, fmt.Errorf("cache: unmarshal: %w", err)
	}

	// Ensure maps are non-nil.
	if sc.EngineVersions == nil {
		sc.EngineVersions = make(map[string]string)
	}
	if sc.EngineEntries == nil {
		sc.EngineEntries = make(map[string]map[string]*CacheEntry)
	}
	if sc.Entries == nil {
		sc.Entries = make(map[string]*CacheEntry)
	}

	return &sc, nil
}

// fileModTime returns the modification time of a file, or the zero time on error.
func fileModTime(path string) time.Time {
	info, err := os.Stat(path)
	if err != nil {
		return time.Time{}
	}
	return info.ModTime()
}
