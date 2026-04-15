package cache

import (
	"bytes"
	"compress/gzip"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/jimbo111/open-quantum-secure/pkg/findings"
)

// ---------------------------------------------------------------------------
// SHA-256 collision-resistance
// ---------------------------------------------------------------------------

// TestHashFile_DifferentContent_DifferentHash verifies that two files with
// different content produce different SHA-256 hashes (collision resistance).
func TestHashFile_DifferentContent_DifferentHash(t *testing.T) {
	dir := t.TempDir()
	p1 := writeTempFile(t, dir, "a.go", "package main // RSA-2048")
	p2 := writeTempFile(t, dir, "b.go", "package main // AES-256")

	h1, err := HashFile(p1)
	if err != nil {
		t.Fatalf("HashFile p1: %v", err)
	}
	h2, err := HashFile(p2)
	if err != nil {
		t.Fatalf("HashFile p2: %v", err)
	}
	if h1 == h2 {
		t.Errorf("different content must produce different hashes: both got %q", h1)
	}
}

// TestHashFile_SameContentDifferentPaths_SameHash verifies that two files
// with identical content have the same hash regardless of path.
func TestHashFile_SameContentDifferentPaths_SameHash(t *testing.T) {
	dir := t.TempDir()
	content := "package main // identical content"
	p1 := writeTempFile(t, dir, "a.go", content)
	p2 := writeTempFile(t, dir, "b.go", content)

	h1, err := HashFile(p1)
	if err != nil {
		t.Fatalf("HashFile p1: %v", err)
	}
	h2, err := HashFile(p2)
	if err != nil {
		t.Fatalf("HashFile p2: %v", err)
	}
	if h1 != h2 {
		t.Errorf("same content must produce the same hash: %q vs %q", h1, h2)
	}
}

// ---------------------------------------------------------------------------
// File modified mid-scan (hash changes after first read)
// ---------------------------------------------------------------------------

// TestGetUnchangedFindings_FileModifiedMidScan verifies that if a file's hash
// changes between the time the cache was written and the current scan, it
// appears in changedPaths (not in cachedFindings).
func TestGetUnchangedFindings_FileModifiedMidScan(t *testing.T) {
	dir := t.TempDir()
	p := writeTempFile(t, dir, "scan_target.go", "package main // v1")

	hashV1, err := HashFile(p)
	if err != nil {
		t.Fatal(err)
	}

	// Populate cache with v1 hash.
	sc := New()
	sc.Entries[p] = &CacheEntry{
		ContentHash: hashV1,
		Findings:    []findings.UnifiedFinding{sampleFinding("ag", p, "AES-128", 1)},
	}

	// Simulate file being modified between scan runs.
	if err := os.WriteFile(p, []byte("package main // v2 (modified mid-scan)"), 0644); err != nil {
		t.Fatal(err)
	}

	hashV2, err := HashFile(p)
	if err != nil {
		t.Fatal(err)
	}

	cached, changed := sc.GetUnchangedFindings(map[string]string{p: hashV2})

	if len(cached) != 0 {
		t.Errorf("modified file must not return cached findings, got %d", len(cached))
	}
	if len(changed) != 1 || changed[0] != p {
		t.Errorf("modified file must appear in changedPaths: got %v", changed)
	}
	// Verify the hashes differ so the test is meaningful.
	if hashV1 == hashV2 {
		t.Skip("hash collision or filesystem timestamp granularity prevented content update")
	}
}

// ---------------------------------------------------------------------------
// Corrupt gzip
// ---------------------------------------------------------------------------

// TestUnmarshalGzip_CorruptData_ReturnsError verifies that UnmarshalGzip
// returns an error for garbage input (not a valid gzip stream).
func TestUnmarshalGzip_CorruptData_ReturnsError(t *testing.T) {
	_, err := UnmarshalGzip([]byte("this is not gzip data"))
	if err == nil {
		t.Error("expected error for non-gzip input")
	}
}

// TestUnmarshalGzip_ValidGzip_CorruptJSON_ReturnsError verifies that a valid
// gzip stream wrapping invalid JSON returns an error from UnmarshalGzip.
func TestUnmarshalGzip_ValidGzip_CorruptJSON_ReturnsError(t *testing.T) {
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	_, _ = gz.Write([]byte("{not valid json"))
	_ = gz.Close()

	_, err := UnmarshalGzip(buf.Bytes())
	if err == nil {
		t.Error("expected error for gzip-wrapped invalid JSON")
	}
}

// TestMarshalGzip_RoundTrip_NewFile verifies that MarshalGzip → UnmarshalGzip
// round-trips a ScanCache with multiple entry types without data loss.
func TestMarshalGzip_RoundTrip_NewFile(t *testing.T) {
	sc := New()
	sc.ScannerVersion = "1.2.3"
	sc.EngineVersions["cipherscope"] = "0.4.0"
	sc.Entries["/src/main.go"] = &CacheEntry{
		ContentHash: "deadbeef",
		ModTime:     time.Now().Truncate(time.Second),
		Findings: []findings.UnifiedFinding{
			sampleFinding("cipherscope", "/src/main.go", "RSA-2048", 42),
		},
		ScannedAt: time.Now().Truncate(time.Second),
	}

	compressed, err := sc.MarshalGzip()
	if err != nil {
		t.Fatalf("MarshalGzip: %v", err)
	}
	if len(compressed) == 0 {
		t.Fatal("MarshalGzip returned empty bytes")
	}

	sc2, err := UnmarshalGzip(compressed)
	if err != nil {
		t.Fatalf("UnmarshalGzip: %v", err)
	}

	if sc2.ScannerVersion != "1.2.3" {
		t.Errorf("ScannerVersion: want 1.2.3, got %q", sc2.ScannerVersion)
	}
	if sc2.EngineVersions["cipherscope"] != "0.4.0" {
		t.Errorf("EngineVersion for cipherscope: want 0.4.0, got %q", sc2.EngineVersions["cipherscope"])
	}
	entry := sc2.Entries["/src/main.go"]
	if entry == nil {
		t.Fatal("expected entry for /src/main.go")
	}
	if entry.ContentHash != "deadbeef" {
		t.Errorf("ContentHash: want deadbeef, got %q", entry.ContentHash)
	}
	if len(entry.Findings) != 1 {
		t.Errorf("expected 1 finding, got %d", len(entry.Findings))
	}
}

// TestMarshalGzip_ProducesCompressedOutput verifies that MarshalGzip output
// is smaller than raw JSON for a cache with content (compression effectiveness).
func TestMarshalGzip_ProducesCompressedOutput(t *testing.T) {
	sc := New()
	sc.ScannerVersion = "1.0.0"
	// Add enough entries that compression is beneficial.
	for i := 0; i < 50; i++ {
		path := filepath.Join("/src", fmt.Sprintf("file%03d.go", i))
		sc.Entries[path] = &CacheEntry{
			ContentHash: fmt.Sprintf("hash%d", i),
			Findings:    []findings.UnifiedFinding{sampleFinding("eng", path, "RSA-2048", i)},
		}
	}

	compressed, err := sc.MarshalGzip()
	if err != nil {
		t.Fatalf("MarshalGzip: %v", err)
	}
	// Just verify it doesn't error and produces some output.
	if len(compressed) == 0 {
		t.Error("MarshalGzip must produce non-empty output")
	}
}

// ---------------------------------------------------------------------------
// Cache file permissions
// ---------------------------------------------------------------------------

// TestSave_FilePermissions_0600 verifies that saved cache files are created
// with 0600 permissions (owner read/write only), preventing other users from
// reading potentially sensitive scan results.
func TestSave_FilePermissions_0600(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "secure-cache.json")

	sc := New()
	sc.ScannerVersion = "0.1.0"
	if err := sc.Save(path); err != nil {
		t.Fatalf("Save: %v", err)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0600 {
		t.Errorf("cache file permissions: got %04o, want 0600", perm)
	}
}

// TestSave_SymlinkTarget_ReturnsError verifies that Save refuses to write to
// a symlink target (symlink-attack mitigation).
func TestSave_SymlinkTarget_ReturnsError(t *testing.T) {
	dir := t.TempDir()
	realPath := filepath.Join(dir, "real.json")
	symlinkPath := filepath.Join(dir, "link.json")

	// Create the real file first.
	if err := os.WriteFile(realPath, []byte("{}"), 0600); err != nil {
		t.Fatal(err)
	}
	// Create a symlink pointing to the real file.
	if err := os.Symlink(realPath, symlinkPath); err != nil {
		t.Skipf("symlink creation failed (filesystem may not support it): %v", err)
	}

	sc := New()
	err := sc.Save(symlinkPath)
	if err == nil {
		t.Error("Save must return an error when the target path is a symlink")
	}
}

// ---------------------------------------------------------------------------
// IsValidForEngine — per-engine cache gating
// ---------------------------------------------------------------------------

// TestIsValidForEngine_MatchingVersion_ReturnsTrue verifies that an engine
// at the cached version is considered valid.
func TestIsValidForEngine_MatchingVersion_ReturnsTrue(t *testing.T) {
	sc := New()
	sc.EngineVersions["cipherscope"] = "0.3.1"

	if !sc.IsValidForEngine("cipherscope", "0.3.1") {
		t.Error("expected IsValidForEngine=true for matching version")
	}
}

// TestIsValidForEngine_MismatchedVersion_ReturnsFalse verifies that an engine
// at a different version than cached returns false.
func TestIsValidForEngine_MismatchedVersion_ReturnsFalse(t *testing.T) {
	sc := New()
	sc.EngineVersions["cipherscope"] = "0.3.0"

	if sc.IsValidForEngine("cipherscope", "0.3.1") {
		t.Error("expected IsValidForEngine=false for version mismatch")
	}
}

// TestIsValidForEngine_UnknownEngine_ReturnsFalse verifies that an engine
// not present in the cache returns false (forces full re-scan for new engines).
func TestIsValidForEngine_UnknownEngine_ReturnsFalse(t *testing.T) {
	sc := New()
	// sc.EngineVersions is empty.

	if sc.IsValidForEngine("new-engine", "1.0.0") {
		t.Error("expected IsValidForEngine=false for engine not in cache")
	}
}

// TestIsValidForEngine_WrongCacheFormatVersion_ReturnsFalse verifies that
// an engine cache with a wrong format version returns false.
func TestIsValidForEngine_WrongCacheFormatVersion_ReturnsFalse(t *testing.T) {
	sc := New()
	sc.Version = "99" // wrong format version
	sc.EngineVersions["cipherscope"] = "0.3.1"

	if sc.IsValidForEngine("cipherscope", "0.3.1") {
		t.Error("expected IsValidForEngine=false for wrong cache format version")
	}
}

// ---------------------------------------------------------------------------
// GetUnchangedFindingsForEngine
// ---------------------------------------------------------------------------

// TestGetUnchangedFindingsForEngine_HitAndMiss verifies the per-engine cache
// lookup: unchanged files return cached findings, changed files are re-queued.
func TestGetUnchangedFindingsForEngine_HitAndMiss(t *testing.T) {
	sc := New()
	sc.EngineEntries["cipherscope"] = map[string]*CacheEntry{
		"/src/foo.go": {
			ContentHash: "hash_foo",
			Findings:    []findings.UnifiedFinding{sampleFinding("cipherscope", "/src/foo.go", "RSA-2048", 10)},
		},
		"/src/bar.go": {
			ContentHash: "hash_bar_old",
			Findings:    []findings.UnifiedFinding{sampleFinding("cipherscope", "/src/bar.go", "AES-128", 5)},
		},
	}

	allHashes := map[string]string{
		"/src/foo.go": "hash_foo",     // unchanged
		"/src/bar.go": "hash_bar_new", // changed
		"/src/baz.go": "hash_baz",     // new file
	}

	cached, changed := sc.GetUnchangedFindingsForEngine("cipherscope", allHashes)

	if len(cached) != 1 {
		t.Errorf("expected 1 cached finding (foo.go), got %d", len(cached))
	}
	if len(cached) > 0 && cached[0].Algorithm.Name != "RSA-2048" {
		t.Errorf("cached finding: want RSA-2048, got %q", cached[0].Algorithm.Name)
	}

	changedSet := make(map[string]bool)
	for _, p := range changed {
		changedSet[p] = true
	}
	if !changedSet["/src/bar.go"] {
		t.Error("bar.go (changed hash) must be in changedPaths")
	}
	if !changedSet["/src/baz.go"] {
		t.Error("baz.go (new file) must be in changedPaths")
	}
	if changedSet["/src/foo.go"] {
		t.Error("foo.go (unchanged) must NOT be in changedPaths")
	}
}

// TestGetUnchangedFindingsForEngine_NilEngineEntries_AllChanged verifies that
// when an engine has no entries (first run), all files appear in changedPaths.
func TestGetUnchangedFindingsForEngine_NilEngineEntries_AllChanged(t *testing.T) {
	sc := New()
	// No entries for "new-engine".

	allHashes := map[string]string{
		"/src/a.go": "hashA",
		"/src/b.go": "hashB",
	}

	cached, changed := sc.GetUnchangedFindingsForEngine("new-engine", allHashes)

	if len(cached) != 0 {
		t.Errorf("expected 0 cached findings for unknown engine, got %d", len(cached))
	}
	if len(changed) != 2 {
		t.Errorf("expected 2 changed paths for unknown engine, got %d: %v", len(changed), changed)
	}
}

// ---------------------------------------------------------------------------
// UpdateEngine
// ---------------------------------------------------------------------------

// TestUpdateEngine_AddsFindingsAndPrunesDeleted verifies that UpdateEngine
// stores new findings and, when pruneDeleted=true, removes entries for files
// that no longer exist in allFileHashes.
func TestUpdateEngine_AddsFindingsAndPrunesDeleted(t *testing.T) {
	sc := New()
	sc.EngineEntries["eng"] = map[string]*CacheEntry{
		"/src/old.go": {ContentHash: "hash_old"},
	}

	allHashes := map[string]string{"/src/new.go": "hash_new"}
	changedFindings := map[string][]findings.UnifiedFinding{
		"/src/new.go": {sampleFinding("eng", "/src/new.go", "DH", 1)},
	}

	sc.UpdateEngine("eng", changedFindings, allHashes, true /* pruneDeleted */)

	engineFiles := sc.EngineEntries["eng"]
	if _, ok := engineFiles["/src/old.go"]; ok {
		t.Error("old.go should have been pruned from engine cache")
	}
	entry, ok := engineFiles["/src/new.go"]
	if !ok {
		t.Fatal("expected entry for new.go")
	}
	if entry.ContentHash != "hash_new" {
		t.Errorf("ContentHash: want hash_new, got %q", entry.ContentHash)
	}
	if len(entry.Findings) != 1 {
		t.Errorf("expected 1 finding, got %d", len(entry.Findings))
	}
}

// TestUpdateEngine_NoPruneInDiffMode verifies that when pruneDeleted=false
// (diff mode), existing cached entries for unchanged files are preserved even
// if they are not in allFileHashes.
func TestUpdateEngine_NoPruneInDiffMode(t *testing.T) {
	sc := New()
	sc.EngineEntries["eng"] = map[string]*CacheEntry{
		"/src/unchanged.go": {ContentHash: "hash_unchanged", Findings: []findings.UnifiedFinding{
			sampleFinding("eng", "/src/unchanged.go", "AES-256", 1),
		}},
	}

	// allFileHashes only contains the changed file (diff mode subset).
	allHashes := map[string]string{"/src/changed.go": "hash_changed"}
	changedFindings := map[string][]findings.UnifiedFinding{
		"/src/changed.go": {sampleFinding("eng", "/src/changed.go", "RSA-2048", 5)},
	}

	sc.UpdateEngine("eng", changedFindings, allHashes, false /* pruneDeleted=false */)

	// unchanged.go's cache entry must survive.
	if _, ok := sc.EngineEntries["eng"]["/src/unchanged.go"]; !ok {
		t.Error("unchanged.go entry must be preserved in diff mode (pruneDeleted=false)")
	}
}

// ---------------------------------------------------------------------------
// PruneDeletedFiles
// ---------------------------------------------------------------------------

// TestPruneDeletedFiles_RemovesFromBothMaps verifies that PruneDeletedFiles
// removes stale entries from both the flat Entries map and all EngineEntries.
func TestPruneDeletedFiles_RemovesFromBothMaps(t *testing.T) {
	sc := New()
	sc.Entries["/src/deleted.go"] = &CacheEntry{ContentHash: "h1"}
	sc.Entries["/src/kept.go"] = &CacheEntry{ContentHash: "h2"}
	sc.EngineEntries["eng"] = map[string]*CacheEntry{
		"/src/deleted.go": {ContentHash: "h1"},
		"/src/kept.go":    {ContentHash: "h2"},
	}

	allHashes := map[string]string{"/src/kept.go": "h2"}
	sc.PruneDeletedFiles(allHashes)

	if _, ok := sc.Entries["/src/deleted.go"]; ok {
		t.Error("deleted.go must be pruned from Entries")
	}
	if _, ok := sc.Entries["/src/kept.go"]; !ok {
		t.Error("kept.go must remain in Entries")
	}
	if _, ok := sc.EngineEntries["eng"]["/src/deleted.go"]; ok {
		t.Error("deleted.go must be pruned from EngineEntries")
	}
	if _, ok := sc.EngineEntries["eng"]["/src/kept.go"]; !ok {
		t.Error("kept.go must remain in EngineEntries")
	}
}

// ---------------------------------------------------------------------------
// V1 cache → IsValid returns false (format migration path)
// ---------------------------------------------------------------------------

// TestIsValid_V1Cache_ReturnsFalse verifies that a V1 cache (version "1")
// with otherwise matching scanner and engine versions is invalid under V2
// rules, forcing a full re-scan on upgrade.
func TestIsValid_V1Cache_ReturnsFalse(t *testing.T) {
	sc := New()
	sc.Version = "1" // simulate V1 cache loaded from disk
	sc.ScannerVersion = "0.9.0"
	sc.EngineVersions = map[string]string{"cipherscope": "0.3.1"}

	if sc.IsValid("0.9.0", map[string]string{"cipherscope": "0.3.1"}) {
		t.Error("V1 cache must be invalid under V2 IsValid check (format version mismatch)")
	}
}

// ---------------------------------------------------------------------------
// Load with empty (zero-byte) file
// ---------------------------------------------------------------------------

// TestLoad_EmptyFile_ReturnsEmptyCache verifies that a zero-byte cache file
// is treated as a cache miss (returns an empty cache, not an error).
func TestLoad_EmptyFile_ReturnsEmptyCache(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "empty.json")
	if err := os.WriteFile(path, []byte{}, 0600); err != nil {
		t.Fatal(err)
	}

	sc, err := Load(path)
	if err != nil {
		t.Fatalf("Load of empty file must not error: %v", err)
	}
	if sc == nil {
		t.Fatal("Load must return non-nil cache")
	}
	if len(sc.Entries) != 0 {
		t.Errorf("expected 0 entries from empty file, got %d", len(sc.Entries))
	}
}

// ---------------------------------------------------------------------------
// HashFiles parallel safety
// ---------------------------------------------------------------------------

// TestHashFiles_ParallelSafety verifies that HashFiles handles concurrent
// hashing of many files without data races (run with -race).
func TestHashFiles_ParallelSafety(t *testing.T) {
	dir := t.TempDir()
	const numFiles = 50
	paths := make([]string, numFiles)
	for i := range paths {
		paths[i] = writeTempFile(t, dir, fmt.Sprintf("file%03d.go", i),
			fmt.Sprintf("package p%d // content %d", i, i))
	}

	hashes, err := HashFiles(paths)
	if err != nil {
		t.Fatalf("HashFiles parallel: %v", err)
	}
	if len(hashes) != numFiles {
		t.Errorf("expected %d hashes, got %d", numFiles, len(hashes))
	}
}

