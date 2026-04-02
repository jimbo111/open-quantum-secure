package cache

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jimbo111/open-quantum-secure/pkg/findings"
)

// -- helpers --

func sampleFinding(engine, file, alg string, line int) findings.UnifiedFinding {
	return findings.UnifiedFinding{
		Location:     findings.Location{File: file, Line: line},
		Algorithm:    &findings.Algorithm{Name: alg},
		Confidence:   findings.ConfidenceMedium,
		SourceEngine: engine,
		Reachable:    findings.ReachableUnknown,
	}
}

func writeTempFile(t *testing.T, dir, name, content string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatalf("write temp file: %v", err)
	}
	return path
}

// -- Load tests --

func TestLoad_NonExistentFile_ReturnsEmptyCache(t *testing.T) {
	sc, err := Load("/tmp/does-not-exist-oqs-cache.json")
	if err != nil {
		t.Fatalf("expected nil error, got: %v", err)
	}
	if sc == nil {
		t.Fatal("expected non-nil cache")
	}
	if len(sc.Entries) != 0 {
		t.Errorf("expected 0 entries, got %d", len(sc.Entries))
	}
	if sc.Version != cacheFormatVersion {
		t.Errorf("expected version %q, got %q", cacheFormatVersion, sc.Version)
	}
}

func TestLoad_CorruptJSON_ReturnsEmptyCache(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "cache.json")
	if err := os.WriteFile(path, []byte("{not valid json"), 0644); err != nil {
		t.Fatal(err)
	}

	sc, err := Load(path)
	if err != nil {
		t.Fatalf("expected nil error for corrupt file, got: %v", err)
	}
	if len(sc.Entries) != 0 {
		t.Errorf("expected 0 entries after corrupt load, got %d", len(sc.Entries))
	}
}

func TestLoad_NullMaps_InitializedToNonNil(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "cache.json")
	// JSON with explicit null maps.
	data := `{"version":"1","scannerVersion":"v1","engineVersions":null,"entries":null}`
	if err := os.WriteFile(path, []byte(data), 0644); err != nil {
		t.Fatal(err)
	}

	sc, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if sc.EngineVersions == nil {
		t.Error("EngineVersions should not be nil after load")
	}
	if sc.EngineEntries == nil {
		t.Error("EngineEntries should not be nil after load")
	}
	if sc.Entries == nil {
		t.Error("Entries should not be nil after load")
	}
}

// -- Save / round-trip tests --

func TestSaveAndLoad_RoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "cache.json")

	sc := New()
	sc.ScannerVersion = "0.9.0"
	sc.EngineVersions = map[string]string{"cipherscope": "0.3.1", "ast-grep": "0.15.0"}
	sc.Entries["/src/foo.go"] = &CacheEntry{
		ContentHash: "abc123",
		ModTime:     time.Now().Truncate(time.Millisecond),
		Findings:    []findings.UnifiedFinding{sampleFinding("ast-grep", "/src/foo.go", "AES-128", 42)},
		ScannedAt:   time.Now().Truncate(time.Millisecond),
	}

	if err := sc.Save(path); err != nil {
		t.Fatalf("Save failed: %v", err)
	}

	// Verify file exists with 0644 perms.
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat cache file: %v", err)
	}
	if info.Mode().Perm() != 0600 {
		t.Errorf("expected 0600 perms, got %o", info.Mode().Perm())
	}

	loaded, err := Load(path)
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}

	if loaded.ScannerVersion != sc.ScannerVersion {
		t.Errorf("ScannerVersion: want %q, got %q", sc.ScannerVersion, loaded.ScannerVersion)
	}
	if loaded.EngineVersions["cipherscope"] != "0.3.1" {
		t.Errorf("engine version mismatch")
	}
	entry, ok := loaded.Entries["/src/foo.go"]
	if !ok {
		t.Fatal("expected entry for /src/foo.go")
	}
	if entry.ContentHash != "abc123" {
		t.Errorf("ContentHash: want abc123, got %q", entry.ContentHash)
	}
	if len(entry.Findings) != 1 {
		t.Errorf("expected 1 finding, got %d", len(entry.Findings))
	}
	if entry.Findings[0].Algorithm.Name != "AES-128" {
		t.Errorf("finding algorithm: got %q", entry.Findings[0].Algorithm.Name)
	}
}

func TestSave_AtomicWrite_NoTempFileLeft(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "cache.json")

	sc := New()
	if err := sc.Save(path); err != nil {
		t.Fatalf("Save failed: %v", err)
	}

	// No temp files should remain.
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if e.Name() != "cache.json" {
			t.Errorf("unexpected leftover file: %s", e.Name())
		}
	}
}

func TestSave_WritesValidJSON(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "cache.json")

	sc := New()
	sc.ScannerVersion = "1.0.0"
	if err := sc.Save(path); err != nil {
		t.Fatal(err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]interface{}
	if err := json.Unmarshal(data, &m); err != nil {
		t.Errorf("saved JSON is not valid: %v", err)
	}
}

// -- IsValid tests --

func TestIsValid_MatchingVersions_ReturnsTrue(t *testing.T) {
	sc := New()
	sc.ScannerVersion = "0.9.0"
	sc.EngineVersions = map[string]string{"cipherscope": "0.3.1"}

	if !sc.IsValid("0.9.0", map[string]string{"cipherscope": "0.3.1"}) {
		t.Error("expected IsValid=true for matching versions")
	}
}

func TestIsValid_DifferentScannerVersion_ReturnsFalse(t *testing.T) {
	sc := New()
	sc.ScannerVersion = "0.9.0"
	if sc.IsValid("0.10.0", map[string]string{}) {
		t.Error("expected IsValid=false for different scanner version")
	}
}

func TestIsValid_DifferentEngineVersion_ReturnsFalse(t *testing.T) {
	sc := New()
	sc.ScannerVersion = "0.9.0"
	sc.EngineVersions = map[string]string{"cipherscope": "0.3.0"}

	if sc.IsValid("0.9.0", map[string]string{"cipherscope": "0.3.1"}) {
		t.Error("expected IsValid=false for different engine version")
	}
}

func TestIsValid_ExtraEngine_ReturnsFalse(t *testing.T) {
	sc := New()
	sc.ScannerVersion = "0.9.0"
	sc.EngineVersions = map[string]string{"cipherscope": "0.3.1"}

	// Current run has an extra engine.
	if sc.IsValid("0.9.0", map[string]string{"cipherscope": "0.3.1", "ast-grep": "0.15.0"}) {
		t.Error("expected IsValid=false when current has extra engine")
	}
}

func TestIsValid_WrongCacheFormatVersion_ReturnsFalse(t *testing.T) {
	sc := New()
	sc.Version = "99"
	sc.ScannerVersion = "0.9.0"
	if sc.IsValid("0.9.0", map[string]string{}) {
		t.Error("expected IsValid=false for wrong cache format version")
	}
}

// -- GetUnchangedFindings tests --

func TestGetUnchangedFindings_AllUnchanged(t *testing.T) {
	sc := New()
	sc.Entries["/src/foo.go"] = &CacheEntry{
		ContentHash: "hash1",
		Findings:    []findings.UnifiedFinding{sampleFinding("ag", "/src/foo.go", "RSA-1024", 10)},
	}
	sc.Entries["/src/bar.go"] = &CacheEntry{
		ContentHash: "hash2",
		Findings:    []findings.UnifiedFinding{sampleFinding("ag", "/src/bar.go", "AES-128", 20)},
	}

	allHashes := map[string]string{
		"/src/foo.go": "hash1",
		"/src/bar.go": "hash2",
	}

	cached, changed := sc.GetUnchangedFindings(allHashes)
	if len(changed) != 0 {
		t.Errorf("expected 0 changed, got %d: %v", len(changed), changed)
	}
	if len(cached) != 2 {
		t.Errorf("expected 2 cached findings, got %d", len(cached))
	}
}

func TestGetUnchangedFindings_ModifiedFile_AppearsInChanged(t *testing.T) {
	sc := New()
	sc.Entries["/src/foo.go"] = &CacheEntry{
		ContentHash: "oldhash",
		Findings:    []findings.UnifiedFinding{sampleFinding("ag", "/src/foo.go", "RSA-1024", 10)},
	}

	allHashes := map[string]string{
		"/src/foo.go": "newhash", // content changed
	}

	cached, changed := sc.GetUnchangedFindings(allHashes)
	if len(cached) != 0 {
		t.Errorf("expected 0 cached findings for modified file, got %d", len(cached))
	}
	if len(changed) != 1 || changed[0] != "/src/foo.go" {
		t.Errorf("expected changed=[/src/foo.go], got %v", changed)
	}
}

func TestGetUnchangedFindings_NewFile_AppearsInChanged(t *testing.T) {
	sc := New() // empty cache — no entries

	allHashes := map[string]string{
		"/src/new.go": "hashA",
	}

	cached, changed := sc.GetUnchangedFindings(allHashes)
	if len(cached) != 0 {
		t.Errorf("expected 0 cached, got %d", len(cached))
	}
	if len(changed) != 1 || changed[0] != "/src/new.go" {
		t.Errorf("expected changed=[/src/new.go], got %v", changed)
	}
}

func TestGetUnchangedFindings_DeletedFile_FindingsNotReturned(t *testing.T) {
	sc := New()
	// File exists in cache but is not in allFileHashes (deleted).
	sc.Entries["/src/deleted.go"] = &CacheEntry{
		ContentHash: "hash1",
		Findings:    []findings.UnifiedFinding{sampleFinding("ag", "/src/deleted.go", "MD5", 5)},
	}

	// Current disk has no files.
	cached, changed := sc.GetUnchangedFindings(map[string]string{})
	if len(cached) != 0 {
		t.Errorf("expected 0 cached (deleted file), got %d", len(cached))
	}
	if len(changed) != 0 {
		t.Errorf("expected 0 changed (deleted file not re-queued), got %v", changed)
	}
}

func TestGetUnchangedFindings_MixedState(t *testing.T) {
	sc := New()
	sc.Entries["/src/unchanged.go"] = &CacheEntry{
		ContentHash: "hashU",
		Findings:    []findings.UnifiedFinding{sampleFinding("ag", "/src/unchanged.go", "AES-256", 1)},
	}
	sc.Entries["/src/modified.go"] = &CacheEntry{
		ContentHash: "hashOld",
		Findings:    []findings.UnifiedFinding{sampleFinding("ag", "/src/modified.go", "RSA-512", 2)},
	}
	// /src/deleted.go is in cache but not on disk.
	sc.Entries["/src/deleted.go"] = &CacheEntry{
		ContentHash: "hashD",
		Findings:    []findings.UnifiedFinding{sampleFinding("ag", "/src/deleted.go", "DES", 3)},
	}

	allHashes := map[string]string{
		"/src/unchanged.go": "hashU",
		"/src/modified.go":  "hashNew",  // changed
		"/src/new.go":       "hashN",    // new file
	}

	cached, changed := sc.GetUnchangedFindings(allHashes)

	if len(cached) != 1 || cached[0].Algorithm.Name != "AES-256" {
		t.Errorf("expected 1 cached finding (AES-256), got %v", cached)
	}

	// Both modified and new should appear in changed.
	changedSet := make(map[string]bool)
	for _, p := range changed {
		changedSet[p] = true
	}
	if !changedSet["/src/modified.go"] {
		t.Error("expected /src/modified.go in changed")
	}
	if !changedSet["/src/new.go"] {
		t.Error("expected /src/new.go in changed")
	}
	if changedSet["/src/deleted.go"] {
		t.Error("deleted file should not appear in changed")
	}
}

// -- Update tests --

func TestUpdate_AddsNewEntries(t *testing.T) {
	sc := New()

	allHashes := map[string]string{"/src/foo.go": "hash1"}
	changedFindings := map[string][]findings.UnifiedFinding{
		"/src/foo.go": {sampleFinding("ag", "/src/foo.go", "RSA-1024", 10)},
	}

	sc.Update(changedFindings, allHashes)

	entry, ok := sc.Entries["/src/foo.go"]
	if !ok {
		t.Fatal("expected entry for /src/foo.go")
	}
	if entry.ContentHash != "hash1" {
		t.Errorf("ContentHash: want hash1, got %q", entry.ContentHash)
	}
	if len(entry.Findings) != 1 {
		t.Errorf("expected 1 finding, got %d", len(entry.Findings))
	}
	if entry.ScannedAt.IsZero() {
		t.Error("ScannedAt should not be zero")
	}
}

func TestUpdate_UpdatesExistingEntry(t *testing.T) {
	sc := New()
	sc.Entries["/src/foo.go"] = &CacheEntry{
		ContentHash: "oldhash",
		Findings:    []findings.UnifiedFinding{sampleFinding("ag", "/src/foo.go", "RSA-1024", 10)},
	}

	allHashes := map[string]string{"/src/foo.go": "newhash"}
	changedFindings := map[string][]findings.UnifiedFinding{
		"/src/foo.go": {sampleFinding("ag", "/src/foo.go", "AES-256", 5)},
	}

	sc.Update(changedFindings, allHashes)

	entry := sc.Entries["/src/foo.go"]
	if entry.ContentHash != "newhash" {
		t.Errorf("expected newhash, got %q", entry.ContentHash)
	}
	if entry.Findings[0].Algorithm.Name != "AES-256" {
		t.Errorf("expected updated finding AES-256, got %q", entry.Findings[0].Algorithm.Name)
	}
}

func TestUpdate_PrunesDeletedFiles(t *testing.T) {
	sc := New()
	sc.Entries["/src/gone.go"] = &CacheEntry{ContentHash: "hashG"}
	sc.Entries["/src/kept.go"] = &CacheEntry{ContentHash: "hashK"}

	// Only /src/kept.go is still on disk.
	allHashes := map[string]string{"/src/kept.go": "hashK"}
	sc.Update(map[string][]findings.UnifiedFinding{}, allHashes)

	if _, ok := sc.Entries["/src/gone.go"]; ok {
		t.Error("expected /src/gone.go to be pruned from cache")
	}
	if _, ok := sc.Entries["/src/kept.go"]; !ok {
		t.Error("expected /src/kept.go to remain in cache")
	}
}

func TestUpdate_SkipsFilesNotOnDisk(t *testing.T) {
	// A file appears in changedFindings but not in allFileHashes (race condition
	// or error during hashing). It should not be added to the cache.
	sc := New()

	changedFindings := map[string][]findings.UnifiedFinding{
		"/src/phantom.go": {sampleFinding("ag", "/src/phantom.go", "RSA-1024", 1)},
	}
	allHashes := map[string]string{} // phantom.go not on disk

	sc.Update(changedFindings, allHashes)

	if _, ok := sc.Entries["/src/phantom.go"]; ok {
		t.Error("phantom file should not be cached when not in allFileHashes")
	}
}

// -- HashFile / HashFiles tests --

func TestHashFile_KnownContent(t *testing.T) {
	dir := t.TempDir()
	path := writeTempFile(t, dir, "test.go", "hello world")

	hash, err := HashFile(path)
	if err != nil {
		t.Fatalf("HashFile: %v", err)
	}
	// sha256("hello world") verified via: echo -n "hello world" | sha256sum
	want := "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
	if hash != want {
		t.Errorf("HashFile(\"hello world\") = %q, want %q", hash, want)
	}
}

func TestHashFile_NonExistent_ReturnsError(t *testing.T) {
	_, err := HashFile("/tmp/does-not-exist-oqs-test-file.txt")
	if err == nil {
		t.Error("expected error for non-existent file")
	}
}

func TestHashFile_Deterministic(t *testing.T) {
	dir := t.TempDir()
	path := writeTempFile(t, dir, "test.txt", "deterministic content 42")

	h1, err := HashFile(path)
	if err != nil {
		t.Fatal(err)
	}
	h2, err := HashFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if h1 != h2 {
		t.Errorf("hash is not deterministic: %q != %q", h1, h2)
	}
}

func TestHashFiles_MultipleFiles(t *testing.T) {
	dir := t.TempDir()
	p1 := writeTempFile(t, dir, "a.go", "content a")
	p2 := writeTempFile(t, dir, "b.go", "content b")
	p3 := writeTempFile(t, dir, "c.go", "content c")

	hashes, err := HashFiles([]string{p1, p2, p3})
	if err != nil {
		t.Fatalf("HashFiles: %v", err)
	}
	if len(hashes) != 3 {
		t.Errorf("expected 3 hashes, got %d", len(hashes))
	}
	for _, p := range []string{p1, p2, p3} {
		if hashes[p] == "" {
			t.Errorf("missing hash for %s", p)
		}
	}
	// All hashes should be distinct (different content).
	seen := make(map[string]bool)
	for _, h := range hashes {
		if seen[h] {
			t.Error("unexpected duplicate hash for different content")
		}
		seen[h] = true
	}
}

func TestHashFiles_ContentChanges_HashChanges(t *testing.T) {
	dir := t.TempDir()
	path := writeTempFile(t, dir, "foo.go", "original content")

	hashes1, err := HashFiles([]string{path})
	if err != nil {
		t.Fatal(err)
	}

	// Modify the file.
	if err := os.WriteFile(path, []byte("modified content"), 0644); err != nil {
		t.Fatal(err)
	}

	hashes2, err := HashFiles([]string{path})
	if err != nil {
		t.Fatal(err)
	}

	if hashes1[path] == hashes2[path] {
		t.Error("hash should change when file content changes")
	}
}

func TestHashFiles_EmptyList_ReturnsEmptyMap(t *testing.T) {
	hashes, err := HashFiles([]string{})
	if err != nil {
		t.Fatalf("HashFiles with empty list: %v", err)
	}
	if len(hashes) != 0 {
		t.Errorf("expected empty map, got %d entries", len(hashes))
	}
}

// -- Integration-style test: full cache lifecycle --

func TestCacheLifecycle_FirstScanThenIncremental(t *testing.T) {
	dir := t.TempDir()
	cachePath := filepath.Join(dir, ".oqs-cache.json")

	// Create two source files.
	fileA := writeTempFile(t, dir, "a.go", "package main // uses AES")
	fileB := writeTempFile(t, dir, "b.go", "package main // uses RSA")

	// Simulate first (full) scan.
	hashesFirst, err := HashFiles([]string{fileA, fileB})
	if err != nil {
		t.Fatal(err)
	}

	findingsA := []findings.UnifiedFinding{sampleFinding("ag", fileA, "AES-256", 1)}
	findingsB := []findings.UnifiedFinding{sampleFinding("ag", fileB, "RSA-2048", 1)}

	sc := New()
	sc.ScannerVersion = "0.9.0"
	sc.EngineVersions = map[string]string{"ast-grep": "0.15.0"}
	sc.Update(map[string][]findings.UnifiedFinding{
		fileA: findingsA,
		fileB: findingsB,
	}, hashesFirst)

	if err := sc.Save(cachePath); err != nil {
		t.Fatalf("Save: %v", err)
	}

	// --- Second scan: no files changed ---
	sc2, err := Load(cachePath)
	if err != nil {
		t.Fatal(err)
	}

	if !sc2.IsValid("0.9.0", map[string]string{"ast-grep": "0.15.0"}) {
		t.Fatal("cache should be valid on second scan")
	}

	hashesSecond, err := HashFiles([]string{fileA, fileB})
	if err != nil {
		t.Fatal(err)
	}

	cached, changed := sc2.GetUnchangedFindings(hashesSecond)
	if len(changed) != 0 {
		t.Errorf("expected no changed files, got %v", changed)
	}
	if len(cached) != 2 {
		t.Errorf("expected 2 cached findings, got %d", len(cached))
	}

	// --- Third scan: file A modified ---
	if err := os.WriteFile(fileA, []byte("package main // now uses ChaCha20"), 0644); err != nil {
		t.Fatal(err)
	}

	hashesThird, err := HashFiles([]string{fileA, fileB})
	if err != nil {
		t.Fatal(err)
	}

	cachedThird, changedThird := sc2.GetUnchangedFindings(hashesThird)
	if len(changedThird) != 1 || changedThird[0] != fileA {
		t.Errorf("expected only fileA changed, got %v", changedThird)
	}
	// fileB should still be cached.
	if len(cachedThird) != 1 || cachedThird[0].Algorithm.Name != "RSA-2048" {
		t.Errorf("expected cached finding for fileB (RSA-2048), got %v", cachedThird)
	}

	// Update cache with new finding for fileA.
	newFindingsA := []findings.UnifiedFinding{sampleFinding("ag", fileA, "ChaCha20", 1)}
	sc2.Update(map[string][]findings.UnifiedFinding{fileA: newFindingsA}, hashesThird)

	if err := sc2.Save(cachePath); err != nil {
		t.Fatalf("Save after update: %v", err)
	}

	// Reload and verify.
	sc3, err := Load(cachePath)
	if err != nil {
		t.Fatal(err)
	}
	entryA := sc3.Entries[fileA]
	if entryA == nil {
		t.Fatal("expected entry for fileA")
	}
	if len(entryA.Findings) != 1 || entryA.Findings[0].Algorithm.Name != "ChaCha20" {
		t.Errorf("expected ChaCha20 finding, got %v", entryA.Findings)
	}

	// --- Fourth scan: file B deleted ---
	if err := os.Remove(fileB); err != nil {
		t.Fatal(err)
	}
	hashesForDeletion, err := HashFiles([]string{fileA})
	if err != nil {
		t.Fatal(err)
	}

	sc3.Update(map[string][]findings.UnifiedFinding{}, hashesForDeletion)

	if _, ok := sc3.Entries[fileB]; ok {
		t.Error("deleted file should be pruned from cache")
	}
	if _, ok := sc3.Entries[fileA]; !ok {
		t.Error("remaining file should still be in cache")
	}
}

// ============================================================================
// V2 per-engine cache tests
// ============================================================================

func TestNew_V2Format(t *testing.T) {
	sc := New()
	if sc.Version != "2" {
		t.Errorf("expected version 2, got %q", sc.Version)
	}
	if sc.EngineEntries == nil {
		t.Fatal("EngineEntries should be non-nil")
	}
	if len(sc.EngineEntries) != 0 {
		t.Errorf("expected 0 engine entries, got %d", len(sc.EngineEntries))
	}
}

func TestLoad_V1Cache_FormatMismatch(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "cache.json")
	// V1 cache — version "1".
	data := `{"version":"1","scannerVersion":"0.9.0","engineVersions":{"a":"1.0"},"entries":{"/f":{"contentHash":"h","findings":[]}}}`
	if err := os.WriteFile(path, []byte(data), 0644); err != nil {
		t.Fatal(err)
	}

	sc, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	// V1 cache loads successfully but IsValid returns false (format mismatch).
	if sc.IsValid("0.9.0", map[string]string{"a": "1.0"}) {
		t.Error("IsValid should return false for V1 cache (format mismatch)")
	}
	// EngineEntries should be initialized (empty since V1 JSON has no engineEntries).
	if sc.EngineEntries == nil {
		t.Error("EngineEntries should be initialized to non-nil")
	}
	// V1 entries are preserved in flat Entries.
	if sc.Entries["/f"] == nil {
		t.Error("V1 flat entries should be preserved after load")
	}
}

func TestLoad_V2Cache_PreservesEngineEntries(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "cache.json")

	sc := New()
	sc.ScannerVersion = "1.0.0"
	sc.EngineVersions["ast-grep"] = "0.15.0"
	sc.EngineEntries["ast-grep"] = map[string]*CacheEntry{
		"/src/foo.go": {
			ContentHash: "abc123",
			Findings:    []findings.UnifiedFinding{sampleFinding("ast-grep", "/src/foo.go", "AES-128", 42)},
		},
	}
	if err := sc.Save(path); err != nil {
		t.Fatal(err)
	}

	loaded, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.Version != "2" {
		t.Errorf("version: want 2, got %q", loaded.Version)
	}
	agEntries := loaded.EngineEntries["ast-grep"]
	if agEntries == nil {
		t.Fatal("expected engine entries for ast-grep")
	}
	entry := agEntries["/src/foo.go"]
	if entry == nil || entry.ContentHash != "abc123" {
		t.Errorf("expected entry with hash abc123, got %v", entry)
	}
	if len(entry.Findings) != 1 || entry.Findings[0].Algorithm.Name != "AES-128" {
		t.Errorf("expected AES-128 finding, got %v", entry.Findings)
	}
}

// -- IsValidForEngine tests --

func TestIsValidForEngine_MatchingVersion(t *testing.T) {
	sc := New()
	sc.EngineVersions["cipherscope"] = "0.3.1"

	if !sc.IsValidForEngine("cipherscope", "0.3.1") {
		t.Error("expected valid for matching engine version")
	}
}

func TestIsValidForEngine_MismatchedVersion(t *testing.T) {
	sc := New()
	sc.EngineVersions["cipherscope"] = "0.3.0"

	if sc.IsValidForEngine("cipherscope", "0.3.1") {
		t.Error("expected invalid for mismatched engine version")
	}
}

func TestIsValidForEngine_MissingEngine(t *testing.T) {
	sc := New()

	if sc.IsValidForEngine("cipherscope", "0.3.1") {
		t.Error("expected invalid for engine not in cache")
	}
}

func TestIsValidForEngine_WrongFormatVersion(t *testing.T) {
	sc := New()
	sc.Version = "1" // force V1 format
	sc.EngineVersions["cipherscope"] = "0.3.1"

	if sc.IsValidForEngine("cipherscope", "0.3.1") {
		t.Error("expected invalid for wrong format version")
	}
}

func TestIsValidForEngine_IndependentEngines(t *testing.T) {
	sc := New()
	sc.EngineVersions["cipherscope"] = "0.3.1"
	sc.EngineVersions["ast-grep"] = "0.15.0"

	// cipherscope upgraded, ast-grep unchanged.
	if sc.IsValidForEngine("cipherscope", "0.4.0") {
		t.Error("cipherscope should be invalid (version changed)")
	}
	if !sc.IsValidForEngine("ast-grep", "0.15.0") {
		t.Error("ast-grep should still be valid (version unchanged)")
	}
}

// -- GetUnchangedFindingsForEngine tests --

func TestGetUnchangedFindingsForEngine_AllUnchanged(t *testing.T) {
	sc := New()
	sc.EngineEntries["ast-grep"] = map[string]*CacheEntry{
		"/src/foo.go": {ContentHash: "h1", Findings: []findings.UnifiedFinding{sampleFinding("ag", "/src/foo.go", "RSA-1024", 10)}},
		"/src/bar.go": {ContentHash: "h2", Findings: []findings.UnifiedFinding{sampleFinding("ag", "/src/bar.go", "AES-128", 20)}},
	}

	hashes := map[string]string{"/src/foo.go": "h1", "/src/bar.go": "h2"}
	cached, changed := sc.GetUnchangedFindingsForEngine("ast-grep", hashes)

	if len(changed) != 0 {
		t.Errorf("expected 0 changed, got %v", changed)
	}
	if len(cached) != 2 {
		t.Errorf("expected 2 cached findings, got %d", len(cached))
	}
}

func TestGetUnchangedFindingsForEngine_ModifiedFile(t *testing.T) {
	sc := New()
	sc.EngineEntries["ast-grep"] = map[string]*CacheEntry{
		"/src/foo.go": {ContentHash: "oldhash", Findings: []findings.UnifiedFinding{sampleFinding("ag", "/src/foo.go", "RSA-1024", 10)}},
	}

	hashes := map[string]string{"/src/foo.go": "newhash"}
	cached, changed := sc.GetUnchangedFindingsForEngine("ast-grep", hashes)

	if len(cached) != 0 {
		t.Errorf("expected 0 cached, got %d", len(cached))
	}
	if len(changed) != 1 || changed[0] != "/src/foo.go" {
		t.Errorf("expected [/src/foo.go] changed, got %v", changed)
	}
}

func TestGetUnchangedFindingsForEngine_NoEngineEntries(t *testing.T) {
	sc := New() // no entries for any engine

	hashes := map[string]string{"/src/foo.go": "h1", "/src/bar.go": "h2"}
	cached, changed := sc.GetUnchangedFindingsForEngine("ast-grep", hashes)

	if len(cached) != 0 {
		t.Errorf("expected 0 cached, got %d", len(cached))
	}
	if len(changed) != 2 {
		t.Errorf("expected 2 changed, got %d", len(changed))
	}
}

func TestGetUnchangedFindingsForEngine_DeletedFile(t *testing.T) {
	sc := New()
	sc.EngineEntries["ast-grep"] = map[string]*CacheEntry{
		"/src/deleted.go": {ContentHash: "h1", Findings: []findings.UnifiedFinding{sampleFinding("ag", "/src/deleted.go", "MD5", 5)}},
	}

	// File no longer on disk.
	cached, changed := sc.GetUnchangedFindingsForEngine("ast-grep", map[string]string{})

	if len(cached) != 0 {
		t.Errorf("expected 0 cached for deleted file, got %d", len(cached))
	}
	if len(changed) != 0 {
		t.Errorf("expected 0 changed for deleted file, got %v", changed)
	}
}

func TestGetUnchangedFindingsForEngine_MixedState(t *testing.T) {
	sc := New()
	sc.EngineEntries["cipherscope"] = map[string]*CacheEntry{
		"/src/unchanged.go": {ContentHash: "hU", Findings: []findings.UnifiedFinding{sampleFinding("cs", "/src/unchanged.go", "AES-256", 1)}},
		"/src/modified.go":  {ContentHash: "hOld", Findings: []findings.UnifiedFinding{sampleFinding("cs", "/src/modified.go", "RSA-512", 2)}},
		"/src/deleted.go":   {ContentHash: "hD", Findings: []findings.UnifiedFinding{sampleFinding("cs", "/src/deleted.go", "DES", 3)}},
	}

	hashes := map[string]string{
		"/src/unchanged.go": "hU",
		"/src/modified.go":  "hNew",
		"/src/newfile.go":   "hN",
	}

	cached, changed := sc.GetUnchangedFindingsForEngine("cipherscope", hashes)

	if len(cached) != 1 || cached[0].Algorithm.Name != "AES-256" {
		t.Errorf("expected 1 cached (AES-256), got %v", cached)
	}

	changedSet := make(map[string]bool)
	for _, p := range changed {
		changedSet[p] = true
	}
	if !changedSet["/src/modified.go"] {
		t.Error("modified.go should be in changed")
	}
	if !changedSet["/src/newfile.go"] {
		t.Error("newfile.go should be in changed")
	}
	if changedSet["/src/deleted.go"] {
		t.Error("deleted.go should not be in changed")
	}
}

func TestGetUnchangedFindingsForEngine_MultipleEnginesSameFile(t *testing.T) {
	sc := New()
	// Two engines scanned the same file with different findings.
	sc.EngineEntries["ast-grep"] = map[string]*CacheEntry{
		"/src/foo.go": {ContentHash: "h1", Findings: []findings.UnifiedFinding{sampleFinding("ag", "/src/foo.go", "RSA-1024", 10)}},
	}
	sc.EngineEntries["cipherscope"] = map[string]*CacheEntry{
		"/src/foo.go": {ContentHash: "h1", Findings: []findings.UnifiedFinding{sampleFinding("cs", "/src/foo.go", "AES-128", 20)}},
	}

	hashes := map[string]string{"/src/foo.go": "h1"}

	// Each engine query returns its own findings independently.
	agCached, agChanged := sc.GetUnchangedFindingsForEngine("ast-grep", hashes)
	csCached, csChanged := sc.GetUnchangedFindingsForEngine("cipherscope", hashes)

	if len(agCached) != 1 || agCached[0].Algorithm.Name != "RSA-1024" {
		t.Errorf("ast-grep: expected RSA-1024, got %v", agCached)
	}
	if len(agChanged) != 0 {
		t.Errorf("ast-grep: expected 0 changed, got %v", agChanged)
	}
	if len(csCached) != 1 || csCached[0].Algorithm.Name != "AES-128" {
		t.Errorf("cipherscope: expected AES-128, got %v", csCached)
	}
	if len(csChanged) != 0 {
		t.Errorf("cipherscope: expected 0 changed, got %v", csChanged)
	}
}

// -- UpdateEngine tests --

func TestUpdateEngine_CreatesNewEntries(t *testing.T) {
	sc := New()

	hashes := map[string]string{"/src/foo.go": "h1"}
	changedFindings := map[string][]findings.UnifiedFinding{
		"/src/foo.go": {sampleFinding("ag", "/src/foo.go", "RSA-1024", 10)},
	}

	sc.UpdateEngine("ast-grep", changedFindings, hashes, true)

	engineFiles := sc.EngineEntries["ast-grep"]
	if engineFiles == nil {
		t.Fatal("expected engine entries for ast-grep")
	}
	entry := engineFiles["/src/foo.go"]
	if entry == nil || entry.ContentHash != "h1" {
		t.Errorf("expected entry with hash h1, got %v", entry)
	}
	if len(entry.Findings) != 1 {
		t.Errorf("expected 1 finding, got %d", len(entry.Findings))
	}
	if entry.ScannedAt.IsZero() {
		t.Error("ScannedAt should not be zero")
	}
}

func TestUpdateEngine_UpdatesExistingEntry(t *testing.T) {
	sc := New()
	sc.EngineEntries["ast-grep"] = map[string]*CacheEntry{
		"/src/foo.go": {ContentHash: "oldhash", Findings: []findings.UnifiedFinding{sampleFinding("ag", "/src/foo.go", "RSA-1024", 10)}},
	}

	hashes := map[string]string{"/src/foo.go": "newhash"}
	changedFindings := map[string][]findings.UnifiedFinding{
		"/src/foo.go": {sampleFinding("ag", "/src/foo.go", "AES-256", 5)},
	}

	sc.UpdateEngine("ast-grep", changedFindings, hashes, true)

	entry := sc.EngineEntries["ast-grep"]["/src/foo.go"]
	if entry.ContentHash != "newhash" {
		t.Errorf("expected newhash, got %q", entry.ContentHash)
	}
	if entry.Findings[0].Algorithm.Name != "AES-256" {
		t.Errorf("expected AES-256, got %q", entry.Findings[0].Algorithm.Name)
	}
}

func TestUpdateEngine_PrunesDeletedFiles(t *testing.T) {
	sc := New()
	sc.EngineEntries["ast-grep"] = map[string]*CacheEntry{
		"/src/gone.go": {ContentHash: "hG"},
		"/src/kept.go": {ContentHash: "hK"},
	}

	hashes := map[string]string{"/src/kept.go": "hK"}
	sc.UpdateEngine("ast-grep", map[string][]findings.UnifiedFinding{}, hashes, true)

	if _, ok := sc.EngineEntries["ast-grep"]["/src/gone.go"]; ok {
		t.Error("gone.go should be pruned")
	}
	if _, ok := sc.EngineEntries["ast-grep"]["/src/kept.go"]; !ok {
		t.Error("kept.go should remain")
	}
}

func TestUpdateEngine_SkipsPhantomFiles(t *testing.T) {
	sc := New()

	changedFindings := map[string][]findings.UnifiedFinding{
		"/src/phantom.go": {sampleFinding("ag", "/src/phantom.go", "RSA-1024", 1)},
	}
	// phantom.go not in hashes (deleted between scan and update).
	sc.UpdateEngine("ast-grep", changedFindings, map[string]string{}, true)

	engineFiles := sc.EngineEntries["ast-grep"]
	if _, ok := engineFiles["/src/phantom.go"]; ok {
		t.Error("phantom file should not be cached")
	}
}

func TestUpdateEngine_IndependentEngines(t *testing.T) {
	sc := New()

	hashesAG := map[string]string{"/src/foo.go": "h1"}
	hashesCS := map[string]string{"/src/foo.go": "h1", "/src/bar.rs": "h2"}

	sc.UpdateEngine("ast-grep", map[string][]findings.UnifiedFinding{
		"/src/foo.go": {sampleFinding("ag", "/src/foo.go", "RSA", 1)},
	}, hashesAG, true)

	sc.UpdateEngine("cipherscope", map[string][]findings.UnifiedFinding{
		"/src/bar.rs": {sampleFinding("cs", "/src/bar.rs", "AES", 1)},
	}, hashesCS, true)

	// Verify engines are independent — each has only files with findings.
	if len(sc.EngineEntries["ast-grep"]) != 1 {
		t.Errorf("ast-grep should have 1 entry, got %d", len(sc.EngineEntries["ast-grep"]))
	}
	if len(sc.EngineEntries["cipherscope"]) != 1 {
		t.Errorf("cipherscope should have 1 entry (bar.rs), got %d", len(sc.EngineEntries["cipherscope"]))
	}
	if sc.EngineEntries["ast-grep"]["/src/foo.go"] == nil {
		t.Error("ast-grep should have foo.go")
	}
	if sc.EngineEntries["cipherscope"]["/src/bar.rs"] == nil {
		t.Error("cipherscope should have bar.rs")
	}
}

func TestUpdateEngine_EmptyFindings(t *testing.T) {
	sc := New()

	hashes := map[string]string{"/src/clean.go": "h1"}
	sc.UpdateEngine("ast-grep", map[string][]findings.UnifiedFinding{
		"/src/clean.go": {}, // no findings for this file
	}, hashes, true)

	entry := sc.EngineEntries["ast-grep"]["/src/clean.go"]
	if entry == nil {
		t.Fatal("expected entry for clean file (even with empty findings)")
	}
	if len(entry.Findings) != 0 {
		t.Errorf("expected 0 findings, got %d", len(entry.Findings))
	}
}

// -- PruneDeletedFiles tests --

func TestPruneDeletedFiles_BothMaps(t *testing.T) {
	sc := New()
	sc.Entries["/src/gone.go"] = &CacheEntry{ContentHash: "h1"}
	sc.Entries["/src/kept.go"] = &CacheEntry{ContentHash: "h2"}
	sc.EngineEntries["ast-grep"] = map[string]*CacheEntry{
		"/src/gone.go": {ContentHash: "h1"},
		"/src/kept.go": {ContentHash: "h2"},
	}

	// Only kept.go is on disk.
	sc.PruneDeletedFiles(map[string]string{"/src/kept.go": "h2"})

	if _, ok := sc.Entries["/src/gone.go"]; ok {
		t.Error("gone.go should be pruned from Entries")
	}
	if _, ok := sc.Entries["/src/kept.go"]; !ok {
		t.Error("kept.go should remain in Entries")
	}
	if _, ok := sc.EngineEntries["ast-grep"]["/src/gone.go"]; ok {
		t.Error("gone.go should be pruned from EngineEntries")
	}
	if _, ok := sc.EngineEntries["ast-grep"]["/src/kept.go"]; !ok {
		t.Error("kept.go should remain in EngineEntries")
	}
}

func TestPruneDeletedFiles_MultipleEngines(t *testing.T) {
	sc := New()
	sc.EngineEntries["ast-grep"] = map[string]*CacheEntry{
		"/src/a.go": {ContentHash: "h1"},
		"/src/b.go": {ContentHash: "h2"},
	}
	sc.EngineEntries["cipherscope"] = map[string]*CacheEntry{
		"/src/a.go": {ContentHash: "h1"},
		"/src/c.go": {ContentHash: "h3"},
	}

	// Only a.go remains on disk.
	sc.PruneDeletedFiles(map[string]string{"/src/a.go": "h1"})

	if _, ok := sc.EngineEntries["ast-grep"]["/src/b.go"]; ok {
		t.Error("b.go should be pruned from ast-grep")
	}
	if _, ok := sc.EngineEntries["cipherscope"]["/src/c.go"]; ok {
		t.Error("c.go should be pruned from cipherscope")
	}
	// a.go should remain in both.
	if _, ok := sc.EngineEntries["ast-grep"]["/src/a.go"]; !ok {
		t.Error("a.go should remain in ast-grep")
	}
	if _, ok := sc.EngineEntries["cipherscope"]["/src/a.go"]; !ok {
		t.Error("a.go should remain in cipherscope")
	}
}

// -- V2 lifecycle integration test --

func TestCacheLifecycleV2_PerEngine(t *testing.T) {
	dir := t.TempDir()
	cachePath := filepath.Join(dir, "cache.json")

	fileA := writeTempFile(t, dir, "a.go", "package main // uses AES")
	fileB := writeTempFile(t, dir, "b.rs", "fn main() { /* RSA */ }")

	// --- First scan: two engines ---
	hashesAll, err := HashFiles([]string{fileA, fileB})
	if err != nil {
		t.Fatal(err)
	}

	sc := New()
	sc.ScannerVersion = "1.0.0"
	sc.EngineVersions = map[string]string{
		"ast-grep":    "0.15.0",
		"cipherscope": "0.3.1",
	}

	// ast-grep only scanned Go files.
	sc.UpdateEngine("ast-grep", map[string][]findings.UnifiedFinding{
		fileA: {sampleFinding("ag", fileA, "AES-256", 1)},
	}, map[string]string{fileA: hashesAll[fileA]}, true)

	// cipherscope scanned both.
	sc.UpdateEngine("cipherscope", map[string][]findings.UnifiedFinding{
		fileA: {sampleFinding("cs", fileA, "AES-128", 1)},
		fileB: {sampleFinding("cs", fileB, "RSA-2048", 1)},
	}, hashesAll, true)

	if err := sc.Save(cachePath); err != nil {
		t.Fatal(err)
	}

	// --- Second scan: no changes ---
	sc2, err := Load(cachePath)
	if err != nil {
		t.Fatal(err)
	}

	if !sc2.IsValidForEngine("ast-grep", "0.15.0") {
		t.Error("ast-grep cache should be valid")
	}
	if !sc2.IsValidForEngine("cipherscope", "0.3.1") {
		t.Error("cipherscope cache should be valid")
	}

	hashesSecond, _ := HashFiles([]string{fileA, fileB})

	agCached, agChanged := sc2.GetUnchangedFindingsForEngine("ast-grep", map[string]string{fileA: hashesSecond[fileA]})
	if len(agChanged) != 0 {
		t.Errorf("ast-grep: expected 0 changed, got %v", agChanged)
	}
	if len(agCached) != 1 || agCached[0].Algorithm.Name != "AES-256" {
		t.Errorf("ast-grep: expected AES-256, got %v", agCached)
	}

	csCached, csChanged := sc2.GetUnchangedFindingsForEngine("cipherscope", hashesSecond)
	if len(csChanged) != 0 {
		t.Errorf("cipherscope: expected 0 changed, got %v", csChanged)
	}
	if len(csCached) != 2 {
		t.Errorf("cipherscope: expected 2 cached, got %d", len(csCached))
	}

	// --- Third scan: cipherscope upgraded, ast-grep unchanged ---
	if !sc2.IsValidForEngine("ast-grep", "0.15.0") {
		t.Error("ast-grep should still be valid after cipherscope upgrade")
	}
	if sc2.IsValidForEngine("cipherscope", "0.4.0") {
		t.Error("cipherscope should be invalid with new version")
	}

	// Cipherscope full rescan — fileA modified too.
	if err := os.WriteFile(fileA, []byte("package main // now ChaCha20"), 0644); err != nil {
		t.Fatal(err)
	}

	hashesThird, _ := HashFiles([]string{fileA, fileB})

	// ast-grep sees fileA changed.
	agCached3, agChanged3 := sc2.GetUnchangedFindingsForEngine("ast-grep", map[string]string{fileA: hashesThird[fileA]})
	if len(agCached3) != 0 {
		t.Errorf("ast-grep: fileA changed, expected 0 cached, got %d", len(agCached3))
	}
	if len(agChanged3) != 1 || agChanged3[0] != fileA {
		t.Errorf("ast-grep: expected [%s] changed, got %v", fileA, agChanged3)
	}

	// Update ast-grep with new finding.
	sc2.UpdateEngine("ast-grep", map[string][]findings.UnifiedFinding{
		fileA: {sampleFinding("ag", fileA, "ChaCha20", 1)},
	}, map[string]string{fileA: hashesThird[fileA]}, true)

	// Cipherscope full rescan (version changed).
	sc2.EngineVersions["cipherscope"] = "0.4.0"
	sc2.UpdateEngine("cipherscope", map[string][]findings.UnifiedFinding{
		fileA: {sampleFinding("cs", fileA, "ChaCha20-Poly1305", 1)},
		fileB: {sampleFinding("cs", fileB, "RSA-2048", 1)},
	}, hashesThird, true)

	if err := sc2.Save(cachePath); err != nil {
		t.Fatal(err)
	}

	// --- Fourth scan: verify saved state ---
	sc3, err := Load(cachePath)
	if err != nil {
		t.Fatal(err)
	}

	agEntry := sc3.EngineEntries["ast-grep"][fileA]
	if agEntry == nil || agEntry.Findings[0].Algorithm.Name != "ChaCha20" {
		t.Errorf("expected ChaCha20 in ast-grep cache, got %v", agEntry)
	}

	csEntry := sc3.EngineEntries["cipherscope"][fileA]
	if csEntry == nil || csEntry.Findings[0].Algorithm.Name != "ChaCha20-Poly1305" {
		t.Errorf("expected ChaCha20-Poly1305 in cipherscope cache, got %v", csEntry)
	}

	// --- Fifth scan: fileB deleted ---
	if err := os.Remove(fileB); err != nil {
		t.Fatal(err)
	}

	hashesForDeletion, _ := HashFiles([]string{fileA})
	sc3.PruneDeletedFiles(hashesForDeletion)

	if _, ok := sc3.EngineEntries["cipherscope"][fileB]; ok {
		t.Error("deleted fileB should be pruned from cipherscope")
	}
	if _, ok := sc3.EngineEntries["ast-grep"][fileA]; !ok {
		t.Error("fileA should remain in ast-grep")
	}
	if _, ok := sc3.EngineEntries["cipherscope"][fileA]; !ok {
		t.Error("fileA should remain in cipherscope")
	}
}

// ============================================================================
// MarshalGzip / UnmarshalGzip tests
// ============================================================================

func TestMarshalGzip_RoundTrip(t *testing.T) {
	sc := New()
	sc.ScannerVersion = "1.2.3"
	sc.EngineVersions = map[string]string{
		"ast-grep":    "0.15.0",
		"cipherscope": "0.3.1",
	}
	sc.Entries["/src/foo.go"] = &CacheEntry{
		ContentHash: "deadbeef",
		Findings:    []findings.UnifiedFinding{sampleFinding("ag", "/src/foo.go", "AES-256", 42)},
		ScannedAt:   time.Now().Truncate(time.Second),
	}
	sc.EngineEntries["ast-grep"] = map[string]*CacheEntry{
		"/src/foo.go": {ContentHash: "deadbeef", Findings: nil},
	}

	gz, err := sc.MarshalGzip()
	if err != nil {
		t.Fatalf("MarshalGzip: %v", err)
	}
	if len(gz) == 0 {
		t.Fatal("MarshalGzip returned empty bytes")
	}

	restored, err := UnmarshalGzip(gz)
	if err != nil {
		t.Fatalf("UnmarshalGzip: %v", err)
	}
	if restored.ScannerVersion != "1.2.3" {
		t.Errorf("ScannerVersion: got %q, want 1.2.3", restored.ScannerVersion)
	}
	if restored.EngineVersions["ast-grep"] != "0.15.0" {
		t.Errorf("engine version: got %q", restored.EngineVersions["ast-grep"])
	}
	entry, ok := restored.Entries["/src/foo.go"]
	if !ok {
		t.Fatal("expected Entries[/src/foo.go]")
	}
	if entry.ContentHash != "deadbeef" {
		t.Errorf("ContentHash: got %q", entry.ContentHash)
	}
	if len(entry.Findings) != 1 || entry.Findings[0].Algorithm.Name != "AES-256" {
		t.Errorf("Findings: got %v", entry.Findings)
	}
}

func TestMarshalGzip_EmptyCache(t *testing.T) {
	sc := New()

	gz, err := sc.MarshalGzip()
	if err != nil {
		t.Fatalf("MarshalGzip empty cache: %v", err)
	}
	if len(gz) == 0 {
		t.Fatal("expected non-empty gzip for empty cache")
	}

	restored, err := UnmarshalGzip(gz)
	if err != nil {
		t.Fatalf("UnmarshalGzip empty cache: %v", err)
	}
	if restored.Version != cacheFormatVersion {
		t.Errorf("Version: got %q, want %q", restored.Version, cacheFormatVersion)
	}
	if len(restored.Entries) != 0 {
		t.Errorf("expected 0 entries, got %d", len(restored.Entries))
	}
	if len(restored.EngineEntries) != 0 {
		t.Errorf("expected 0 engine entries, got %d", len(restored.EngineEntries))
	}
	// Maps must be non-nil after round-trip.
	if restored.EngineVersions == nil {
		t.Error("EngineVersions should not be nil")
	}
	if restored.EngineEntries == nil {
		t.Error("EngineEntries should not be nil")
	}
	if restored.Entries == nil {
		t.Error("Entries should not be nil")
	}
}

func TestUnmarshalGzip_InvalidData(t *testing.T) {
	randomBytes := []byte("this is definitely not gzip data \x00\x01\x02\x03")

	_, err := UnmarshalGzip(randomBytes)
	if err == nil {
		t.Fatal("expected error for non-gzip data")
	}
	if !strings.Contains(err.Error(), "gzip") {
		t.Errorf("error should mention gzip: %v", err)
	}
}

func TestUnmarshalGzip_NotGzip(t *testing.T) {
	// Valid JSON but NOT gzip-compressed.
	plainJSON := []byte(`{"version":"2","scannerVersion":"1.0.0","engineVersions":{},"entries":{}}`)

	_, err := UnmarshalGzip(plainJSON)
	if err == nil {
		t.Fatal("expected error for uncompressed JSON input")
	}
}

func TestUnmarshalGzip_GzipButInvalidJSON(t *testing.T) {
	// Valid gzip but contains garbage inside.
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	_, _ = gz.Write([]byte("{not valid json!!!"))
	_ = gz.Close()

	_, err := UnmarshalGzip(buf.Bytes())
	if err == nil {
		t.Fatal("expected error for gzip-of-invalid-JSON")
	}
}

func TestMarshalGzip_SizeLimit(t *testing.T) {
	// Gzip output should be smaller than raw JSON for a non-trivial cache.
	sc := New()
	sc.ScannerVersion = "1.0.0"
	// Add enough entries so gzip has something to compress.
	for i := 0; i < 100; i++ {
		key := "/src/file_with_a_long_path_that_will_compress_well.go"
		sc.Entries[key] = &CacheEntry{
			ContentHash: "abc123def456abc123def456abc123def456abc123def456abc123def456abc1",
			Findings:    []findings.UnifiedFinding{sampleFinding("ast-grep", key, "AES-256-GCM", 42)},
		}
	}

	gzBytes, err := sc.MarshalGzip()
	if err != nil {
		t.Fatalf("MarshalGzip: %v", err)
	}

	rawJSON, err := json.Marshal(sc)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}

	// Gzip should always be smaller than raw JSON for compressible data.
	if len(gzBytes) >= len(rawJSON) {
		t.Errorf("expected gzip (%d bytes) < raw JSON (%d bytes)", len(gzBytes), len(rawJSON))
	}
}

func TestMarshalGzip_PreservesNilFindings(t *testing.T) {
	sc := New()
	sc.EngineEntries["ast-grep"] = map[string]*CacheEntry{
		"/src/clean.go": {ContentHash: "h1", Findings: nil},
	}

	gz, err := sc.MarshalGzip()
	if err != nil {
		t.Fatalf("MarshalGzip: %v", err)
	}

	restored, err := UnmarshalGzip(gz)
	if err != nil {
		t.Fatalf("UnmarshalGzip: %v", err)
	}

	entry := restored.EngineEntries["ast-grep"]["/src/clean.go"]
	if entry == nil {
		t.Fatal("expected engine entry after round-trip")
	}
	// nil findings can round-trip to nil or empty slice — both are acceptable.
	if len(entry.Findings) != 0 {
		t.Errorf("expected 0 findings, got %d", len(entry.Findings))
	}
}

// -- Edge case: engine with no prior entries gets added --

func TestGetUnchangedFindingsForEngine_NewEngine(t *testing.T) {
	sc := New()
	// Existing engine with cached data.
	sc.EngineEntries["ast-grep"] = map[string]*CacheEntry{
		"/src/foo.go": {ContentHash: "h1", Findings: []findings.UnifiedFinding{sampleFinding("ag", "/src/foo.go", "RSA", 1)}},
	}

	hashes := map[string]string{"/src/foo.go": "h1"}

	// Query for a completely new engine — all files should be changed.
	cached, changed := sc.GetUnchangedFindingsForEngine("new-engine", hashes)
	if len(cached) != 0 {
		t.Errorf("new engine should have 0 cached, got %d", len(cached))
	}
	if len(changed) != 1 {
		t.Errorf("new engine should have all files as changed, got %d", len(changed))
	}

	// ast-grep should still work independently.
	agCached, agChanged := sc.GetUnchangedFindingsForEngine("ast-grep", hashes)
	if len(agCached) != 1 {
		t.Errorf("ast-grep should have 1 cached, got %d", len(agCached))
	}
	if len(agChanged) != 0 {
		t.Errorf("ast-grep should have 0 changed, got %d", len(agChanged))
	}
}
