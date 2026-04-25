// Package cache — sophisticated tests covering scanner version guard,
// engine version guard, gzip round-trip, and concurrent safety.
package cache

import (
	"path/filepath"
	"testing"

	"github.com/jimbo111/open-quantum-secure/pkg/findings"
)

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func makeHashes(paths ...string) map[string]string {
	m := make(map[string]string, len(paths))
	for _, p := range paths {
		m[p] = "deadbeef" + p // deterministic fake hash
	}
	return m
}

func makeFinding(file, alg string) findings.UnifiedFinding {
	return findings.UnifiedFinding{
		Location:     findings.Location{File: file, Line: 10},
		Algorithm:    &findings.Algorithm{Name: alg},
		SourceEngine: "test-engine",
	}
}

// ---------------------------------------------------------------------------
// 1. Version guard: cache from older scanner version → cache miss (fix d6ccdb7)
// ---------------------------------------------------------------------------

func TestGetUnchangedFindings_OlderScannerVersion_CacheMiss(t *testing.T) {
	sc := New()
	sc.ScannerVersion = "v0.1.0" // written with old version

	// Populate cache entry for one file.
	path := "/project/main.go"
	sc.Entries[path] = &CacheEntry{
		ContentHash: "deadbeef" + path,
		Findings:    []findings.UnifiedFinding{makeFinding(path, "RSA")},
	}

	// Query with newer scanner version.
	hashes := makeHashes(path)
	cached, changed := sc.GetUnchangedFindings("v0.2.0", hashes)

	// Version mismatch → every path must be reported as changed.
	if len(cached) > 0 {
		t.Errorf("expected 0 cached findings from older scanner version; got %d", len(cached))
	}
	if len(changed) != 1 || changed[0] != path {
		t.Errorf("expected [%s] in changedPaths; got %v", path, changed)
	}
}

// ---------------------------------------------------------------------------
// 2. Version guard: same scanner version → cache hit
// ---------------------------------------------------------------------------

func TestGetUnchangedFindings_SameScannerVersion_CacheHit(t *testing.T) {
	sc := New()
	sc.ScannerVersion = "v0.2.0"

	path := "/project/auth.go"
	hash := "abc123"
	sc.Entries[path] = &CacheEntry{
		ContentHash: hash,
		Findings:    []findings.UnifiedFinding{makeFinding(path, "ECDSA")},
	}

	hashes := map[string]string{path: hash}
	cached, changed := sc.GetUnchangedFindings("v0.2.0", hashes)

	if len(cached) != 1 {
		t.Errorf("expected 1 cached finding; got %d", len(cached))
	}
	if len(changed) != 0 {
		t.Errorf("expected no changed paths; got %v", changed)
	}
}

// ---------------------------------------------------------------------------
// 3. Per-engine version guard: GetUnchangedFindingsForEngine with old engine version
// ---------------------------------------------------------------------------

func TestGetUnchangedFindingsForEngine_OldEngineVersion_CacheMiss(t *testing.T) {
	sc := New()
	// Simulate cached entry from cipherscope v0.3.0.
	engName := "cipherscope"
	sc.EngineVersions[engName] = "v0.3.0"
	path := "/project/rsa.go"
	sc.EnsureEngineEntry(engName)
	sc.EngineEntries[engName][path] = &CacheEntry{
		ContentHash: "deadbeef",
		Findings:    []findings.UnifiedFinding{makeFinding(path, "RSA")},
	}

	hashes := map[string]string{path: "deadbeef"}
	// Engine is now v0.4.0 — version mismatch.
	cached, changed := sc.GetUnchangedFindingsForEngine(engName, "v0.4.0", hashes)

	if len(cached) > 0 {
		t.Errorf("expected 0 cached findings on engine version mismatch; got %d", len(cached))
	}
	if len(changed) != 1 {
		t.Errorf("expected 1 changed path; got %v", changed)
	}
}

// ---------------------------------------------------------------------------
// 4. Per-engine version guard: same engine version → cache hit
// ---------------------------------------------------------------------------

func TestGetUnchangedFindingsForEngine_SameEngineVersion_CacheHit(t *testing.T) {
	sc := New()
	engName := "cryptoscan"
	sc.EngineVersions[engName] = "v1.0.0"
	path := "/project/crypto.go"
	hash := "aabbcc"
	sc.EnsureEngineEntry(engName)
	sc.EngineEntries[engName][path] = &CacheEntry{
		ContentHash: hash,
		Findings:    []findings.UnifiedFinding{makeFinding(path, "AES")},
	}

	hashes := map[string]string{path: hash}
	cached, changed := sc.GetUnchangedFindingsForEngine(engName, "v1.0.0", hashes)

	if len(cached) != 1 {
		t.Errorf("expected 1 cached finding; got %d", len(cached))
	}
	if len(changed) != 0 {
		t.Errorf("expected 0 changed paths; got %v", changed)
	}
}

// ---------------------------------------------------------------------------
// 5. Changed file hash → cache miss for that file, hit for unchanged
// ---------------------------------------------------------------------------

func TestGetUnchangedFindings_ChangedHash_PartialMiss(t *testing.T) {
	sc := New()
	sc.ScannerVersion = "v1.0.0"

	unchanged := "/project/stable.go"
	changed := "/project/modified.go"

	sc.Entries[unchanged] = &CacheEntry{ContentHash: "aaa", Findings: []findings.UnifiedFinding{makeFinding(unchanged, "RSA")}}
	sc.Entries[changed] = &CacheEntry{ContentHash: "bbb", Findings: []findings.UnifiedFinding{makeFinding(changed, "ECDSA")}}

	hashes := map[string]string{
		unchanged: "aaa", // same hash
		changed:   "ccc", // CHANGED
	}

	cached, changedPaths := sc.GetUnchangedFindings("v1.0.0", hashes)
	if len(cached) != 1 {
		t.Errorf("expected 1 cached finding (unchanged file); got %d", len(cached))
	}
	if len(changedPaths) != 1 || changedPaths[0] != changed {
		t.Errorf("expected [%s] in changedPaths; got %v", changed, changedPaths)
	}
}

// ---------------------------------------------------------------------------
// 6. UpdateEngine stores findings and removes deleted files when pruneDeleted=true
// ---------------------------------------------------------------------------

func TestUpdateEngine_PruneDeleted(t *testing.T) {
	sc := New()
	engName := "cipherscope"
	sc.EnsureEngineEntry(engName)

	// Pre-populate an old entry for a file that no longer exists.
	deleted := "/project/deleted.go"
	sc.EngineEntries[engName][deleted] = &CacheEntry{ContentHash: "xxx"}

	existing := "/project/existing.go"
	hashes := map[string]string{existing: "newhash"}
	changed := map[string][]findings.UnifiedFinding{
		existing: {makeFinding(existing, "RSA")},
	}

	sc.UpdateEngine(engName, changed, hashes, true /* pruneDeleted */)

	if _, ok := sc.EngineEntries[engName][deleted]; ok {
		t.Error("deleted file entry should be pruned when pruneDeleted=true")
	}
	if _, ok := sc.EngineEntries[engName][existing]; !ok {
		t.Error("existing file entry should be stored after UpdateEngine")
	}
}

// ---------------------------------------------------------------------------
// 7. UpdateEngine in diff mode: pruneDeleted=false preserves old entries
// ---------------------------------------------------------------------------

func TestUpdateEngine_DiffMode_DoesNotPrune(t *testing.T) {
	sc := New()
	engName := "cipherscope"
	sc.EnsureEngineEntry(engName)

	// Old entry for an unchanged file (NOT in the diff's hash set).
	unchanged := "/project/unchanged.go"
	sc.EngineEntries[engName][unchanged] = &CacheEntry{ContentHash: "old"}

	// Diff only includes one changed file.
	changed := "/project/changed.go"
	hashes := map[string]string{changed: "newhash"}
	changedFindings := map[string][]findings.UnifiedFinding{
		changed: {makeFinding(changed, "ECDSA")},
	}

	sc.UpdateEngine(engName, changedFindings, hashes, false /* pruneDeleted */)

	// The unchanged file's entry must survive in diff mode.
	if _, ok := sc.EngineEntries[engName][unchanged]; !ok {
		t.Error("unchanged file's cache entry was incorrectly pruned in diff mode")
	}
}

// ---------------------------------------------------------------------------
// 8. Save/Load round-trip preserves ScannerVersion and findings
// ---------------------------------------------------------------------------

func TestSaveLoad_RoundTrip(t *testing.T) {
	dir := t.TempDir()
	cachePath := filepath.Join(dir, "cache.json")

	sc := New()
	sc.ScannerVersion = "v1.2.3"
	path := "/project/main.go"
	sc.Entries[path] = &CacheEntry{
		ContentHash: "abc",
		Findings:    []findings.UnifiedFinding{makeFinding(path, "RSA")},
	}

	if err := sc.Save(cachePath); err != nil {
		t.Fatalf("Save() error: %v", err)
	}

	loaded, err := Load(cachePath)
	if err != nil {
		t.Fatalf("Load() error: %v", err)
	}

	if loaded.ScannerVersion != "v1.2.3" {
		t.Errorf("ScannerVersion = %q; want v1.2.3", loaded.ScannerVersion)
	}
	entry, ok := loaded.Entries[path]
	if !ok {
		t.Fatal("expected entry for /project/main.go after load")
	}
	if entry.ContentHash != "abc" {
		t.Errorf("ContentHash = %q; want abc", entry.ContentHash)
	}
	if len(entry.Findings) != 1 {
		t.Errorf("len(Findings) = %d; want 1", len(entry.Findings))
	}
}

// ---------------------------------------------------------------------------
// 9. Gzip round-trip: MarshalGzip / UnmarshalGzip
// ---------------------------------------------------------------------------

func TestGzipRoundTrip(t *testing.T) {
	sc := New()
	sc.ScannerVersion = "v2.0.0"
	sc.Entries["/a.go"] = &CacheEntry{ContentHash: "zzz"}

	gz, err := sc.MarshalGzip()
	if err != nil {
		t.Fatalf("MarshalGzip() error: %v", err)
	}

	decoded, err := UnmarshalGzip(gz)
	if err != nil {
		t.Fatalf("UnmarshalGzip() error: %v", err)
	}

	if decoded.ScannerVersion != "v2.0.0" {
		t.Errorf("ScannerVersion after gzip round-trip = %q; want v2.0.0", decoded.ScannerVersion)
	}
	if _, ok := decoded.Entries["/a.go"]; !ok {
		t.Error("cache entry missing after gzip round-trip")
	}
}

// ---------------------------------------------------------------------------
// 10. Load non-existent file → returns empty (valid) cache, no error
// ---------------------------------------------------------------------------

func TestLoad_NonExistentFile_ReturnsEmpty(t *testing.T) {
	sc, err := Load("/nonexistent/path/cache.json")
	if err != nil {
		t.Fatalf("Load() returned error for non-existent file: %v", err)
	}
	if sc == nil {
		t.Fatal("Load() returned nil cache")
	}
	if sc.Version != cacheFormatVersion {
		t.Errorf("Version = %q; want %q", sc.Version, cacheFormatVersion)
	}
}

// ---------------------------------------------------------------------------
// 11. IsValid: mismatched format version → false
// ---------------------------------------------------------------------------

func TestIsValid_WrongFormatVersion(t *testing.T) {
	sc := New()
	sc.Version = "1" // old format
	sc.ScannerVersion = "v1.0.0"

	if sc.IsValid("v1.0.0", nil) {
		t.Error("IsValid should return false for wrong cache format version")
	}
}

// ---------------------------------------------------------------------------
// 12. IsValidForEngine: unknown engine → false
// ---------------------------------------------------------------------------

func TestIsValidForEngine_UnknownEngine_False(t *testing.T) {
	sc := New()
	if sc.IsValidForEngine("unknown-engine", "v1.0.0") {
		t.Error("IsValidForEngine should return false for an engine not in the cache")
	}
}

// ---------------------------------------------------------------------------
// 13. SetEngineVersion and IsValidForEngine: round-trip
// ---------------------------------------------------------------------------

func TestSetEngineVersion_RoundTrip(t *testing.T) {
	sc := New()
	sc.SetEngineVersion("cipherscope", "v1.5.0")

	if !sc.IsValidForEngine("cipherscope", "v1.5.0") {
		t.Error("IsValidForEngine should return true after SetEngineVersion with matching version")
	}
	if sc.IsValidForEngine("cipherscope", "v1.6.0") {
		t.Error("IsValidForEngine should return false for different version")
	}
}
