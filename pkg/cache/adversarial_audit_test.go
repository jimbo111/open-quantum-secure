// Package cache — adversarial audit fixtures.
//
// These tests were added as part of the 2026-04-20 scanner-layer audit to
// probe the incremental cache for race conditions, version-invalidation
// regressions, path-vs-content confusions, and symlink handling. Tests that
// document known issues use t.Errorf / t.Logf so regressions are tracked.
package cache

import (
	"bytes"
	"compress/gzip"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jimbo111/open-quantum-secure/pkg/findings"
)

// ---------------------------------------------------------------------------
// CACHE CONCURRENCY — concurrent Update/UpdateEngine/Save races.
// ---------------------------------------------------------------------------

// Audit_F20_ConcurrentUpdate_Race documents that ScanCache.Update is NOT
// safe for concurrent calls from multiple goroutines. The Entries map has
// no mutex, so parallel Updates produce either a `-race` data-race report
// or, under sufficient contention, a `fatal error: concurrent map writes`
// crash that terminates the process.
//
// Skipped by default to let the remainder of the cache test binary run.
// Run with `go test -race -run TestAudit_F20_ConcurrentUpdate_Race -args -audit-race=1`
// (or remove the skip) to confirm the race.
func TestAudit_F20_ConcurrentUpdate_Race(t *testing.T) {
	// 2026-04-20: formerly env-gated because the test crashed the binary.
	// After adding sync.RWMutex to ScanCache this test is safe to run always.
	sc := New()
	var wg sync.WaitGroup
	for g := 0; g < 4; g++ {
		wg.Add(1)
		go func(gid int) {
			defer wg.Done()
			for i := 0; i < 50; i++ {
				p := filepath.Join("/src", "g", string(rune('A'+gid)), string(rune('0'+i%10)))
				findingsForFile := map[string][]findings.UnifiedFinding{
					p: {sampleFinding("eng", p, "RSA-2048", i)},
				}
				hashes := map[string]string{p: "hash"}
				sc.Update(findingsForFile, hashes)
			}
		}(g)
	}
	wg.Wait()
}

// Audit_F21_ConcurrentUpdateEngine_Race — same pattern for UpdateEngine.
// Produces `fatal error: concurrent map writes`. Skipped by default.
func TestAudit_F21_ConcurrentUpdateEngine_Race(t *testing.T) {
	// 2026-04-20: un-gated after sync.RWMutex fix.
	sc := New()
	var wg sync.WaitGroup
	for g := 0; g < 4; g++ {
		wg.Add(1)
		go func(gid int) {
			defer wg.Done()
			for i := 0; i < 50; i++ {
				p := filepath.Join("/src", "f", string(rune('A'+gid)), string(rune('0'+i%10)))
				ch := map[string][]findings.UnifiedFinding{
					p: {sampleFinding("eng", p, "AES-128", i)},
				}
				h := map[string]string{p: "h"}
				sc.UpdateEngine("eng", ch, h, false)
			}
		}(g)
	}
	wg.Wait()
}

// Audit_F22_GetAndUpdateInterleaved_Race — reader + writer without a mutex.
// The reader's map iteration (GetUnchangedFindings ranges Entries) will race
// the writer's map writes. Skipped by default.
func TestAudit_F22_GetAndUpdateInterleaved_Race(t *testing.T) {
	// 2026-04-20: un-gated after sync.RWMutex fix.
	sc := New()
	sc.Entries["/src/seed.go"] = &CacheEntry{ContentHash: "h1",
		Findings: []findings.UnifiedFinding{sampleFinding("eng", "/src/seed.go", "RSA", 1)}}

	var wg sync.WaitGroup
	var reads atomic.Int64
	for g := 0; g < 4; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 200; i++ {
				h := map[string]string{"/src/seed.go": "h1"}
				_, _ = sc.GetUnchangedFindings(h)
				reads.Add(1)
			}
		}()
	}
	for g := 0; g < 4; g++ {
		wg.Add(1)
		go func(gid int) {
			defer wg.Done()
			for i := 0; i < 200; i++ {
				p := filepath.Join("/src/w", string(rune('A'+gid)), string(rune('0'+i%10)))
				ff := map[string][]findings.UnifiedFinding{p: nil}
				h := map[string]string{p: "x"}
				sc.Update(ff, h)
			}
		}(g)
	}
	wg.Wait()
	t.Logf("reads=%d", reads.Load())
}

// ---------------------------------------------------------------------------
// VERSION INVALIDATION — stale cache must not leak when scanner upgrades.
// ---------------------------------------------------------------------------

// Audit_F23_ScannerVersionChange_MustInvalidateV1 verifies that a cache
// produced by scanner vOLD but loaded by scanner vNEW is flagged invalid.
// The V1 flat map path (GetUnchangedFindings) does NOT call IsValid — it
// simply returns cached findings. If the caller forgets to check IsValid,
// stale findings leak. This test documents the contract failure.
func TestAudit_F23_V1_GetUnchangedFindings_IgnoresScannerVersion(t *testing.T) {
	sc := New()
	sc.ScannerVersion = "v1.0.0-OLD"
	sc.Entries["/src/a.go"] = &CacheEntry{
		ContentHash: "hash_a",
		Findings:    []findings.UnifiedFinding{sampleFinding("eng", "/src/a.go", "RSA-2048", 1)},
	}

	// Caller "upgrades to v2.0.0" but forgets to call IsValid.
	allHashes := map[string]string{"/src/a.go": "hash_a"}
	cached, changed := sc.GetUnchangedFindings(allHashes)

	// The API happily returns the stale cached finding — there is no
	// internal check, so ANY caller who skips IsValid leaks stale results.
	if len(cached) != 1 {
		t.Errorf("unexpected cached count=%d", len(cached))
	}
	if len(changed) != 0 {
		t.Errorf("unexpected changed count=%d", len(changed))
	}

	// Record: the API returns stale entries regardless of scanner version.
	// This is a contract-sharp-edge, documented as F23.
	t.Logf("CONTRACT DOC: GetUnchangedFindings returned %d cached findings despite ScannerVersion mismatch;"+
		" caller MUST check IsValid separately. If they forget → regression hazard.", len(cached))
}

// Audit_F24_PerEngine_GetUnchangedFindingsForEngine_IgnoresVersion — same
// sharp edge for the per-engine path.
func TestAudit_F24_PerEngine_GetUnchangedFindingsForEngine_IgnoresVersion(t *testing.T) {
	sc := New()
	sc.EngineVersions["cipherscope"] = "0.3.0-OLD"
	sc.EngineEntries["cipherscope"] = map[string]*CacheEntry{
		"/src/b.go": {
			ContentHash: "hash_b",
			Findings:    []findings.UnifiedFinding{sampleFinding("cipherscope", "/src/b.go", "AES-128", 2)},
		},
	}

	// Caller upgrades cipherscope to 0.3.1 but forgets IsValidForEngine.
	allHashes := map[string]string{"/src/b.go": "hash_b"}
	cached, _ := sc.GetUnchangedFindingsForEngine("cipherscope", allHashes)

	if len(cached) != 1 {
		t.Errorf("unexpected cached count = %d", len(cached))
	}
	t.Logf("CONTRACT DOC: GetUnchangedFindingsForEngine ignored EngineVersion mismatch."+
		" Caller must call IsValidForEngine first. Bug class: silent-stale.")
}

// Audit_F25_CacheFormatVersion_Increment_Invalidates verifies that bumping
// Version in code correctly invalidates on-disk caches.
func TestAudit_F25_CacheFormatVersion_OldVersion_Invalid(t *testing.T) {
	sc := New()
	sc.Version = "0" // older than current

	if sc.IsValid("v1.0", map[string]string{}) {
		t.Error("cache with older format version must be invalid")
	}
	if sc.IsValidForEngine("e", "1") {
		t.Error("engine cache with older format version must be invalid")
	}
}

// ---------------------------------------------------------------------------
// PATH vs CONTENT — rename, symlink, same content/different paths
// ---------------------------------------------------------------------------

// Audit_F26_FileRename_DoubleScans verifies that renaming a file (same
// content) is treated as a new file needing scan, and the old path is
// pruned. This is by-design (cache is path-keyed), but document.
func TestAudit_F26_RenamePath_DoubleScans(t *testing.T) {
	dir := t.TempDir()
	oldPath := writeTempFile(t, dir, "old.go", "package main // fixed content")
	hash, _ := HashFile(oldPath)

	sc := New()
	sc.Entries[oldPath] = &CacheEntry{ContentHash: hash,
		Findings: []findings.UnifiedFinding{sampleFinding("e", oldPath, "RSA", 1)}}

	// Rename file — same content, new path.
	newPath := filepath.Join(dir, "new.go")
	if err := os.Rename(oldPath, newPath); err != nil {
		t.Fatal(err)
	}
	newHash, _ := HashFile(newPath)

	allHashes := map[string]string{newPath: newHash}
	cached, changed := sc.GetUnchangedFindings(allHashes)

	// Identical content at a new path counts as a MISS — re-scan required.
	// Document this path-keyed cost.
	if len(cached) != 0 {
		t.Errorf("renamed file should miss cache (path-keyed), got %d cached findings", len(cached))
	}
	if len(changed) != 1 || changed[0] != newPath {
		t.Errorf("renamed file should appear in changedPaths: %v", changed)
	}

	// After Update with only newPath in hashes, old entry gets pruned.
	sc.Update(map[string][]findings.UnifiedFinding{newPath: nil}, allHashes)
	if _, ok := sc.Entries[oldPath]; ok {
		t.Error("old entry should be pruned after Update")
	}
}

// Audit_F27_SymlinkChain_HashesTarget documents that HashFile follows
// symlinks (uses os.Open which resolves symlinks). So a symlink and its
// target both produce the same hash — the cache entry is keyed by path,
// so each is a separate entry with matching content hashes. There is NO
// loop protection for symlink chains. If the chain is circular HashFile
// returns an error (os.Open circular symlink) — but for a long chain it
// will happily resolve.
func TestAudit_F27_SymlinkHashTarget(t *testing.T) {
	dir := t.TempDir()
	real := writeTempFile(t, dir, "real.go", "package main // real")
	realHash, _ := HashFile(real)

	link := filepath.Join(dir, "link.go")
	if err := os.Symlink(real, link); err != nil {
		t.Skipf("symlink creation failed: %v", err)
	}
	linkHash, err := HashFile(link)
	if err != nil {
		t.Fatalf("HashFile via symlink: %v", err)
	}
	if realHash != linkHash {
		t.Errorf("symlink hash should equal target hash: got %q vs %q", linkHash, realHash)
	}
}

// Audit_F28_CircularSymlink_NoHang verifies that circular symlinks fail
// cleanly rather than hanging HashFile indefinitely.
func TestAudit_F28_CircularSymlink_NoHang(t *testing.T) {
	dir := t.TempDir()
	a := filepath.Join(dir, "a")
	b := filepath.Join(dir, "b")
	if err := os.Symlink(b, a); err != nil {
		t.Skipf("symlink creation failed: %v", err)
	}
	if err := os.Symlink(a, b); err != nil {
		t.Skipf("symlink creation failed: %v", err)
	}

	done := make(chan struct{})
	go func() {
		_, _ = HashFile(a)
		close(done)
	}()
	select {
	case <-done:
		// pass — HashFile returned (with error, presumably)
	case <-time.After(5 * time.Second):
		t.Error("HashFile hung on circular symlink (no timeout protection)")
	}
}

// Audit_F29_SameContentDifferentPath_NoShare verifies that two files with
// identical content at two different paths each consume their own cache entry.
// Cache is path-keyed, so no sharing. Document.
func TestAudit_F29_SameContent_DifferentPaths_NoSharing(t *testing.T) {
	dir := t.TempDir()
	p1 := writeTempFile(t, dir, "a.go", "IDENTICAL")
	p2 := writeTempFile(t, dir, "b.go", "IDENTICAL")
	h, _ := HashFile(p1)

	sc := New()
	sc.Entries[p1] = &CacheEntry{ContentHash: h,
		Findings: []findings.UnifiedFinding{sampleFinding("e", p1, "RSA", 1)}}

	// p2 has same content but different path — expect MISS.
	hashes := map[string]string{p1: h, p2: h}
	cached, changed := sc.GetUnchangedFindings(hashes)
	if len(cached) != 1 {
		t.Errorf("p1 should hit cache (1 finding), got %d", len(cached))
	}
	if len(changed) != 1 || changed[0] != p2 {
		t.Errorf("p2 (same content different path) should appear in changedPaths: %v", changed)
	}
}

// ---------------------------------------------------------------------------
// CORRECTNESS: cache entries surviving an Update should match the hash.
// ---------------------------------------------------------------------------

// Audit_F30_UpdateOverwritesEntry_UsesNewHash verifies that Update replaces
// the cache entry with a new ContentHash reflecting the latest scan.
func TestAudit_F30_UpdateOverwritesContentHash(t *testing.T) {
	dir := t.TempDir()
	p := writeTempFile(t, dir, "f.go", "content v1")
	h1, _ := HashFile(p)

	sc := New()
	sc.Entries[p] = &CacheEntry{ContentHash: h1,
		Findings: []findings.UnifiedFinding{sampleFinding("e", p, "RSA", 1)}}

	// Mutate file: content v2.
	if err := os.WriteFile(p, []byte("content v2"), 0644); err != nil {
		t.Fatal(err)
	}
	h2, _ := HashFile(p)
	if h1 == h2 {
		t.Skip("content hashes equal — content didn't actually change")
	}

	sc.Update(
		map[string][]findings.UnifiedFinding{p: {sampleFinding("e", p, "ECDH", 5)}},
		map[string]string{p: h2},
	)

	entry := sc.Entries[p]
	if entry == nil {
		t.Fatal("entry missing after Update")
	}
	if entry.ContentHash != h2 {
		t.Errorf("ContentHash should equal h2=%q, got %q", h2, entry.ContentHash)
	}
	if len(entry.Findings) != 1 {
		t.Errorf("should have 1 finding after Update, got %d", len(entry.Findings))
	}
	if entry.Findings[0].Algorithm.Name != "ECDH" {
		t.Errorf("should have new ECDH finding, got %q", entry.Findings[0].Algorithm.Name)
	}
}

// Audit_F31_UpdateWithMissingFileHash_SkipsEntry verifies that when
// changedFindings has a path but allFileHashes doesn't, the entry is skipped
// (rather than cached with zero hash).
func TestAudit_F31_UpdateMissingHash_Skips(t *testing.T) {
	sc := New()
	sc.Update(
		map[string][]findings.UnifiedFinding{
			"/src/missing.go": {sampleFinding("e", "/src/missing.go", "RSA", 1)},
		},
		map[string]string{}, // no hash
	)
	if _, ok := sc.Entries["/src/missing.go"]; ok {
		t.Error("Update should NOT create an entry when file has no hash; zero-hash would cause stale matches")
	}
}

// Audit_F32_DecompressionBombRejected verifies that UnmarshalGzip rejects
// a gzip stream whose decompressed size exceeds the 500 MB cap, preventing
// a compact malicious cache file from exhausting memory.
func TestAudit_F32_DecompressionBombRejected(t *testing.T) {
	if testing.Short() {
		t.Skip("skip long decompress test in short mode")
	}
	// Only run when explicitly requested — this test allocates ~500 MB.
	if os.Getenv("OQS_AUDIT_DECOMPRESS_BOMB") == "" {
		t.Skip("decompression-bomb test is heavy; set OQS_AUDIT_DECOMPRESS_BOMB=1 to run")
	}

	// Build a gzip stream of zero bytes large enough to exceed the 500 MB cap.
	var gzBuf bytes.Buffer
	gz := gzip.NewWriter(&gzBuf)
	chunk := make([]byte, 1<<20) // 1 MB of zeros
	for i := 0; i < 600; i++ {
		if _, err := gz.Write(chunk); err != nil {
			t.Fatal(err)
		}
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}

	_, err := UnmarshalGzip(gzBuf.Bytes())
	if err == nil {
		t.Error("UnmarshalGzip should reject decompressed size > 500 MB (bomb protection)")
	}
}

// ---------------------------------------------------------------------------
// MOD-TIME VS HASH — modtime is a quick check, hash is authoritative.
// The code stores ModTime but GetUnchangedFindings uses HASH only. Verify.
// ---------------------------------------------------------------------------

// Audit_F33_ModTimeChangedButHashSame_NoMiss verifies that touching a file
// (modtime bumps but content stays identical) does NOT cause a cache miss,
// because GetUnchangedFindings keys on ContentHash, not ModTime.
func TestAudit_F33_ModTimeChangedContentSame_HitCache(t *testing.T) {
	dir := t.TempDir()
	p := writeTempFile(t, dir, "f.go", "same content")
	h, _ := HashFile(p)

	sc := New()
	sc.Entries[p] = &CacheEntry{
		ContentHash: h,
		ModTime:     time.Now().Add(-time.Hour), // old modtime
		Findings:    []findings.UnifiedFinding{sampleFinding("e", p, "RSA", 1)},
	}

	// Touch the file to update modtime. Content unchanged.
	newModTime := time.Now().Add(1 * time.Hour)
	if err := os.Chtimes(p, newModTime, newModTime); err != nil {
		t.Fatal(err)
	}

	cached, changed := sc.GetUnchangedFindings(map[string]string{p: h})
	if len(cached) != 1 {
		t.Errorf("modtime bump with same content should hit cache; got %d cached, %d changed",
			len(cached), len(changed))
	}
}

// ---------------------------------------------------------------------------
// GZIP NEGATIVE TESTS
// ---------------------------------------------------------------------------

// Audit_F34_GzipEmpty returns an error.
func TestAudit_F34_GzipEmpty(t *testing.T) {
	_, err := UnmarshalGzip([]byte{})
	if err == nil {
		t.Error("UnmarshalGzip(empty) should return error")
	}
}

// Audit_F35_GzipTruncated returns an error.
func TestAudit_F35_GzipTruncated(t *testing.T) {
	sc := New()
	data, err := sc.MarshalGzip()
	if err != nil {
		t.Fatal(err)
	}
	// Truncate final half
	trunc := data[:len(data)/2]
	_, err = UnmarshalGzip(trunc)
	if err == nil {
		t.Error("UnmarshalGzip(truncated) should return error")
	}
}
