package cache

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jimbo111/open-quantum-secure/pkg/findings"
)

// --- V2 ScannerVersion guard (cache poisoning defense-in-depth) ---

// TestGetUnchangedFindingsForEngine_ScannerVersionMismatch_AllChanged verifies
// that the per-engine V2 path enforces the ScannerVersion guard like V1: a
// cache written by (or crafted for) a different scanner binary must never
// serve cached findings, even when engine versions and content hashes match.
func TestGetUnchangedFindingsForEngine_ScannerVersionMismatch_AllChanged(t *testing.T) {
	sc := New()
	sc.ScannerVersion = "1.0.0"
	sc.EngineVersions["cipherscope"] = "0.3.1"
	sc.EngineEntries["cipherscope"] = map[string]*CacheEntry{
		"/src/a.go": {
			ContentHash: "hash-a",
			Findings: []findings.UnifiedFinding{{
				Location:     findings.Location{File: "/src/a.go", Line: 1},
				Algorithm:    &findings.Algorithm{Name: "AES-128"},
				SourceEngine: "cipherscope",
			}},
		},
	}

	allHashes := map[string]string{"/src/a.go": "hash-a"}

	// Matching scanner version → cache hit (sanity check).
	cached, changed := sc.GetUnchangedFindingsForEngine("cipherscope", "0.3.1", "1.0.0", allHashes)
	if len(cached) != 1 || len(changed) != 0 {
		t.Fatalf("matching versions: expected 1 cached / 0 changed, got %d / %d", len(cached), len(changed))
	}

	// Mismatched scanner version → everything changed, nothing served.
	cached, changed = sc.GetUnchangedFindingsForEngine("cipherscope", "0.3.1", "2.0.0", allHashes)
	if len(cached) != 0 {
		t.Errorf("scanner version mismatch must serve 0 cached findings, got %d", len(cached))
	}
	if len(changed) != 1 || changed[0] != "/src/a.go" {
		t.Errorf("scanner version mismatch must report all paths changed, got %v", changed)
	}
}

// --- Hash size cap (pre-scan hashing DoS) ---

func TestHashFileWithLimit_ErrFileTooLarge(t *testing.T) {
	dir := t.TempDir()
	big := filepath.Join(dir, "big.bin")
	if err := os.WriteFile(big, make([]byte, 2048), 0644); err != nil {
		t.Fatal(err)
	}

	_, err := HashFileWithLimit(big, 1024)
	if !errors.Is(err, ErrFileTooLarge) {
		t.Fatalf("expected ErrFileTooLarge, got: %v", err)
	}

	// No limit → hashes fine.
	if _, err := HashFileWithLimit(big, 0); err != nil {
		t.Fatalf("no-limit hash should succeed: %v", err)
	}
}

func TestHashFilesWithLimit_SkipsOversized(t *testing.T) {
	dir := t.TempDir()
	small := filepath.Join(dir, "small.go")
	big := filepath.Join(dir, "big.go")
	if err := os.WriteFile(small, []byte("package main"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(big, make([]byte, 4096), 0644); err != nil {
		t.Fatal(err)
	}

	hashes, skipped, err := HashFilesWithLimit([]string{small, big}, 1024)
	if err != nil {
		t.Fatalf("oversized files must not be errors: %v", err)
	}
	if _, ok := hashes[small]; !ok {
		t.Error("small file should be hashed")
	}
	if _, ok := hashes[big]; ok {
		t.Error("oversized file must NOT appear in the hash map")
	}
	if len(skipped) != 1 || skipped[0] != big {
		t.Errorf("expected skipped=[%s], got %v", big, skipped)
	}
}

// --- Default cache path lives outside the scan tree ---

func TestDefaultPath_OutsideScanTree(t *testing.T) {
	fakeHome := t.TempDir()
	t.Setenv("HOME", fakeHome)
	t.Setenv("APPDATA", fakeHome) // Windows equivalent

	scanDir := t.TempDir()
	p := DefaultPath(scanDir)

	absScan, _ := filepath.Abs(scanDir)
	if strings.HasPrefix(p, absScan+string(filepath.Separator)) {
		t.Errorf("default cache path %q must not live inside the scan tree %q", p, absScan)
	}
	if !strings.HasSuffix(p, ".json") {
		t.Errorf("expected .json cache file, got %q", p)
	}

	// Two different absolute paths with the same basename must get distinct slugs.
	dirA := filepath.Join(t.TempDir(), "proj")
	dirB := filepath.Join(t.TempDir(), "proj")
	if DefaultPath(dirA) == DefaultPath(dirB) {
		t.Error("distinct scan paths with the same basename must map to distinct cache files")
	}
	// The same path must be stable.
	if DefaultPath(dirA) != DefaultPath(dirA) {
		t.Error("DefaultPath must be deterministic")
	}
}
