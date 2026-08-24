package orchestrator

// Regression tests for the incremental-cache hardening:
//   1. A repo-local .oqs-scanner-cache.json inside the scanned tree is IGNORED
//      by default (cache-poisoning defense) — the default cache lives under
//      ~/.oqs/cache/scans/ instead.
//   2. walkSourceFiles skips well-known dependency/build directories so their
//      contents are never SHA-256 hashed (pre-engine DoS defense).
//   3. Files exceeding MaxFileMB are never hashed or cached — they are treated
//      as always-changed and re-scanned every run.

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jimbo111/open-quantum-secure/pkg/cache"
	"github.com/jimbo111/open-quantum-secure/pkg/engines"
	"github.com/jimbo111/open-quantum-secure/pkg/findings"
)

// TestRunIncremental_RepoLocalCacheIgnoredByDefault plants a poisoned
// repo-local cache — correct content hash, matching scanner and engine
// versions, fabricated findings — inside the scanned directory and verifies
// that a default-path scan (no --cache-path) neither loads it nor serves its
// findings: the engine still runs and only its real findings surface.
func TestRunIncremental_RepoLocalCacheIgnoredByDefault(t *testing.T) {
	fakeHome := t.TempDir()
	t.Setenv("HOME", fakeHome)
	t.Setenv("APPDATA", fakeHome) // Windows equivalent

	dir := t.TempDir()
	goFile := writeIncrFile(t, dir, "main.go", "package main // uses RSA")

	realHash, err := cache.HashFile(goFile)
	if err != nil {
		t.Fatal(err)
	}

	// Craft the poisoned cache exactly as a malicious repo would: version
	// fields that match the current scan, the file's true content hash, and
	// fabricated findings.
	absDir, _ := filepath.Abs(dir)
	absGoFile := filepath.Join(absDir, "main.go")
	poisoned := cache.New()
	poisoned.ScannerVersion = "1.0.0"
	poisoned.EngineVersions["go-scanner"] = "1.0.0"
	poisoned.EngineEntries["go-scanner"] = map[string]*cache.CacheEntry{
		absGoFile: {
			ContentHash: realHash,
			Findings: []findings.UnifiedFinding{{
				Location:     findings.Location{File: absGoFile, Line: 1},
				Algorithm:    &findings.Algorithm{Name: "FABRICATED-SAFE"},
				SourceEngine: "go-scanner",
			}},
		},
	}
	repoLocalCache := filepath.Join(dir, ".oqs-scanner-cache.json")
	if err := poisoned.Save(repoLocalCache); err != nil {
		t.Fatal(err)
	}

	eng := &mockIncrEngine{
		name: "go-scanner", tier: engines.Tier1Pattern, langs: []string{"go"}, version: "1.0.0",
		scanFn: func(_ context.Context, _ engines.ScanOptions) ([]findings.UnifiedFinding, error) {
			return []findings.UnifiedFinding{incrFinding("go-scanner", goFile, "RSA-2048", 1)}, nil
		},
	}

	orch := New(eng)
	opts := engines.ScanOptions{
		TargetPath:  dir,
		Mode:        engines.ModeFull,
		Incremental: true,
		CachePath:   "", // default path — must NOT resolve to the repo-local file
	}

	results, err := orch.runIncremental(context.Background(), opts, []engines.Engine{eng}, "1.0.0")
	if err != nil {
		t.Fatalf("runIncremental: %v", err)
	}

	// The engine must actually run: the poisoned cache would have suppressed it.
	if eng.scanCount() != 1 {
		t.Errorf("engine must run despite the repo-local cache (poisoning defense), got %d calls", eng.scanCount())
	}
	for _, f := range results {
		if f.Algorithm != nil && f.Algorithm.Name == "FABRICATED-SAFE" {
			t.Fatal("fabricated finding from the repo-local cache was served — cache poisoning not prevented")
		}
	}
	if len(results) != 1 || results[0].Algorithm.Name != "RSA-2048" {
		t.Errorf("expected the engine's real RSA-2048 finding, got %v", results)
	}

	// The default cache must have been written OUTSIDE the scan tree.
	defaultPath := cache.DefaultPath(dir)
	if strings.HasPrefix(defaultPath, absDir+string(filepath.Separator)) {
		t.Errorf("default cache path %q is inside the scan tree", defaultPath)
	}
	if _, err := os.Stat(defaultPath); err != nil {
		t.Errorf("default cache should have been written at %q: %v", defaultPath, err)
	}
}

// TestWalkSourceFiles_SkipsDependencyDirs verifies node_modules and other
// dependency/build trees are never walked (and therefore never hashed).
func TestWalkSourceFiles_SkipsDependencyDirs(t *testing.T) {
	dir := t.TempDir()
	writeIncrFile(t, dir, "main.go", "package main")

	for _, sub := range []string{"node_modules/pkg", "vendor/lib", "target/debug", "build", "dist", "__pycache__", "venv/lib", ".venv/lib"} {
		full := filepath.Join(dir, filepath.FromSlash(sub))
		if err := os.MkdirAll(full, 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(full, "dep.go"), []byte("package dep"), 0644); err != nil {
			t.Fatal(err)
		}
	}

	paths, err := walkSourceFiles(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(paths) != 1 {
		t.Fatalf("expected only main.go to be walked, got %d paths: %v", len(paths), paths)
	}
	if filepath.Base(paths[0]) != "main.go" {
		t.Errorf("expected main.go, got %s", paths[0])
	}
}

// TestRunIncremental_OversizedFileAlwaysRescanned verifies that a file larger
// than MaxFileMB is (a) still handed to the engine every run and (b) never
// cached — its content is never read for hashing.
func TestRunIncremental_OversizedFileAlwaysRescanned(t *testing.T) {
	dir := t.TempDir()
	bigFile := filepath.Join(dir, "big.go")
	// 1 MB limit; write ~1.5 MB.
	if err := os.WriteFile(bigFile, make([]byte, 1536*1024), 0644); err != nil {
		t.Fatal(err)
	}

	var lastChanged []string
	eng := &mockIncrEngine{
		name: "go-scanner", tier: engines.Tier1Pattern, langs: []string{"go"}, version: "1.0.0",
		scanFn: func(_ context.Context, opts engines.ScanOptions) ([]findings.UnifiedFinding, error) {
			lastChanged = opts.ChangedFiles
			return []findings.UnifiedFinding{incrFinding("go-scanner", bigFile, "RSA-2048", 1)}, nil
		},
	}

	orch := New(eng)
	cachePath := filepath.Join(dir, ".cache.json")
	opts := engines.ScanOptions{
		TargetPath:  dir,
		Mode:        engines.ModeFull,
		Incremental: true,
		CachePath:   cachePath,
		MaxFileMB:   1,
	}

	// First run — engine scans the oversized file.
	if _, err := orch.runIncremental(context.Background(), opts, []engines.Engine{eng}, "1.0.0"); err != nil {
		t.Fatal(err)
	}
	if eng.scanCount() != 1 {
		t.Fatalf("first run: expected 1 scan call, got %d", eng.scanCount())
	}
	found := false
	for _, cf := range lastChanged {
		if filepath.Base(cf) == "big.go" {
			found = true
		}
	}
	if !found {
		t.Errorf("oversized file must be passed to the engine as changed, got %v", lastChanged)
	}

	// Second run, nothing modified — the oversized file must STILL be
	// re-scanned (it was never cached).
	if _, err := orch.runIncremental(context.Background(), opts, []engines.Engine{eng}, "1.0.0"); err != nil {
		t.Fatal(err)
	}
	if eng.scanCount() != 2 {
		t.Errorf("oversized file must be re-scanned every run (never cached), got %d calls", eng.scanCount())
	}

	// And its findings must not be in the persisted cache.
	sc, err := cache.Load(cachePath)
	if err != nil {
		t.Fatal(err)
	}
	absBig, _ := filepath.Abs(bigFile)
	if _, ok := sc.EngineEntries["go-scanner"][absBig]; ok {
		t.Error("oversized file must not have a cache entry")
	}
}
