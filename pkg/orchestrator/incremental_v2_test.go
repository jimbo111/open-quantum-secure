package orchestrator

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"

	"github.com/jimbo111/open-quantum-secure/pkg/engines"
	"github.com/jimbo111/open-quantum-secure/pkg/findings"
)

// mockIncrEngine is a configurable mock engine for incremental V2 tests.
// It tracks how many times Scan was called via atomic counter.
type mockIncrEngine struct {
	name    string
	tier    engines.Tier
	langs   []string
	version string
	scanFn  func(ctx context.Context, opts engines.ScanOptions) ([]findings.UnifiedFinding, error)
	count   int32 // atomic scan call counter
}

func (m *mockIncrEngine) Name() string                 { return m.name }
func (m *mockIncrEngine) Tier() engines.Tier           { return m.tier }
func (m *mockIncrEngine) SupportedLanguages() []string { return m.langs }
func (m *mockIncrEngine) Available() bool              { return true }
func (m *mockIncrEngine) Version() string              { return m.version }
func (m *mockIncrEngine) Scan(ctx context.Context, opts engines.ScanOptions) ([]findings.UnifiedFinding, error) {
	atomic.AddInt32(&m.count, 1)
	if m.scanFn != nil {
		return m.scanFn(ctx, opts)
	}
	return nil, nil
}

func (m *mockIncrEngine) scanCount() int { return int(atomic.LoadInt32(&m.count)) }

// writeIncrFile is a helper that creates a file in dir and returns its absolute path.
func writeIncrFile(t *testing.T, dir, name, content string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatalf("write file %s: %v", name, err)
	}
	return path
}

// incrFinding creates a finding with the given parameters.
func incrFinding(engine, file, alg string, line int) findings.UnifiedFinding {
	return findings.UnifiedFinding{
		Location:     findings.Location{File: file, Line: line},
		Algorithm:    &findings.Algorithm{Name: alg},
		Confidence:   findings.ConfidenceMedium,
		SourceEngine: engine,
		Reachable:    findings.ReachableUnknown,
	}
}

// -- Helper function tests --

func TestFilterHashesByExtension_NilExts(t *testing.T) {
	hashes := map[string]string{"/a.go": "h1", "/b.rs": "h2", "/c.py": "h3"}

	result := filterHashesByExtension(hashes, nil)
	if len(result) != 3 {
		t.Errorf("nil exts should return all hashes, got %d", len(result))
	}
}

func TestFilterHashesByExtension_GoOnly(t *testing.T) {
	hashes := map[string]string{
		"/src/main.go":    "h1",
		"/src/lib.rs":     "h2",
		"/src/app.py":     "h3",
		"/src/go.mod":     "h4",
		"/src/.env":       "h5",
		"/src/.env.local": "h6",
	}

	exts := map[string]bool{".go": true, ".mod": true, ".sum": true}
	result := filterHashesByExtension(hashes, exts)

	// .go and .mod should match via extension. .env should match via basename prefix.
	if _, ok := result["/src/main.go"]; !ok {
		t.Error("main.go should be included")
	}
	if _, ok := result["/src/go.mod"]; !ok {
		t.Error("go.mod should be included")
	}
	if _, ok := result["/src/.env"]; !ok {
		t.Error(".env should be included (basename match)")
	}
	if _, ok := result["/src/.env.local"]; !ok {
		t.Error(".env.local should be included (basename match)")
	}
	if _, ok := result["/src/lib.rs"]; ok {
		t.Error("lib.rs should NOT be included")
	}
	if _, ok := result["/src/app.py"]; ok {
		t.Error("app.py should NOT be included")
	}
}

func TestToRelativePaths(t *testing.T) {
	paths := []string{"/repo/src/main.go", "/repo/pkg/util.go"}
	rel := toRelativePaths(paths, "/repo")

	if len(rel) != 2 {
		t.Fatalf("expected 2 relative paths, got %d", len(rel))
	}
	if rel[0] != "src/main.go" {
		t.Errorf("expected src/main.go, got %q", rel[0])
	}
	if rel[1] != "pkg/util.go" {
		t.Errorf("expected pkg/util.go, got %q", rel[1])
	}
}

func TestToRelativePaths_SameDir(t *testing.T) {
	paths := []string{"/repo/file.go"}
	rel := toRelativePaths(paths, "/repo")
	if rel[0] != "file.go" {
		t.Errorf("expected file.go, got %q", rel[0])
	}
}

// -- Incremental V2 integration tests --

func TestRunIncrementalV2_FirstScan_AllEnginesRun(t *testing.T) {
	dir := t.TempDir()
	goFile := writeIncrFile(t, dir, "main.go", "package main // uses RSA")
	rsFile := writeIncrFile(t, dir, "lib.rs", "fn main() { /* AES */ }")

	goEng := &mockIncrEngine{
		name: "go-scanner", tier: engines.Tier1Pattern, langs: []string{"go"}, version: "1.0.0",
		scanFn: func(_ context.Context, _ engines.ScanOptions) ([]findings.UnifiedFinding, error) {
			return []findings.UnifiedFinding{incrFinding("go-scanner", goFile, "RSA-2048", 1)}, nil
		},
	}
	rsEng := &mockIncrEngine{
		name: "rust-scanner", tier: engines.Tier1Pattern, langs: []string{"rust"}, version: "1.0.0",
		scanFn: func(_ context.Context, _ engines.ScanOptions) ([]findings.UnifiedFinding, error) {
			return []findings.UnifiedFinding{incrFinding("rust-scanner", rsFile, "AES-256", 1)}, nil
		},
	}

	orch := New(goEng, rsEng)
	cachePath := filepath.Join(dir, ".cache.json")
	opts := engines.ScanOptions{
		TargetPath:  dir,
		Mode:        engines.ModeFull,
		Incremental: true,
		CachePath:   cachePath,
	}

	results, err := orch.runIncremental(context.Background(), opts, []engines.Engine{goEng, rsEng}, "1.0.0")
	if err != nil {
		t.Fatalf("runIncremental: %v", err)
	}

	if goEng.scanCount() != 1 {
		t.Errorf("go-scanner: expected 1 scan call, got %d", goEng.scanCount())
	}
	if rsEng.scanCount() != 1 {
		t.Errorf("rust-scanner: expected 1 scan call, got %d", rsEng.scanCount())
	}
	if len(results) != 2 {
		t.Errorf("expected 2 findings, got %d", len(results))
	}

	// Cache file should exist.
	if _, err := os.Stat(cachePath); err != nil {
		t.Errorf("cache file should exist: %v", err)
	}
}

func TestRunIncrementalV2_AllUnchanged_NoBodyScansCalled(t *testing.T) {
	dir := t.TempDir()
	goFile := writeIncrFile(t, dir, "main.go", "package main // uses RSA")

	goEng := &mockIncrEngine{
		name: "go-scanner", tier: engines.Tier1Pattern, langs: []string{"go"}, version: "1.0.0",
		scanFn: func(_ context.Context, _ engines.ScanOptions) ([]findings.UnifiedFinding, error) {
			return []findings.UnifiedFinding{incrFinding("go-scanner", goFile, "RSA-2048", 1)}, nil
		},
	}

	orch := New(goEng)
	cachePath := filepath.Join(dir, ".cache.json")
	opts := engines.ScanOptions{
		TargetPath:  dir,
		Mode:        engines.ModeFull,
		Incremental: true,
		CachePath:   cachePath,
	}

	// First scan — populates cache.
	results1, err := orch.runIncremental(context.Background(), opts, []engines.Engine{goEng}, "1.0.0")
	if err != nil {
		t.Fatalf("first scan: %v", err)
	}
	if len(results1) != 1 {
		t.Fatalf("first scan: expected 1 finding, got %d", len(results1))
	}
	if goEng.scanCount() != 1 {
		t.Fatalf("first scan: expected 1 scan call, got %d", goEng.scanCount())
	}

	// Second scan — nothing changed, should use cache.
	results2, err := orch.runIncremental(context.Background(), opts, []engines.Engine{goEng}, "1.0.0")
	if err != nil {
		t.Fatalf("second scan: %v", err)
	}

	// Engine should NOT have been called a second time.
	if goEng.scanCount() != 1 {
		t.Errorf("second scan: expected scanCount=1 (cached), got %d", goEng.scanCount())
	}
	// Should still return the cached finding.
	if len(results2) != 1 {
		t.Fatalf("second scan: expected 1 cached finding, got %d", len(results2))
	}
	if results2[0].Algorithm.Name != "RSA-2048" {
		t.Errorf("cached finding: expected RSA-2048, got %q", results2[0].Algorithm.Name)
	}
}

func TestRunIncrementalV2_FileModified_OnlyChangedEnginesRescan(t *testing.T) {
	dir := t.TempDir()
	goFile := writeIncrFile(t, dir, "main.go", "package main // original")

	goEng := &mockIncrEngine{
		name: "go-scanner", tier: engines.Tier1Pattern, langs: []string{"go"}, version: "1.0.0",
		scanFn: func(_ context.Context, _ engines.ScanOptions) ([]findings.UnifiedFinding, error) {
			// Read current content to return appropriate findings.
			return []findings.UnifiedFinding{incrFinding("go-scanner", goFile, "RSA-2048", 1)}, nil
		},
	}

	orch := New(goEng)
	cachePath := filepath.Join(dir, ".cache.json")
	opts := engines.ScanOptions{
		TargetPath:  dir,
		Mode:        engines.ModeFull,
		Incremental: true,
		CachePath:   cachePath,
	}

	// First scan — populates cache.
	_, err := orch.runIncremental(context.Background(), opts, []engines.Engine{goEng}, "1.0.0")
	if err != nil {
		t.Fatalf("first scan: %v", err)
	}

	// Modify the file.
	if err := os.WriteFile(goFile, []byte("package main // modified content"), 0644); err != nil {
		t.Fatal(err)
	}

	// Update scanFn to return different finding for modified content.
	goEng.scanFn = func(_ context.Context, _ engines.ScanOptions) ([]findings.UnifiedFinding, error) {
		return []findings.UnifiedFinding{incrFinding("go-scanner", goFile, "ChaCha20", 1)}, nil
	}

	// Second scan — file changed, should rescan.
	results2, err := orch.runIncremental(context.Background(), opts, []engines.Engine{goEng}, "1.0.0")
	if err != nil {
		t.Fatalf("second scan: %v", err)
	}

	if goEng.scanCount() != 2 {
		t.Errorf("expected 2 scan calls (first + rescan), got %d", goEng.scanCount())
	}
	if len(results2) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(results2))
	}
	if results2[0].Algorithm.Name != "ChaCha20" {
		t.Errorf("expected ChaCha20 (new scan), got %q", results2[0].Algorithm.Name)
	}
}

func TestRunIncrementalV2_PerEngineInvalidation(t *testing.T) {
	dir := t.TempDir()
	goFile := writeIncrFile(t, dir, "main.go", "package main // uses AES")

	// Both engines scan .go files.
	engA := &mockIncrEngine{
		name: "engine-a", tier: engines.Tier1Pattern, langs: []string{"go"}, version: "1.0.0",
		scanFn: func(_ context.Context, _ engines.ScanOptions) ([]findings.UnifiedFinding, error) {
			return []findings.UnifiedFinding{incrFinding("engine-a", goFile, "AES-128", 1)}, nil
		},
	}
	engB := &mockIncrEngine{
		name: "engine-b", tier: engines.Tier1Pattern, langs: []string{"go"}, version: "1.0.0",
		scanFn: func(_ context.Context, _ engines.ScanOptions) ([]findings.UnifiedFinding, error) {
			return []findings.UnifiedFinding{incrFinding("engine-b", goFile, "RSA-2048", 5)}, nil
		},
	}

	orch := New(engA, engB)
	cachePath := filepath.Join(dir, ".cache.json")
	opts := engines.ScanOptions{
		TargetPath:  dir,
		Mode:        engines.ModeFull,
		Incremental: true,
		CachePath:   cachePath,
	}

	// First scan — both engines run.
	_, err := orch.runIncremental(context.Background(), opts, []engines.Engine{engA, engB}, "1.0.0")
	if err != nil {
		t.Fatalf("first scan: %v", err)
	}
	if engA.scanCount() != 1 || engB.scanCount() != 1 {
		t.Fatalf("first scan: expected both engines called once, got a=%d b=%d", engA.scanCount(), engB.scanCount())
	}

	// Upgrade engine-a version; engine-b unchanged.
	engA.version = "2.0.0"

	// Second scan — engine-a should rescan (version changed), engine-b should use cache.
	results2, err := orch.runIncremental(context.Background(), opts, []engines.Engine{engA, engB}, "1.0.0")
	if err != nil {
		t.Fatalf("second scan: %v", err)
	}

	if engA.scanCount() != 2 {
		t.Errorf("engine-a should have been called again (version changed), got count=%d", engA.scanCount())
	}
	if engB.scanCount() != 1 {
		t.Errorf("engine-b should NOT have been called again (cached), got count=%d", engB.scanCount())
	}
	if len(results2) != 2 {
		t.Errorf("expected 2 findings (1 fresh + 1 cached), got %d", len(results2))
	}
}

func TestRunIncrementalV2_ExtensionFiltering(t *testing.T) {
	dir := t.TempDir()
	goFile := writeIncrFile(t, dir, "main.go", "package main")
	rsFile := writeIncrFile(t, dir, "lib.rs", "fn main() {}")

	// Go engine only sees .go files.
	goEng := &mockIncrEngine{
		name: "go-scanner", tier: engines.Tier1Pattern, langs: []string{"go"}, version: "1.0.0",
		scanFn: func(_ context.Context, opts engines.ScanOptions) ([]findings.UnifiedFinding, error) {
			// Verify only .go files are in ChangedFiles.
			for _, cf := range opts.ChangedFiles {
				if filepath.Ext(cf) != ".go" && filepath.Base(cf) != "go.mod" && filepath.Base(cf) != "go.sum" {
					return nil, fmt.Errorf("go-scanner received non-Go file: %s", cf)
				}
			}
			return []findings.UnifiedFinding{incrFinding("go-scanner", goFile, "RSA-2048", 1)}, nil
		},
	}

	// Rust engine only sees .rs files.
	rsEng := &mockIncrEngine{
		name: "rust-scanner", tier: engines.Tier1Pattern, langs: []string{"rust"}, version: "1.0.0",
		scanFn: func(_ context.Context, opts engines.ScanOptions) ([]findings.UnifiedFinding, error) {
			for _, cf := range opts.ChangedFiles {
				if filepath.Ext(cf) != ".rs" && filepath.Ext(cf) != ".toml" {
					return nil, fmt.Errorf("rust-scanner received non-Rust file: %s", cf)
				}
			}
			return []findings.UnifiedFinding{incrFinding("rust-scanner", rsFile, "AES-256", 1)}, nil
		},
	}

	orch := New(goEng, rsEng)
	cachePath := filepath.Join(dir, ".cache.json")
	opts := engines.ScanOptions{
		TargetPath:  dir,
		Mode:        engines.ModeFull,
		Incremental: true,
		CachePath:   cachePath,
	}

	results, err := orch.runIncremental(context.Background(), opts, []engines.Engine{goEng, rsEng}, "1.0.0")
	if err != nil {
		t.Fatalf("runIncremental: %v", err)
	}

	// Each engine should have been called once.
	if goEng.scanCount() != 1 {
		t.Errorf("go-scanner count: %d", goEng.scanCount())
	}
	if rsEng.scanCount() != 1 {
		t.Errorf("rust-scanner count: %d", rsEng.scanCount())
	}
	if len(results) != 2 {
		t.Errorf("expected 2 findings, got %d", len(results))
	}

	_ = rsFile // used by rust-scanner
}

func TestRunIncrementalV2_NewEngineAdded(t *testing.T) {
	dir := t.TempDir()
	goFile := writeIncrFile(t, dir, "main.go", "package main // RSA")

	engA := &mockIncrEngine{
		name: "engine-a", tier: engines.Tier1Pattern, langs: []string{"go"}, version: "1.0.0",
		scanFn: func(_ context.Context, _ engines.ScanOptions) ([]findings.UnifiedFinding, error) {
			return []findings.UnifiedFinding{incrFinding("engine-a", goFile, "RSA-2048", 1)}, nil
		},
	}

	orch := New(engA)
	cachePath := filepath.Join(dir, ".cache.json")
	opts := engines.ScanOptions{
		TargetPath:  dir,
		Mode:        engines.ModeFull,
		Incremental: true,
		CachePath:   cachePath,
	}

	// First scan — only engine-a.
	_, err := orch.runIncremental(context.Background(), opts, []engines.Engine{engA}, "1.0.0")
	if err != nil {
		t.Fatalf("first scan: %v", err)
	}

	// Add engine-b.
	engB := &mockIncrEngine{
		name: "engine-b", tier: engines.Tier1Pattern, langs: []string{"go"}, version: "1.0.0",
		scanFn: func(_ context.Context, _ engines.ScanOptions) ([]findings.UnifiedFinding, error) {
			return []findings.UnifiedFinding{incrFinding("engine-b", goFile, "AES-128", 3)}, nil
		},
	}

	// Second scan — both engines. engine-a should use cache, engine-b should scan.
	results2, err := orch.runIncremental(context.Background(), opts, []engines.Engine{engA, engB}, "1.0.0")
	if err != nil {
		t.Fatalf("second scan: %v", err)
	}

	if engA.scanCount() != 1 {
		t.Errorf("engine-a should be cached, got count=%d", engA.scanCount())
	}
	if engB.scanCount() != 1 {
		t.Errorf("engine-b should have scanned, got count=%d", engB.scanCount())
	}
	if len(results2) != 2 {
		t.Errorf("expected 2 findings, got %d", len(results2))
	}
}

func TestRunIncrementalV2_ScannerVersionChange_FullInvalidation(t *testing.T) {
	dir := t.TempDir()
	goFile := writeIncrFile(t, dir, "main.go", "package main")

	eng := &mockIncrEngine{
		name: "go-scanner", tier: engines.Tier1Pattern, langs: []string{"go"}, version: "1.0.0",
		scanFn: func(_ context.Context, _ engines.ScanOptions) ([]findings.UnifiedFinding, error) {
			return []findings.UnifiedFinding{incrFinding("go-scanner", goFile, "RSA-2048", 1)}, nil
		},
	}

	orch := New(eng)
	cachePath := filepath.Join(dir, ".cache.json")
	opts := engines.ScanOptions{
		TargetPath:  dir,
		Mode:        engines.ModeFull,
		Incremental: true,
		CachePath:   cachePath,
	}

	// First scan with scanner v1.0.0.
	_, err := orch.runIncremental(context.Background(), opts, []engines.Engine{eng}, "1.0.0")
	if err != nil {
		t.Fatalf("first scan: %v", err)
	}

	// Second scan with scanner v2.0.0 — full invalidation even though files unchanged.
	_, err = orch.runIncremental(context.Background(), opts, []engines.Engine{eng}, "2.0.0")
	if err != nil {
		t.Fatalf("second scan: %v", err)
	}

	if eng.scanCount() != 2 {
		t.Errorf("scanner version change should force full rescan, got count=%d", eng.scanCount())
	}
}

func TestRunIncrementalV2_PartialEngineFailure(t *testing.T) {
	dir := t.TempDir()
	goFile := writeIncrFile(t, dir, "main.go", "package main")

	goodEng := &mockIncrEngine{
		name: "good-engine", tier: engines.Tier1Pattern, langs: []string{"go"}, version: "1.0.0",
		scanFn: func(_ context.Context, _ engines.ScanOptions) ([]findings.UnifiedFinding, error) {
			return []findings.UnifiedFinding{incrFinding("good-engine", goFile, "AES-256", 1)}, nil
		},
	}
	badEng := &mockIncrEngine{
		name: "bad-engine", tier: engines.Tier1Pattern, langs: []string{"go"}, version: "1.0.0",
		scanFn: func(_ context.Context, _ engines.ScanOptions) ([]findings.UnifiedFinding, error) {
			return nil, fmt.Errorf("simulated engine failure")
		},
	}

	orch := New(goodEng, badEng)
	cachePath := filepath.Join(dir, ".cache.json")
	opts := engines.ScanOptions{
		TargetPath:  dir,
		Mode:        engines.ModeFull,
		Incremental: true,
		CachePath:   cachePath,
	}

	results, err := orch.runIncremental(context.Background(), opts, []engines.Engine{goodEng, badEng}, "1.0.0")
	if err != nil {
		t.Fatalf("partial failure should not return error, got: %v", err)
	}
	if len(results) != 1 {
		t.Errorf("expected 1 finding from good engine, got %d", len(results))
	}
	if results[0].Algorithm.Name != "AES-256" {
		t.Errorf("expected AES-256, got %q", results[0].Algorithm.Name)
	}
}

func TestRunIncrementalV2_AllEnginesFail(t *testing.T) {
	dir := t.TempDir()
	writeIncrFile(t, dir, "main.go", "package main")

	bad1 := &mockIncrEngine{
		name: "bad1", tier: engines.Tier1Pattern, langs: []string{"go"}, version: "1.0.0",
		scanFn: func(_ context.Context, _ engines.ScanOptions) ([]findings.UnifiedFinding, error) {
			return nil, fmt.Errorf("boom")
		},
	}
	bad2 := &mockIncrEngine{
		name: "bad2", tier: engines.Tier1Pattern, langs: []string{"go"}, version: "1.0.0",
		scanFn: func(_ context.Context, _ engines.ScanOptions) ([]findings.UnifiedFinding, error) {
			return nil, fmt.Errorf("bang")
		},
	}

	orch := New(bad1, bad2)
	cachePath := filepath.Join(dir, ".cache.json")
	opts := engines.ScanOptions{
		TargetPath:  dir,
		Mode:        engines.ModeFull,
		Incremental: true,
		CachePath:   cachePath,
	}

	_, err := orch.runIncremental(context.Background(), opts, []engines.Engine{bad1, bad2}, "1.0.0")
	if err == nil {
		t.Fatal("all engines failing should return error")
	}
}

func TestRunIncrementalV2_ContextCancelled(t *testing.T) {
	dir := t.TempDir()
	writeIncrFile(t, dir, "main.go", "package main")

	eng := &mockIncrEngine{
		name: "blocker", tier: engines.Tier1Pattern, langs: []string{"go"}, version: "1.0.0",
		scanFn: func(ctx context.Context, _ engines.ScanOptions) ([]findings.UnifiedFinding, error) {
			<-ctx.Done()
			return nil, ctx.Err()
		},
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel immediately

	orch := New(eng)
	cachePath := filepath.Join(dir, ".cache.json")
	opts := engines.ScanOptions{
		TargetPath:  dir,
		Mode:        engines.ModeFull,
		Incremental: true,
		CachePath:   cachePath,
	}

	_, err := orch.runIncremental(ctx, opts, []engines.Engine{eng}, "1.0.0")
	if err == nil {
		t.Fatal("cancelled context should return error")
	}
}

func TestRunIncrementalV2_EmptyDirectory_NoFindings(t *testing.T) {
	dir := t.TempDir() // empty

	eng := &mockIncrEngine{
		name: "scanner", tier: engines.Tier1Pattern, langs: []string{"go"}, version: "1.0.0",
	}

	orch := New(eng)
	cachePath := filepath.Join(dir, ".cache.json")
	opts := engines.ScanOptions{
		TargetPath:  dir,
		Mode:        engines.ModeFull,
		Incremental: true,
		CachePath:   cachePath,
	}

	results, err := orch.runIncremental(context.Background(), opts, []engines.Engine{eng}, "1.0.0")
	if err != nil {
		t.Fatalf("empty dir scan: %v", err)
	}
	if len(results) != 0 {
		t.Errorf("expected 0 findings for empty dir, got %d", len(results))
	}
	// Engine should not be called since there are no relevant files.
	if eng.scanCount() != 0 {
		t.Errorf("engine should not be called for empty dir, got count=%d", eng.scanCount())
	}
}

func TestRunIncrementalV2_ArtifactEngine_SeesAllFiles(t *testing.T) {
	dir := t.TempDir()
	goFile := writeIncrFile(t, dir, "main.go", "package main")
	rsFile := writeIncrFile(t, dir, "lib.rs", "fn main() {}")
	jarFile := writeIncrFile(t, dir, "app.jar", "PK\x03\x04fake")

	var seenFiles int
	artEng := &mockIncrEngine{
		name: "artifact-scanner", tier: engines.Tier4Binary, langs: []string{"(artifacts)"},
		version: "1.0.0",
		scanFn: func(_ context.Context, opts engines.ScanOptions) ([]findings.UnifiedFinding, error) {
			seenFiles = len(opts.ChangedFiles)
			return nil, nil
		},
	}

	orch := New(artEng)
	cachePath := filepath.Join(dir, ".cache.json")
	opts := engines.ScanOptions{
		TargetPath:  dir,
		Mode:        engines.ModeFull,
		Incremental: true,
		CachePath:   cachePath,
	}

	_, err := orch.runIncremental(context.Background(), opts, []engines.Engine{artEng}, "1.0.0")
	if err != nil {
		t.Fatalf("runIncremental: %v", err)
	}

	// Artifact scanner with "(artifacts)" should see all 3 files.
	if seenFiles != 3 {
		t.Errorf("artifact engine should see all 3 files, got %d", seenFiles)
	}

	_ = goFile
	_ = rsFile
	_ = jarFile
}

func TestRunIncrementalV2_CacheRoundTrip_ThirdScan(t *testing.T) {
	dir := t.TempDir()
	fileA := writeIncrFile(t, dir, "a.go", "package main // AES")
	fileB := writeIncrFile(t, dir, "b.go", "package main // RSA")

	eng := &mockIncrEngine{
		name: "scanner", tier: engines.Tier1Pattern, langs: []string{"go"}, version: "1.0.0",
		scanFn: func(_ context.Context, _ engines.ScanOptions) ([]findings.UnifiedFinding, error) {
			return []findings.UnifiedFinding{
				incrFinding("scanner", fileA, "AES-256", 1),
				incrFinding("scanner", fileB, "RSA-2048", 1),
			}, nil
		},
	}

	orch := New(eng)
	cachePath := filepath.Join(dir, ".cache.json")
	opts := engines.ScanOptions{
		TargetPath:  dir,
		Mode:        engines.ModeFull,
		Incremental: true,
		CachePath:   cachePath,
	}

	// Scan 1: populate cache.
	results1, err := orch.runIncremental(context.Background(), opts, []engines.Engine{eng}, "1.0.0")
	if err != nil {
		t.Fatal(err)
	}
	if len(results1) != 2 {
		t.Fatalf("scan 1: expected 2 findings, got %d", len(results1))
	}

	// Scan 2: modify file A only.
	if err := os.WriteFile(fileA, []byte("package main // ChaCha20 now"), 0644); err != nil {
		t.Fatal(err)
	}
	eng.scanFn = func(_ context.Context, opts engines.ScanOptions) ([]findings.UnifiedFinding, error) {
		// Only return findings for changed files (simulates real engine behavior).
		var ff []findings.UnifiedFinding
		for _, cf := range opts.ChangedFiles {
			abs := filepath.Join(dir, cf)
			if abs == fileA {
				ff = append(ff, incrFinding("scanner", fileA, "ChaCha20", 1))
			}
		}
		return ff, nil
	}

	results2, err := orch.runIncremental(context.Background(), opts, []engines.Engine{eng}, "1.0.0")
	if err != nil {
		t.Fatal(err)
	}

	if eng.scanCount() != 2 {
		t.Errorf("scan 2: expected 2 total calls, got %d", eng.scanCount())
	}
	if len(results2) != 2 {
		t.Fatalf("scan 2: expected 2 findings (1 cached + 1 new), got %d", len(results2))
	}

	// Verify we got the new ChaCha20 finding and cached RSA-2048.
	algSet := make(map[string]bool)
	for _, f := range results2 {
		algSet[f.Algorithm.Name] = true
	}
	if !algSet["ChaCha20"] {
		t.Error("scan 2: expected ChaCha20 (new scan)")
	}
	if !algSet["RSA-2048"] {
		t.Error("scan 2: expected RSA-2048 (cached)")
	}

	// Scan 3: no changes — all cached.
	results3, err := orch.runIncremental(context.Background(), opts, []engines.Engine{eng}, "1.0.0")
	if err != nil {
		t.Fatal(err)
	}

	if eng.scanCount() != 2 {
		t.Errorf("scan 3: expected 2 total calls (no rescan), got %d", eng.scanCount())
	}
	if len(results3) != 2 {
		t.Fatalf("scan 3: expected 2 cached findings, got %d", len(results3))
	}

	algSet3 := make(map[string]bool)
	for _, f := range results3 {
		algSet3[f.Algorithm.Name] = true
	}
	if !algSet3["ChaCha20"] {
		t.Error("scan 3: expected ChaCha20 (cached)")
	}
	if !algSet3["RSA-2048"] {
		t.Error("scan 3: expected RSA-2048 (cached)")
	}
}

func TestRunIncrementalV2_FileDeleted_FindingsPruned(t *testing.T) {
	dir := t.TempDir()
	fileA := writeIncrFile(t, dir, "a.go", "package main // AES")
	fileB := writeIncrFile(t, dir, "b.go", "package main // RSA")

	eng := &mockIncrEngine{
		name: "scanner", tier: engines.Tier1Pattern, langs: []string{"go"}, version: "1.0.0",
		scanFn: func(_ context.Context, _ engines.ScanOptions) ([]findings.UnifiedFinding, error) {
			return []findings.UnifiedFinding{
				incrFinding("scanner", fileA, "AES-256", 1),
				incrFinding("scanner", fileB, "RSA-2048", 1),
			}, nil
		},
	}

	orch := New(eng)
	cachePath := filepath.Join(dir, ".cache.json")
	opts := engines.ScanOptions{
		TargetPath:  dir,
		Mode:        engines.ModeFull,
		Incremental: true,
		CachePath:   cachePath,
	}

	// First scan — populate cache with both files.
	_, err := orch.runIncremental(context.Background(), opts, []engines.Engine{eng}, "1.0.0")
	if err != nil {
		t.Fatal(err)
	}

	// Delete file B.
	if err := os.Remove(fileB); err != nil {
		t.Fatal(err)
	}

	// Second scan — file B is gone, should not appear in results.
	results2, err := orch.runIncremental(context.Background(), opts, []engines.Engine{eng}, "1.0.0")
	if err != nil {
		t.Fatalf("second scan: %v", err)
	}

	// Only file A's finding should remain.
	if len(results2) != 1 {
		t.Fatalf("expected 1 finding after deletion, got %d", len(results2))
	}
	if results2[0].Algorithm.Name != "AES-256" {
		t.Errorf("expected AES-256 (file A), got %q", results2[0].Algorithm.Name)
	}
}

func TestRunIncrementalV2_V1CacheFile_TriggersFullRescan(t *testing.T) {
	dir := t.TempDir()
	goFile := writeIncrFile(t, dir, "main.go", "package main")

	// Write a V1 cache file.
	cachePath := filepath.Join(dir, ".cache.json")
	v1Data := `{"version":"1","scannerVersion":"1.0.0","engineVersions":{"scanner":"1.0.0"},"entries":{"/old/path":{"contentHash":"oldhash","findings":[]}}}`
	if err := os.WriteFile(cachePath, []byte(v1Data), 0644); err != nil {
		t.Fatal(err)
	}

	eng := &mockIncrEngine{
		name: "scanner", tier: engines.Tier1Pattern, langs: []string{"go"}, version: "1.0.0",
		scanFn: func(_ context.Context, _ engines.ScanOptions) ([]findings.UnifiedFinding, error) {
			return []findings.UnifiedFinding{incrFinding("scanner", goFile, "RSA-2048", 1)}, nil
		},
	}

	orch := New(eng)
	opts := engines.ScanOptions{
		TargetPath:  dir,
		Mode:        engines.ModeFull,
		Incremental: true,
		CachePath:   cachePath,
	}

	results, err := orch.runIncremental(context.Background(), opts, []engines.Engine{eng}, "1.0.0")
	if err != nil {
		t.Fatalf("runIncremental: %v", err)
	}

	// V1 cache should trigger full rescan (format mismatch).
	if eng.scanCount() != 1 {
		t.Errorf("V1 cache should trigger full scan, got count=%d", eng.scanCount())
	}
	if len(results) != 1 {
		t.Errorf("expected 1 finding, got %d", len(results))
	}
}

func TestRunIncrementalV2_MultipleEnginesDifferentExtensions(t *testing.T) {
	dir := t.TempDir()
	goFile := writeIncrFile(t, dir, "main.go", "package main // AES")
	rsFile := writeIncrFile(t, dir, "lib.rs", "fn main() { /* RSA */ }")

	goEng := &mockIncrEngine{
		name: "go-scanner", tier: engines.Tier1Pattern, langs: []string{"go"}, version: "1.0.0",
		scanFn: func(_ context.Context, _ engines.ScanOptions) ([]findings.UnifiedFinding, error) {
			return []findings.UnifiedFinding{incrFinding("go-scanner", goFile, "AES-256", 1)}, nil
		},
	}
	rsEng := &mockIncrEngine{
		name: "rust-scanner", tier: engines.Tier1Pattern, langs: []string{"rust"}, version: "1.0.0",
		scanFn: func(_ context.Context, _ engines.ScanOptions) ([]findings.UnifiedFinding, error) {
			return []findings.UnifiedFinding{incrFinding("rust-scanner", rsFile, "RSA-2048", 1)}, nil
		},
	}

	orch := New(goEng, rsEng)
	cachePath := filepath.Join(dir, ".cache.json")
	opts := engines.ScanOptions{
		TargetPath:  dir,
		Mode:        engines.ModeFull,
		Incremental: true,
		CachePath:   cachePath,
	}

	// First scan — both engines run.
	_, err := orch.runIncremental(context.Background(), opts, []engines.Engine{goEng, rsEng}, "1.0.0")
	if err != nil {
		t.Fatal(err)
	}

	// Modify only the Go file.
	if err := os.WriteFile(goFile, []byte("package main // ChaCha20"), 0644); err != nil {
		t.Fatal(err)
	}

	goEng.scanFn = func(_ context.Context, _ engines.ScanOptions) ([]findings.UnifiedFinding, error) {
		return []findings.UnifiedFinding{incrFinding("go-scanner", goFile, "ChaCha20", 1)}, nil
	}

	// Second scan — go-scanner should rescan, rust-scanner should use cache.
	results2, err := orch.runIncremental(context.Background(), opts, []engines.Engine{goEng, rsEng}, "1.0.0")
	if err != nil {
		t.Fatal(err)
	}

	if goEng.scanCount() != 2 {
		t.Errorf("go-scanner should rescan (.go file changed), got count=%d", goEng.scanCount())
	}
	if rsEng.scanCount() != 1 {
		t.Errorf("rust-scanner should use cache (.rs unchanged), got count=%d", rsEng.scanCount())
	}
	if len(results2) != 2 {
		t.Errorf("expected 2 findings, got %d", len(results2))
	}

	algSet := make(map[string]bool)
	for _, f := range results2 {
		algSet[f.Algorithm.Name] = true
	}
	if !algSet["ChaCha20"] {
		t.Error("expected ChaCha20 from go-scanner rescan")
	}
	if !algSet["RSA-2048"] {
		t.Error("expected RSA-2048 from rust-scanner cache")
	}
}

func TestRunIncrementalV2_EnginePanic_RecoveredGracefully(t *testing.T) {
	dir := t.TempDir()
	goFile := writeIncrFile(t, dir, "main.go", "package main")

	goodEng := &mockIncrEngine{
		name: "good", tier: engines.Tier1Pattern, langs: []string{"go"}, version: "1.0.0",
		scanFn: func(_ context.Context, _ engines.ScanOptions) ([]findings.UnifiedFinding, error) {
			return []findings.UnifiedFinding{incrFinding("good", goFile, "AES-256", 1)}, nil
		},
	}
	panicEng := &mockIncrEngine{
		name: "panicker", tier: engines.Tier1Pattern, langs: []string{"go"}, version: "1.0.0",
		scanFn: func(_ context.Context, _ engines.ScanOptions) ([]findings.UnifiedFinding, error) {
			panic("simulated engine panic")
		},
	}

	orch := New(goodEng, panicEng)
	cachePath := filepath.Join(dir, ".cache.json")
	opts := engines.ScanOptions{
		TargetPath:  dir,
		Mode:        engines.ModeFull,
		Incremental: true,
		CachePath:   cachePath,
	}

	// Should not crash — panic is recovered.
	results, err := orch.runIncremental(context.Background(), opts, []engines.Engine{goodEng, panicEng}, "1.0.0")
	if err != nil {
		t.Fatalf("should not return error on partial panic, got: %v", err)
	}
	if len(results) != 1 {
		t.Errorf("expected 1 finding from good engine, got %d", len(results))
	}
}

// --- Incremental Diff Mode Tests ---

func TestRunIncrementalDiff_FirstScan_OnlyHashesChangedFiles(t *testing.T) {
	dir := t.TempDir()
	// Create 3 files but only 2 are "changed" in the diff.
	writeIncrFile(t, dir, "unchanged.go", "package main")
	writeIncrFile(t, dir, "changed1.go", "package main\nvar x = 1")
	writeIncrFile(t, dir, "changed2.go", "package main\nvar y = 2")

	cacheFile := filepath.Join(dir, ".cache.json")

	var scannedFiles []string
	eng := &mockIncrEngine{
		name:    "gocheck",
		tier:    engines.Tier1Pattern,
		langs:   []string{"go"},
		version: "1.0.0",
		scanFn: func(ctx context.Context, opts engines.ScanOptions) ([]findings.UnifiedFinding, error) {
			scannedFiles = opts.ChangedFiles
			return nil, nil
		},
	}

	orch := New(eng)
	opts := engines.ScanOptions{
		TargetPath:  dir,
		Mode:        engines.ModeDiff,
		ChangedFiles: []string{"changed1.go", "changed2.go"},
		Incremental: true,
		CachePath:   cacheFile,
	}

	results, err := orch.runIncremental(context.Background(), opts, []engines.Engine{eng}, "1.0.0")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Engine should be called (first scan, no cache).
	if eng.scanCount() != 1 {
		t.Errorf("expected 1 scan call, got %d", eng.scanCount())
	}

	// Should only scan changed files, not unchanged.go.
	for _, f := range scannedFiles {
		if f == "unchanged.go" {
			t.Error("unchanged.go should NOT be in ChangedFiles for diff mode")
		}
	}

	_ = results
}

func TestRunIncrementalDiff_SecondScan_SkipsCachedFiles(t *testing.T) {
	dir := t.TempDir()
	writeIncrFile(t, dir, "file1.go", "package main\nvar x = 1")
	writeIncrFile(t, dir, "file2.go", "package main\nvar y = 2")

	cacheFile := filepath.Join(dir, ".cache.json")

	scanCount := int32(0)
	eng := &mockIncrEngine{
		name:    "gocheck",
		tier:    engines.Tier1Pattern,
		langs:   []string{"go"},
		version: "1.0.0",
		scanFn: func(ctx context.Context, opts engines.ScanOptions) ([]findings.UnifiedFinding, error) {
			atomic.AddInt32(&scanCount, 1)
			var ff []findings.UnifiedFinding
			for _, f := range opts.ChangedFiles {
				abs := filepath.Join(dir, f)
				ff = append(ff, incrFinding("gocheck", abs, "AES", 1))
			}
			return ff, nil
		},
	}

	orch := New(eng)

	// First scan: both files are changed.
	opts := engines.ScanOptions{
		TargetPath:  dir,
		Mode:        engines.ModeDiff,
		ChangedFiles: []string{"file1.go", "file2.go"},
		Incremental: true,
		CachePath:   cacheFile,
	}

	results1, err := orch.runIncremental(context.Background(), opts, []engines.Engine{eng}, "1.0.0")
	if err != nil {
		t.Fatalf("scan 1 error: %v", err)
	}
	if len(results1) != 2 {
		t.Fatalf("scan 1: expected 2 findings, got %d", len(results1))
	}
	if atomic.LoadInt32(&scanCount) != 1 {
		t.Errorf("scan 1: expected 1 scan call, got %d", atomic.LoadInt32(&scanCount))
	}

	// Second scan: same files, same content → should use cache (0 additional scans).
	eng2 := &mockIncrEngine{
		name:    "gocheck",
		tier:    engines.Tier1Pattern,
		langs:   []string{"go"},
		version: "1.0.0",
	}

	results2, err := orch.runIncremental(context.Background(), opts, []engines.Engine{eng2}, "1.0.0")
	if err != nil {
		t.Fatalf("scan 2 error: %v", err)
	}
	// Should get 2 cached findings.
	if len(results2) != 2 {
		t.Errorf("scan 2: expected 2 cached findings, got %d", len(results2))
	}
	// Engine should NOT be called (all files cached).
	if eng2.scanCount() != 0 {
		t.Errorf("scan 2: expected 0 scan calls, got %d", eng2.scanCount())
	}
}

func TestRunIncrementalDiff_FileModified_RescansOnly(t *testing.T) {
	dir := t.TempDir()
	writeIncrFile(t, dir, "stable.go", "package main\nvar x = 1")
	writeIncrFile(t, dir, "changing.go", "package main\nvar y = 2")

	cacheFile := filepath.Join(dir, ".cache.json")

	eng := &mockIncrEngine{
		name:    "gocheck",
		tier:    engines.Tier1Pattern,
		langs:   []string{"go"},
		version: "1.0.0",
		scanFn: func(ctx context.Context, opts engines.ScanOptions) ([]findings.UnifiedFinding, error) {
			var ff []findings.UnifiedFinding
			for _, f := range opts.ChangedFiles {
				abs := filepath.Join(dir, f)
				ff = append(ff, incrFinding("gocheck", abs, "AES", 1))
			}
			return ff, nil
		},
	}

	orch := New(eng)

	// First scan: both files changed.
	opts := engines.ScanOptions{
		TargetPath:  dir,
		Mode:        engines.ModeDiff,
		ChangedFiles: []string{"stable.go", "changing.go"},
		Incremental: true,
		CachePath:   cacheFile,
	}

	_, err := orch.runIncremental(context.Background(), opts, []engines.Engine{eng}, "1.0.0")
	if err != nil {
		t.Fatalf("scan 1 error: %v", err)
	}

	// Modify changing.go.
	writeIncrFile(t, dir, "changing.go", "package main\nvar y = 3 // modified")

	// Second scan: both files in ChangedFiles, but stable.go hasn't changed content.
	var rescannedFiles []string
	eng2 := &mockIncrEngine{
		name:    "gocheck",
		tier:    engines.Tier1Pattern,
		langs:   []string{"go"},
		version: "1.0.0",
		scanFn: func(ctx context.Context, opts engines.ScanOptions) ([]findings.UnifiedFinding, error) {
			rescannedFiles = opts.ChangedFiles
			var ff []findings.UnifiedFinding
			for _, f := range opts.ChangedFiles {
				abs := filepath.Join(dir, f)
				ff = append(ff, incrFinding("gocheck", abs, "RSA", 1))
			}
			return ff, nil
		},
	}

	results2, err := orch.runIncremental(context.Background(), opts, []engines.Engine{eng2}, "1.0.0")
	if err != nil {
		t.Fatalf("scan 2 error: %v", err)
	}

	// Should have 2 findings total: 1 cached (stable.go) + 1 fresh (changing.go).
	if len(results2) != 2 {
		t.Errorf("scan 2: expected 2 findings (1 cached + 1 fresh), got %d", len(results2))
	}

	// Only changing.go should be rescanned.
	if len(rescannedFiles) != 1 {
		t.Errorf("scan 2: expected 1 file rescanned, got %d: %v", len(rescannedFiles), rescannedFiles)
	}
}

func TestRunIncrementalDiff_DeletedFileInChangedList(t *testing.T) {
	dir := t.TempDir()
	writeIncrFile(t, dir, "exists.go", "package main")
	// "deleted.go" is listed in ChangedFiles but doesn't exist on disk.

	cacheFile := filepath.Join(dir, ".cache.json")

	eng := &mockIncrEngine{
		name:    "gocheck",
		tier:    engines.Tier1Pattern,
		langs:   []string{"go"},
		version: "1.0.0",
	}

	orch := New(eng)
	opts := engines.ScanOptions{
		TargetPath:  dir,
		Mode:        engines.ModeDiff,
		ChangedFiles: []string{"exists.go", "deleted.go"},
		Incremental: true,
		CachePath:   cacheFile,
	}

	results, err := orch.runIncremental(context.Background(), opts, []engines.Engine{eng}, "1.0.0")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Should not crash — deleted.go is skipped during path resolution.
	_ = results
}

func TestRunIncrementalDiff_EmptyChangedFiles(t *testing.T) {
	dir := t.TempDir()
	writeIncrFile(t, dir, "some.go", "package main")

	cacheFile := filepath.Join(dir, ".cache.json")

	eng := &mockIncrEngine{
		name:    "gocheck",
		tier:    engines.Tier1Pattern,
		langs:   []string{"go"},
		version: "1.0.0",
	}

	orch := New(eng)
	opts := engines.ScanOptions{
		TargetPath:  dir,
		Mode:        engines.ModeDiff,
		ChangedFiles: []string{},
		Incremental: true,
		CachePath:   cacheFile,
	}

	results, err := orch.runIncremental(context.Background(), opts, []engines.Engine{eng}, "1.0.0")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// No files to scan → no findings.
	if len(results) != 0 {
		t.Errorf("expected 0 findings for empty changed files, got %d", len(results))
	}
	// Engine should not be called.
	if eng.scanCount() != 0 {
		t.Errorf("expected 0 scan calls, got %d", eng.scanCount())
	}
}

func TestRunIncrementalDiff_CacheNotCorruptedByDiffScope(t *testing.T) {
	dir := t.TempDir()
	writeIncrFile(t, dir, "file_a.go", "package main\nvar a = 1")
	writeIncrFile(t, dir, "file_b.go", "package main\nvar b = 2")
	writeIncrFile(t, dir, "file_c.go", "package main\nvar c = 3")

	cacheFile := filepath.Join(dir, ".cache.json")

	eng := &mockIncrEngine{
		name:    "gocheck",
		tier:    engines.Tier1Pattern,
		langs:   []string{"go"},
		version: "1.0.0",
		scanFn: func(ctx context.Context, opts engines.ScanOptions) ([]findings.UnifiedFinding, error) {
			var ff []findings.UnifiedFinding
			for _, f := range opts.ChangedFiles {
				abs := filepath.Join(dir, f)
				ff = append(ff, incrFinding("gocheck", abs, "AES", 1))
			}
			return ff, nil
		},
	}

	orch := New(eng)

	// Scan 1: diff with file_a and file_b.
	opts1 := engines.ScanOptions{
		TargetPath:  dir,
		Mode:        engines.ModeDiff,
		ChangedFiles: []string{"file_a.go", "file_b.go"},
		Incremental: true,
		CachePath:   cacheFile,
	}
	_, err := orch.runIncremental(context.Background(), opts1, []engines.Engine{eng}, "1.0.0")
	if err != nil {
		t.Fatalf("scan 1 error: %v", err)
	}

	// Scan 2: diff with file_b and file_c. file_b should be cached (same hash).
	eng2 := &mockIncrEngine{
		name:    "gocheck",
		tier:    engines.Tier1Pattern,
		langs:   []string{"go"},
		version: "1.0.0",
		scanFn: func(ctx context.Context, opts engines.ScanOptions) ([]findings.UnifiedFinding, error) {
			var ff []findings.UnifiedFinding
			for _, f := range opts.ChangedFiles {
				abs := filepath.Join(dir, f)
				ff = append(ff, incrFinding("gocheck", abs, "RSA", 1))
			}
			return ff, nil
		},
	}

	opts2 := engines.ScanOptions{
		TargetPath:  dir,
		Mode:        engines.ModeDiff,
		ChangedFiles: []string{"file_b.go", "file_c.go"},
		Incremental: true,
		CachePath:   cacheFile,
	}
	results2, err := orch.runIncremental(context.Background(), opts2, []engines.Engine{eng2}, "1.0.0")
	if err != nil {
		t.Fatalf("scan 2 error: %v", err)
	}

	// file_b should be cached (AES from scan 1), file_c should be fresh (RSA from scan 2).
	if len(results2) != 2 {
		t.Fatalf("expected 2 findings, got %d", len(results2))
	}

	// Only file_c should have been rescanned.
	if eng2.scanCount() != 1 {
		t.Errorf("expected 1 scan call (file_c only), got %d", eng2.scanCount())
	}

	// Verify finding algorithms.
	foundAES := false
	foundRSA := false
	for _, f := range results2 {
		if f.Algorithm != nil {
			switch f.Algorithm.Name {
			case "AES":
				foundAES = true
			case "RSA":
				foundRSA = true
			}
		}
	}
	if !foundAES {
		t.Error("expected cached AES finding from file_b")
	}
	if !foundRSA {
		t.Error("expected fresh RSA finding from file_c")
	}

	// Scan 3: diff with file_a only. file_a's cache entry must NOT have been
	// pruned during scan 2 (file_a was not in scan 2's ChangedFiles).
	eng3 := &mockIncrEngine{
		name:    "gocheck",
		tier:    engines.Tier1Pattern,
		langs:   []string{"go"},
		version: "1.0.0",
		scanFn: func(ctx context.Context, opts engines.ScanOptions) ([]findings.UnifiedFinding, error) {
			t.Fatal("engine should not be called — file_a should be cached from scan 1")
			return nil, nil
		},
	}

	opts3 := engines.ScanOptions{
		TargetPath:   dir,
		Mode:         engines.ModeDiff,
		ChangedFiles: []string{"file_a.go"},
		Incremental:  true,
		CachePath:    cacheFile,
	}
	results3, err := orch.runIncremental(context.Background(), opts3, []engines.Engine{eng3}, "1.0.0")
	if err != nil {
		t.Fatalf("scan 3 error: %v", err)
	}

	// file_a should use cached AES finding from scan 1.
	if len(results3) != 1 {
		t.Fatalf("expected 1 cached finding for file_a, got %d", len(results3))
	}
	if results3[0].Algorithm == nil || results3[0].Algorithm.Name != "AES" {
		t.Errorf("expected cached AES finding, got %v", results3[0])
	}
	// Engine must not have been called (cache hit).
	if eng3.scanCount() != 0 {
		t.Errorf("expected 0 scan calls for cached file_a, got %d", eng3.scanCount())
	}
}

// TestRunIncrementalV2_PanicRecoverySetsFailedFlag verifies that when an engine
// panics during incremental scan, the panic recovery marks scanFailed=true so
// the engine's version is NOT recorded in the cache. Without this fix, a panicked
// engine's version would be cached, potentially causing stale/missing findings on
// subsequent runs.
func TestRunIncrementalV2_PanicRecoverySetsFailedFlag(t *testing.T) {
	dir := t.TempDir()
	writeIncrFile(t, dir, "main.go", "package main\n")

	panicEngine := &mockIncrEngine{
		name:    "panic-engine",
		tier:    engines.Tier1Pattern,
		langs:   []string{"go"},
		version: "1.0.0",
		scanFn: func(ctx context.Context, opts engines.ScanOptions) ([]findings.UnifiedFinding, error) {
			panic("simulated engine panic")
		},
	}
	stableEngine := &mockIncrEngine{
		name:    "stable-engine",
		tier:    engines.Tier1Pattern,
		langs:   []string{"go"},
		version: "2.0.0",
		scanFn: func(ctx context.Context, opts engines.ScanOptions) ([]findings.UnifiedFinding, error) {
			return []findings.UnifiedFinding{incrFinding("stable-engine", opts.ChangedFiles[0], "AES", 1)}, nil
		},
	}

	cachePath := filepath.Join(dir, ".oqs-cache.json")
	orch := New(panicEngine, stableEngine)
	SetScannerVersion("test-panic")

	opts := engines.ScanOptions{
		TargetPath:  dir,
		Mode:        engines.ModeFull,
		Incremental: true,
		CachePath:   cachePath,
	}

	// First run — panic engine panics, stable engine succeeds.
	results, _, _, err := orch.scanPipeline(context.Background(), opts)
	if err != nil {
		t.Fatalf("scanPipeline should not fail entirely: %v", err)
	}

	// Stable engine's findings should still be present.
	foundAES := false
	for _, f := range results {
		if f.Algorithm != nil && f.Algorithm.Name == "AES" {
			foundAES = true
		}
	}
	if !foundAES {
		t.Error("stable engine's AES finding should be present despite panic engine failure")
	}

	// Second run with same cache — panicked engine should be re-scanned
	// (its version should NOT be in the cache).
	panicEngine2 := &mockIncrEngine{
		name:    "panic-engine",
		tier:    engines.Tier1Pattern,
		langs:   []string{"go"},
		version: "1.0.0",
		scanFn: func(ctx context.Context, opts engines.ScanOptions) ([]findings.UnifiedFinding, error) {
			return []findings.UnifiedFinding{incrFinding("panic-engine", opts.ChangedFiles[0], "DES", 1)}, nil
		},
	}
	stableEngine2 := &mockIncrEngine{
		name:    "stable-engine",
		tier:    engines.Tier1Pattern,
		langs:   []string{"go"},
		version: "2.0.0",
	}

	orch2 := New(panicEngine2, stableEngine2)
	results2, _, _, err := orch2.scanPipeline(context.Background(), opts)
	if err != nil {
		t.Fatalf("second scanPipeline error: %v", err)
	}

	// Panic engine should have been re-scanned (version NOT cached).
	if panicEngine2.scanCount() == 0 {
		t.Error("panic engine should be re-scanned on second run (its version should not be cached)")
	}

	// Should have findings from both engines now.
	foundDES := false
	for _, f := range results2 {
		if f.Algorithm != nil && f.Algorithm.Name == "DES" {
			foundDES = true
		}
	}
	if !foundDES {
		t.Error("panic engine's DES finding should be present on second run")
	}
}

// TestRunIncrementalV2_AbsolutePathConsistency verifies that the incremental
// cache stores findings under absolute paths, even when opts.TargetPath is relative.
// This prevents findings from being silently dropped due to path key mismatches.
func TestRunIncrementalV2_AbsolutePathConsistency(t *testing.T) {
	dir := t.TempDir()
	writeIncrFile(t, dir, "crypto.go", "package main\nvar cipher = \"AES\"\n")

	eng := &mockIncrEngine{
		name:    "path-test",
		tier:    engines.Tier1Pattern,
		langs:   []string{"go"},
		version: "1.0.0",
		scanFn: func(ctx context.Context, opts engines.ScanOptions) ([]findings.UnifiedFinding, error) {
			var out []findings.UnifiedFinding
			for _, f := range opts.ChangedFiles {
				// Engine returns findings with the path it received.
				out = append(out, incrFinding("path-test", filepath.Join(opts.TargetPath, f), "AES", 1))
			}
			return out, nil
		},
	}

	cachePath := filepath.Join(dir, ".oqs-cache.json")
	orch := New(eng)
	SetScannerVersion("test-path")

	opts := engines.ScanOptions{
		TargetPath:  dir,
		Mode:        engines.ModeFull,
		Incremental: true,
		CachePath:   cachePath,
	}

	// First run: engine produces findings.
	results1, _, _, err := orch.scanPipeline(context.Background(), opts)
	if err != nil {
		t.Fatalf("first run error: %v", err)
	}
	if len(results1) == 0 {
		t.Fatal("expected findings on first run")
	}

	// Second run: file unchanged — findings should come from cache.
	eng2 := &mockIncrEngine{
		name:    "path-test",
		tier:    engines.Tier1Pattern,
		langs:   []string{"go"},
		version: "1.0.0",
	}
	orch2 := New(eng2)
	results2, _, _, err := orch2.scanPipeline(context.Background(), opts)
	if err != nil {
		t.Fatalf("second run error: %v", err)
	}

	// Engine should NOT have been called (cache hit).
	if eng2.scanCount() != 0 {
		t.Errorf("expected 0 scan calls on cache hit, got %d", eng2.scanCount())
	}

	// Cached findings should be returned.
	if len(results2) == 0 {
		t.Error("expected cached findings on second run — path key mismatch may have caused cache miss")
	}
}

// TestScanPipeline_ExcludePatterns_RelativeTargetPath verifies that
// filterByExcludePatterns works correctly when the caller passes a relative
// TargetPath. Before the fix, scanPipeline did not normalize opts.TargetPath
// to absolute. Engines always emit findings with absolute Location.File paths;
// using a relative base in filepath.Rel caused the relative path to start with
// "../", which never matched the flat exclude patterns, silently ignoring them.
//
// Non-incremental mode is used to isolate the filterByExcludePatterns path
// without the incremental filterByChangedFiles step complicating the assertion.
func TestScanPipeline_ExcludePatterns_RelativeTargetPath(t *testing.T) {
	dir := t.TempDir()

	// Create two Go source files in a subdirectory so the absolute paths are
	// <dir>/src/main.go and <dir>/src/main_test.go.
	subDir := filepath.Join(dir, "src")
	if err := os.Mkdir(subDir, 0755); err != nil {
		t.Fatalf("mkdir src: %v", err)
	}
	mainFile := writeIncrFile(t, subDir, "main.go", "package main")
	testFile := writeIncrFile(t, subDir, "main_test.go", "package main")

	// Engine always returns two findings with absolute Location.File paths,
	// which is the contract all real engines follow.
	eng := &mockIncrEngine{
		name: "go-scanner", tier: engines.Tier1Pattern, langs: []string{"go"}, version: "1.0.0",
		scanFn: func(_ context.Context, _ engines.ScanOptions) ([]findings.UnifiedFinding, error) {
			return []findings.UnifiedFinding{
				incrFinding("go-scanner", mainFile, "RSA-2048", 1),
				incrFinding("go-scanner", testFile, "AES-128", 1),
			}, nil
		},
	}

	orch := New(eng)

	// Change working directory to dir so "src" resolves correctly via filepath.Abs.
	origWd, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	defer func() { _ = os.Chdir(origWd) }()
	if err := os.Chdir(dir); err != nil {
		t.Fatalf("chdir: %v", err)
	}

	opts := engines.ScanOptions{
		TargetPath:      "src",  // relative path — this is the key point of the test
		Mode:            engines.ModeFull,
		Incremental:     false,  // non-incremental isolates filterByExcludePatterns
		ExcludePatterns: []string{"*_test.go"},
	}

	results, _, _, err := orch.scanPipeline(context.Background(), opts)
	if err != nil {
		t.Fatalf("scanPipeline: %v", err)
	}

	// After the fix, opts.TargetPath is normalized to abs(<dir>/src) before
	// filterByExcludePatterns. filepath.Rel(<dir>/src, <dir>/src/main_test.go)
	// = "main_test.go", which matches "*_test.go". Without the fix, the
	// relative base "src" would produce a "../..." relative path for absolute
	// finding paths, making the pattern match fail silently.
	if len(results) != 1 {
		t.Errorf("expected 1 finding after excluding *_test.go, got %d", len(results))
		for _, f := range results {
			t.Logf("  finding file: %s", f.Location.File)
		}
	}
	if len(results) >= 1 {
		if results[0].Location.File != mainFile {
			t.Errorf("surviving finding: got %s, want %s", results[0].Location.File, mainFile)
		}
	}
	_ = testFile // referenced for clarity, excluded by the pattern
}
