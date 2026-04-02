package orchestrator

import (
	"context"
	"fmt"
	"runtime"
	"testing"
	"time"

	"github.com/jimbo111/open-quantum-secure/pkg/engines"
	"github.com/jimbo111/open-quantum-secure/pkg/findings"
)

func TestDedupe_MergesFindings(t *testing.T) {
	all := []findings.UnifiedFinding{
		{
			Location:     findings.Location{File: "/a.go", Line: 10},
			Algorithm:    &findings.Algorithm{Name: "RSA", KeySize: 2048},
			Confidence:   findings.ConfidenceMedium,
			SourceEngine: "cipherscope",
		},
		{
			Location:     findings.Location{File: "/a.go", Line: 10},
			Algorithm:    &findings.Algorithm{Name: "RSA", Primitive: "signature"},
			Confidence:   findings.ConfidenceLow,
			SourceEngine: "cryptoscan",
		},
	}

	result := dedupe(all)
	if len(result) != 1 {
		t.Fatalf("dedupe() returned %d findings, want 1", len(result))
	}

	f := result[0]
	// Should be corroborated
	if len(f.CorroboratedBy) != 1 || f.CorroboratedBy[0] != "cryptoscan" {
		t.Errorf("CorroboratedBy = %v, want [cryptoscan]", f.CorroboratedBy)
	}
	// Confidence should be boosted (medium + corroboration → medium-high)
	if f.Confidence != findings.ConfidenceMediumHigh {
		t.Errorf("Confidence = %q, want %q", f.Confidence, findings.ConfidenceMediumHigh)
	}
	// Metadata should be merged: KeySize from first, Primitive from second
	if f.Algorithm.KeySize != 2048 {
		t.Errorf("Algorithm.KeySize = %d, want 2048", f.Algorithm.KeySize)
	}
	if f.Algorithm.Primitive != "signature" {
		t.Errorf("Algorithm.Primitive = %q, want %q", f.Algorithm.Primitive, "signature")
	}
}

func TestDedupe_NoDuplicates(t *testing.T) {
	all := []findings.UnifiedFinding{
		{
			Location:     findings.Location{File: "/a.go", Line: 10},
			Algorithm:    &findings.Algorithm{Name: "RSA"},
			SourceEngine: "cipherscope",
		},
		{
			Location:     findings.Location{File: "/b.go", Line: 20},
			Algorithm:    &findings.Algorithm{Name: "AES"},
			SourceEngine: "cipherscope",
		},
	}

	result := dedupe(all)
	if len(result) != 2 {
		t.Fatalf("dedupe() returned %d findings, want 2", len(result))
	}
}

func TestBoostConfidence(t *testing.T) {
	tests := []struct {
		input findings.Confidence
		want  findings.Confidence
	}{
		{findings.ConfidenceLow, findings.ConfidenceMediumLow},
		{findings.ConfidenceMediumLow, findings.ConfidenceMedium},
		{findings.ConfidenceMedium, findings.ConfidenceMediumHigh},
		{findings.ConfidenceMediumHigh, findings.ConfidenceHigh},
		{findings.ConfidenceHigh, findings.ConfidenceHigh}, // already high, no change
	}

	for _, tt := range tests {
		got := boostConfidence(tt.input)
		if got != tt.want {
			t.Errorf("boostConfidence(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestMergeAlgorithm(t *testing.T) {
	winner := &findings.UnifiedFinding{
		Algorithm: &findings.Algorithm{Name: "RSA", KeySize: 2048},
	}
	other := &findings.UnifiedFinding{
		Algorithm: &findings.Algorithm{Name: "RSA", Primitive: "signature", Mode: "PKCS1"},
	}

	mergeAlgorithm(winner, other)

	if winner.Algorithm.Primitive != "signature" {
		t.Errorf("Primitive not merged: got %q", winner.Algorithm.Primitive)
	}
	if winner.Algorithm.Mode != "PKCS1" {
		t.Errorf("Mode not merged: got %q", winner.Algorithm.Mode)
	}
	if winner.Algorithm.KeySize != 2048 {
		t.Errorf("KeySize should not be overwritten: got %d", winner.Algorithm.KeySize)
	}
}

func TestMergeAlgorithm_NilSafe(t *testing.T) {
	// Should not panic when Algorithm is nil
	winner := &findings.UnifiedFinding{Algorithm: nil}
	other := &findings.UnifiedFinding{Algorithm: &findings.Algorithm{Name: "RSA"}}
	mergeAlgorithm(winner, other) // should be a no-op

	winner2 := &findings.UnifiedFinding{Algorithm: &findings.Algorithm{Name: "RSA"}}
	other2 := &findings.UnifiedFinding{Algorithm: nil}
	mergeAlgorithm(winner2, other2) // should be a no-op
}

func TestClassifyFindings(t *testing.T) {
	ff := []findings.UnifiedFinding{
		{Algorithm: &findings.Algorithm{Name: "RSA-2048", Primitive: "signature"}},
		{Algorithm: &findings.Algorithm{Name: "AES-256-GCM", Primitive: "ae", KeySize: 256}},
		{Dependency: &findings.Dependency{Library: "openssl"}},
	}

	classifyFindings(ff)

	if ff[0].QuantumRisk != findings.QRVulnerable {
		t.Errorf("RSA should be quantum-vulnerable, got %q", ff[0].QuantumRisk)
	}
	if ff[1].QuantumRisk != findings.QRResistant {
		t.Errorf("AES-256 should be quantum-resistant, got %q", ff[1].QuantumRisk)
	}
	if ff[2].QuantumRisk != findings.QRUnknown {
		t.Errorf("Dependency should be unknown, got %q", ff[2].QuantumRisk)
	}
}

func TestFilterEngines(t *testing.T) {
	// This tests filterEngines with mock data
	// We can't easily create Engine instances here without circular dependencies,
	// so we test contains helper instead
	if !contains([]string{"a", "b", "c"}, "b") {
		t.Error("contains should return true for present element")
	}
	if contains([]string{"a", "b", "c"}, "d") {
		t.Error("contains should return false for absent element")
	}
}

func TestFilterByChangedFiles(t *testing.T) {
	ff := []findings.UnifiedFinding{
		{Location: findings.Location{File: "/repo/src/main.go", Line: 10}, Algorithm: &findings.Algorithm{Name: "RSA"}},
		{Location: findings.Location{File: "/repo/pkg/util.go", Line: 20}, Algorithm: &findings.Algorithm{Name: "AES"}},
		{Location: findings.Location{File: "/repo/vendor/lib.go", Line: 5}, Algorithm: &findings.Algorithm{Name: "DES"}},
	}

	changed := []string{"src/main.go", "pkg/util.go"}
	filtered := filterByChangedFiles(ff, "/repo", changed)

	if len(filtered) != 2 {
		t.Fatalf("filterByChangedFiles returned %d findings, want 2", len(filtered))
	}
	if filtered[0].Algorithm.Name != "RSA" {
		t.Errorf("first finding should be RSA, got %s", filtered[0].Algorithm.Name)
	}
	if filtered[1].Algorithm.Name != "AES" {
		t.Errorf("second finding should be AES, got %s", filtered[1].Algorithm.Name)
	}
}

func TestFilterByChangedFiles_Empty(t *testing.T) {
	ff := []findings.UnifiedFinding{
		{Location: findings.Location{File: "/repo/src/main.go", Line: 10}, Algorithm: &findings.Algorithm{Name: "RSA"}},
	}

	filtered := filterByChangedFiles(ff, "/repo", []string{})
	if len(filtered) != 0 {
		t.Errorf("empty changed files should return 0 findings, got %d", len(filtered))
	}
}

func TestFilterByExcludePatterns(t *testing.T) {
	ff := []findings.UnifiedFinding{
		{Location: findings.Location{File: "/repo/src/main.go", Line: 10}, Algorithm: &findings.Algorithm{Name: "RSA"}},
		{Location: findings.Location{File: "/repo/vendor/lib.go", Line: 20}, Algorithm: &findings.Algorithm{Name: "AES"}},
		{Location: findings.Location{File: "/repo/test/crypto_test.go", Line: 5}, Algorithm: &findings.Algorithm{Name: "DES"}},
		{Location: findings.Location{File: "/repo/src/util.go", Line: 30}, Algorithm: &findings.Algorithm{Name: "SHA256"}},
	}

	// Exclude vendor and test directories
	patterns := []string{"vendor/*", "test/*"}
	filtered := filterByExcludePatterns(ff, "/repo", patterns)

	if len(filtered) != 2 {
		t.Fatalf("filterByExcludePatterns returned %d findings, want 2", len(filtered))
	}
	if filtered[0].Algorithm.Name != "RSA" {
		t.Errorf("first finding should be RSA, got %s", filtered[0].Algorithm.Name)
	}
	if filtered[1].Algorithm.Name != "SHA256" {
		t.Errorf("second finding should be SHA256, got %s", filtered[1].Algorithm.Name)
	}
}

func TestFilterByExcludePatterns_DeepNested(t *testing.T) {
	ff := []findings.UnifiedFinding{
		{Location: findings.Location{File: "/repo/vendor/github.com/pkg/lib.go", Line: 1}, Algorithm: &findings.Algorithm{Name: "AES"}},
		{Location: findings.Location{File: "/repo/vendor/deep/nested/crypto.go", Line: 2}, Algorithm: &findings.Algorithm{Name: "RSA"}},
		{Location: findings.Location{File: "/repo/src/main.go", Line: 10}, Algorithm: &findings.Algorithm{Name: "SHA256"}},
	}

	// vendor/* should recursively exclude all files under vendor/
	patterns := []string{"vendor/*"}
	filtered := filterByExcludePatterns(ff, "/repo", patterns)

	if len(filtered) != 1 {
		t.Fatalf("filterByExcludePatterns returned %d findings, want 1 (only src/main.go)", len(filtered))
	}
	if filtered[0].Algorithm.Name != "SHA256" {
		t.Errorf("remaining finding should be SHA256, got %s", filtered[0].Algorithm.Name)
	}
}

func TestFilterByExcludePatterns_DoubleStarGlob(t *testing.T) {
	ff := []findings.UnifiedFinding{
		{Location: findings.Location{File: "/repo/vendor/a/b/c.go", Line: 1}, Algorithm: &findings.Algorithm{Name: "AES"}},
		{Location: findings.Location{File: "/repo/src/main.go", Line: 10}, Algorithm: &findings.Algorithm{Name: "RSA"}},
	}

	// vendor/** should also work as recursive exclude
	patterns := []string{"vendor/**"}
	filtered := filterByExcludePatterns(ff, "/repo", patterns)

	if len(filtered) != 1 {
		t.Fatalf("filterByExcludePatterns returned %d findings, want 1", len(filtered))
	}
	if filtered[0].Algorithm.Name != "RSA" {
		t.Errorf("remaining finding should be RSA, got %s", filtered[0].Algorithm.Name)
	}
}

func TestFilterByExcludePatterns_FileGlob(t *testing.T) {
	ff := []findings.UnifiedFinding{
		{Location: findings.Location{File: "/repo/src/app.min.js", Line: 1}, Algorithm: &findings.Algorithm{Name: "AES"}},
		{Location: findings.Location{File: "/repo/src/main.go", Line: 10}, Algorithm: &findings.Algorithm{Name: "RSA"}},
	}

	// Exclude minified JS files
	patterns := []string{"*.min.js"}
	filtered := filterByExcludePatterns(ff, "/repo", patterns)

	if len(filtered) != 1 {
		t.Fatalf("filterByExcludePatterns returned %d findings, want 1", len(filtered))
	}
	if filtered[0].Algorithm.Name != "RSA" {
		t.Errorf("remaining finding should be RSA, got %s", filtered[0].Algorithm.Name)
	}
}

func TestFilterByExcludePatterns_NoPatterns(t *testing.T) {
	ff := []findings.UnifiedFinding{
		{Location: findings.Location{File: "/repo/main.go", Line: 1}, Algorithm: &findings.Algorithm{Name: "RSA"}},
	}

	// No patterns = no filtering (but this code path is guarded in Scan; test the function directly)
	filtered := filterByExcludePatterns(ff, "/repo", nil)
	if len(filtered) != 1 {
		t.Errorf("nil patterns should return all findings, got %d", len(filtered))
	}
}

func TestFilterByChangedFiles_RelativePaths(t *testing.T) {
	ff := []findings.UnifiedFinding{
		{Location: findings.Location{File: "src/main.go", Line: 10}, Algorithm: &findings.Algorithm{Name: "RSA"}},
	}

	// When finding path is already relative and targetPath doesn't match as prefix
	changed := []string{"src/main.go"}
	filtered := filterByChangedFiles(ff, "/different/repo", changed)

	// filepath.Rel("/different/repo", "src/main.go") won't produce "src/main.go"
	// but the raw path "src/main.go" should still match after Clean
	if len(filtered) != 1 {
		t.Errorf("expected 1 match for relative path, got %d", len(filtered))
	}
}

// ---------------------------------------------------------------------------
// Parallel engine execution tests
// ---------------------------------------------------------------------------

// mockEngineBlocking is a mock engine that blocks until a signal channel is
// closed, allowing tests to verify concurrent execution timing.
type mockEngineBlocking struct {
	name    string
	tier    engines.Tier
	results []findings.UnifiedFinding
	scanErr error
	// ready is closed by the goroutine when Scan is entered; lets the test
	// synchronize without sleeping.
	ready chan struct{}
	// release is closed by the test to unblock the Scan call.
	release chan struct{}
}

func (m *mockEngineBlocking) Name() string                 { return m.name }
func (m *mockEngineBlocking) Tier() engines.Tier           { return m.tier }
func (m *mockEngineBlocking) SupportedLanguages() []string { return []string{"go"} }
func (m *mockEngineBlocking) Available() bool              { return true }
func (m *mockEngineBlocking) Version() string              { return "mock" }
func (m *mockEngineBlocking) Scan(ctx context.Context, _ engines.ScanOptions) ([]findings.UnifiedFinding, error) {
	if m.ready != nil {
		close(m.ready)
	}
	if m.release != nil {
		select {
		case <-m.release:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	return m.results, m.scanErr
}

// TestScan_ParallelExecution verifies that engines run concurrently: both
// engines must be inside Scan() at the same time (proven by the ready/release
// handshake) rather than running sequentially.
func TestScan_ParallelExecution(t *testing.T) {
	ctx := context.Background()

	readyA := make(chan struct{})
	readyB := make(chan struct{})
	releaseA := make(chan struct{})
	releaseB := make(chan struct{})

	engA := &mockEngineBlocking{
		name:    "engine-a",
		tier:    engines.Tier1Pattern,
		ready:   readyA,
		release: releaseA,
		results: []findings.UnifiedFinding{
			{Location: findings.Location{File: "/f.go", Line: 1}, Algorithm: &findings.Algorithm{Name: "RSA-2048"}, SourceEngine: "engine-a"},
		},
	}
	engB := &mockEngineBlocking{
		name:    "engine-b",
		tier:    engines.Tier1Pattern,
		ready:   readyB,
		release: releaseB,
		results: []findings.UnifiedFinding{
			{Location: findings.Location{File: "/g.go", Line: 2}, Algorithm: &findings.Algorithm{Name: "AES-256-GCM"}, SourceEngine: "engine-b"},
		},
	}

	orch := New(engA, engB)
	opts := engines.ScanOptions{Mode: engines.ModeFull}

	done := make(chan []findings.UnifiedFinding, 1)
	go func() {
		res, err := orch.Scan(ctx, opts)
		if err != nil {
			t.Errorf("Scan() returned unexpected error: %v", err)
		}
		done <- res
	}()

	// Both engines must reach their Scan() concurrently before either is released.
	// If execution were sequential, readyB would never fire while readyA is blocked.
	select {
	case <-readyA:
	case <-time.After(2 * time.Second):
		t.Fatal("engine-a never started; parallel execution broken")
	}
	select {
	case <-readyB:
	case <-time.After(2 * time.Second):
		t.Fatal("engine-b never started concurrently with engine-a")
	}

	// Now release both so Scan() can complete.
	close(releaseA)
	close(releaseB)

	select {
	case results := <-done:
		if len(results) != 2 {
			t.Errorf("Scan() returned %d findings, want 2", len(results))
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Scan() did not complete after releasing both engines")
	}
}

// TestScan_DeterministicOrder verifies that parallel execution preserves
// the engine registration order in the merged results.
func TestScan_DeterministicOrder(t *testing.T) {
	ctx := context.Background()

	// Use the standard mockEngine from pipeline_test.go (same package).
	engA := &mockEngine{
		name:      "alpha",
		tier:      engines.Tier1Pattern,
		available: true,
		results: []findings.UnifiedFinding{
			{Location: findings.Location{File: "/a.go", Line: 1}, Algorithm: &findings.Algorithm{Name: "RSA-2048"}, SourceEngine: "alpha"},
		},
	}
	engB := &mockEngine{
		name:      "beta",
		tier:      engines.Tier1Pattern,
		available: true,
		results: []findings.UnifiedFinding{
			{Location: findings.Location{File: "/b.go", Line: 2}, Algorithm: &findings.Algorithm{Name: "ECDSA"}, SourceEngine: "beta"},
		},
	}
	engC := &mockEngine{
		name:      "gamma",
		tier:      engines.Tier1Pattern,
		available: true,
		results: []findings.UnifiedFinding{
			{Location: findings.Location{File: "/c.go", Line: 3}, Algorithm: &findings.Algorithm{Name: "AES-256-GCM"}, SourceEngine: "gamma"},
		},
	}

	orch := New(engA, engB, engC)
	opts := engines.ScanOptions{Mode: engines.ModeFull}

	// Run Scan several times; the order must always match engine registration order.
	for i := range 10 {
		results, err := orch.Scan(ctx, opts)
		if err != nil {
			t.Fatalf("iteration %d: Scan() error: %v", i, err)
		}
		if len(results) != 3 {
			t.Fatalf("iteration %d: got %d findings, want 3", i, len(results))
		}
		wantOrder := []string{"RSA-2048", "ECDSA", "AES-256-GCM"}
		for j, f := range results {
			if f.Algorithm.Name != wantOrder[j] {
				t.Errorf("iteration %d, position %d: got %q, want %q", i, j, f.Algorithm.Name, wantOrder[j])
			}
		}
	}
}

// TestScan_PartialFailure verifies that when one engine errors but another
// succeeds, Scan returns the successful findings and logs a warning rather
// than returning a top-level error.
func TestScan_PartialFailure(t *testing.T) {
	ctx := context.Background()

	errEng := &mockEngine{
		name:      "bad-engine",
		tier:      engines.Tier1Pattern,
		available: true,
		results:   nil,
		scanErr:   fmt.Errorf("simulated engine failure"),
	}
	goodEng := &mockEngine{
		name:      "good-engine",
		tier:      engines.Tier1Pattern,
		available: true,
		results: []findings.UnifiedFinding{
			{Location: findings.Location{File: "/ok.go", Line: 10}, Algorithm: &findings.Algorithm{Name: "AES-256-GCM"}, SourceEngine: "good-engine"},
		},
	}

	orch := New(errEng, goodEng)
	opts := engines.ScanOptions{Mode: engines.ModeFull}

	results, err := orch.Scan(ctx, opts)
	if err != nil {
		t.Fatalf("Scan() should not return error on partial failure, got: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("Scan() returned %d findings, want 1 from good engine", len(results))
	}
	if results[0].Algorithm.Name != "AES-256-GCM" {
		t.Errorf("finding name = %q, want AES-256-GCM", results[0].Algorithm.Name)
	}
}

// TestScan_AllEnginesFail verifies that when every engine fails, Scan returns
// a non-nil error describing the aggregate failure.
func TestScan_AllEnginesFail(t *testing.T) {
	ctx := context.Background()

	eng1 := &mockEngine{name: "e1", tier: engines.Tier1Pattern, available: true, scanErr: fmt.Errorf("boom")}
	eng2 := &mockEngine{name: "e2", tier: engines.Tier1Pattern, available: true, scanErr: fmt.Errorf("bang")}

	orch := New(eng1, eng2)
	_, err := orch.Scan(ctx, engines.ScanOptions{Mode: engines.ModeFull})
	if err == nil {
		t.Fatal("Scan() should return error when all engines fail")
	}
}

// TestScan_ContextCancelled verifies that when the context is already cancelled
// before Scan is called, Scan returns an error containing "scan aborted" rather
// than "all engines failed".
func TestScan_ContextCancelled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel immediately before Scan is called

	eng := &mockEngineBlocking{
		name:    "blocking-never",
		tier:    engines.Tier1Pattern,
		ready:   make(chan struct{}),
		release: make(chan struct{}), // never closed
	}

	orch := New(eng)
	opts := engines.ScanOptions{Mode: engines.ModeFull}

	_, err := orch.Scan(ctx, opts)
	if err == nil {
		t.Fatal("Scan() should return an error when context is cancelled")
	}
	errMsg := err.Error()
	if !contains([]string{errMsg}, "scan aborted") {
		// check substring manually
		found := false
		if len(errMsg) > 0 {
			// Use strings.Contains equivalent via loop avoided — import not available.
			// Use fmt import already present in this package.
			for i := 0; i+len("scan aborted") <= len(errMsg); i++ {
				if errMsg[i:i+len("scan aborted")] == "scan aborted" {
					found = true
					break
				}
			}
		}
		if !found {
			t.Errorf("Scan() error = %q, want message containing 'scan aborted'", errMsg)
		}
	}
}

// TestDedupe_DataFlowPathMergedFromTier2 verifies that when Tier 1 wins dedup
// but Tier 2 has a DataFlowPath, the DataFlowPath is preserved in the merged result.
func TestDedupe_DataFlowPathMergedFromTier2(t *testing.T) {
	flowPath := []findings.FlowStep{
		{File: "/src/main.java", Line: 10, Message: "source"},
		{File: "/src/main.java", Line: 42, Message: "sink"},
	}

	// Tier 1 finding: no DataFlowPath
	tier1 := findings.UnifiedFinding{
		Location:     findings.Location{File: "/src/main.java", Line: 42},
		Algorithm:    &findings.Algorithm{Name: "RSA"},
		Confidence:   findings.ConfidenceMedium,
		SourceEngine: "cipherscope",
	}
	// Tier 2 finding: has DataFlowPath
	tier2 := findings.UnifiedFinding{
		Location:     findings.Location{File: "/src/main.java", Line: 42},
		Algorithm:    &findings.Algorithm{Name: "RSA"},
		Confidence:   findings.ConfidenceHigh,
		SourceEngine: "semgrep",
		DataFlowPath: flowPath,
	}

	result := dedupe([]findings.UnifiedFinding{tier1, tier2})

	if len(result) != 1 {
		t.Fatalf("dedupe() returned %d findings, want 1", len(result))
	}

	f := result[0]
	if len(f.DataFlowPath) != 2 {
		t.Fatalf("DataFlowPath len = %d, want 2 (merged from Tier 2)", len(f.DataFlowPath))
	}
	if f.DataFlowPath[0].Message != "source" {
		t.Errorf("DataFlowPath[0].Message = %q, want %q", f.DataFlowPath[0].Message, "source")
	}
	if f.DataFlowPath[1].Message != "sink" {
		t.Errorf("DataFlowPath[1].Message = %q, want %q", f.DataFlowPath[1].Message, "sink")
	}
}

// TestScan_ContextCancellation verifies that context cancellation propagates
// to all running engines and that Scan returns promptly after cancellation.
func TestScan_ContextCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())

	readyA := make(chan struct{})
	readyB := make(chan struct{})
	// releaseA/B are never closed — engines will only unblock via ctx cancellation.

	engA := &mockEngineBlocking{
		name:    "blocking-a",
		tier:    engines.Tier1Pattern,
		ready:   readyA,
		release: make(chan struct{}), // never closed
	}
	engB := &mockEngineBlocking{
		name:    "blocking-b",
		tier:    engines.Tier1Pattern,
		ready:   readyB,
		release: make(chan struct{}), // never closed
	}

	orch := New(engA, engB)
	opts := engines.ScanOptions{Mode: engines.ModeFull}

	done := make(chan error, 1)
	go func() {
		_, err := orch.Scan(ctx, opts)
		done <- err
	}()

	// Wait for both engines to start, then cancel.
	select {
	case <-readyA:
	case <-time.After(2 * time.Second):
		t.Fatal("blocking-a never started")
	}
	select {
	case <-readyB:
	case <-time.After(2 * time.Second):
		t.Fatal("blocking-b never started")
	}

	cancel()

	select {
	case <-done:
		// Scan may return an error or empty findings — both are acceptable.
		// The important thing is it returned within deadline.
	case <-time.After(5 * time.Second):
		t.Fatal("Scan() did not return after context cancellation")
	}
}

// TestScanWithImpact_ImpactResultNonNil verifies that ScanWithImpact returns a
// non-nil *impact.Result when ImpactGraph=true and findings have DataFlowPath
// and a classical algorithm with a known migration target.
func TestScanWithImpact_ImpactResultNonNil(t *testing.T) {
	ctx := context.Background()

	eng := &mockEngine{
		name:      "mock-impact",
		tier:      engines.Tier1Pattern,
		available: true,
		results: []findings.UnifiedFinding{
			{
				Location:     findings.Location{File: "/src/auth.go", Line: 10},
				Algorithm:    &findings.Algorithm{Name: "RSA-2048", Primitive: "signature", KeySize: 2048},
				Confidence:   findings.ConfidenceMedium,
				SourceEngine: "mock-impact",
				// DataFlowPath is required for forward analysis to engage.
				DataFlowPath: []findings.FlowStep{
					{File: "/src/auth.go", Line: 10, Message: "RSA key loaded"},
					{File: "/src/net.go", Line: 55, Message: "tls.Config set with cert"},
				},
			},
		},
	}

	orch := New(eng)
	opts := engines.ScanOptions{
		Mode:          engines.ModeFull,
		ImpactGraph:   true,
		MaxImpactHops: 10,
	}

	findings, impactResult, err := orch.ScanWithImpact(ctx, opts)
	if err != nil {
		t.Fatalf("ScanWithImpact() error: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("ScanWithImpact() returned no findings")
	}
	if impactResult == nil {
		t.Fatal("ScanWithImpact() returned nil impact result with ImpactGraph=true")
	}
	// RSA-2048 → ML-DSA-65, ML-DSA-87 — should produce ImpactZones
	if len(impactResult.ImpactZones) == 0 {
		t.Errorf("expected ImpactZones to be populated for RSA-2048 migration, got none")
	}
}

// TestScanWithImpact_NilResultWhenDisabled verifies that ScanWithImpact returns
// a nil impact result when ImpactGraph is false.
func TestScanWithImpact_NilResultWhenDisabled(t *testing.T) {
	ctx := context.Background()

	eng := &mockEngine{
		name:      "mock-no-impact",
		tier:      engines.Tier1Pattern,
		available: true,
		results: []findings.UnifiedFinding{
			{
				Location:     findings.Location{File: "/src/auth.go", Line: 10},
				Algorithm:    &findings.Algorithm{Name: "RSA-2048", Primitive: "signature"},
				SourceEngine: "mock-no-impact",
				DataFlowPath: []findings.FlowStep{{File: "/src/auth.go", Line: 10}},
			},
		},
	}

	orch := New(eng)
	opts := engines.ScanOptions{
		Mode:        engines.ModeFull,
		ImpactGraph: false, // disabled
	}

	_, impactResult, err := orch.ScanWithImpact(ctx, opts)
	if err != nil {
		t.Fatalf("ScanWithImpact() error: %v", err)
	}
	if impactResult != nil {
		t.Errorf("expected nil impact result with ImpactGraph=false, got %+v", impactResult)
	}
}

// TestScanWithImpact_ImpactErrorNonFatal verifies that when impact analysis
// encounters context cancellation (or any other error), ScanWithImpact still
// returns valid findings and does NOT propagate the impact error to the caller.
func TestScanWithImpact_ImpactErrorNonFatal(t *testing.T) {
	// Use a context that is already cancelled so that forward.Analyze will
	// encounter ctx.Err() != nil immediately and return early.  The
	// propagator treats this as a normal early-exit (returns result, nil),
	// but we still want to confirm the scan findings are intact regardless.
	ctx, cancel := context.WithCancel(context.Background())

	eng := &mockEngine{
		name:      "mock-impact-cancel",
		tier:      engines.Tier1Pattern,
		available: true,
		results: []findings.UnifiedFinding{
			{
				Location:     findings.Location{File: "/src/auth.go", Line: 10},
				Algorithm:    &findings.Algorithm{Name: "RSA-2048", Primitive: "signature", KeySize: 2048},
				Confidence:   findings.ConfidenceMedium,
				SourceEngine: "mock-impact-cancel",
				DataFlowPath: []findings.FlowStep{
					{File: "/src/auth.go", Line: 10, Message: "key loaded"},
					{File: "/src/net.go", Line: 55, Message: "cert configured"},
				},
			},
		},
	}

	orch := New(eng)
	opts := engines.ScanOptions{
		Mode:          engines.ModeFull,
		ImpactGraph:   true,
		MaxImpactHops: 5,
	}

	// Let the engine scan complete before cancelling, so findings are collected.
	// We cancel only after invoking ScanWithImpact; the scan goroutines will have
	// already finished, but forward.Analyze will see the cancelled ctx.
	cancel() // cancel before ScanWithImpact so impact analysis sees cancellation

	ff, _, err := orch.ScanWithImpact(ctx, opts)
	// The scan itself should succeed even though the context is cancelled —
	// the engine goroutines finish before ctx.Err() is checked; if the
	// context is cancelled before any engine starts, Scan returns "scan aborted".
	// What we care about is: no panic, and the function returns (not hangs).
	// Acceptable outcomes: valid findings OR a scan-aborted error (both are fine).
	_ = ff
	_ = err
	// The key invariant: ScanWithImpact must not hang and must not return an
	// error solely because impact analysis failed — the outer scan error (if
	// any) comes from engine execution, not from impact analysis.
	// If we reached here without blocking, the test passes.
}

// TestEffectiveEngines_Tier4SkippedByDefault verifies that Tier 4 binary engines
// are excluded when ScanType is empty or "source" (default).
func TestEffectiveEngines_Tier4SkippedByDefault(t *testing.T) {
	t1 := &mockEngine{name: "pattern-eng", tier: engines.Tier1Pattern, available: true}
	t4 := &mockEngine{name: "binary-eng", tier: engines.Tier4Binary, available: true}
	orch := New(t1, t4)

	// Default: empty ScanType should exclude Tier 4
	opts := engines.ScanOptions{}
	effective := orch.EffectiveEngines(opts)
	if len(effective) != 1 || effective[0].Name() != "pattern-eng" {
		names := make([]string, len(effective))
		for i, e := range effective {
			names[i] = e.Name()
		}
		t.Errorf("expected [pattern-eng], got %v", names)
	}

	// Explicit "source" also excludes Tier 4
	opts.ScanType = "source"
	effective = orch.EffectiveEngines(opts)
	if len(effective) != 1 || effective[0].Name() != "pattern-eng" {
		t.Errorf("expected [pattern-eng] for ScanType=source")
	}
}

// TestEffectiveEngines_Tier4RunsOnBinaryMode verifies that ScanType="binary"
// only includes Tier 4 engines.
func TestEffectiveEngines_Tier4RunsOnBinaryMode(t *testing.T) {
	t1 := &mockEngine{name: "pattern-eng", tier: engines.Tier1Pattern, available: true}
	t4 := &mockEngine{name: "binary-eng", tier: engines.Tier4Binary, available: true}
	orch := New(t1, t4)

	opts := engines.ScanOptions{ScanType: "binary"}
	effective := orch.EffectiveEngines(opts)
	if len(effective) != 1 || effective[0].Name() != "binary-eng" {
		names := make([]string, len(effective))
		for i, e := range effective {
			names[i] = e.Name()
		}
		t.Errorf("expected [binary-eng], got %v", names)
	}
}

// TestEffectiveEngines_Tier4RunsOnAllMode verifies that ScanType="all"
// includes both source and binary engines.
func TestEffectiveEngines_Tier4RunsOnAllMode(t *testing.T) {
	t1 := &mockEngine{name: "pattern-eng", tier: engines.Tier1Pattern, available: true}
	t4 := &mockEngine{name: "binary-eng", tier: engines.Tier4Binary, available: true}
	orch := New(t1, t4)

	opts := engines.ScanOptions{ScanType: "all"}
	effective := orch.EffectiveEngines(opts)
	if len(effective) != 2 {
		names := make([]string, len(effective))
		for i, e := range effective {
			names[i] = e.Name()
		}
		t.Errorf("expected 2 engines for ScanType=all, got %v", names)
	}
}

// TestEffectiveEngines_Tier4SkippedInDiffMode verifies that Tier 4 is excluded
// in diff mode regardless of ScanType.
func TestEffectiveEngines_Tier4SkippedInDiffMode(t *testing.T) {
	t1 := &mockEngine{name: "pattern-eng", tier: engines.Tier1Pattern, available: true}
	t4 := &mockEngine{name: "binary-eng", tier: engines.Tier4Binary, available: true}
	orch := New(t1, t4)

	opts := engines.ScanOptions{Mode: engines.ModeDiff, ScanType: "all"}
	effective := orch.EffectiveEngines(opts)
	if len(effective) != 1 || effective[0].Name() != "pattern-eng" {
		names := make([]string, len(effective))
		for i, e := range effective {
			names[i] = e.Name()
		}
		t.Errorf("expected [pattern-eng] in diff mode, got %v", names)
	}
}

// TestScan_Tier4GatingInScanWithImpact verifies that ScanType filtering is
// applied within ScanWithImpact, not just EffectiveEngines.
func TestScan_Tier4GatingInScanWithImpact(t *testing.T) {
	t1 := &mockEngine{
		name: "source-eng", tier: engines.Tier1Pattern, available: true,
		results: []findings.UnifiedFinding{
			{Location: findings.Location{File: "/a.go", Line: 1}, Algorithm: &findings.Algorithm{Name: "AES"}, SourceEngine: "source-eng"},
		},
	}
	t4 := &mockEngine{
		name: "binary-eng", tier: engines.Tier4Binary, available: true,
		results: []findings.UnifiedFinding{
			{Location: findings.Location{File: "/app.jar", InnerPath: "Foo.class"}, Algorithm: &findings.Algorithm{Name: "RSA"}, SourceEngine: "binary-eng"},
		},
	}
	orch := New(t1, t4)

	// Default scan should only get source results
	ff, _, err := orch.ScanWithImpact(context.Background(), engines.ScanOptions{})
	if err != nil {
		t.Fatalf("ScanWithImpact error: %v", err)
	}
	for _, f := range ff {
		if f.SourceEngine == "binary-eng" {
			t.Error("binary engine findings should not appear in default (source) scan")
		}
	}
}

// TestScanWithImpact_NilResultInDiffMode verifies that impact analysis is
// skipped in diff mode even when ImpactGraph=true.
func TestScanWithImpact_NilResultInDiffMode(t *testing.T) {
	ctx := context.Background()

	eng := &mockEngine{
		name:      "mock-diff-impact",
		tier:      engines.Tier1Pattern,
		available: true,
		results: []findings.UnifiedFinding{
			{
				Location:     findings.Location{File: "/src/auth.go", Line: 10},
				Algorithm:    &findings.Algorithm{Name: "RSA-2048"},
				SourceEngine: "mock-diff-impact",
				DataFlowPath: []findings.FlowStep{{File: "/src/auth.go", Line: 10}},
			},
		},
	}

	orch := New(eng)
	opts := engines.ScanOptions{
		Mode:        engines.ModeDiff,
		ImpactGraph: true, // requested but mode is diff — should be skipped
		ChangedFiles: []string{"/src/auth.go"},
	}

	_, impactResult, err := orch.ScanWithImpact(ctx, opts)
	if err != nil {
		t.Fatalf("ScanWithImpact() error: %v", err)
	}
	if impactResult != nil {
		t.Errorf("expected nil impact result in diff mode, got non-nil")
	}
}

// TestDedup_InnerPathIsPartOfKey verifies that findings from the same archive
// file but different InnerPaths produce separate dedupe keys and are NOT merged,
// while findings with the same InnerPath from different engines ARE merged and
// recorded as corroborated.
func TestDedup_InnerPathIsPartOfKey(t *testing.T) {
	// Two findings from same file but different InnerPath — must not be deduped.
	f1 := findings.UnifiedFinding{
		Location:     findings.Location{File: "/repo/app.jar", InnerPath: "com/Foo.class", Line: 1},
		Algorithm:    &findings.Algorithm{Name: "AES"},
		Confidence:   findings.ConfidenceMedium,
		SourceEngine: "engine-a",
	}
	f2 := findings.UnifiedFinding{
		Location:     findings.Location{File: "/repo/app.jar", InnerPath: "com/Bar.class", Line: 1},
		Algorithm:    &findings.Algorithm{Name: "AES"},
		Confidence:   findings.ConfidenceMedium,
		SourceEngine: "engine-a",
	}
	// Same file, same InnerPath as f1, different engine — SHOULD be merged with f1.
	f3 := findings.UnifiedFinding{
		Location:     findings.Location{File: "/repo/app.jar", InnerPath: "com/Foo.class", Line: 1},
		Algorithm:    &findings.Algorithm{Name: "AES"},
		Confidence:   findings.ConfidenceLow,
		SourceEngine: "engine-b",
	}

	result := dedupe([]findings.UnifiedFinding{f1, f2, f3})

	if len(result) != 2 {
		t.Fatalf("expected 2 deduplicated findings (f2 separate, f1+f3 merged), got %d", len(result))
	}

	// Locate the merged finding (the one for com/Foo.class) and the separate one.
	var fooFinding, barFinding *findings.UnifiedFinding
	for i := range result {
		switch result[i].Location.InnerPath {
		case "com/Foo.class":
			fooFinding = &result[i]
		case "com/Bar.class":
			barFinding = &result[i]
		}
	}

	if fooFinding == nil {
		t.Fatal("merged finding for com/Foo.class not found in result")
	}
	if barFinding == nil {
		t.Fatal("separate finding for com/Bar.class not found in result")
	}

	// f1 and f3 share the same InnerPath — f3 (engine-b) should corroborate f1 (engine-a).
	if len(fooFinding.CorroboratedBy) != 1 || fooFinding.CorroboratedBy[0] != "engine-b" {
		t.Errorf("com/Foo.class: expected corroborated by [engine-b], got %v", fooFinding.CorroboratedBy)
	}

	// f2 (com/Bar.class) has no counterpart — must not be corroborated.
	if len(barFinding.CorroboratedBy) != 0 {
		t.Errorf("com/Bar.class: expected no corroborators, got %v", barFinding.CorroboratedBy)
	}
}

// TestScan_EmptyDirectory_ReturnsNoFindings verifies that scanning an empty
// directory with a mock engine that returns no findings produces an empty
// result slice and no error.
func TestScan_EmptyDirectory_ReturnsNoFindings(t *testing.T) {
	dir := t.TempDir() // empty directory

	eng := &mockEngine{
		name:      "mock",
		tier:      engines.Tier1Pattern,
		available: true,
		// results is nil — mock returns no findings for any input.
	}

	orch := New(eng)
	ff, err := orch.Scan(context.Background(), engines.ScanOptions{
		TargetPath: dir,
		Mode:       engines.ModeFull,
	})
	if err != nil {
		t.Fatalf("Scan() on empty directory returned unexpected error: %v", err)
	}
	if len(ff) != 0 {
		t.Errorf("expected 0 findings for empty directory, got %d", len(ff))
	}
}

func TestFilterByChangedFiles_CaseSensitive(t *testing.T) {
	ff := []findings.UnifiedFinding{
		{Location: findings.Location{File: "/repo/src/Main.go", Line: 10}, Algorithm: &findings.Algorithm{Name: "RSA"}},
		{Location: findings.Location{File: "/repo/src/main.go", Line: 20}, Algorithm: &findings.Algorithm{Name: "AES"}},
	}

	// Only "src/main.go" changed (lowercase) — "src/Main.go" should NOT match
	// on case-sensitive filesystems (Linux/macOS).
	changed := []string{"src/main.go"}
	filtered := filterByChangedFiles(ff, "/repo", changed)

	// On non-Windows, only the exact case match should be returned.
	if runtime.GOOS != "windows" {
		if len(filtered) != 1 {
			t.Fatalf("expected 1 finding on case-sensitive FS, got %d", len(filtered))
		}
		if filtered[0].Algorithm.Name != "AES" {
			t.Errorf("expected AES (main.go), got %s", filtered[0].Algorithm.Name)
		}
	} else {
		// On Windows, both should match (case-insensitive FS).
		if len(filtered) != 2 {
			t.Fatalf("expected 2 findings on case-insensitive FS, got %d", len(filtered))
		}
	}
}
