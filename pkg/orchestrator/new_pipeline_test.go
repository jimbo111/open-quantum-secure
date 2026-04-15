package orchestrator

import (
	"context"
	"fmt"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jimbo111/open-quantum-secure/pkg/engines"
	"github.com/jimbo111/open-quantum-secure/pkg/findings"
)

// ---------------------------------------------------------------------------
// Additional mock engine types for error/panic/timeout scenarios
// ---------------------------------------------------------------------------

// errorEngine returns a hard error from Scan.
type errorEngine struct {
	name string
	tier engines.Tier
}

func (e *errorEngine) Name() string               { return e.name }
func (e *errorEngine) Tier() engines.Tier         { return e.tier }
func (e *errorEngine) SupportedLanguages() []string { return []string{"go"} }
func (e *errorEngine) Available() bool             { return true }
func (e *errorEngine) Version() string             { return "err-mock" }
func (e *errorEngine) Scan(_ context.Context, _ engines.ScanOptions) ([]findings.UnifiedFinding, error) {
	return nil, fmt.Errorf("engine %s: simulated hard failure", e.name)
}

// panicEngine panics inside Scan.
type panicEngine struct {
	name string
}

func (p *panicEngine) Name() string               { return p.name }
func (p *panicEngine) Tier() engines.Tier         { return engines.Tier1Pattern }
func (p *panicEngine) SupportedLanguages() []string { return []string{"go"} }
func (p *panicEngine) Available() bool             { return true }
func (p *panicEngine) Version() string             { return "panic-mock" }
func (p *panicEngine) Scan(_ context.Context, _ engines.ScanOptions) ([]findings.UnifiedFinding, error) {
	panic("intentional panic for testing")
}

// slowEngine sleeps until ctx is done or sleepFor elapses.
type slowEngine struct {
	name      string
	sleepFor  time.Duration
	results   []findings.UnifiedFinding
}

func (s *slowEngine) Name() string               { return s.name }
func (s *slowEngine) Tier() engines.Tier         { return engines.Tier1Pattern }
func (s *slowEngine) SupportedLanguages() []string { return []string{"go"} }
func (s *slowEngine) Available() bool             { return true }
func (s *slowEngine) Version() string             { return "slow-mock" }
func (s *slowEngine) Scan(ctx context.Context, _ engines.ScanOptions) ([]findings.UnifiedFinding, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-time.After(s.sleepFor):
		return s.results, nil
	}
}

// networkMockEngine pretends to be a Tier5Network engine.
type networkMockEngine struct {
	name    string
	results []findings.UnifiedFinding
	scanErr error
}

func (n *networkMockEngine) Name() string               { return n.name }
func (n *networkMockEngine) Tier() engines.Tier         { return engines.Tier5Network }
func (n *networkMockEngine) SupportedLanguages() []string { return nil }
func (n *networkMockEngine) Available() bool             { return true }
func (n *networkMockEngine) Version() string             { return "net-mock" }
func (n *networkMockEngine) Scan(_ context.Context, _ engines.ScanOptions) ([]findings.UnifiedFinding, error) {
	return n.results, n.scanErr
}

// unavailableEngine is always unavailable.
type unavailableEngine struct{ name string }

func (u *unavailableEngine) Name() string               { return u.name }
func (u *unavailableEngine) Tier() engines.Tier         { return engines.Tier1Pattern }
func (u *unavailableEngine) SupportedLanguages() []string { return []string{"go"} }
func (u *unavailableEngine) Available() bool             { return false }
func (u *unavailableEngine) Version() string             { return "unavail" }
func (u *unavailableEngine) Scan(_ context.Context, _ engines.ScanOptions) ([]findings.UnifiedFinding, error) {
	return nil, nil
}

// countingEngine records how many times Scan is called.
type countingEngine struct {
	name    string
	calls   atomic.Int32
	results []findings.UnifiedFinding
}

func (c *countingEngine) Name() string               { return c.name }
func (c *countingEngine) Tier() engines.Tier         { return engines.Tier1Pattern }
func (c *countingEngine) SupportedLanguages() []string { return []string{"go"} }
func (c *countingEngine) Available() bool             { return true }
func (c *countingEngine) Version() string             { return "count-mock" }
func (c *countingEngine) Scan(_ context.Context, _ engines.ScanOptions) ([]findings.UnifiedFinding, error) {
	c.calls.Add(1)
	return c.results, nil
}

// ---------------------------------------------------------------------------
// 1. Engine error → scan continues with remaining engines
// ---------------------------------------------------------------------------

// TestScan_OneEngineErrors_OtherEnginesContinue verifies that when one engine
// returns an error, the orchestrator still returns findings from the engines
// that succeeded (partial result, no hard failure).
func TestScan_OneEngineErrors_OtherEnginesContinue(t *testing.T) {
	ctx := context.Background()

	goodEng := &mockEngine{
		name:      "good-engine",
		tier:      engines.Tier1Pattern,
		available: true,
		results: []findings.UnifiedFinding{
			{Location: loc("/repo/main.go", 10), Algorithm: alg("AES-256-GCM", "ae", 256), SourceEngine: "good-engine"},
		},
	}
	badEng := &errorEngine{name: "bad-engine", tier: engines.Tier1Pattern}

	orch := New(goodEng, badEng)
	results, err := orch.Scan(ctx, engines.ScanOptions{Mode: engines.ModeFull})

	// With one good engine producing results, Scan must NOT return an error.
	if err != nil {
		t.Fatalf("Scan() must not error when at least one engine succeeds, got: %v", err)
	}
	if len(results) == 0 {
		t.Error("expected at least 1 finding from the good engine")
	}
}

// TestScan_AllEnginesFail_ReturnsError verifies that when every engine fails
// and no findings are collected, Scan returns a non-nil error.
func TestScan_AllEnginesFail_ReturnsError(t *testing.T) {
	ctx := context.Background()
	bad1 := &errorEngine{name: "fail-1", tier: engines.Tier1Pattern}
	bad2 := &errorEngine{name: "fail-2", tier: engines.Tier1Pattern}

	orch := New(bad1, bad2)
	_, err := orch.Scan(ctx, engines.ScanOptions{Mode: engines.ModeFull})
	if err == nil {
		t.Error("Scan() must return error when all engines fail with no findings")
	}
}

// ---------------------------------------------------------------------------
// 2. Engine panics → scan continues (recover in goroutine)
// ---------------------------------------------------------------------------

// TestScan_PanicEngine_DoesNotCrashOrchestrator verifies that a panicking
// engine is caught by the deferred recover inside the goroutine and does NOT
// bring down the entire scan process. Other engines' results are preserved.
func TestScan_PanicEngine_DoesNotCrashOrchestrator(t *testing.T) {
	ctx := context.Background()

	panicEng := &panicEngine{name: "panicker"}
	goodEng := &mockEngine{
		name:      "good-after-panic",
		tier:      engines.Tier1Pattern,
		available: true,
		results: []findings.UnifiedFinding{
			{Location: loc("/repo/safe.go", 5), Algorithm: alg("RSA-2048", "pke", 2048), SourceEngine: "good-after-panic"},
		},
	}

	orch := New(panicEng, goodEng)

	// Must not panic at the test level.
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("Scan() leaked panic to caller: %v", r)
		}
	}()

	results, _ := orch.Scan(ctx, engines.ScanOptions{Mode: engines.ModeFull})
	// The good engine's findings must be present even though the other panicked.
	if len(results) == 0 {
		t.Error("expected findings from good engine to survive the panic in the sibling engine")
	}
}

// ---------------------------------------------------------------------------
// 3. Context cancellation / timeout
// ---------------------------------------------------------------------------

// TestScan_ContextCancelled_ReturnsCancelError verifies that when the context
// is cancelled before Scan completes, the pipeline returns a context error and
// not a generic "all engines failed" message.
func TestScan_ContextCancelled_ReturnsCancelError(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	// Cancel immediately so the slow engine can't finish.
	cancel()

	slowEng := &slowEngine{
		name:     "slow-timeout",
		sleepFor: 5 * time.Second,
	}

	orch := New(slowEng)
	_, err := orch.Scan(ctx, engines.ScanOptions{Mode: engines.ModeFull})
	if err == nil {
		t.Fatal("expected error when context is cancelled")
	}
	if ctx.Err() == nil {
		t.Error("context should be in cancelled state")
	}
}

// ---------------------------------------------------------------------------
// 4. No engines available → error
// ---------------------------------------------------------------------------

// TestScan_NoAvailableEngines_ReturnsError verifies that an orchestrator with
// only unavailable engines returns an error rather than empty results.
func TestScan_NoAvailableEngines_ReturnsError(t *testing.T) {
	ctx := context.Background()
	unavail := &unavailableEngine{name: "ghost-engine"}

	orch := New(unavail)
	_, err := orch.Scan(ctx, engines.ScanOptions{Mode: engines.ModeFull})
	if err == nil {
		t.Error("Scan() with no available engines must return an error")
	}
}

// TestScan_EmptyEngineList_ReturnsError verifies that an orchestrator with
// zero registered engines returns an error.
func TestScan_EmptyEngineList_ReturnsError(t *testing.T) {
	ctx := context.Background()
	orch := New() // zero engines
	_, err := orch.Scan(ctx, engines.ScanOptions{Mode: engines.ModeFull})
	if err == nil {
		t.Error("Scan() with empty engine list must return an error")
	}
}

// ---------------------------------------------------------------------------
// 5. Tier5Network gating on TLSTargets empty
// ---------------------------------------------------------------------------

// TestEffectiveEngines_Tier5Network_SkippedWithNoTLSTargets verifies that a
// Tier5Network engine is NOT included in EffectiveEngines when TLSTargets is
// empty — it must be self-gated.
func TestEffectiveEngines_Tier5Network_SkippedWithNoTLSTargets(t *testing.T) {
	netEng := &networkMockEngine{name: "tls-probe"}
	srcEng := &mockEngine{name: "src-engine", tier: engines.Tier1Pattern, available: true}

	orch := New(netEng, srcEng)
	opts := engines.ScanOptions{Mode: engines.ModeFull} // TLSTargets empty
	effective := orch.EffectiveEngines(opts)

	for _, e := range effective {
		if e.Tier() == engines.Tier5Network {
			t.Errorf("Tier5Network engine %q must not be in EffectiveEngines when TLSTargets is empty", e.Name())
		}
	}
}

// TestEffectiveEngines_Tier5Network_IncludedWithTLSTargets verifies that a
// Tier5Network engine IS included in EffectiveEngines when TLSTargets is set,
// even in diff mode (which normally restricts to Tier 1).
func TestEffectiveEngines_Tier5Network_IncludedWithTLSTargets(t *testing.T) {
	netEng := &networkMockEngine{name: "tls-probe"}
	srcEng := &mockEngine{name: "src-engine", tier: engines.Tier1Pattern, available: true}

	orch := New(netEng, srcEng)
	opts := engines.ScanOptions{
		Mode:       engines.ModeDiff,
		TLSTargets: []string{"example.com:443"},
	}
	effective := orch.EffectiveEngines(opts)

	found := false
	for _, e := range effective {
		if e.Tier() == engines.Tier5Network {
			found = true
		}
	}
	if !found {
		t.Error("Tier5Network engine must be in EffectiveEngines when TLSTargets is non-empty")
	}
}

// ---------------------------------------------------------------------------
// 6. Network engine findings in diff-mode filtering
// ---------------------------------------------------------------------------

// TestScan_DiffMode_TLSProbeFindings_NotFiltered verifies the fix from
// commit 4253de8: TLS probe findings with synthetic paths (starting with "(")
// must pass through the diff-mode changed-file filter unchanged.
func TestScan_DiffMode_TLSProbeFindings_NotFiltered(t *testing.T) {
	ctx := context.Background()

	netEng := &networkMockEngine{
		name: "tls-probe",
		results: []findings.UnifiedFinding{
			{
				Location:     findings.Location{File: "(tls-probe)/example.com:443#kex", Line: 0},
				Algorithm:    &findings.Algorithm{Name: "RSA", Primitive: "key-exchange"},
				SourceEngine: "tls-probe",
			},
		},
	}
	// Source engine also reports something on a non-changed file.
	srcEng := &mockEngine{
		name:      "src-engine",
		tier:      engines.Tier1Pattern,
		available: true,
		results: []findings.UnifiedFinding{
			{
				Location:     findings.Location{File: "/repo/unchanged.go", Line: 1},
				Algorithm:    &findings.Algorithm{Name: "AES-128"},
				SourceEngine: "src-engine",
			},
		},
	}

	orch := New(srcEng, netEng)
	opts := engines.ScanOptions{
		Mode:         engines.ModeDiff,
		TargetPath:   "/repo",
		ChangedFiles: []string{"changed.go"}, // unchanged.go not in changed list
		TLSTargets:   []string{"example.com:443"},
	}
	results, err := orch.Scan(ctx, opts)
	if err != nil {
		t.Fatalf("Scan() diff mode with TLS targets returned error: %v", err)
	}

	// TLS probe finding must survive diff filtering (synthetic path).
	tlsFound := false
	for _, f := range results {
		if f.SourceEngine == "tls-probe" {
			tlsFound = true
		}
	}
	if !tlsFound {
		t.Error("TLS probe finding must NOT be filtered out in diff mode (synthetic path fix from 4253de8)")
	}
	// Source finding for unchanged.go must be filtered out.
	for _, f := range results {
		if f.Location.File == "/repo/unchanged.go" {
			t.Error("source finding for unchanged.go must be filtered out in diff mode")
		}
	}
}

// ---------------------------------------------------------------------------
// 7. Parallel safety (race detector)
// ---------------------------------------------------------------------------

// TestScan_ParallelSafety_RaceDetector runs multiple concurrent Scan calls on
// the same Orchestrator. Regression: engines that cache and re-return the same
// result slice used to expose a data race because scanPipeline mutated the
// engine-owned Algorithm pointer in normalizeFindings. scanPipeline now clones
// each finding before post-processing, so concurrent Scans are race-free.
// Run with -race to verify.
func TestScan_ParallelSafety_RaceDetector(t *testing.T) {
	ctx := context.Background()

	engs := make([]engines.Engine, 5)
	for i := range engs {
		engs[i] = &countingEngine{
			name: fmt.Sprintf("parallel-eng-%d", i),
			results: []findings.UnifiedFinding{
				{
					Location:     loc(fmt.Sprintf("/file%d.go", i), i+1),
					Algorithm:    alg("AES-256-GCM", "ae", 256),
					SourceEngine: fmt.Sprintf("parallel-eng-%d", i),
				},
			},
		}
	}

	orch := New(engs...)
	opts := engines.ScanOptions{Mode: engines.ModeFull}

	const goroutines = 10
	errCh := make(chan error, goroutines)

	for g := 0; g < goroutines; g++ {
		go func() {
			_, err := orch.Scan(ctx, opts)
			errCh <- err
		}()
	}

	for g := 0; g < goroutines; g++ {
		if err := <-errCh; err != nil {
			t.Errorf("concurrent Scan() error: %v", err)
		}
	}
}

// ---------------------------------------------------------------------------
// 8. AvailableEngines filtering
// ---------------------------------------------------------------------------

// TestAvailableEngines_FiltersByAvailability verifies that AvailableEngines
// returns only engines whose Available() method returns true.
func TestAvailableEngines_FiltersByAvailability(t *testing.T) {
	avail := &mockEngine{name: "avail", tier: engines.Tier1Pattern, available: true}
	unavail := &unavailableEngine{name: "unavail"}

	orch := New(avail, unavail)
	got := orch.AvailableEngines()

	if len(got) != 1 {
		t.Fatalf("expected 1 available engine, got %d", len(got))
	}
	if got[0].Name() != "avail" {
		t.Errorf("wrong engine returned: %q, want avail", got[0].Name())
	}
}

// ---------------------------------------------------------------------------
// 9. SelectedEngines name filter
// ---------------------------------------------------------------------------

// TestSelectedEngines_NameFilter verifies that SelectedEngines filters by
// explicit engine names and ignores engines not in the name list.
func TestSelectedEngines_NameFilter(t *testing.T) {
	eng1 := &mockEngine{name: "scanner-a", tier: engines.Tier1Pattern, available: true}
	eng2 := &mockEngine{name: "scanner-b", tier: engines.Tier1Pattern, available: true}
	eng3 := &mockEngine{name: "scanner-c", tier: engines.Tier1Pattern, available: true}

	orch := New(eng1, eng2, eng3)
	got := orch.SelectedEngines([]string{"scanner-a", "scanner-c"})

	if len(got) != 2 {
		t.Fatalf("expected 2 engines after name filter, got %d", len(got))
	}
	names := make(map[string]bool)
	for _, e := range got {
		names[e.Name()] = true
	}
	if !names["scanner-a"] || !names["scanner-c"] {
		t.Errorf("wrong engines returned: %v", names)
	}
	if names["scanner-b"] {
		t.Error("scanner-b should have been filtered out")
	}
}
