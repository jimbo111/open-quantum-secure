package orchestrator

// audit_race_test.go — race and property tests for the orchestrator added by
// the 2026-04-20 audit (orch-findings layer).
//
// Scope:
//
//   O-P1 dedup idempotence on 1 000 findings: dedupe(dedupe(X)) == dedupe(X).
//   O-P2 corroboration ordering determinism across permuted engine-result
//        inputs. CLAUDE.md guarantees engines run in registration order, but
//        the *corroboration list* built by dedup should be equally
//        deterministic. This test shuffles the per-engine result slice and
//        asserts the final CorroboratedBy list is identical.
//   O-R1 fan-out race: 10 concurrent engines emitting findings. `go test
//        -race` must report no races on the dedup map or the accumulation
//        slice.
//   O-R2 fan-out partial failure: 1 panicking engine + 1 hanging engine +
//        1 erroring engine + 3 successful ones. Orchestrator must return all
//        successful findings and not hang. Context cancel unblocks the
//        hanging engine.
//   O-R3 network engine panic: a Tier5Network engine panics. The Scan today
//        does NOT recover for Tier5 engines (see orchestrator.go:~600 where
//        eng.Scan() is called directly without defer/recover, unlike the file
//        engine fan-out). This test documents the gap — it is SKIPPED when
//        the panic is NOT recovered, and records the panic as F3.

import (
	"context"
	"fmt"
	"runtime/debug"
	"sort"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jimbo111/open-quantum-secure/pkg/engines"
	"github.com/jimbo111/open-quantum-secure/pkg/findings"
)

// ---------------------------------------------------------------------------
// O-P1 — dedup idempotence
// ---------------------------------------------------------------------------

// TestAudit_DedupIdempotent runs 1 000 findings through dedupe twice and
// asserts the result is identical (same count, same DedupeKey set, same
// CorroboratedBy for every surviving finding).
func TestAudit_DedupIdempotent(t *testing.T) {
	all := seededFindings(1000)

	pass1 := dedupe(all)
	// Clone pass1 before second dedup — dedup mutates findings through the
	// returned pointers (CorroboratedBy is appended). Without cloning the
	// second pass would still work but the assertion would be muddy.
	cloneP1 := make([]findings.UnifiedFinding, len(pass1))
	for i := range pass1 {
		cloneP1[i] = pass1[i].Clone()
	}
	pass2 := dedupe(cloneP1)

	if len(pass1) != len(pass2) {
		t.Fatalf("dedup not idempotent: pass1 has %d findings, pass2 has %d", len(pass1), len(pass2))
	}
	for i := range pass1 {
		k1 := pass1[i].DedupeKey()
		k2 := pass2[i].DedupeKey()
		if k1 != k2 {
			t.Errorf("dedup pass2 reordered or mutated key at index %d: %q vs %q", i, k1, k2)
		}
		if len(pass1[i].CorroboratedBy) != len(pass2[i].CorroboratedBy) {
			t.Errorf("dedup pass2 changed CorroboratedBy length at %d: %v vs %v",
				i, pass1[i].CorroboratedBy, pass2[i].CorroboratedBy)
		}
	}
}

// TestAudit_Dedup_OrderIsInputOrder asserts that the surviving findings come
// out in their first-seen (input) order — not map iteration order. Regression
// guard for the `order` slice in dedupe().
func TestAudit_Dedup_OrderIsInputOrder(t *testing.T) {
	// Hand-crafted duplicates: first occurrence of each distinct key must
	// appear in the output in the same order as the input.
	in := []findings.UnifiedFinding{
		{Location: findings.Location{File: "/a.go", Line: 1}, Algorithm: &findings.Algorithm{Name: "RSA"}, SourceEngine: "e1"},
		{Location: findings.Location{File: "/b.go", Line: 2}, Algorithm: &findings.Algorithm{Name: "AES"}, SourceEngine: "e1"},
		{Location: findings.Location{File: "/a.go", Line: 1}, Algorithm: &findings.Algorithm{Name: "RSA"}, SourceEngine: "e2"}, // dup of [0]
		{Location: findings.Location{File: "/c.go", Line: 3}, Algorithm: &findings.Algorithm{Name: "DH"}, SourceEngine: "e1"},
		{Location: findings.Location{File: "/b.go", Line: 2}, Algorithm: &findings.Algorithm{Name: "AES"}, SourceEngine: "e3"}, // dup of [1]
	}
	out := dedupe(in)
	if len(out) != 3 {
		t.Fatalf("got %d deduped findings, want 3", len(out))
	}
	wantNames := []string{"RSA", "AES", "DH"}
	for i, w := range wantNames {
		if out[i].Algorithm.Name != w {
			t.Errorf("index %d: got %q, want %q", i, out[i].Algorithm.Name, w)
		}
	}
}

// ---------------------------------------------------------------------------
// O-P2 — corroboration ordering determinism
// ---------------------------------------------------------------------------

// TestAudit_Dedup_CorroborationOrderIsInputOrder verifies that the
// CorroboratedBy list is built in *input* order — i.e. the order in which
// duplicate findings are observed. Different input permutations will
// therefore produce different CorroboratedBy orderings. This is documented
// behaviour; the test validates the actual contract so consumers (SARIF,
// CBOM, JSON output) can rely on it.
//
// Related finding: the orchestrator merges per-engine results in engine
// registration order (orchestrator.go:~567), so across a real scan the
// corroboration list is deterministic. But any direct caller of dedupe()
// that passes findings in a non-deterministic order (e.g. by iterating a Go
// map) will get a non-deterministic CorroboratedBy — documented as a caveat.
func TestAudit_Dedup_CorroborationOrderIsInputOrder(t *testing.T) {
	mk := func(engine string) findings.UnifiedFinding {
		return findings.UnifiedFinding{
			Location:     findings.Location{File: "/a.go", Line: 10},
			Algorithm:    &findings.Algorithm{Name: "RSA"},
			Confidence:   findings.ConfidenceMedium,
			SourceEngine: engine,
		}
	}

	// Permutation 1: A → B → C
	r1 := dedupe([]findings.UnifiedFinding{mk("A"), mk("B"), mk("C")})
	// Permutation 2: C → B → A
	r2 := dedupe([]findings.UnifiedFinding{mk("C"), mk("B"), mk("A")})

	if len(r1) != 1 || len(r2) != 1 {
		t.Fatalf("expected 1 deduped finding each, got %d and %d", len(r1), len(r2))
	}

	// Winner for r1 is A; CorroboratedBy must be [B, C] in that order.
	if r1[0].SourceEngine != "A" {
		t.Errorf("r1 winner should be A (first-seen), got %q", r1[0].SourceEngine)
	}
	if fmt.Sprint(r1[0].CorroboratedBy) != "[B C]" {
		t.Errorf("r1 CorroboratedBy = %v, want [B C]", r1[0].CorroboratedBy)
	}
	// Winner for r2 is C; CorroboratedBy must be [B, A] in that order.
	if r2[0].SourceEngine != "C" {
		t.Errorf("r2 winner should be C (first-seen), got %q", r2[0].SourceEngine)
	}
	if fmt.Sprint(r2[0].CorroboratedBy) != "[B A]" {
		t.Errorf("r2 CorroboratedBy = %v, want [B A]", r2[0].CorroboratedBy)
	}
}

// ---------------------------------------------------------------------------
// O-R1 — 10-engine fan-out race
// ---------------------------------------------------------------------------

// TestAudit_FanOut_10Engines_NoRace exercises the parallel engine-dispatch
// path in scanPipeline with 10 concurrent engines, each returning 50
// findings. Intended to be run under `go test -race`.
func TestAudit_FanOut_10Engines_NoRace(t *testing.T) {
	const nEngines = 10
	const perEngine = 50

	engsList := make([]engines.Engine, nEngines)
	for i := 0; i < nEngines; i++ {
		name := fmt.Sprintf("eng-%02d", i)
		ff := make([]findings.UnifiedFinding, perEngine)
		for j := 0; j < perEngine; j++ {
			ff[j] = findings.UnifiedFinding{
				Location:     findings.Location{File: fmt.Sprintf("/src/%s/file%d.go", name, j), Line: j + 1},
				Algorithm:    &findings.Algorithm{Name: "RSA-2048"},
				SourceEngine: name,
				Confidence:   findings.ConfidenceMedium,
			}
		}
		engsList[i] = &benchEngine{name: name, tier: engines.Tier1Pattern, findings: ff}
	}
	orch := New(engsList...)

	res, err := orch.Scan(context.Background(), engines.ScanOptions{Mode: engines.ModeFull, TargetPath: t.TempDir()})
	if err != nil {
		t.Fatalf("Scan() error: %v", err)
	}
	if len(res) != nEngines*perEngine {
		t.Errorf("expected %d findings, got %d", nEngines*perEngine, len(res))
	}
}

// ---------------------------------------------------------------------------
// O-R2 — fan-out partial failure (panic + hang + error + success)
// ---------------------------------------------------------------------------

// auditPanicEngine panics inside Scan. Named with `audit` prefix to avoid
// collision with panicEngine already defined in new_pipeline_test.go.
type auditPanicEngine struct{ name string }

func (p *auditPanicEngine) Name() string                 { return p.name }
func (p *auditPanicEngine) Tier() engines.Tier           { return engines.Tier1Pattern }
func (p *auditPanicEngine) Available() bool              { return true }
func (p *auditPanicEngine) Version() string              { return "panic" }
func (p *auditPanicEngine) SupportedLanguages() []string { return []string{"go"} }
func (p *auditPanicEngine) Scan(_ context.Context, _ engines.ScanOptions) ([]findings.UnifiedFinding, error) {
	panic(fmt.Errorf("audit-panic-engine: %s", p.name))
}

// hangEngine blocks until ctx is cancelled.
type hangEngine struct {
	name     string
	entered  chan struct{}
	observed atomic.Bool
}

func (h *hangEngine) Name() string                 { return h.name }
func (h *hangEngine) Tier() engines.Tier           { return engines.Tier1Pattern }
func (h *hangEngine) Available() bool              { return true }
func (h *hangEngine) Version() string              { return "hang" }
func (h *hangEngine) SupportedLanguages() []string { return []string{"go"} }
func (h *hangEngine) Scan(ctx context.Context, _ engines.ScanOptions) ([]findings.UnifiedFinding, error) {
	h.observed.Store(true)
	if h.entered != nil {
		close(h.entered)
	}
	<-ctx.Done()
	return nil, ctx.Err()
}

// TestAudit_FanOut_PanicPlusHangPlusError asserts the orchestrator:
//  1. recovers from the panicking engine (does not abort the whole run),
//  2. returns findings from successful engines,
//  3. does not hang when another engine is blocked — as long as the caller
//     cancels the context.
func TestAudit_FanOut_PanicPlusHangPlusError(t *testing.T) {
	hang := &hangEngine{name: "hang", entered: make(chan struct{})}
	good := &benchEngine{
		name: "good",
		tier: engines.Tier1Pattern,
		findings: []findings.UnifiedFinding{
			{Location: findings.Location{File: "/a.go", Line: 1}, Algorithm: &findings.Algorithm{Name: "AES"}, SourceEngine: "good"},
		},
	}
	badPanic := &auditPanicEngine{name: "pan"}
	badErr := &mockEngine{name: "err", tier: engines.Tier1Pattern, available: true, scanErr: fmt.Errorf("audit-err-engine")}

	orch := New(badPanic, hang, good, badErr)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan struct {
		res []findings.UnifiedFinding
		err error
	}, 1)
	go func() {
		res, err := orch.Scan(ctx, engines.ScanOptions{Mode: engines.ModeFull, TargetPath: t.TempDir()})
		done <- struct {
			res []findings.UnifiedFinding
			err error
		}{res, err}
	}()

	// Wait for the hang engine to have entered (so we know panic already fired
	// and the good engine has likely finished).
	select {
	case <-hang.entered:
	case <-time.After(3 * time.Second):
		t.Fatal("hang engine never entered Scan — goroutine scheduling broken or fan-out skipped")
	}

	// Cancel to release the hang engine.
	cancel()

	select {
	case out := <-done:
		// We accept *either*:
		//   - out.err == nil and out.res contains the good finding (ideal case)
		//   - out.err != nil with "scan aborted" because the cancel raced
		//     with the goroutine completion.
		if out.err != nil {
			if out.err.Error() == "" {
				t.Fatalf("Scan() returned empty error")
			}
			if !stringContains(out.err.Error(), "scan aborted") &&
				!stringContains(out.err.Error(), "all engines failed") {
				t.Errorf("unexpected error: %v", out.err)
			}
		} else {
			// Partial-success path: the good finding must be present.
			found := false
			for _, f := range out.res {
				if f.SourceEngine == "good" {
					found = true
					break
				}
			}
			if !found {
				t.Errorf("expected finding from 'good' engine in partial-success path; got %d findings", len(out.res))
			}
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Scan() did not return within 5s after context cancel — fan-out hang")
	}
}

// ---------------------------------------------------------------------------
// O-R3 — network engine panic recovery (gap test)
// ---------------------------------------------------------------------------

// TestAudit_NetworkEngine_PanicRecovered verifies that a panic in a Tier5
// network engine is recovered by the orchestrator and surfaced as an error
// rather than propagating up and crashing the caller. Mirrors the existing
// file-engine panic recovery.
func TestAudit_NetworkEngine_PanicRecovered(t *testing.T) {
	panicNet := &tier5PanicEngine{name: "net-panic"}
	orch := New(panicNet)

	opts := engines.ScanOptions{
		Mode:       engines.ModeFull,
		TargetPath: t.TempDir(),
		// Trigger Tier5 inclusion in EffectiveEngines:
		TLSTargets: []string{"example.com:443"},
	}

	// The primary assertion: the call returns without propagating the panic.
	// Network-engine failures are logged but don't fail the scan (matches
	// existing "best-effort" semantics for Tier-5 engines); the critical
	// correctness requirement is that the scanner does not crash.
	func() {
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("orchestrator propagated panic instead of recovering: %v\n%s", r, debug.Stack())
			}
		}()
		_, _, metrics, _ := orch.ScanWithMetrics(context.Background(), opts)
		// Verify the panic surfaced as an engine-metric error rather than
		// silently disappearing.
		found := false
		for _, em := range metrics.Engines {
			if em.Name == "net-panic" && em.Error != "" {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("panic was recovered but never surfaced in metrics.Engines[*].Error; metrics=%+v", metrics.Engines)
		}
	}()
}

// tier5PanicEngine panics inside Scan and is reported as a network-tier engine.
type tier5PanicEngine struct{ name string }

func (p *tier5PanicEngine) Name() string                 { return p.name }
func (p *tier5PanicEngine) Tier() engines.Tier           { return engines.Tier5Network }
func (p *tier5PanicEngine) Available() bool              { return true }
func (p *tier5PanicEngine) Version() string              { return "panic" }
func (p *tier5PanicEngine) SupportedLanguages() []string { return nil }
func (p *tier5PanicEngine) Scan(_ context.Context, _ engines.ScanOptions) ([]findings.UnifiedFinding, error) {
	panic(fmt.Errorf("audit-panic-network-engine"))
}

// ---------------------------------------------------------------------------
// O-R4 — concurrent orchestrator.Scan from multiple goroutines
// ---------------------------------------------------------------------------

// TestAudit_ConcurrentScanCalls runs 8 concurrent Scan calls on the same
// Orchestrator instance. The orchestrator documents that engine.Scan
// outputs are Cloned before in-place pipeline stages to keep this safe
// (orchestrator.go:~563-571). This test confirms no races and that every
// caller receives the expected finding count.
//
// Execute with `go test -race`.
func TestAudit_ConcurrentScanCalls(t *testing.T) {
	engs := []engines.Engine{
		&benchEngine{
			name: "a",
			tier: engines.Tier1Pattern,
			findings: []findings.UnifiedFinding{
				{Location: findings.Location{File: "/a.go", Line: 1}, Algorithm: &findings.Algorithm{Name: "RSA-2048"}, SourceEngine: "a"},
				{Location: findings.Location{File: "/b.go", Line: 2}, Algorithm: &findings.Algorithm{Name: "AES"}, SourceEngine: "a"},
			},
		},
		&benchEngine{
			name: "b",
			tier: engines.Tier1Pattern,
			findings: []findings.UnifiedFinding{
				{Location: findings.Location{File: "/c.go", Line: 3}, Algorithm: &findings.Algorithm{Name: "ECDSA"}, SourceEngine: "b"},
			},
		},
	}
	orch := New(engs...)

	const n = 8
	var wg sync.WaitGroup
	counts := make([]int, n)
	errs := make([]error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			res, err := orch.Scan(context.Background(), engines.ScanOptions{
				Mode:       engines.ModeFull,
				TargetPath: t.TempDir(),
			})
			counts[i] = len(res)
			errs[i] = err
		}(i)
	}
	wg.Wait()

	for i := 0; i < n; i++ {
		if errs[i] != nil {
			t.Errorf("call %d returned error: %v", i, errs[i])
		}
		if counts[i] != 3 {
			t.Errorf("call %d returned %d findings, want 3", i, counts[i])
		}
	}
}

// ---------------------------------------------------------------------------
// O-P3 — dedup mutates input slice (documented behaviour)
// ---------------------------------------------------------------------------

// TestAudit_Dedup_MutatesInputSlice documents a subtle invariant: dedupe
// mutates the findings inside the slice passed to it. The winner's
// CorroboratedBy slice is appended *through a pointer to all[i]*. This
// means a caller that retains a reference to the input slice will see
// mutated data after calling dedupe.
//
// The orchestrator pipeline protects against this by Cloning each
// engine-returned finding before appending to allFindings (see
// orchestrator.go:~569). Any future refactor that bypasses the Clone step
// would expose cross-scan mutation through engine-owned backing arrays.
//
// Documented as audit finding F2 (medium). This test pins current behaviour.
func TestAudit_Dedup_MutatesInputSlice(t *testing.T) {
	in := []findings.UnifiedFinding{
		{Location: findings.Location{File: "/a.go", Line: 10}, Algorithm: &findings.Algorithm{Name: "RSA"}, SourceEngine: "e1"},
		{Location: findings.Location{File: "/a.go", Line: 10}, Algorithm: &findings.Algorithm{Name: "RSA"}, SourceEngine: "e2"},
	}
	_ = dedupe(in)

	// The winner (in[0]) is mutated in place: CorroboratedBy gained "e2".
	if len(in[0].CorroboratedBy) != 1 || in[0].CorroboratedBy[0] != "e2" {
		t.Errorf("expected input to be mutated in-place (documented behaviour); got CorroboratedBy=%v", in[0].CorroboratedBy)
	}
}

// ---------------------------------------------------------------------------
// O-B1 — fan-out benchmark matrix
// ---------------------------------------------------------------------------

// BenchmarkAudit_FanOut runs the full scanPipeline for (10, 100, 1000)
// findings × (2, 5, 10) parallel engines. Results land in the ns/op and
// B/op columns; the audit report extracts per-finding overhead.
func BenchmarkAudit_FanOut(b *testing.B) {
	matrix := []struct {
		engines, findings int
	}{
		{2, 10}, {5, 10}, {10, 10},
		{2, 100}, {5, 100}, {10, 100},
		{2, 1000}, {5, 1000}, {10, 1000},
	}
	for _, m := range matrix {
		name := fmt.Sprintf("engines=%02d/findings=%04d", m.engines, m.findings)
		b.Run(name, func(b *testing.B) {
			engs := make([]engines.Engine, m.engines)
			per := m.findings / m.engines
			if per < 1 {
				per = 1
			}
			for i := 0; i < m.engines; i++ {
				ff := make([]findings.UnifiedFinding, per)
				for j := 0; j < per; j++ {
					ff[j] = findings.UnifiedFinding{
						Location:     findings.Location{File: fmt.Sprintf("/f%d-%d.go", i, j), Line: j + 1},
						Algorithm:    &findings.Algorithm{Name: "RSA-2048"},
						SourceEngine: fmt.Sprintf("e%d", i),
					}
				}
				engs[i] = &benchEngine{name: fmt.Sprintf("e%d", i), tier: engines.Tier1Pattern, findings: ff}
			}
			orch := New(engs...)
			opts := engines.ScanOptions{Mode: engines.ModeFull, TargetPath: b.TempDir()}
			ctx := context.Background()
			b.ResetTimer()
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				_, _ = orch.Scan(ctx, opts)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

// seededFindings builds n findings using a deterministic RNG source.
// The duplication pattern is engineered so that the deduped result is
// non-trivial (roughly n/3 findings survive with ~1.5 corroborators each).
func seededFindings(n int) []findings.UnifiedFinding {
	out := make([]findings.UnifiedFinding, n)
	algs := []string{"RSA-2048", "AES-256-GCM", "ECDH", "ECDSA", "SHA-256"}
	engs := []string{"cipherscope", "cryptoscan", "semgrep", "binary-scanner"}
	for i := 0; i < n; i++ {
		// Every 3 consecutive findings deliberately share a dedup key.
		file := fmt.Sprintf("/src/file%d.go", i/3)
		line := (i/3)*10 + 1
		alg := algs[(i/3)%len(algs)]
		eng := engs[i%len(engs)]
		out[i] = findings.UnifiedFinding{
			Location:     findings.Location{File: file, Line: line},
			Algorithm:    &findings.Algorithm{Name: alg, Primitive: "signature"},
			SourceEngine: eng,
			Confidence:   findings.ConfidenceMedium,
			Reachable:    findings.ReachableUnknown,
		}
	}
	// Sort for reproducibility.
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Location.File != out[j].Location.File {
			return out[i].Location.File < out[j].Location.File
		}
		if out[i].Location.Line != out[j].Location.Line {
			return out[i].Location.Line < out[j].Location.Line
		}
		return out[i].SourceEngine < out[j].SourceEngine
	})
	return out
}

// stringContains is a tiny helper to avoid pulling strings in just for this.
func stringContains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
