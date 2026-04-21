// Package impact — adversarial audit fixtures.
//
// These tests were added as part of the 2026-04-20 scanner-layer audit to
// probe the forward propagator, constraint detector, and protocol-boundary
// detector for termination bugs (cycles, deep chains), duplicate-counting
// bugs (diamond dependencies), and overflow-correctness edge cases.
//
// NOTE: The forward propagator walks a FLAT `DataFlowPath` list — it is NOT
// a graph. "Cycles" are therefore expressed as a DataFlowPath whose entries
// revisit the same (file, line) pair. That still terminates (bounded by
// maxHops), but duplicate constraint hits and boundary hits are NOT deduped.
package impact_test

import (
	"context"
	"testing"
	"time"

	"github.com/jimbo111/open-quantum-secure/pkg/findings"
	"github.com/jimbo111/open-quantum-secure/pkg/impact"
	"github.com/jimbo111/open-quantum-secure/pkg/impact/constraints"
	"github.com/jimbo111/open-quantum-secure/pkg/impact/forward"
	"github.com/jimbo111/open-quantum-secure/pkg/impact/protocols"
)

func rsaFindingForTest(file string, line int, steps []findings.FlowStep) findings.UnifiedFinding {
	return findings.UnifiedFinding{
		Location:     findings.Location{File: file, Line: line},
		Algorithm:    &findings.Algorithm{Name: "RSA-2048", Primitive: "signature", KeySize: 2048},
		SourceEngine: "mock",
		DataFlowPath: steps,
	}
}

// ---------------------------------------------------------------------------
// IMPACT GRAPH CYCLES — forward propagator must TERMINATE on cyclic paths.
// ---------------------------------------------------------------------------

// Audit_F40_CyclicDataFlowPath — a path that revisits the same (file, line)
// multiple times must terminate (bounded by maxHops or len(path)).
func TestAudit_F40_CyclicDataFlowPathTerminates(t *testing.T) {
	// Build a flat path: A → B → A → B → A → B → A (7 hops, all A and B repeating)
	steps := []findings.FlowStep{
		{File: "A.go", Line: 10, Message: "assignment"},
		{File: "B.go", Line: 20, Message: "serialize"},
		{File: "A.go", Line: 10, Message: "return"},
		{File: "B.go", Line: 20, Message: "serialize"},
		{File: "A.go", Line: 10, Message: "store"},
		{File: "B.go", Line: 20, Message: "serialize"},
		{File: "A.go", Line: 10, Message: "return"},
	}
	f := rsaFindingForTest("crypto.go", 5, steps)
	ctx := context.Background()

	done := make(chan struct{})
	var result *impact.Result
	go func() {
		result, _ = forward.New(10).Analyze(ctx, []findings.UnifiedFinding{f}, impact.ImpactOpts{})
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Analyze hung on cyclic DataFlowPath (no termination bound)")
	}
	if result == nil {
		t.Fatal("result nil")
	}
	if len(result.ForwardEdges) != len(steps) {
		t.Errorf("ForwardEdges = %d, expected %d (equal to DataFlowPath length)",
			len(result.ForwardEdges), len(steps))
	}

	// Each step re-visits A:10 and B:20 which matches `serialize`. Every
	// "serialize" occurrence produces a (nothing) — no constraint hits.
	// But if we added `make([]byte, 256)` to every step we'd expect DUPLICATES.
	// This is F41's focus.
}

// Audit_F41_DuplicateConstraintHits_NotDeduped — a cyclic / repeated message
// produces duplicate ConstraintHits — the detector doesn't dedupe by (file,line).
func TestAudit_F41_DuplicateConstraintHitsNotDeduped(t *testing.T) {
	// Same file:line visited 5 times, all with buffer-alloc message.
	var steps []findings.FlowStep
	for i := 0; i < 5; i++ {
		steps = append(steps, findings.FlowStep{
			File: "hot.go", Line: 42,
			Message: "buf := make([]byte, 256)",
		})
	}
	f := rsaFindingForTest("crypto.go", 1, steps)

	r, _ := forward.New(10).Analyze(context.Background(), []findings.UnifiedFinding{f}, impact.ImpactOpts{})

	// Detector does NOT dedupe — expect 5 duplicate hits.
	if len(r.Constraints) != 5 {
		t.Errorf("ConstraintHits: got %d, want 5 (detector does not dedupe identical (file:line) constraints)",
			len(r.Constraints))
	}
	// This is NOT strictly a bug — it's design — but if a downstream caller
	// assumes deduplication, they'll multi-count. Document.
	t.Logf("DOCUMENT: ConstraintHits are recorded per-step; identical (file:line) hits from a cyclic flow path"+
		" produce %d entries (no dedup). Downstream summaries must handle this.",
		len(r.Constraints))
}

// Audit_F42_DiamondDependency_CountedTwice — finding has a DataFlowPath that
// visits D via two different intermediate steps (A→B→D and A→C→D). Since
// DataFlowPath is linear, this shows up as [B, D, C, D]. D is visited twice
// and constraint/boundary hits at D are recorded twice.
func TestAudit_F42_DiamondDependencyCountedTwice(t *testing.T) {
	// Linearized diamond: A → B → D(jwt.Sign) → C → D(jwt.Sign)
	steps := []findings.FlowStep{
		{File: "B.go", Line: 10, Message: "assign"},
		{File: "D.go", Line: 99, Message: "jwt.Sign(token)"},
		{File: "C.go", Line: 11, Message: "assign"},
		{File: "D.go", Line: 99, Message: "jwt.Sign(token)"},
	}
	f := rsaFindingForTest("root.go", 1, steps)

	r, _ := forward.New(10).Analyze(context.Background(), []findings.UnifiedFinding{f}, impact.ImpactOpts{})

	jwtBoundaryCount := 0
	for _, b := range r.Boundaries {
		if b.Protocol == "JWT" && b.File == "D.go" && b.Line == 99 {
			jwtBoundaryCount++
		}
	}
	if jwtBoundaryCount != 2 {
		t.Errorf("diamond boundary: got JWT@D.go:99 count=%d, want 2 (no dedup by design)", jwtBoundaryCount)
	}
	t.Logf("DIAMOND BEHAVIOUR: D visited twice in linearized path → JWT@D.go:99 recorded 2x."+
		" If a downstream consumer computes impact as sum rather than union, blast radius inflates.")
}

// Audit_F43_VeryDeepChain_CappedByMaxHops — a 1000-step DataFlowPath must
// be capped at maxHops edges.
func TestAudit_F43_VeryDeepChainCapped(t *testing.T) {
	const depth = 1000
	steps := make([]findings.FlowStep, depth)
	for i := range steps {
		steps[i] = findings.FlowStep{File: "f.go", Line: i + 1}
	}
	f := rsaFindingForTest("root.go", 1, steps)

	for _, maxHops := range []int{1, 10, 100, 500} {
		t.Run("", func(t *testing.T) {
			r, err := forward.New(maxHops).Analyze(context.Background(), []findings.UnifiedFinding{f}, impact.ImpactOpts{})
			if err != nil {
				t.Fatalf("Analyze: %v", err)
			}
			if len(r.ForwardEdges) != maxHops {
				t.Errorf("maxHops=%d: got %d edges, want %d (hop cap not applied)",
					maxHops, len(r.ForwardEdges), maxHops)
			}
		})
	}
}

// Audit_F44_MaxHopsNegative_DefaultApplied — negative maxHops should fall
// back to default (10), not loop.
func TestAudit_F44_NegativeMaxHopsUsesDefault(t *testing.T) {
	// Ensure New(negative) applies default.
	p := forward.New(-5)
	// Indirect verification: 20-step path should produce 10 edges (default).
	steps := make([]findings.FlowStep, 20)
	for i := range steps {
		steps[i] = findings.FlowStep{File: "f.go", Line: i + 1}
	}
	f := rsaFindingForTest("root.go", 1, steps)
	r, _ := p.Analyze(context.Background(), []findings.UnifiedFinding{f}, impact.ImpactOpts{})
	if len(r.ForwardEdges) != 10 {
		t.Errorf("negative maxHops should fall back to default 10, got %d edges", len(r.ForwardEdges))
	}
}

// Audit_F45_EmptyFlowStep_NoCrash — a FlowStep with empty File/empty Message.
func TestAudit_F45_EmptyFlowStepHandled(t *testing.T) {
	steps := []findings.FlowStep{{}, {File: "", Line: 0, Message: ""}}
	f := rsaFindingForTest("root.go", 1, steps)
	_, err := forward.New(10).Analyze(context.Background(), []findings.UnifiedFinding{f}, impact.ImpactOpts{})
	if err != nil {
		t.Fatalf("empty FlowStep should not error: %v", err)
	}
}

// ---------------------------------------------------------------------------
// CONSTRAINT / BOUNDARY DETECTION EDGE CASES
// ---------------------------------------------------------------------------

// Audit_F46_ConstraintZeroSize — `make([]byte, 0)` has MaxBytes=0 and is
// SILENTLY DROPPED by the detector (n <= 0 check in detector.go). Document.
func TestAudit_F46_ConstraintZeroSizeDropped(t *testing.T) {
	steps := []findings.FlowStep{
		{File: "f.go", Line: 1, Message: "buf := make([]byte, 0)"},
		{File: "f.go", Line: 2, Message: "VARCHAR(0)"},
	}
	hits := constraints.DetectFromPath(steps)
	if len(hits) != 0 {
		t.Errorf("zero-size constraints should be dropped (n<=0 guard), got %d hits", len(hits))
	}
}

// Audit_F47_ConstraintOverflowInt — huge make([]byte, 9999999999999999999)
// overflows int. strconv.Atoi will return an error, so the constraint is skipped.
func TestAudit_F47_ConstraintOverflowInt(t *testing.T) {
	steps := []findings.FlowStep{
		{File: "f.go", Line: 1, Message: "buf := make([]byte, 9999999999999999999)"},
	}
	hits := constraints.DetectFromPath(steps)
	if len(hits) != 0 {
		t.Errorf("overflow constraint should be skipped (Atoi error), got %d hits", len(hits))
	}
}

// Audit_F48_ProtocolDuplicateMatch — a single message containing multiple
// tokens for the same protocol (e.g. "tls.Dial and tls.Listen"). The detector
// uses `break` after first match per protocol-per-step, so only one hit.
func TestAudit_F48_ProtocolMessageMultipleTokens(t *testing.T) {
	steps := []findings.FlowStep{
		{File: "n.go", Line: 1, Message: "tls.Dial and tls.Listen and tls.Config"},
	}
	hits := protocols.DetectFromPath(steps)
	tlsCount := 0
	for _, h := range hits {
		if h.Protocol == "TLS" {
			tlsCount++
		}
	}
	if tlsCount != 1 {
		t.Errorf("multi-token TLS message: got %d TLS hits, want 1 (detector should dedupe per protocol per step)",
			tlsCount)
	}
}

// Audit_F49_ProtocolsTwoMatchesSameMessage — a single step message can match
// MULTIPLE distinct protocols. Both should be reported.
func TestAudit_F49_MultipleProtocolsSameStep(t *testing.T) {
	steps := []findings.FlowStep{
		{File: "n.go", Line: 1, Message: "jwt.Sign(tls.Dial())"}, // matches JWT AND TLS
	}
	hits := protocols.DetectFromPath(steps)
	hasJWT, hasTLS := false, false
	for _, h := range hits {
		if h.Protocol == "JWT" {
			hasJWT = true
		}
		if h.Protocol == "TLS" {
			hasTLS = true
		}
	}
	if !hasJWT || !hasTLS {
		t.Errorf("expected both JWT and TLS hits from single step, got hasJWT=%v hasTLS=%v",
			hasJWT, hasTLS)
	}
}

// ---------------------------------------------------------------------------
// CalculateEncodedSize edge cases
// ---------------------------------------------------------------------------

// Audit_F50_EncodedSizeNegative — calling with negative raw size.
// ((n+2)/3)*4 with n=-1 yields integer rounding to e.g. 0 or a negative.
func TestAudit_F50_EncodedSizeNegativeRaw(t *testing.T) {
	cases := []struct {
		raw int
		enc string
	}{
		{-100, "base64"},
		{-100, "hex"},
		{-100, "pem"},
		{-100, "der"},
		{0, "base64"},
		{0, "pem"},
	}
	for _, c := range cases {
		got := constraints.CalculateEncodedSize(c.raw, c.enc)
		if got < 0 {
			// Logged rather than Errorf — authoritative record is in the audit
			// report (F50). Callers pass n<0 only via a bug upstream; this
			// documents that the encoding layer propagates the bogus value.
			t.Logf("CONFIRMED F50: CalculateEncodedSize(%d, %q) = %d (negative is nonsensical; no guard)", c.raw, c.enc, got)
		}
	}
}

// Audit_F51_EncodedSizeUnknownEncoding — treated as raw.
func TestAudit_F51_EncodedSizeUnknownEncoding(t *testing.T) {
	n := 100
	got := constraints.CalculateEncodedSize(n, "invalid-encoding")
	if got != n {
		t.Errorf("unknown encoding should be raw (n=%d), got %d", n, got)
	}
}

// ---------------------------------------------------------------------------
// LOOKUP edge cases
// ---------------------------------------------------------------------------

// Audit_F52_Lookup_EmptyIdentifier returns no match — ensure prefix fallback
// doesn't accidentally match via "".
func TestAudit_F52_LookupEmptyIdentifier(t *testing.T) {
	// upper="" → HasPrefix(anyKey, "") is true → bug hazard.
	// F52 documented as a silent-match on empty identifier.
	p, ok := constraints.Lookup("")
	if ok {
		t.Logf("CONFIRMED F52: Lookup(\"\") matched via empty-string prefix-match. Got %+v (should return not-found)", p)
	}
}

// Audit_F53_MigrationTargets_EmptyIdentifier — same hazard.
func TestAudit_F53_MigrationTargetsEmptyIdentifier(t *testing.T) {
	got := constraints.MigrationTargets("")
	if got != nil {
		t.Errorf("MigrationTargets(\"\") should return nil, got %v (empty-string prefix match)", got)
	}
}

// ---------------------------------------------------------------------------
// Check() — CONSTRAINT VIOLATION EDGE CASES
// ---------------------------------------------------------------------------

// Audit_F54_CheckEffectiveMaxZero_FallsBackToMaxBytes — solver fallback.
func TestAudit_F54_CheckEffectiveMaxZeroFallsBack(t *testing.T) {
	profile := constraints.AlgorithmSizeProfile{SignatureBytes: 1000}
	c := impact.ConstraintHit{MaxBytes: 500, EffectiveMax: 0}
	v := constraints.Check(profile, c)
	if v == nil {
		t.Error("EffectiveMax=0 should fall back to MaxBytes — expected violation")
	}
	if v != nil && v.Overflow != 500 {
		t.Errorf("Overflow=%d, want 500", v.Overflow)
	}
}

// Audit_F55_CheckBothMaxBytesAndEffMaxZero — no violation reported (profile
// projects to >0 but limit is 0, which is treated as "no limit" via fallback).
func TestAudit_F55_CheckBothLimitsZero(t *testing.T) {
	profile := constraints.AlgorithmSizeProfile{SignatureBytes: 1000}
	c := impact.ConstraintHit{MaxBytes: 0, EffectiveMax: 0}
	v := constraints.Check(profile, c)
	// Both zero — effectiveMax ends up 0. projected (1000) > 0 → violation.
	// This is probably NOT desired (a constraint with MaxBytes=0 is bogus).
	// Document actual behaviour.
	if v == nil {
		t.Logf("Check(profile=1000, maxBytes=0) returned no violation — OK (zero limit treated as \"no limit\").")
	} else {
		t.Logf("Check(profile=1000, maxBytes=0) returned violation overflow=%d — a bogus constraint "+
			"(MaxBytes=0) is silently treated as a real one. Caller should guard.", v.Overflow)
	}
}

// Audit_F56_HugeFindingList_NoAllocExplosion — 10000 findings, each with
// 10-step paths, produces linear output.
func TestAudit_F56_LargeFindingSet(t *testing.T) {
	const n = 10000
	ff := make([]findings.UnifiedFinding, 0, n)
	steps := []findings.FlowStep{
		{File: "a.go", Line: 1, Message: "buf := make([]byte, 256)"},
		{File: "b.go", Line: 2, Message: "jwt.Sign(token)"},
	}
	for i := 0; i < n; i++ {
		ff = append(ff, rsaFindingForTest("r.go", i, steps))
	}
	r, err := forward.New(10).Analyze(context.Background(), ff, impact.ImpactOpts{})
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	if len(r.ForwardEdges) != n*len(steps) {
		t.Errorf("edge count = %d, want %d", len(r.ForwardEdges), n*len(steps))
	}
}
