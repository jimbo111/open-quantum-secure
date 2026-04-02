package orchestrator

import (
	"context"
	"testing"

	"github.com/jimbo111/open-quantum-secure/pkg/engines"
	"github.com/jimbo111/open-quantum-secure/pkg/findings"
)

// ---------------------------------------------------------------------------
// Mock engine used throughout the pipeline tests
// ---------------------------------------------------------------------------

// mockEngine is a fully controllable in-process engine for unit testing.
type mockEngine struct {
	name      string
	tier      engines.Tier
	available bool
	results   []findings.UnifiedFinding
	scanErr   error
}

func (m *mockEngine) Name() string                  { return m.name }
func (m *mockEngine) Tier() engines.Tier            { return m.tier }
func (m *mockEngine) SupportedLanguages() []string  { return []string{"go"} }
func (m *mockEngine) Available() bool               { return m.available }
func (m *mockEngine) Version() string               { return "mock" }
func (m *mockEngine) Scan(_ context.Context, _ engines.ScanOptions) ([]findings.UnifiedFinding, error) {
	return m.results, m.scanErr
}

// alg is a small helper that builds a *findings.Algorithm pointer.
func alg(name, primitive string, keySize int) *findings.Algorithm {
	return &findings.Algorithm{Name: name, Primitive: primitive, KeySize: keySize}
}

// loc is a small helper that builds a findings.Location value.
func loc(file string, line int) findings.Location {
	return findings.Location{File: file, Line: line}
}

// ---------------------------------------------------------------------------
// 1. Dedup: Three-way merge
// ---------------------------------------------------------------------------

// TestDedup_ThreeWayMerge verifies that when three different engines all
// report the same finding (file + line + algorithm name), dedupe collapses
// them to a single finding that records exactly two corroborators.
func TestDedup_ThreeWayMerge(t *testing.T) {
	all := []findings.UnifiedFinding{
		{Location: loc("/repo/main.go", 42), Algorithm: alg("RSA-2048", "pke", 2048), Confidence: findings.ConfidenceLow, SourceEngine: "alpha"},
		{Location: loc("/repo/main.go", 42), Algorithm: alg("RSA-2048", "pke", 2048), Confidence: findings.ConfidenceLow, SourceEngine: "beta"},
		{Location: loc("/repo/main.go", 42), Algorithm: alg("RSA-2048", "pke", 2048), Confidence: findings.ConfidenceLow, SourceEngine: "gamma"},
	}

	result := dedupe(all)

	if len(result) != 1 {
		t.Fatalf("three-way merge: got %d findings, want 1", len(result))
	}
	f := result[0]
	if len(f.CorroboratedBy) != 2 {
		t.Errorf("CorroboratedBy length = %d, want 2; got %v", len(f.CorroboratedBy), f.CorroboratedBy)
	}
	// The winner is "alpha" (first seen); beta and gamma are corroborators.
	if f.SourceEngine != "alpha" {
		t.Errorf("winner SourceEngine = %q, want %q", f.SourceEngine, "alpha")
	}
	if !contains(f.CorroboratedBy, "beta") {
		t.Errorf("beta missing from CorroboratedBy: %v", f.CorroboratedBy)
	}
	if !contains(f.CorroboratedBy, "gamma") {
		t.Errorf("gamma missing from CorroboratedBy: %v", f.CorroboratedBy)
	}
}

// ---------------------------------------------------------------------------
// 2. Dedup: Metadata merge priority — winner keeps non-empty, fills from loser
// ---------------------------------------------------------------------------

// TestDedup_MetadataMergePriority verifies that when two findings are merged
// the winner keeps its own non-empty fields and adopts the loser's values
// only for the fields it was missing.
func TestDedup_MetadataMergePriority(t *testing.T) {
	// Winner has KeySize and Curve; loser has Primitive and Mode.
	winner := findings.UnifiedFinding{
		Location:     loc("/a.go", 10),
		Algorithm:    &findings.Algorithm{Name: "ECDH", KeySize: 256, Curve: "P-256"},
		Confidence:   findings.ConfidenceMedium,
		SourceEngine: "engine-A",
	}
	loser := findings.UnifiedFinding{
		Location:     loc("/a.go", 10),
		Algorithm:    &findings.Algorithm{Name: "ECDH", Primitive: "key-agree", Mode: "HYBRID"},
		Confidence:   findings.ConfidenceLow,
		SourceEngine: "engine-B",
	}

	result := dedupe([]findings.UnifiedFinding{winner, loser})

	if len(result) != 1 {
		t.Fatalf("metadata merge: got %d results, want 1", len(result))
	}
	f := result[0]

	// Winner's original fields must survive.
	if f.Algorithm.KeySize != 256 {
		t.Errorf("KeySize overwritten: got %d, want 256", f.Algorithm.KeySize)
	}
	if f.Algorithm.Curve != "P-256" {
		t.Errorf("Curve overwritten: got %q, want P-256", f.Algorithm.Curve)
	}
	// Loser's fields that were absent in winner must be adopted.
	if f.Algorithm.Primitive != "key-agree" {
		t.Errorf("Primitive not adopted from loser: got %q, want key-agree", f.Algorithm.Primitive)
	}
	if f.Algorithm.Mode != "HYBRID" {
		t.Errorf("Mode not adopted from loser: got %q, want HYBRID", f.Algorithm.Mode)
	}
}

// ---------------------------------------------------------------------------
// 3. Dedup: Confidence boost chain — low → medium → high across merges
// ---------------------------------------------------------------------------

// TestDedup_ConfidenceBoostChain verifies the full low → medium → high
// confidence escalation path driven by successive corroborations.
//
// Round 1: winner starts at Low, first corroborator boosts it to Medium.
// Round 2: a second corroborator should then boost Medium → High.
func TestDedup_ConfidenceBoostChain(t *testing.T) {
	all := []findings.UnifiedFinding{
		{Location: loc("/x.go", 1), Algorithm: alg("DH", "", 0), Confidence: findings.ConfidenceLow, SourceEngine: "eng1"},
		{Location: loc("/x.go", 1), Algorithm: alg("DH", "", 0), Confidence: findings.ConfidenceLow, SourceEngine: "eng2"},
		{Location: loc("/x.go", 1), Algorithm: alg("DH", "", 0), Confidence: findings.ConfidenceLow, SourceEngine: "eng3"},
	}

	result := dedupe(all)

	if len(result) != 1 {
		t.Fatalf("expected 1 merged finding, got %d", len(result))
	}
	f := result[0]

	// After two corroborations the confidence must be Medium (low → medium-low → medium).
	if f.Confidence != findings.ConfidenceMedium {
		t.Errorf("Confidence after two boosts = %q, want %q", f.Confidence, findings.ConfidenceMedium)
	}
	if len(f.CorroboratedBy) != 2 {
		t.Errorf("CorroboratedBy length = %d, want 2", len(f.CorroboratedBy))
	}
}

// ---------------------------------------------------------------------------
// 4. Dedup: Nil Algorithm handling — must not panic
// ---------------------------------------------------------------------------

// TestDedup_NilAlgorithmHandling verifies that findings with a nil Algorithm
// are handled safely and do not cause a nil-pointer panic during merging.
func TestDedup_NilAlgorithmHandling(t *testing.T) {
	// Two findings with no Algorithm (raw-identifier fallback key path).
	// Each has a different SourceEngine so they have different dedupe keys.
	all := []findings.UnifiedFinding{
		{Location: loc("/b.go", 5), Algorithm: nil, RawIdentifier: "crypto-lib", SourceEngine: "eng1"},
		{Location: loc("/b.go", 5), Algorithm: nil, RawIdentifier: "crypto-lib", SourceEngine: "eng2"},
	}

	// Must not panic.
	var result []findings.UnifiedFinding
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("dedupe panicked with nil Algorithm: %v", r)
		}
	}()

	result = dedupe(all)
	// The fallback key includes SourceEngine, so they should remain separate.
	if len(result) != 2 {
		t.Errorf("nil Algorithm findings: got %d results, want 2", len(result))
	}
}

// ---------------------------------------------------------------------------
// 5. Dedup: Nil Dependency handling — must not panic
// ---------------------------------------------------------------------------

// TestDedup_NilDependencyHandling verifies that findings with a nil Dependency
// and nil Algorithm are deduplicated via the raw-identifier fallback without panic.
func TestDedup_NilDependencyHandling(t *testing.T) {
	all := []findings.UnifiedFinding{
		{Location: loc("/c.go", 0), Dependency: nil, Algorithm: nil, RawIdentifier: "", SourceEngine: "eng1"},
		{Location: loc("/c.go", 0), Dependency: nil, Algorithm: nil, RawIdentifier: "", SourceEngine: "eng1"},
	}

	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("dedupe panicked with nil Dependency: %v", r)
		}
	}()

	result := dedupe(all)
	// Same engine + same key — only one entry expected.
	if len(result) != 1 {
		t.Errorf("nil Dependency findings: got %d results, want 1", len(result))
	}
}

// ---------------------------------------------------------------------------
// 6. Dedup: Same engine same location — must NOT self-corroborate
// ---------------------------------------------------------------------------

// TestDedup_SameEngineSameLocation verifies that when the same engine reports
// an identical finding twice, the duplicate is collapsed but the engine is NOT
// added to CorroboratedBy (engines cannot corroborate themselves).
func TestDedup_SameEngineSameLocation(t *testing.T) {
	all := []findings.UnifiedFinding{
		{Location: loc("/d.go", 20), Algorithm: alg("AES-256-GCM", "ae", 256), Confidence: findings.ConfidenceMedium, SourceEngine: "scanner"},
		{Location: loc("/d.go", 20), Algorithm: alg("AES-256-GCM", "ae", 256), Confidence: findings.ConfidenceMedium, SourceEngine: "scanner"},
	}

	result := dedupe(all)

	if len(result) != 1 {
		t.Fatalf("same-engine duplicate: got %d findings, want 1", len(result))
	}
	f := result[0]
	if len(f.CorroboratedBy) != 0 {
		t.Errorf("same engine should not self-corroborate, CorroboratedBy = %v", f.CorroboratedBy)
	}
	// Confidence must NOT be boosted by self-report.
	if f.Confidence != findings.ConfidenceMedium {
		t.Errorf("Confidence = %q, want medium (no boost from same engine)", f.Confidence)
	}
}

// ---------------------------------------------------------------------------
// 7. Dedup: Different algorithms at the same location → 2 findings
// ---------------------------------------------------------------------------

// TestDedup_DifferentAlgorithmsSameLocation verifies that two different
// algorithms found at the same file+line produce two independent findings
// (they have different dedupe keys).
func TestDedup_DifferentAlgorithmsSameLocation(t *testing.T) {
	all := []findings.UnifiedFinding{
		{Location: loc("/e.go", 7), Algorithm: alg("RSA-2048", "pke", 2048), SourceEngine: "eng1"},
		{Location: loc("/e.go", 7), Algorithm: alg("AES-256-GCM", "ae", 256), SourceEngine: "eng1"},
	}

	result := dedupe(all)

	if len(result) != 2 {
		t.Fatalf("different algorithms same location: got %d findings, want 2", len(result))
	}
}

// ---------------------------------------------------------------------------
// 8. Dedup: Same algorithm different files → 2 findings
// ---------------------------------------------------------------------------

// TestDedup_SameAlgorithmDifferentFiles verifies that the same algorithm
// found in two different files is NOT merged (location is part of the key).
func TestDedup_SameAlgorithmDifferentFiles(t *testing.T) {
	all := []findings.UnifiedFinding{
		{Location: loc("/pkg/auth/login.go", 12), Algorithm: alg("RSA-2048", "pke", 2048), SourceEngine: "eng1"},
		{Location: loc("/pkg/crypto/rsa.go", 12), Algorithm: alg("RSA-2048", "pke", 2048), SourceEngine: "eng1"},
	}

	result := dedupe(all)

	if len(result) != 2 {
		t.Fatalf("same algorithm different files: got %d findings, want 2", len(result))
	}
}

// ---------------------------------------------------------------------------
// 9. classifyFindings integration — RSA vulnerable, AES-256 resistant, ML-KEM safe
// ---------------------------------------------------------------------------

// TestClassifyFindings_Integration verifies quantum risk classification for
// the three principal categories: quantum-vulnerable, quantum-resistant, and
// quantum-safe (PQC) algorithms.
func TestClassifyFindings_Integration(t *testing.T) {
	tests := []struct {
		name     string
		finding  findings.UnifiedFinding
		wantRisk findings.QuantumRisk
	}{
		{
			name:     "RSA is quantum-vulnerable",
			finding:  findings.UnifiedFinding{Algorithm: alg("RSA-2048", "pke", 2048)},
			wantRisk: findings.QRVulnerable,
		},
		{
			name:     "AES-256-GCM is quantum-resistant",
			finding:  findings.UnifiedFinding{Algorithm: alg("AES-256-GCM", "ae", 256)},
			wantRisk: findings.QRResistant,
		},
		{
			name:     "ML-KEM-768 is quantum-safe",
			finding:  findings.UnifiedFinding{Algorithm: alg("ML-KEM-768", "kem", 0)},
			wantRisk: findings.QRSafe,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ff := []findings.UnifiedFinding{tt.finding}
			classifyFindings(ff)
			if ff[0].QuantumRisk != tt.wantRisk {
				t.Errorf("QuantumRisk = %q, want %q", ff[0].QuantumRisk, tt.wantRisk)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// 10. classifyFindings: dependency findings get unknown risk
// ---------------------------------------------------------------------------

// TestClassifyFindings_DependencyGetsUnknown verifies that dependency findings
// (no Algorithm) receive QRUnknown and SevInfo classification.
func TestClassifyFindings_DependencyGetsUnknown(t *testing.T) {
	ff := []findings.UnifiedFinding{
		{Dependency: &findings.Dependency{Library: "bouncycastle"}},
		{Dependency: &findings.Dependency{Library: "openssl"}},
	}

	classifyFindings(ff)

	for i, f := range ff {
		if f.QuantumRisk != findings.QRUnknown {
			t.Errorf("ff[%d] QuantumRisk = %q, want %q", i, f.QuantumRisk, findings.QRUnknown)
		}
		if f.Severity != findings.SevInfo {
			t.Errorf("ff[%d] Severity = %q, want %q", i, f.Severity, findings.SevInfo)
		}
	}
}

// ---------------------------------------------------------------------------
// 11. normalizeFindings integration — name variants resolve to same canonical
// ---------------------------------------------------------------------------

// TestNormalizeFindings_NameVariantsConverge verifies that two different raw
// representations of the same algorithm (e.g., "AES-256-GCM" and "AES_256_GCM")
// are both normalized to the same canonical name before deduplication, which
// allows the subsequent dedupe step to merge them correctly.
func TestNormalizeFindings_NameVariantsConverge(t *testing.T) {
	// "AES-256-GCM" and "AES_256_GCM" represent the same algorithm.
	// normalizeFindings should resolve both to "AES-256-GCM" (exact match,
	// because cleanInput converts underscores to hyphens before pattern matching).
	ff := []findings.UnifiedFinding{
		{
			Location:     loc("/f.go", 1),
			Algorithm:    &findings.Algorithm{Name: "AES-256-GCM"},
			SourceEngine: "eng1",
		},
		{
			Location:     loc("/f.go", 1),
			Algorithm:    &findings.Algorithm{Name: "AES_256_GCM"},
			SourceEngine: "eng2",
		},
	}

	normalizeFindings(ff)

	// After normalization both names must be identical canonical names.
	nameA := ff[0].Algorithm.Name
	nameB := ff[1].Algorithm.Name
	if nameA != nameB {
		t.Errorf("after normalization names differ: %q vs %q (should both be canonical AES-256-GCM)", nameA, nameB)
	}

	// Verify the canonical name is the expected registry value.
	if nameA != "AES-256-GCM" {
		t.Errorf("canonical name = %q, want AES-256-GCM", nameA)
	}

	// As a consequence, dedupe should now merge the two into one finding.
	merged := dedupe(ff)
	if len(merged) != 1 {
		t.Errorf("after normalization+dedup: got %d findings, want 1", len(merged))
	}
}

// TestNormalizeFindings_PrimitiveBackfill verifies that normalizeFindings
// backfills the Primitive field from the registry when the finding has none.
func TestNormalizeFindings_PrimitiveBackfill(t *testing.T) {
	ff := []findings.UnifiedFinding{
		{Algorithm: &findings.Algorithm{Name: "AES-256-GCM", Primitive: ""}},
	}

	normalizeFindings(ff)

	// The registry defines AES-256-GCM as "ae" primitive.
	if ff[0].Algorithm.Primitive == "" {
		t.Errorf("Primitive was not backfilled; got empty string, expected registry value (ae)")
	}
}

// TestNormalizeFindings_CurveAlias verifies that the curve resolver normalizes
// known curve aliases (e.g., "secp256r1") to the canonical form ("nist/P-256").
func TestNormalizeFindings_CurveAlias(t *testing.T) {
	ff := []findings.UnifiedFinding{
		{Algorithm: &findings.Algorithm{Name: "ECDH", Curve: "secp256r1"}},
	}

	normalizeFindings(ff)

	// "secp256r1" is a well-known alias for "nist/P-256".
	if ff[0].Algorithm.Curve != "nist/P-256" {
		t.Errorf("Curve after alias resolution = %q, want nist/P-256", ff[0].Algorithm.Curve)
	}
}

// TestNormalizeFindings_NilAlgorithmSkipped verifies that findings without an
// Algorithm pointer are skipped without panic.
func TestNormalizeFindings_NilAlgorithmSkipped(t *testing.T) {
	ff := []findings.UnifiedFinding{
		{Dependency: &findings.Dependency{Library: "libssl"}, Algorithm: nil},
	}

	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("normalizeFindings panicked on nil Algorithm: %v", r)
		}
	}()

	normalizeFindings(ff) // must not panic
}

// ---------------------------------------------------------------------------
// 12. filterByTier — Tier 1 filtering with mock engines
// ---------------------------------------------------------------------------

// TestFilterByTier verifies that only engines whose Tier matches the requested
// tier are returned by filterByTier.
func TestFilterByTier(t *testing.T) {
	tier1a := &mockEngine{name: "pattern-scanner-a", tier: engines.Tier1Pattern, available: true}
	tier1b := &mockEngine{name: "pattern-scanner-b", tier: engines.Tier1Pattern, available: true}
	tier2 := &mockEngine{name: "flow-engine", tier: engines.Tier2Flow, available: true}
	tier3 := &mockEngine{name: "formal-engine", tier: engines.Tier3Formal, available: true}

	all := []engines.Engine{tier1a, tier1b, tier2, tier3}
	filtered := filterByTier(all, engines.Tier1Pattern)

	if len(filtered) != 2 {
		t.Fatalf("filterByTier(Tier1): got %d engines, want 2", len(filtered))
	}
	for _, e := range filtered {
		if e.Tier() != engines.Tier1Pattern {
			t.Errorf("unexpected tier %v for engine %q", e.Tier(), e.Name())
		}
	}
}

// TestFilterByTier_EmptyResult verifies that filterByTier returns nil (no
// engines) when no engine matches the requested tier.
func TestFilterByTier_EmptyResult(t *testing.T) {
	tier2 := &mockEngine{name: "flow-engine", tier: engines.Tier2Flow, available: true}
	filtered := filterByTier([]engines.Engine{tier2}, engines.Tier1Pattern)
	if len(filtered) != 0 {
		t.Errorf("filterByTier should return empty for non-matching tier, got %d", len(filtered))
	}
}

// ---------------------------------------------------------------------------
// 13. filterByChangedFiles: path normalization
// ---------------------------------------------------------------------------

// TestFilterByChangedFiles_PathNormalization verifies that the function
// correctly handles path variations: absolute paths on findings vs. relative
// paths in changedFiles, and back-slash separators (Windows-style).
func TestFilterByChangedFiles_PathNormalization(t *testing.T) {
	tests := []struct {
		name         string
		findingFile  string
		targetPath   string
		changedFiles []string
		wantCount    int
	}{
		{
			name:         "absolute finding path made relative to target",
			findingFile:  "/project/src/auth.go",
			targetPath:   "/project",
			changedFiles: []string{"src/auth.go"},
			wantCount:    1,
		},
		{
			name:         "already relative finding path matches directly",
			findingFile:  "src/crypto.go",
			targetPath:   "/other/root",
			changedFiles: []string{"src/crypto.go"},
			wantCount:    1,
		},
		{
			name:         "backslash separator in changed file list (Windows path)",
			findingFile:  "/repo/pkg/util.go",
			targetPath:   "/repo",
			changedFiles: []string{"pkg/util.go"},
			wantCount:    1,
		},
		{
			name:         "mismatched path yields no results",
			findingFile:  "/repo/vendor/lib.go",
			targetPath:   "/repo",
			changedFiles: []string{"src/main.go"},
			wantCount:    0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ff := []findings.UnifiedFinding{
				{Location: loc(tt.findingFile, 1), Algorithm: alg("RSA", "", 0)},
			}
			filtered := filterByChangedFiles(ff, tt.targetPath, tt.changedFiles)
			if len(filtered) != tt.wantCount {
				t.Errorf("got %d findings, want %d", len(filtered), tt.wantCount)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// 14. filterByChangedFiles: no matching files returns empty
// ---------------------------------------------------------------------------

// TestFilterByChangedFiles_NoMatch verifies that when none of the changed
// files correspond to any finding, an empty slice is returned.
func TestFilterByChangedFiles_NoMatch(t *testing.T) {
	ff := []findings.UnifiedFinding{
		{Location: loc("/repo/internal/pkg.go", 5), Algorithm: alg("AES-256-GCM", "ae", 256)},
		{Location: loc("/repo/cmd/main.go", 99), Algorithm: alg("RSA-2048", "pke", 2048)},
	}

	filtered := filterByChangedFiles(ff, "/repo", []string{"docs/README.md", "Makefile"})

	if len(filtered) != 0 {
		t.Errorf("expected 0 results when no finding matches changed files, got %d", len(filtered))
	}
}

// TestFilterByChangedFiles_MultipleMatches verifies that all findings whose
// file paths appear in the changed set are retained.
func TestFilterByChangedFiles_MultipleMatches(t *testing.T) {
	ff := []findings.UnifiedFinding{
		{Location: loc("/root/a/alpha.go", 1), Algorithm: alg("RSA-2048", "pke", 2048)},
		{Location: loc("/root/b/beta.go", 2), Algorithm: alg("ECDSA", "signature", 0)},
		{Location: loc("/root/c/gamma.go", 3), Algorithm: alg("AES-256-GCM", "ae", 256)},
	}

	changed := []string{"a/alpha.go", "c/gamma.go"}
	filtered := filterByChangedFiles(ff, "/root", changed)

	if len(filtered) != 2 {
		t.Fatalf("expected 2 findings, got %d", len(filtered))
	}
	names := make(map[string]bool)
	for _, f := range filtered {
		names[f.Algorithm.Name] = true
	}
	if !names["RSA-2048"] {
		t.Error("RSA-2048 finding should be in filtered results")
	}
	if !names["AES-256-GCM"] {
		t.Error("AES-256-GCM finding should be in filtered results")
	}
	if names["ECDSA"] {
		t.Error("ECDSA finding should NOT be in filtered results")
	}
}

// ---------------------------------------------------------------------------
// 15. Full pipeline test — normalize → dedup → classify end-to-end
// ---------------------------------------------------------------------------

// TestFullPipeline_NormalizeDedupeClassify simulates the exact sequence that
// Scan() applies (without running real engines) to verify the combined effect
// of normalizeFindings → dedupe → classifyFindings.
//
// Setup:
//   - Engine A reports "AES_256_GCM" (underscore variant) at file.go:10
//   - Engine B reports "AES-256-GCM" (canonical form) at file.go:10
//   - Engine A also reports "RSA-2048" at file.go:20 (no duplicate)
//
// Expected outcome:
//   - 2 findings (AES-256-GCM merged to 1; RSA-2048 stays 1)
//   - AES-256-GCM is corroborated by engine-B, confidence boosted, risk = quantum-resistant
//   - RSA-2048 has no corroborators, risk = quantum-vulnerable
func TestFullPipeline_NormalizeDedupeClassify(t *testing.T) {
	allFindings := []findings.UnifiedFinding{
		// Engine A — AES variant with underscores
		{
			Location:     loc("/repo/service.go", 10),
			Algorithm:    &findings.Algorithm{Name: "AES_256_GCM", KeySize: 256},
			Confidence:   findings.ConfidenceLow,
			SourceEngine: "engine-A",
		},
		// Engine B — same algorithm, canonical spelling
		{
			Location:     loc("/repo/service.go", 10),
			Algorithm:    &findings.Algorithm{Name: "AES-256-GCM", KeySize: 256},
			Confidence:   findings.ConfidenceLow,
			SourceEngine: "engine-B",
		},
		// Engine A — RSA finding only from one engine
		{
			Location:     loc("/repo/service.go", 20),
			Algorithm:    &findings.Algorithm{Name: "RSA-2048", KeySize: 2048},
			Confidence:   findings.ConfidenceMedium,
			SourceEngine: "engine-A",
		},
	}

	// Step 1: normalize (matches Scan() behavior)
	normalizeFindings(allFindings)

	// Step 2: dedupe (only when len(engines) > 1, which is our case)
	deduped := dedupe(allFindings)

	// Step 3: classify
	classifyFindings(deduped)

	// Assertions
	if len(deduped) != 2 {
		t.Fatalf("pipeline produced %d findings, want 2", len(deduped))
	}

	// Find AES and RSA findings.
	var aesFinding, rsaFinding *findings.UnifiedFinding
	for i := range deduped {
		f := &deduped[i]
		switch f.Algorithm.Name {
		case "AES-256-GCM":
			aesFinding = f
		case "RSA-2048":
			rsaFinding = f
		}
	}

	if aesFinding == nil {
		t.Fatal("AES-256-GCM finding missing from pipeline output")
	}
	if rsaFinding == nil {
		t.Fatal("RSA-2048 finding missing from pipeline output")
	}

	// AES: corroborated, confidence boosted low→medium-low, quantum-resistant.
	if len(aesFinding.CorroboratedBy) != 1 {
		t.Errorf("AES CorroboratedBy = %v, want 1 entry", aesFinding.CorroboratedBy)
	}
	if aesFinding.Confidence != findings.ConfidenceMediumLow {
		t.Errorf("AES Confidence = %q, want medium-low (boosted from low)", aesFinding.Confidence)
	}
	if aesFinding.QuantumRisk != findings.QRResistant {
		t.Errorf("AES QuantumRisk = %q, want quantum-resistant", aesFinding.QuantumRisk)
	}

	// RSA: no corroboration, confidence unchanged, quantum-vulnerable.
	if len(rsaFinding.CorroboratedBy) != 0 {
		t.Errorf("RSA CorroboratedBy = %v, want empty", rsaFinding.CorroboratedBy)
	}
	if rsaFinding.Confidence != findings.ConfidenceMedium {
		t.Errorf("RSA Confidence = %q, want medium (unchanged)", rsaFinding.Confidence)
	}
	if rsaFinding.QuantumRisk != findings.QRVulnerable {
		t.Errorf("RSA QuantumRisk = %q, want quantum-vulnerable", rsaFinding.QuantumRisk)
	}
}

// TestFullPipeline_WithMockEngines runs the Orchestrator.Scan() method with
// two mock engines to exercise the complete wiring: available engine selection
// → scan → normalize → dedupe → classify.
func TestFullPipeline_WithMockEngines(t *testing.T) {
	ctx := context.Background()

	engA := &mockEngine{
		name:      "mock-a",
		tier:      engines.Tier1Pattern,
		available: true,
		results: []findings.UnifiedFinding{
			{
				Location:     loc("/src/main.go", 5),
				Algorithm:    &findings.Algorithm{Name: "ECDSA", Primitive: "signature"},
				Confidence:   findings.ConfidenceLow,
				SourceEngine: "mock-a",
			},
			{
				Location:     loc("/src/util.go", 15),
				Algorithm:    &findings.Algorithm{Name: "AES-256-GCM", Primitive: "ae", KeySize: 256},
				Confidence:   findings.ConfidenceMedium,
				SourceEngine: "mock-a",
			},
		},
	}
	engB := &mockEngine{
		name:      "mock-b",
		tier:      engines.Tier1Pattern,
		available: true,
		results: []findings.UnifiedFinding{
			// Same ECDSA finding — should be merged with mock-a's entry.
			{
				Location:     loc("/src/main.go", 5),
				Algorithm:    &findings.Algorithm{Name: "ECDSA", Primitive: "signature"},
				Confidence:   findings.ConfidenceLow,
				SourceEngine: "mock-b",
			},
		},
	}

	orch := New(engA, engB)
	opts := engines.ScanOptions{Mode: engines.ModeFull}
	results, err := orch.Scan(ctx, opts)
	if err != nil {
		t.Fatalf("Scan() returned error: %v", err)
	}

	// Expect 2 findings: ECDSA (merged) + AES-256-GCM (unique).
	if len(results) != 2 {
		t.Fatalf("Scan() returned %d findings, want 2", len(results))
	}

	var ecdsaFound, aesFound bool
	for _, f := range results {
		switch f.Algorithm.Name {
		case "ECDSA":
			ecdsaFound = true
			if len(f.CorroboratedBy) != 1 || f.CorroboratedBy[0] != "mock-b" {
				t.Errorf("ECDSA CorroboratedBy = %v, want [mock-b]", f.CorroboratedBy)
			}
			if f.QuantumRisk != findings.QRVulnerable {
				t.Errorf("ECDSA QuantumRisk = %q, want quantum-vulnerable", f.QuantumRisk)
			}
		case "AES-256-GCM":
			aesFound = true
			if len(f.CorroboratedBy) != 0 {
				t.Errorf("AES-256-GCM should have no corroborators, got %v", f.CorroboratedBy)
			}
			if f.QuantumRisk != findings.QRResistant {
				t.Errorf("AES-256-GCM QuantumRisk = %q, want quantum-resistant", f.QuantumRisk)
			}
		}
	}
	if !ecdsaFound {
		t.Error("ECDSA finding missing from Scan() output")
	}
	if !aesFound {
		t.Error("AES-256-GCM finding missing from Scan() output")
	}
}

// TestFullPipeline_DiffModeFiltering verifies that in ModeDiff the pipeline
// filters findings to only those in the changed file list, then normalizes
// and classifies only the retained findings.
func TestFullPipeline_DiffModeFiltering(t *testing.T) {
	ctx := context.Background()

	eng := &mockEngine{
		name:      "mock-diff",
		tier:      engines.Tier1Pattern,
		available: true,
		results: []findings.UnifiedFinding{
			{
				Location:     loc("/repo/changed.go", 1),
				Algorithm:    &findings.Algorithm{Name: "RSA-2048", Primitive: "pke", KeySize: 2048},
				Confidence:   findings.ConfidenceMedium,
				SourceEngine: "mock-diff",
			},
			{
				Location:     loc("/repo/unchanged.go", 99),
				Algorithm:    &findings.Algorithm{Name: "AES-256-GCM", Primitive: "ae", KeySize: 256},
				Confidence:   findings.ConfidenceMedium,
				SourceEngine: "mock-diff",
			},
		},
	}

	orch := New(eng)
	opts := engines.ScanOptions{
		Mode:         engines.ModeDiff,
		TargetPath:   "/repo",
		ChangedFiles: []string{"changed.go"},
	}
	results, err := orch.Scan(ctx, opts)
	if err != nil {
		t.Fatalf("Scan() in diff mode returned error: %v", err)
	}

	// Only the finding from changed.go should survive.
	if len(results) != 1 {
		t.Fatalf("diff mode: got %d findings, want 1", len(results))
	}
	if results[0].Algorithm.Name != "RSA-2048" {
		t.Errorf("diff mode retained wrong finding: %q, want RSA-2048", results[0].Algorithm.Name)
	}
	if results[0].QuantumRisk != findings.QRVulnerable {
		t.Errorf("diff mode RSA QuantumRisk = %q, want quantum-vulnerable", results[0].QuantumRisk)
	}
}
