// Package orchestrator — sophisticated tests covering panic recovery, dedup
// property tests, cross-engine corroboration, and incremental cache versioning.
package orchestrator

import (
	"context"
	"fmt"
	"testing"

	"github.com/jimbo111/open-quantum-secure/pkg/engines"
	"github.com/jimbo111/open-quantum-secure/pkg/findings"
)

// ---------------------------------------------------------------------------
// Stub engines
// ---------------------------------------------------------------------------

type stubEngine struct {
	name     string
	tier     engines.Tier
	results  []findings.UnifiedFinding
	err      error
	panicMsg string // if non-empty, Scan panics with this message
}

func (s *stubEngine) Name() string                   { return s.name }
func (s *stubEngine) Tier() engines.Tier             { return s.tier }
func (s *stubEngine) Available() bool                { return true }
func (s *stubEngine) Version() string                { return "0.1.0" }
func (s *stubEngine) SupportedLanguages() []string   { return nil }
func (s *stubEngine) Scan(_ context.Context, _ engines.ScanOptions) ([]findings.UnifiedFinding, error) {
	if s.panicMsg != "" {
		panic(s.panicMsg)
	}
	return s.results, s.err
}

// ---------------------------------------------------------------------------
// 1. Panic recovery: Tier-5 panicking engine must not crash the scan
// ---------------------------------------------------------------------------

func TestScanPipeline_NetworkEnginePanic_DoesNotCrash(t *testing.T) {
	// A normal file engine that returns one finding.
	goodEngine := &stubEngine{
		name: "good-engine",
		tier: engines.Tier1Pattern,
		results: []findings.UnifiedFinding{
			{
				Location:     findings.Location{File: "/app/main.go", Line: 10},
				Algorithm:    &findings.Algorithm{Name: "RSA", Primitive: "asymmetric", KeySize: 2048},
				SourceEngine: "good-engine",
				Confidence:   findings.ConfidenceMedium,
			},
		},
	}

	// A Tier-5 engine that panics.
	panicEngine := &stubEngine{
		name:     "panic-tls-probe",
		tier:     engines.Tier5Network,
		panicMsg: "simulated crash: nil pointer in TLS peer",
	}

	o := New(goodEngine, panicEngine)
	ctx := context.Background()

	// Provide a TLS target so the orchestrator includes the network engine.
	opts := engines.ScanOptions{
		TargetPath: t.TempDir(),
		TLSTargets: []string{"example.com:443"},
	}

	ff, err := o.Scan(ctx, opts)

	// The scan must NOT return an error just because the network engine panicked.
	if err != nil {
		t.Fatalf("Scan() error = %v; want nil (panic engine must not propagate)", err)
	}
	// We must still get the good engine's result.
	if len(ff) == 0 {
		t.Error("Scan() returned 0 findings; expected at least the good-engine result")
	}
}

// ---------------------------------------------------------------------------
// 2. Panic recovery: file-engine panic — partial results still returned
// ---------------------------------------------------------------------------

func TestScanPipeline_FileEnginePanic_PartialResults(t *testing.T) {
	good := &stubEngine{
		name: "good-engine",
		tier: engines.Tier1Pattern,
		results: []findings.UnifiedFinding{
			{
				Location:     findings.Location{File: "/app/crypto.go", Line: 5},
				Algorithm:    &findings.Algorithm{Name: "AES", Primitive: "symmetric", KeySize: 128},
				SourceEngine: "good-engine",
				Confidence:   findings.ConfidenceHigh,
			},
		},
	}
	bad := &stubEngine{
		name:     "crash-engine",
		tier:     engines.Tier1Pattern,
		panicMsg: "intentional panic",
	}

	o := New(good, bad)
	ctx := context.Background()
	opts := engines.ScanOptions{TargetPath: t.TempDir()}

	ff, err := o.Scan(ctx, opts)
	// Should not hard-fail as long as at least one engine succeeded.
	if err != nil {
		t.Fatalf("Scan() error = %v; expected nil (partial results path)", err)
	}
	if len(ff) == 0 {
		t.Error("expected good-engine finding to survive the crash of crash-engine")
	}
}

// ---------------------------------------------------------------------------
// 3. Dedup property: distinct (file, line, algorithm) → distinct DedupeKeys
// ---------------------------------------------------------------------------

func TestDedupeKey_DistinctTriples_DistinctKeys(t *testing.T) {
	type triple struct {
		file string
		line int
		alg  string
	}

	triples := []triple{
		{"/a.go", 1, "RSA"},
		{"/a.go", 2, "RSA"},    // same file+alg, different line
		{"/b.go", 1, "RSA"},    // same alg+line, different file
		{"/a.go", 1, "AES"},    // same file+line, different alg
		{"/a.go", 1, "ECDSA"},  // same file+line, different alg #2
	}

	keys := make(map[string]triple, len(triples))
	for _, tr := range triples {
		f := findings.UnifiedFinding{
			Location:  findings.Location{File: tr.file, Line: tr.line},
			Algorithm: &findings.Algorithm{Name: tr.alg},
		}
		k := f.DedupeKey()
		if existing, dup := keys[k]; dup {
			t.Errorf("DedupeKey collision: %+v and %+v both produce %q", tr, existing, k)
		}
		keys[k] = tr
	}
}

// ---------------------------------------------------------------------------
// 4. Dedup: same finding from multiple engines → single entry with CorroboratedBy
// ---------------------------------------------------------------------------

func TestDedupe_CrossEngineCorroboration(t *testing.T) {
	// Three engines report the same RSA finding at the same location.
	const (
		file = "/srv/auth/rsa.go"
		line = 42
	)
	all := []findings.UnifiedFinding{
		{
			Location:     findings.Location{File: file, Line: line},
			Algorithm:    &findings.Algorithm{Name: "RSA", KeySize: 2048},
			SourceEngine: "cipherscope",
			Confidence:   findings.ConfidenceMedium,
		},
		{
			Location:     findings.Location{File: file, Line: line},
			Algorithm:    &findings.Algorithm{Name: "RSA", Primitive: "asymmetric"},
			SourceEngine: "cryptoscan",
			Confidence:   findings.ConfidenceLow,
		},
		{
			Location:     findings.Location{File: file, Line: line},
			Algorithm:    &findings.Algorithm{Name: "RSA"},
			SourceEngine: "cbomkit",
			Confidence:   findings.ConfidenceLow,
		},
	}

	result := dedupe(all)
	if len(result) != 1 {
		t.Fatalf("dedupe() = %d findings; want 1", len(result))
	}

	f := result[0]
	// Both non-winner engines must appear in CorroboratedBy.
	if len(f.CorroboratedBy) != 2 {
		t.Errorf("CorroboratedBy = %v; want 2 entries", f.CorroboratedBy)
	}
	// Rich metadata: KeySize from first finding, Primitive from second.
	if f.Algorithm.KeySize != 2048 {
		t.Errorf("merged KeySize = %d; want 2048", f.Algorithm.KeySize)
	}
	if f.Algorithm.Primitive != "asymmetric" {
		t.Errorf("merged Primitive = %q; want %q", f.Algorithm.Primitive, "asymmetric")
	}
}

// ---------------------------------------------------------------------------
// 5. Dedup: dependency findings across different engines merge by library name
// ---------------------------------------------------------------------------

func TestDedupe_DependencyFindingsMerge(t *testing.T) {
	all := []findings.UnifiedFinding{
		{
			Location:     findings.Location{File: "go.sum", Line: 0},
			Dependency:   &findings.Dependency{Library: "crypto/rsa", Version: "1.0.0"},
			SourceEngine: "cryptodeps",
			Confidence:   findings.ConfidenceMedium,
		},
		{
			Location:     findings.Location{File: "go.sum", Line: 0},
			Dependency:   &findings.Dependency{Library: "crypto/rsa", Version: "1.0.0"},
			SourceEngine: "cbomkit",
			Confidence:   findings.ConfidenceLow,
		},
	}

	result := dedupe(all)
	if len(result) != 1 {
		t.Fatalf("dedupe() = %d; want 1 for same dependency", len(result))
	}
	if len(result[0].CorroboratedBy) != 1 {
		t.Errorf("CorroboratedBy = %v; want [cbomkit]", result[0].CorroboratedBy)
	}
}

// ---------------------------------------------------------------------------
// 6. Dedup: different versions of same library do NOT merge
// ---------------------------------------------------------------------------

func TestDedupe_DifferentVersionsStayDistinct(t *testing.T) {
	all := []findings.UnifiedFinding{
		{
			Location:     findings.Location{File: "go.sum"},
			Dependency:   &findings.Dependency{Library: "openssl", Version: "1.0.0"},
			SourceEngine: "cryptodeps",
		},
		{
			Location:     findings.Location{File: "go.sum"},
			Dependency:   &findings.Dependency{Library: "openssl", Version: "1.1.1"},
			SourceEngine: "cryptodeps",
		},
	}

	result := dedupe(all)
	if len(result) != 2 {
		t.Errorf("dedupe() = %d; want 2 (different versions must not merge)", len(result))
	}
}

// ---------------------------------------------------------------------------
// 7. Dedup: CorroboratedBy idempotency — adding same engine twice is a no-op
// ---------------------------------------------------------------------------

func TestDedupe_NoDuplicateCorroborations(t *testing.T) {
	all := []findings.UnifiedFinding{
		{
			Location:     findings.Location{File: "/a.go", Line: 10},
			Algorithm:    &findings.Algorithm{Name: "ECDSA"},
			SourceEngine: "cipherscope",
		},
		{
			Location:     findings.Location{File: "/a.go", Line: 10},
			Algorithm:    &findings.Algorithm{Name: "ECDSA"},
			SourceEngine: "cipherscope", // same source engine as first
		},
	}

	result := dedupe(all)
	if len(result) != 1 {
		t.Fatalf("dedupe() = %d; want 1", len(result))
	}
	// Same source engine — CorroboratedBy must NOT contain the engine name.
	for _, e := range result[0].CorroboratedBy {
		if e == "cipherscope" {
			t.Errorf("CorroboratedBy incorrectly contains the source engine itself: %v", result[0].CorroboratedBy)
		}
	}
}

// ---------------------------------------------------------------------------
// 8. Reachability merge: ReachableYes wins over ReachableUnknown/No
// ---------------------------------------------------------------------------

func TestMergeReachability_YesWins(t *testing.T) {
	all := []findings.UnifiedFinding{
		{
			Location:     findings.Location{File: "/a.go", Line: 1},
			Algorithm:    &findings.Algorithm{Name: "RSA"},
			SourceEngine: "cipherscope",
			Reachable:    findings.ReachableNo,
		},
		{
			Location:     findings.Location{File: "/a.go", Line: 1},
			Algorithm:    &findings.Algorithm{Name: "RSA"},
			SourceEngine: "semgrep",
			Reachable:    findings.ReachableYes,
		},
	}

	result := dedupe(all)
	if len(result) != 1 {
		t.Fatalf("dedupe() = %d; want 1", len(result))
	}
	if result[0].Reachable != findings.ReachableYes {
		t.Errorf("Reachable = %q; want %q", result[0].Reachable, findings.ReachableYes)
	}
}

// ---------------------------------------------------------------------------
// 9. scanNetworkEngineWithRecover: panic converted to error, nil results
// ---------------------------------------------------------------------------

func TestScanNetworkEngineWithRecover_Panic(t *testing.T) {
	panicEngine := &stubEngine{
		name:     "tls-probe",
		tier:     engines.Tier5Network,
		panicMsg: "nil deref in probe",
	}

	ctx := context.Background()
	res, err := scanNetworkEngineWithRecover(ctx, panicEngine, engines.ScanOptions{})

	if err == nil {
		t.Error("expected non-nil error from panicking engine; got nil")
	}
	if res != nil {
		t.Errorf("expected nil results from panicking engine; got %v", res)
	}
	if err != nil && len(err.Error()) == 0 {
		t.Error("error from panic should have a non-empty message")
	}
}

// ---------------------------------------------------------------------------
// 10. scanNetworkEngineWithRecover: non-panicking engine returns results
// ---------------------------------------------------------------------------

func TestScanNetworkEngineWithRecover_Normal(t *testing.T) {
	want := []findings.UnifiedFinding{
		{
			Location:     findings.Location{File: "(tls-probe)/example.com:443#kex"},
			Algorithm:    &findings.Algorithm{Name: "ECDHE"},
			SourceEngine: "tls-probe",
		},
	}
	eng := &stubEngine{
		name:    "tls-probe",
		tier:    engines.Tier5Network,
		results: want,
	}

	ctx := context.Background()
	res, err := scanNetworkEngineWithRecover(ctx, eng, engines.ScanOptions{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(res) != len(want) {
		t.Errorf("len(res) = %d; want %d", len(res), len(want))
	}
}

// ---------------------------------------------------------------------------
// 11. filterByExcludePatterns: vendor/* exclusion
// ---------------------------------------------------------------------------

func TestFilterByExcludePatterns_VendorExcluded(t *testing.T) {
	ff := []findings.UnifiedFinding{
		{Location: findings.Location{File: "/project/main.go"}},
		{Location: findings.Location{File: "/project/vendor/lib/rsa.go"}},
		{Location: findings.Location{File: "/project/vendor/crypto/aes.go"}},
	}

	filtered := filterByExcludePatterns(ff, "/project", []string{"vendor/*"})
	for _, f := range filtered {
		if f.Location.File != "/project/main.go" {
			t.Errorf("unexpectedly kept vendor file: %s", f.Location.File)
		}
	}
	if len(filtered) != 1 {
		t.Errorf("len(filtered) = %d; want 1", len(filtered))
	}
}

// ---------------------------------------------------------------------------
// 12. filterByChangedFiles: network engine synthetic paths are preserved
// ---------------------------------------------------------------------------

func TestFilterByChangedFiles_NetworkPathPreserved(t *testing.T) {
	ff := []findings.UnifiedFinding{
		{Location: findings.Location{File: "(tls-probe)/example.com:443#kex"}},
		{Location: findings.Location{File: "/project/auth.go"}},
	}
	// Only "config.go" is in the changed set — but the TLS finding should always survive.
	filtered := filterByChangedFiles(ff, "/project", []string{"config.go"})

	hasNetwork := false
	for _, f := range filtered {
		if f.Location.File == "(tls-probe)/example.com:443#kex" {
			hasNetwork = true
		}
	}
	if !hasNetwork {
		t.Error("network engine synthetic path was incorrectly filtered out")
	}
}

// ---------------------------------------------------------------------------
// 13. All engines failed + zero findings → hard error
// ---------------------------------------------------------------------------

func TestScanPipeline_AllEnginesFail_ReturnsError(t *testing.T) {
	bad := &stubEngine{
		name: "bad-engine",
		tier: engines.Tier1Pattern,
		err:  fmt.Errorf("subprocess failed"),
	}

	o := New(bad)
	ctx := context.Background()
	opts := engines.ScanOptions{TargetPath: t.TempDir()}

	_, err := o.Scan(ctx, opts)
	if err == nil {
		t.Error("expected error when all engines fail and produce no findings; got nil")
	}
}

// ---------------------------------------------------------------------------
// 14. Confidence boost chain: low → medium-low → medium → medium-high → high
// ---------------------------------------------------------------------------

func TestBoostConfidence_Chain(t *testing.T) {
	chain := []findings.Confidence{
		findings.ConfidenceLow,
		findings.ConfidenceMediumLow,
		findings.ConfidenceMedium,
		findings.ConfidenceMediumHigh,
		findings.ConfidenceHigh,
	}

	for i := 0; i < len(chain)-1; i++ {
		got := boostConfidence(chain[i])
		if got != chain[i+1] {
			t.Errorf("boostConfidence(%q) = %q; want %q", chain[i], got, chain[i+1])
		}
	}

	// High stays high.
	if boostConfidence(findings.ConfidenceHigh) != findings.ConfidenceHigh {
		t.Error("boostConfidence(high) must remain high")
	}
}
