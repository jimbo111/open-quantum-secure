package cryptoscan

// AUDIT: adversarial fixtures authored for the 2026-04-20 Tier-1 scanner audit.
// See docs/audits/2026-04-20-scanner-layer-audit/01-t1-source.md for the report.

import (
	"testing"

	"github.com/jimbo111/open-quantum-secure/pkg/findings"
)

// -----------------------------------------------------------------------------
// F-CRYPTOSCAN-1 — mapPrimitive is case-sensitive but the upstream binary
// docs do not pin the case of primitive strings.  Any upper-case or
// mixed-case variant falls through unchanged, producing non-canonical
// primitives downstream.
// -----------------------------------------------------------------------------

func TestAudit_MapPrimitive_CaseSensitivity(t *testing.T) {
	// 2026-04-21: flipped after case-insensitive normalisation fix.
	cases := []struct {
		in   string
		want string
	}{
		{"PKE", "asymmetric"},
		{"Pke", "asymmetric"},
		{"AEAD", "symmetric"},
		{"Block-Cipher", "symmetric"},
		{"Stream-Cipher", "symmetric"},
		{"Key-Exchange", "key-exchange"},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.in, func(t *testing.T) {
			got := mapPrimitive(tc.in)
			if got != tc.want {
				t.Errorf("mapPrimitive(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

// -----------------------------------------------------------------------------
// F-CRYPTOSCAN-2 — mapConfidence collapses ALL unknown values to
// ConfidenceMedium.  This silently elevates unknown/empty tokens, which
// means a buggy upstream emitter sending garbage confidence strings produces
// Medium-confidence findings that policy rules trust.
// -----------------------------------------------------------------------------

func TestAudit_MapConfidence_UnknownSilentlyPromoted(t *testing.T) {
	// These should arguably map to Low (conservative) or propagate an
	// "Unknown" sentinel, but the current code returns Medium.
	cases := []string{"", "garbage", "CRITICAL", "NONE", "nil", "0"}
	for _, c := range cases {
		c := c
		t.Run(c, func(t *testing.T) {
			got := mapConfidence(c)
			if got != findings.ConfidenceMedium {
				t.Errorf("mapConfidence(%q) = %q, want %q (current behaviour)",
					c, got, findings.ConfidenceMedium)
			}
		})
	}
}

// -----------------------------------------------------------------------------
// F-CRYPTOSCAN-3 — normalize on a config/protocol finding with empty
// Algorithm string leaves uf.Algorithm == nil.  The Scan() filter keeps it
// alive because FindingType != "algorithm", but the unified finding has no
// algorithm name at all — dedup falls back to Location + SourceEngine, which
// may collapse distinct findings.
// -----------------------------------------------------------------------------

func TestAudit_Normalize_ConfigFindingWithoutAlgorithm(t *testing.T) {
	cases := []rawFinding{
		{FindingType: "config", Algorithm: "", File: "app.yaml", Line: 1},
		{FindingType: "protocol", Algorithm: "", File: "nginx.conf", Line: 1},
	}
	for _, raw := range cases {
		raw := raw
		t.Run(raw.FindingType+"/"+raw.File, func(t *testing.T) {
			uf := normalize(raw)
			if uf.Algorithm != nil {
				t.Errorf("Algorithm: expected nil for empty-algorithm config/protocol finding, got %+v", uf.Algorithm)
			}
			if uf.SourceEngine != "cryptoscan" {
				t.Errorf("SourceEngine: got %q", uf.SourceEngine)
			}
		})
	}
}

// -----------------------------------------------------------------------------
// F-CRYPTOSCAN-4 — normalize passes raw.KeySize through even when it is
// negative.  There is no clamp on the upstream int value.  Downstream CBOM /
// SARIF output may surface negative key sizes.
// -----------------------------------------------------------------------------

func TestAudit_Normalize_NegativeKeySizePropagates(t *testing.T) {
	raw := rawFinding{
		FindingType: "algorithm",
		Algorithm:   "RSA",
		Primitive:   "pke",
		KeySize:     -2048, // pathological upstream emitter
		File:        "src/a.go",
		Line:        1,
	}
	uf := normalize(raw)
	if uf.Algorithm == nil {
		t.Fatal("expected Algorithm to be non-nil")
	}
	if uf.Algorithm.KeySize != -2048 {
		t.Errorf("KeySize: got %d, want %d (reproducing current unguarded passthrough)",
			uf.Algorithm.KeySize, -2048)
	}
}

// -----------------------------------------------------------------------------
// F-CRYPTOSCAN-5 — normalize on an unknown FindingType neither matches the
// "algorithm" arm nor the "config"/"protocol" arm, so uf.Algorithm stays nil
// even when raw.Algorithm is non-empty.  The Scan() filter does not drop
// these.  Silent data loss.
// -----------------------------------------------------------------------------

func TestAudit_Normalize_UnknownFindingTypeDropsAlgorithm(t *testing.T) {
	raw := rawFinding{
		FindingType: "misc", // unknown
		Algorithm:   "RSA",
		Primitive:   "pke",
		KeySize:     2048,
		File:        "src/a.go",
		Line:        1,
	}
	uf := normalize(raw)
	if uf.Algorithm != nil {
		// If this ever starts matching, the filter in Scan() becomes
		// load-bearing.  Record current behaviour.
		t.Errorf("unexpected Algorithm populated for unknown FindingType: %+v", uf.Algorithm)
	}
	// The Scan() filter keeps this finding if raw.Algorithm != "".
	// So a finding with no Algorithm field is emitted, breaking the invariant
	// that algorithm-type findings always have .Algorithm populated.
}

// -----------------------------------------------------------------------------
// F-CRYPTOSCAN-6 — Scan skip predicate (covered in existing test but not with
// empty File/Line/Column).  Boundary test: a finding with no location but
// non-empty algorithm is kept.
// -----------------------------------------------------------------------------

func TestAudit_Normalize_NoLocationWithAlgorithm(t *testing.T) {
	raw := rawFinding{
		FindingType: "algorithm",
		Algorithm:   "MD5",
		Primitive:   "hash",
		// File, Line, Column all zero.
	}
	uf := normalize(raw)
	if uf.Algorithm == nil {
		t.Fatal("expected Algorithm to be non-nil")
	}
	if uf.Location.File != "" {
		t.Errorf("File: got %q, want empty", uf.Location.File)
	}
	if uf.Location.Line != 0 || uf.Location.Column != 0 {
		t.Errorf("Line/Column: got %d/%d, want 0/0", uf.Location.Line, uf.Location.Column)
	}
	// Dedup key for such a finding is file:0:0:algorithm — collisions
	// across all unpositioned MD5 findings would be merged.
}

// -----------------------------------------------------------------------------
// F-CRYPTOSCAN-7 — raw.Severity is captured in rawFinding but completely
// ignored by normalize().  There is no mapping to findings.Confidence or to
// any severity field in UnifiedFinding.  Documented for visibility.
// -----------------------------------------------------------------------------

func TestAudit_Normalize_RawSeverityIgnored(t *testing.T) {
	raw := rawFinding{
		FindingType: "algorithm",
		Algorithm:   "DES",
		Severity:    4, // CRITICAL upstream
		Confidence:  "LOW",
	}
	uf := normalize(raw)
	// Severity is discarded; only Confidence survives into UnifiedFinding.
	if uf.Confidence != findings.ConfidenceLow {
		t.Errorf("Confidence: got %q, want %q", uf.Confidence, findings.ConfidenceLow)
	}
	// No way to inspect severity propagation — confirm by inspection that
	// UnifiedFinding lacks a Severity field populated by this engine.
}

// -----------------------------------------------------------------------------
// F-CRYPTOSCAN-8 — raw.QuantumRisk ("VULNERABLE"/"PARTIAL"/"SAFE"/"UNKNOWN")
// is parsed off the wire but discarded by normalize.  The repo does its own
// quantum classification in pkg/quantum, so this is currently fine, but it
// means cryptoscan's own risk judgement is ignored.
// -----------------------------------------------------------------------------

func TestAudit_Normalize_RawQuantumRiskIgnored(t *testing.T) {
	raw := rawFinding{
		FindingType: "algorithm",
		Algorithm:   "RSA",
		KeySize:     2048,
		QuantumRisk: "VULNERABLE",
	}
	uf := normalize(raw)
	// There is no field in UnifiedFinding populated from raw.QuantumRisk.
	// Confirmed by the presence of pkg/quantum/classify.go as single source.
	_ = uf
}
