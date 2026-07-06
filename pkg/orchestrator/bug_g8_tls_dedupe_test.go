package orchestrator

import (
	"testing"

	"github.com/jimbo111/open-quantum-secure/pkg/findings"
)

// TestBugG8_FoldGenericTLSIntoVersioned is the RED test for a G8 regression:
// the B6 fix (pkg/engines/configscanner) made config-scanner emit versioned
// TLS Algorithm names ("TLSv1.0".."TLSv1.3") instead of the generic "TLS".
// cryptoscan (and other pattern engines that don't parse a version out of
// source text) still emit the generic "TLS" name. DedupeKey() is
// file|line|alg|<Algorithm.Name>, so a generic "TLS" and a versioned
// "TLSv1.2" finding at the SAME file+line now produce two DIFFERENT keys and
// no longer merge -- surfacing as two contradictory findings for one config
// line (one quantum-vulnerable, one unknown) instead of one corroborated
// finding.
//
// Fix: fold a generic "TLS"/"SSL" finding into a versioned one when exactly
// one distinct versioned name is present at the same file+line, BEFORE the
// normal DedupeKey-based grouping runs, so the existing corroboration/merge
// machinery in dedupe() handles the rest unchanged.
func TestBugG8_FoldGenericTLSIntoVersioned(t *testing.T) {
	all := []findings.UnifiedFinding{
		{
			Location:     findings.Location{File: "config-crypto/application.yml", Line: 7},
			Algorithm:    &findings.Algorithm{Name: "TLSv1.2", Primitive: "protocol"},
			Confidence:   findings.ConfidenceMedium,
			SourceEngine: "config-scanner",
		},
		{
			Location:     findings.Location{File: "config-crypto/application.yml", Line: 7},
			Algorithm:    &findings.Algorithm{Name: "TLS", Primitive: "protocol"},
			Confidence:   findings.ConfidenceLow,
			SourceEngine: "cryptoscan",
		},
	}

	result := dedupe(all)
	if len(result) != 1 {
		t.Fatalf("dedupe() returned %d findings, want 1 (generic TLS should fold into versioned TLSv1.2): %+v", len(result), result)
	}

	f := result[0]
	if f.Algorithm == nil || f.Algorithm.Name != "TLSv1.2" {
		var got string
		if f.Algorithm != nil {
			got = f.Algorithm.Name
		}
		t.Errorf("Algorithm.Name = %q, want %q (versioned name must win)", got, "TLSv1.2")
	}
	if len(f.CorroboratedBy) != 1 || f.CorroboratedBy[0] != "cryptoscan" {
		t.Errorf("CorroboratedBy = %v, want [cryptoscan]", f.CorroboratedBy)
	}

	// Classification runs after dedupe in the real pipeline (scanPipeline:
	// dedupe -> suppress -> enrich -> classify) -- exercise that ordering
	// here so the merged finding's risk reflects the versioned name, not the
	// generic one.
	classifyFindings(result)
	if result[0].QuantumRisk != findings.QRVulnerable {
		t.Errorf("QuantumRisk = %q, want %q", result[0].QuantumRisk, findings.QRVulnerable)
	}
}

// TestBugG8_FoldGenericTLS_DoesNotCollapseDifferentVersions verifies the
// fold never merges two DIFFERENT versioned findings with each other, only a
// generic name into a versioned one. Two distinct versions at the same line
// is an ambiguous case (which one should the generic finding, if any,
// belong to?) so nothing should be folded and both versioned findings must
// remain separate, distinguishable findings.
func TestBugG8_FoldGenericTLS_DoesNotCollapseDifferentVersions(t *testing.T) {
	all := []findings.UnifiedFinding{
		{
			Location:     findings.Location{File: "a.yml", Line: 5},
			Algorithm:    &findings.Algorithm{Name: "TLSv1.0", Primitive: "protocol"},
			SourceEngine: "config-scanner",
		},
		{
			Location:     findings.Location{File: "a.yml", Line: 5},
			Algorithm:    &findings.Algorithm{Name: "TLSv1.2", Primitive: "protocol"},
			SourceEngine: "cryptoscan",
		},
	}

	result := dedupe(all)
	if len(result) != 2 {
		t.Fatalf("dedupe() returned %d findings, want 2 (different TLS versions must never collapse): %+v", len(result), result)
	}
}

// TestBugG8_FoldGenericTLS_DoesNotMergeAcrossLines verifies the fold is
// scoped to the exact same file+line -- a generic "TLS" finding on a
// different line (or file) from any versioned finding must be left alone.
func TestBugG8_FoldGenericTLS_DoesNotMergeAcrossLines(t *testing.T) {
	all := []findings.UnifiedFinding{
		{
			Location:     findings.Location{File: "a.yml", Line: 7},
			Algorithm:    &findings.Algorithm{Name: "TLSv1.2", Primitive: "protocol"},
			SourceEngine: "config-scanner",
		},
		{
			Location:     findings.Location{File: "a.yml", Line: 99},
			Algorithm:    &findings.Algorithm{Name: "TLS", Primitive: "protocol"},
			SourceEngine: "cryptoscan",
		},
	}

	result := dedupe(all)
	if len(result) != 2 {
		t.Fatalf("dedupe() returned %d findings, want 2 (different lines must never fold together): %+v", len(result), result)
	}

	other := []findings.UnifiedFinding{
		{
			Location:     findings.Location{File: "a.yml", Line: 7},
			Algorithm:    &findings.Algorithm{Name: "TLSv1.2", Primitive: "protocol"},
			SourceEngine: "config-scanner",
		},
		{
			Location:     findings.Location{File: "b.yml", Line: 7},
			Algorithm:    &findings.Algorithm{Name: "TLS", Primitive: "protocol"},
			SourceEngine: "cryptoscan",
		},
	}

	result2 := dedupe(other)
	if len(result2) != 2 {
		t.Fatalf("dedupe() returned %d findings, want 2 (different files must never fold together): %+v", len(result2), result2)
	}
}
