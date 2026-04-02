package orchestrator

import (
	"testing"

	"github.com/jimbo111/open-quantum-secure/pkg/constresolver"
	"github.com/jimbo111/open-quantum-secure/pkg/findings"
)

// TestPhase8_ConfigScannerConfidenceLevel verifies that config-scanner findings
// start at medium confidence and are boosted correctly through the 5-level ladder.
func TestPhase8_ConfigScannerConfidenceLevel(t *testing.T) {
	// Config-scanner findings start at ConfidenceMedium.
	// When corroborated by a source-level engine, they should be boosted to medium-high.
	configFinding := findings.UnifiedFinding{
		Location:     loc("/app/application.yml", 5),
		Algorithm:    alg("AES", "symmetric", 256),
		Confidence:   findings.ConfidenceMedium,
		SourceEngine: "config-scanner",
	}
	sourceFinding := findings.UnifiedFinding{
		Location:     loc("/app/application.yml", 5),
		Algorithm:    alg("AES", "symmetric", 256),
		Confidence:   findings.ConfidenceMedium,
		SourceEngine: "cipherscope",
	}

	result := dedupe([]findings.UnifiedFinding{configFinding, sourceFinding})
	if len(result) != 1 {
		t.Fatalf("expected 1 merged finding, got %d", len(result))
	}

	f := result[0]
	if f.Confidence != findings.ConfidenceMediumHigh {
		t.Errorf("config+source corroboration: confidence = %q, want %q", f.Confidence, findings.ConfidenceMediumHigh)
	}
	if len(f.CorroboratedBy) != 1 {
		t.Errorf("CorroboratedBy = %v, want 1 entry", f.CorroboratedBy)
	}
}

// TestPhase8_FiveLevelConfidenceLadder verifies the full 5-level confidence ladder:
// low → medium-low → medium → medium-high → high
func TestPhase8_FiveLevelConfidenceLadder(t *testing.T) {
	// Create 5 findings from 5 different engines at the same location.
	// Starting at low, after 4 boosts: low → medium-low → medium → medium-high → high
	all := []findings.UnifiedFinding{
		{Location: loc("/x.go", 1), Algorithm: alg("SHA-1", "hash", 0), Confidence: findings.ConfidenceLow, SourceEngine: "eng1"},
		{Location: loc("/x.go", 1), Algorithm: alg("SHA-1", "hash", 0), Confidence: findings.ConfidenceLow, SourceEngine: "eng2"},
		{Location: loc("/x.go", 1), Algorithm: alg("SHA-1", "hash", 0), Confidence: findings.ConfidenceLow, SourceEngine: "eng3"},
		{Location: loc("/x.go", 1), Algorithm: alg("SHA-1", "hash", 0), Confidence: findings.ConfidenceLow, SourceEngine: "eng4"},
		{Location: loc("/x.go", 1), Algorithm: alg("SHA-1", "hash", 0), Confidence: findings.ConfidenceLow, SourceEngine: "eng5"},
	}

	result := dedupe(all)
	if len(result) != 1 {
		t.Fatalf("expected 1 merged finding, got %d", len(result))
	}

	f := result[0]
	if f.Confidence != findings.ConfidenceHigh {
		t.Errorf("after 4 corroborations: confidence = %q, want %q", f.Confidence, findings.ConfidenceHigh)
	}
	if len(f.CorroboratedBy) != 4 {
		t.Errorf("CorroboratedBy length = %d, want 4", len(f.CorroboratedBy))
	}
}

// TestPhase8_ConstEnrichmentPipeline verifies that const enrichment fills
// missing KeySize values correctly by actually calling EnrichFindings.
func TestPhase8_ConstEnrichmentPipeline(t *testing.T) {
	ff := []findings.UnifiedFinding{
		{
			Location:      loc("/app/CryptoService.java", 10),
			Algorithm:     &findings.Algorithm{Name: "AES"},
			Confidence:    findings.ConfidenceMedium,
			SourceEngine:  "cipherscope",
			RawIdentifier: "AES_KEY_SIZE",
		},
		{
			Location:      loc("/app/CryptoService.java", 20),
			Algorithm:     &findings.Algorithm{Name: "RSA"},
			Confidence:    findings.ConfidenceMedium,
			SourceEngine:  "cipherscope",
			RawIdentifier: "RSA_KEY_LENGTH",
		},
		{
			// Already has KeySize — should NOT be overwritten.
			Location:      loc("/app/CryptoService.java", 30),
			Algorithm:     &findings.Algorithm{Name: "AES", KeySize: 128},
			Confidence:    findings.ConfidenceMedium,
			SourceEngine:  "cipherscope",
			RawIdentifier: "AES_KEY_SIZE",
		},
	}

	cm := constresolver.ConstMap{
		"CryptoService.AES_KEY_SIZE":  256,
		"CryptoService.RSA_KEY_LENGTH": 2048,
	}

	constresolver.EnrichFindings(ff, cm)

	if ff[0].Algorithm.KeySize != 256 {
		t.Errorf("finding[0] AES KeySize = %d, want 256", ff[0].Algorithm.KeySize)
	}
	if ff[1].Algorithm.KeySize != 2048 {
		t.Errorf("finding[1] RSA KeySize = %d, want 2048", ff[1].Algorithm.KeySize)
	}
	if ff[2].Algorithm.KeySize != 128 {
		t.Errorf("finding[2] AES KeySize = %d, want 128 (should not be overwritten)", ff[2].Algorithm.KeySize)
	}
}

// TestPhase8_SubConfidenceLevelsInDedupeKey verifies that the new confidence
// levels don't interfere with DedupeKey generation.
func TestPhase8_SubConfidenceLevelsInDedupeKey(t *testing.T) {
	// Two findings with different sub-confidence levels but same location and algorithm
	// should still have the same DedupeKey.
	f1 := findings.UnifiedFinding{
		Location:   loc("/a.go", 10),
		Algorithm:  alg("RSA", "pke", 2048),
		Confidence: findings.ConfidenceMediumLow,
	}
	f2 := findings.UnifiedFinding{
		Location:   loc("/a.go", 10),
		Algorithm:  alg("RSA", "pke", 2048),
		Confidence: findings.ConfidenceMediumHigh,
	}

	if f1.DedupeKey() != f2.DedupeKey() {
		t.Errorf("DedupeKey differs for same location+alg with different confidence:\n  %q\n  %q", f1.DedupeKey(), f2.DedupeKey())
	}
}
