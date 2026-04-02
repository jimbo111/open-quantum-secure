package constresolver

import (
	"testing"

	"github.com/jimbo111/open-quantum-secure/pkg/findings"
)

func newFinding(rawID string, alg *findings.Algorithm) findings.UnifiedFinding {
	return findings.UnifiedFinding{
		RawIdentifier: rawID,
		Algorithm:     alg,
		Confidence:    findings.ConfidenceMedium,
	}
}

func TestEnrichFindings_EmptyConstMap(t *testing.T) {
	ff := []findings.UnifiedFinding{
		newFinding("AES_KEY_SIZE", &findings.Algorithm{Name: "AES", KeySize: 0}),
	}
	EnrichFindings(ff, ConstMap{})
	// KeySize should remain 0 — no-op.
	if ff[0].Algorithm.KeySize != 0 {
		t.Errorf("expected KeySize=0, got %d", ff[0].Algorithm.KeySize)
	}
}

func TestEnrichFindings_NilConstMap(t *testing.T) {
	ff := []findings.UnifiedFinding{
		newFinding("AES_KEY_SIZE", &findings.Algorithm{Name: "AES", KeySize: 0}),
	}
	EnrichFindings(ff, nil)
	if ff[0].Algorithm.KeySize != 0 {
		t.Errorf("expected KeySize=0, got %d", ff[0].Algorithm.KeySize)
	}
}

func TestEnrichFindings_MatchByFieldName(t *testing.T) {
	cm := ConstMap{
		"CryptoConfig.AES_KEY_SIZE": 256,
	}
	ff := []findings.UnifiedFinding{
		newFinding("AES_KEY_SIZE", &findings.Algorithm{Name: "AES", KeySize: 0}),
	}
	EnrichFindings(ff, cm)
	if ff[0].Algorithm.KeySize != 256 {
		t.Errorf("expected KeySize=256, got %d", ff[0].Algorithm.KeySize)
	}
}

func TestEnrichFindings_NoMatch(t *testing.T) {
	cm := ConstMap{
		"Config.TIMEOUT": 30,
	}
	ff := []findings.UnifiedFinding{
		newFinding("AES_KEY_SIZE", &findings.Algorithm{Name: "AES", KeySize: 0}),
	}
	EnrichFindings(ff, cm)
	if ff[0].Algorithm.KeySize != 0 {
		t.Errorf("expected KeySize=0 (no match), got %d", ff[0].Algorithm.KeySize)
	}
}

func TestEnrichFindings_AlreadyHasKeySize(t *testing.T) {
	cm := ConstMap{
		"Config.KEY_SIZE": 512,
	}
	ff := []findings.UnifiedFinding{
		newFinding("KEY_SIZE", &findings.Algorithm{Name: "AES", KeySize: 256}),
	}
	EnrichFindings(ff, cm)
	// Should NOT overwrite existing KeySize.
	if ff[0].Algorithm.KeySize != 256 {
		t.Errorf("expected KeySize=256 (unchanged), got %d", ff[0].Algorithm.KeySize)
	}
}

func TestEnrichFindings_NilAlgorithm(t *testing.T) {
	cm := ConstMap{
		"Config.KEY_SIZE": 256,
	}
	ff := []findings.UnifiedFinding{
		newFinding("KEY_SIZE", nil),
	}
	// Should not panic.
	EnrichFindings(ff, cm)
	if ff[0].Algorithm != nil {
		t.Error("expected Algorithm to remain nil")
	}
}

func TestEnrichFindings_UnqualifiedKey(t *testing.T) {
	// Key without a dot separator.
	cm := ConstMap{
		"KEY_SIZE": 384,
	}
	ff := []findings.UnifiedFinding{
		newFinding("KEY_SIZE", &findings.Algorithm{Name: "EC", KeySize: 0}),
	}
	EnrichFindings(ff, cm)
	if ff[0].Algorithm.KeySize != 384 {
		t.Errorf("expected KeySize=384 (unqualified key), got %d", ff[0].Algorithm.KeySize)
	}
}

func TestEnrichFindings_MultipleFindings(t *testing.T) {
	cm := ConstMap{
		"Crypto.AES_KEY_BITS":  256,
		"Crypto.RSA_KEY_BITS":  2048,
		"Crypto.EC_KEY_BITS":   384,
	}
	ff := []findings.UnifiedFinding{
		newFinding("AES_KEY_BITS", &findings.Algorithm{Name: "AES", KeySize: 0}),
		newFinding("RSA_KEY_BITS", &findings.Algorithm{Name: "RSA", KeySize: 0}),
		newFinding("EC_KEY_BITS", &findings.Algorithm{Name: "EC", KeySize: 0}),
		newFinding("UNKNOWN_CONST", &findings.Algorithm{Name: "DES", KeySize: 0}),
	}
	EnrichFindings(ff, cm)

	if ff[0].Algorithm.KeySize != 256 {
		t.Errorf("AES: expected 256, got %d", ff[0].Algorithm.KeySize)
	}
	if ff[1].Algorithm.KeySize != 2048 {
		t.Errorf("RSA: expected 2048, got %d", ff[1].Algorithm.KeySize)
	}
	if ff[2].Algorithm.KeySize != 384 {
		t.Errorf("EC: expected 384, got %d", ff[2].Algorithm.KeySize)
	}
	if ff[3].Algorithm.KeySize != 0 {
		t.Errorf("DES: expected 0 (no match), got %d", ff[3].Algorithm.KeySize)
	}
}

func TestEnrichFindings_EmptyRawIdentifier(t *testing.T) {
	cm := ConstMap{
		"Config.KEY_SIZE": 256,
	}
	ff := []findings.UnifiedFinding{
		newFinding("", &findings.Algorithm{Name: "AES", KeySize: 0}),
	}
	EnrichFindings(ff, cm)
	// Empty RawIdentifier should not match anything.
	if ff[0].Algorithm.KeySize != 0 {
		t.Errorf("expected KeySize=0 for empty RawIdentifier, got %d", ff[0].Algorithm.KeySize)
	}
}
