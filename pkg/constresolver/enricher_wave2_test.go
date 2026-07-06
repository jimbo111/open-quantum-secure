package constresolver

import (
	"path/filepath"
	"testing"

	"github.com/jimbo111/open-quantum-secure/pkg/findings"
)

// Wave-2 review V4/V5: the single-candidate branch assigned ANY lone integer
// constant (buffer size, iteration count, retry limit) as Algorithm.KeySize.
// A wrong KeySize actively misclassifies quantum risk in both directions.
func TestEnrichByFile_SingleCandidateRequiresKeyEvidence(t *testing.T) {
	mk := func(constName string, v int) FileConstants {
		return FileConstants{filepath.Clean("a/b.go"): {constName: v}}
	}
	find := func(alg string) []findings.UnifiedFinding {
		return []findings.UnifiedFinding{{
			Location:  findings.Location{File: "a/b.go", Line: 10},
			Algorithm: &findings.Algorithm{Name: alg},
		}}
	}

	// Non-key constants must never be assigned — regardless of algorithm.
	for _, tc := range []struct {
		constName string
		v         int
		alg       string
	}{
		{"pkg.defaultBufSize", 4096, "AES"},   // V4: bufsize → AES "resistant"
		{"pkg.defaultBufSize", 4096, "RSA"},   // same const, plausible RSA value — name must gate it
		{"pkg.iterationCount", 65536, "AES"},  // V5
		{"pkg.maxRetries", 30, "AES"},         // implausible + non-key name
		{"pkg.PARSABLE_LIMIT", 4096, "RSA"},   // reviewer counter-example shape
	} {
		ff := find(tc.alg)
		EnrichFindingsByFile(ff, mk(tc.constName, tc.v))
		if got := ff[0].Algorithm.KeySize; got != 0 {
			t.Errorf("%s=%d + %s finding: KeySize=%d, want 0 (no key evidence)", tc.constName, tc.v, tc.alg, got)
		}
	}

	// Legitimate key constants still enrich (ground-truth shape + variants).
	for _, tc := range []struct {
		constName string
		v         int
		alg       string
	}{
		{"main.KeySize", 256, "AES"},      // go-crypto ground truth
		{"cfg.RSA_KEY_BITS", 2048, "RSA"}, // token + KEY/BITS
		{"x.keyLength", 256, "AES"},
	} {
		ff := find(tc.alg)
		EnrichFindingsByFile(ff, mk(tc.constName, tc.v))
		if got := ff[0].Algorithm.KeySize; got != tc.v {
			t.Errorf("%s=%d + %s finding: KeySize=%d, want %d", tc.constName, tc.v, tc.alg, got, tc.v)
		}
	}

	// Key-ish name but implausible value for the family: rejected.
	ff := find("AES")
	EnrichFindingsByFile(ff, mk("main.KeySize", 4096)) // 4096 is not an AES key size
	if got := ff[0].Algorithm.KeySize; got != 0 {
		t.Errorf("KeySize=4096 + AES: KeySize=%d, want 0 (implausible for family)", got)
	}
}
