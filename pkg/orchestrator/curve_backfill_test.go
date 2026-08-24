package orchestrator

import (
	"testing"

	"github.com/jimbo111/open-quantum-secure/pkg/findings"
)

// classifyFindings must backfill Algorithm.KeySize from Algorithm.Curve so
// size-tiered migration targets apply when an engine reports the curve but
// not the bit size.
func TestClassifyFindings_CurveBackfillsKeySize(t *testing.T) {
	ff := []findings.UnifiedFinding{
		{Algorithm: &findings.Algorithm{Name: "ECDSA", Primitive: "signature", Curve: "P-521"}},
		{Algorithm: &findings.Algorithm{Name: "ECDH", Primitive: "key-exchange", Curve: "secp384r1"}},
		{Algorithm: &findings.Algorithm{Name: "ECDSA", Primitive: "signature", Curve: "P-256"}},
		// Explicit key size must win over the curve.
		{Algorithm: &findings.Algorithm{Name: "ECDSA", Primitive: "signature", Curve: "P-256", KeySize: 521}},
	}
	classifyFindings(ff)

	want := []string{"ML-DSA-87", "ML-KEM-1024", "ML-DSA-65", "ML-DSA-87"}
	for i, w := range want {
		if ff[i].TargetAlgorithm != w {
			t.Errorf("finding %d (curve %s): target=%q, want %q",
				i, ff[i].Algorithm.Curve, ff[i].TargetAlgorithm, w)
		}
	}
}
