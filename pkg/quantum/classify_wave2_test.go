package quantum

import (
	"strings"
	"testing"
)

// Wave-2 review fixes: regression tests for confirmed findings from the
// whole-wave verification pass (see fix-g8 wave-2 notes).

// GOST family scoping: only the ECC signature standard (R 34.10) is
// Shor-breakable. Streebog hashes (R 34.11) and the block ciphers
// (28147-89 / R 34.12 Kuznyechik/Magma) must not inherit the signature
// classification via bare-prefix matching.
func TestGOSTFamilyScoping(t *testing.T) {
	cases := []struct {
		name      string
		primitive string
		wantRisk  Risk
		wantNoSig bool // must NOT carry an ML-DSA signature target
	}{
		{"GOST R 34.10-2012", "signature", RiskVulnerable, false},
		{"GOST3410", "signature", RiskVulnerable, false},
		{"GOST R 34.11-2012", "hash", RiskResistant, true},
		{"GOST3411", "hash", RiskResistant, true},
		{"Streebog-256", "hash", RiskResistant, true},
		{"GOST 28147-89", "symmetric", RiskUnknown, true}, // 256-bit key cipher; risk depends on key size handling
		{"GOST28147", "symmetric", RiskUnknown, true},
		{"Kuznyechik", "symmetric", RiskUnknown, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := ClassifyAlgorithm(tc.name, tc.primitive, 0)
			if tc.wantNoSig {
				if c.Risk == RiskVulnerable {
					t.Errorf("%s: classified quantum-vulnerable (signature overmatch); rec=%q", tc.name, c.Recommendation)
				}
				if strings.Contains(c.TargetAlgorithm, "ML-DSA") {
					t.Errorf("%s: got signature migration target %q for a non-signature algorithm", tc.name, c.TargetAlgorithm)
				}
			} else {
				if c.Risk != tc.wantRisk {
					t.Errorf("%s: risk=%s want %s", tc.name, c.Risk, tc.wantRisk)
				}
				if c.TargetAlgorithm != "ML-DSA-65" {
					t.Errorf("%s: target=%q want ML-DSA-65", tc.name, c.TargetAlgorithm)
				}
			}
		})
	}
}

// Bare "GOST" is ambiguous (could be sig/hash/cipher family) — it must not
// be classified as a Shor-breakable signature on name alone.
func TestBareGOSTNotVulnerable(t *testing.T) {
	c := ClassifyAlgorithm("GOST", "", 0)
	if c.Risk == RiskVulnerable {
		t.Errorf("bare GOST classified vulnerable; want unknown (ambiguous family)")
	}
}
