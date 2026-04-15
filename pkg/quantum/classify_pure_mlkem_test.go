package quantum

import "testing"

// TestClassifyAlgorithm_PureMLKEM_AndSM2Hybrid guards against pqcSafeFamilies
// drift relative to tls_groups.go. All four names added in the X1 fix must
// resolve to RiskSafe so that pure ML-KEM codepoints and the SM2 hybrid are
// never mis-classified as quantum-vulnerable.
func TestClassifyAlgorithm_PureMLKEM_AndSM2Hybrid(t *testing.T) {
	cases := []struct {
		name string
	}{
		{"MLKEM512"},
		{"MLKEM768"},
		{"MLKEM1024"},
		{"curveSM2MLKEM768"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := ClassifyAlgorithm(tc.name, "", 0)
			if got.Risk != RiskSafe {
				t.Errorf("ClassifyAlgorithm(%q): Risk=%q, want %q", tc.name, got.Risk, RiskSafe)
			}
		})
	}
}
