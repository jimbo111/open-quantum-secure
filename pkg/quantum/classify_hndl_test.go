package quantum

// classify_hndl_test.go — regression tests proving:
//   1. Classical KEMs are HNDL-immediate regardless of PFS (TLS 1.3 / ephemeral).
//   2. PQ KEMs (ML-KEM, hybrid X25519MLKEM768) carry no HNDL risk (empty HNDLRisk = LOW).
//
// Academic basis: Mosca, IEEE S&P 2018; Blanco-Romero et al., arXiv:2603.01091 (2026).

import "testing"

// TestClassifyHNDL_ClassicalKEMWithPFSIsStillImmediate is the key regression test
// for S0.1. PFS (ephemeral ECDH) does NOT protect against HNDL because the entire
// TLS handshake — including the ephemeral public key — is captured by the adversary.
// A quantum computer can run Shor's algorithm on that key to recover the session secret.
//
// This test proves the old "PFS lowers HNDL risk" assumption is absent from the
// classifier. It must pass forever; any future change that makes ECDHE/X25519 return
// anything other than HNDLImmediate is a regression.
func TestClassifyHNDL_ClassicalKEMWithPFSIsStillImmediate(t *testing.T) {
	// These algorithms are all classical KEMs used in PFS-capable cipher suites
	// (TLS 1.3 always PFS; ECDHE suites in TLS 1.2 are PFS). The presence of PFS
	// is irrelevant — the ephemeral public key is Shor-breakable.
	pfsKEMs := []struct {
		name      string
		algorithm string
		primitive string
	}{
		{"ECDHE (TLS 1.2 PFS)", "ECDHE", "key-exchange"},
		{"ECDHE key-agree", "ECDHE", "key-agree"},
		{"X25519 (TLS 1.3 default)", "X25519", "key-exchange"},
		{"X25519 key-agree", "X25519", "key-agree"},
		{"X448", "X448", "key-exchange"},
		{"ECDH", "ECDH", "key-exchange"},
		{"DH", "DH", "key-exchange"},
		{"FFDH", "FFDH", "key-agree"},
	}

	for _, tt := range pfsKEMs {
		t.Run(tt.name, func(t *testing.T) {
			c := ClassifyAlgorithm(tt.algorithm, tt.primitive, 0)
			if c.HNDLRisk != HNDLImmediate {
				t.Errorf(
					"classical KEM %q (%s) with PFS must still be HNDLImmediate — "+
						"PFS does NOT protect against quantum decryption of captured handshakes. "+
						"Got HNDLRisk=%q",
					tt.algorithm, tt.primitive, c.HNDLRisk,
				)
			}
			if c.Risk != RiskVulnerable {
				t.Errorf("classical KEM %q should be RiskVulnerable, got %s", tt.algorithm, c.Risk)
			}
		})
	}
}

// TestClassifyHNDL_PQKEMHasNoHNDLRisk verifies that PQ-resistant KEMs have an
// empty HNDLRisk field (= no harvest risk = LOW in the Mosca framework).
//
// ML-KEM-768 (pure PQ KEM) and X25519MLKEM768 (hybrid) both provide PQ security:
// even if a CRQC breaks the X25519 component of the hybrid, the independent
// ML-KEM shared secret remains confidential.
func TestClassifyHNDL_PQKEMHasNoHNDLRisk(t *testing.T) {
	pqKEMs := []struct {
		algorithm string
		primitive string
	}{
		{"ML-KEM-768", "kem"},
		{"ML-KEM-512", "kem"},
		{"ML-KEM-1024", "kem"},
		{"X25519MLKEM768", "kem"},    // hybrid — 0x11EC, production dominant
		{"SecP256r1MLKEM768", "kem"}, // hybrid — 0x11EB
	}

	for _, tt := range pqKEMs {
		t.Run(tt.algorithm, func(t *testing.T) {
			c := ClassifyAlgorithm(tt.algorithm, tt.primitive, 0)
			if c.HNDLRisk != "" {
				t.Errorf(
					"PQ KEM %q should have empty HNDLRisk (no harvest risk, maps to HNDL LOW), got %q",
					tt.algorithm, c.HNDLRisk,
				)
			}
			if c.Risk != RiskSafe {
				t.Errorf("PQ KEM %q should be RiskSafe, got %s", tt.algorithm, c.Risk)
			}
		})
	}
}

// TestClassifyHNDL_PQKEMEmptyRiskMapsToMoscaLow verifies that an empty HNDLRisk
// from a PQ KEM corresponds to HNDLLevelLow in the Mosca framework via
// ComputeHNDLSurplus with shelfLife=0 (no data to harvest = no risk).
func TestClassifyHNDL_PQKEMEmptyRiskMapsToMoscaLow(t *testing.T) {
	// When the KEM is PQ-resistant, there is no harvest risk regardless of data
	// sensitivity. We model this as shelfLife=0 (data has no harvest value to a
	// quantum adversary) which always maps to MEDIUM or LOW depending on lag/crqc.
	// With explicit crqc > lag (e.g. crqc=10, lag=5): surplus = (0+5)-10 = -5 → LOW.
	surplus := ComputeHNDLSurplus(0, 5, 10)
	level := HNDLLevelFromSurplus(surplus)
	if level != HNDLLevelLow {
		t.Errorf("PQ KEM (shelfLife=0, lag=5, crqc=10): surplus=%d, level=%s, want HNDLLevelLow",
			surplus, level)
	}
}

// TestClassifyHNDL_MoscaHighForLongLivedDataWithClassicalKEM verifies that long-lived
// data protected by a classical KEM scores HIGH on the Mosca inequality under default
// parameters. This is the canonical "migrate now" case for financial/medical orgs.
func TestClassifyHNDL_MoscaHighForLongLivedDataWithClassicalKEM(t *testing.T) {
	// ECDHE = HNDLImmediate (classical KEM). With a 10-year data shelf life and
	// default parameters (lag=5, crqc=5 in 2026), surplus = 10 → HIGH.
	c := ClassifyAlgorithm("ECDHE", "key-exchange", 0)
	if c.HNDLRisk != HNDLImmediate {
		t.Fatalf("ECDHE should be HNDLImmediate, got %q", c.HNDLRisk)
	}
	// Mosca scoring: long-lived data protected by this KEM is HIGH urgency.
	surplus := ComputeHNDLSurplus(10, 5, 5)
	level := HNDLLevelFromSurplus(surplus)
	if level != HNDLLevelHigh {
		t.Errorf("10y shelf, lag=5, crqc=5: surplus=%d, level=%s, want HNDLLevelHigh", surplus, level)
	}
}

// TestClassifyHNDL_HyphenatedHybridKEM verifies that hyphenated forms of hybrid KEMs
// (as produced by config-file parsers and some AST tokenisers) are classified as
// PQ-safe, not as their classical component. Without normalisation, "X25519-MLKEM-768"
// would be mis-identified as "X25519" (quantum-vulnerable) because extractBaseName
// would match the "X25519" prefix in quantumVulnerableFamilies.
func TestClassifyHNDL_HyphenatedHybridKEM(t *testing.T) {
	// Note: underscore-separated forms (X25519_MLKEM_768, ML_KEM_768) are intentionally
	// NOT tested here. Underscores indicate variable/constant names in source code, not
	// algorithm names, so those forms remain quantum-vulnerable (see TestClassifyPQCCasing).
	cases := []struct {
		name string
		alg  string
		prim string
	}{
		// Canonical (no hyphens) — already tested in TestClassifyHNDL_PQKEMHasNoHNDLRisk;
		// repeated here alongside hyphenated variants to make the comparison explicit.
		{"X25519MLKEM768 canonical", "X25519MLKEM768", "kem"},
		{"SecP256r1MLKEM768 canonical", "SecP256r1MLKEM768", "kem"},
		// Hyphenated forms — S0.F4 fix.
		{"X25519-MLKEM-768 hyphenated kem", "X25519-MLKEM-768", "kem"},
		{"X25519-MLKEM-768 hyphenated key-exchange", "X25519-MLKEM-768", "key-exchange"},
		{"SecP256r1-MLKEM-768 hyphenated", "SecP256r1-MLKEM-768", "kem"},
	}

	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			c := ClassifyAlgorithm(tt.alg, tt.prim, 0)
			if c.HNDLRisk != "" {
				t.Errorf("%q: expected empty HNDLRisk (PQ-safe), got %q", tt.alg, c.HNDLRisk)
			}
			if c.Risk != RiskSafe {
				t.Errorf("%q: expected RiskSafe, got %s (extractBaseName matched classical component)", tt.alg, c.Risk)
			}
		})
	}
}

// TestClassifyHNDL_EdgeCases covers boundary inputs for the HNDL classifier.
func TestClassifyHNDL_EdgeCases(t *testing.T) {
	t.Run("zero shelf life is not negative surplus panic", func(t *testing.T) {
		// 0 shelf life: surplus = (0 + 5) - 5 = 0 → MEDIUM
		surplus := ComputeHNDLSurplus(0, 5, 5)
		if surplus != 0 {
			t.Errorf("shelfLife=0: surplus=%d, want 0", surplus)
		}
		if HNDLLevelFromSurplus(surplus) != HNDLLevelMedium {
			t.Errorf("surplus=0 should be MEDIUM")
		}
	})

	t.Run("negative shelf life returns negative surplus", func(t *testing.T) {
		surplus := ComputeHNDLSurplus(-1, 5, 5)
		if surplus != -1 {
			t.Errorf("shelfLife=-1: surplus=%d, want -1", surplus)
		}
		if HNDLLevelFromSurplus(surplus) != HNDLLevelLow {
			t.Errorf("surplus=-1 should be LOW")
		}
	})

	t.Run("empty sector returns default shelf life", func(t *testing.T) {
		years := ShelfLifeForSector("")
		if years != DefaultSectorShelfLifeYears {
			t.Errorf("empty sector should return %d, got %d", DefaultSectorShelfLifeYears, years)
		}
	})

	t.Run("unknown sector returns default shelf life", func(t *testing.T) {
		years := ShelfLifeForSector("unknown-sector-xyz")
		if years != DefaultSectorShelfLifeYears {
			t.Errorf("unknown sector should return %d, got %d", DefaultSectorShelfLifeYears, years)
		}
	})
}
