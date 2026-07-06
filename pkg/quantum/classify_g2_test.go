package quantum

// classify_g2_test.go — regression coverage for review findings A2/B1/B2
// (SCANNER_REVIEW_2026-07-05.md): pre-standard PQC names misclassified as
// quantum-vulnerable, HMAC-composite names escaping the deprecated-hash
// check, and Chinese/Russian national crypto (SM2/SM3/SM4/GOST) unclassified.

import (
	"strings"
	"testing"
)

// ─── A2/F1: bare pre-standard PQC names → RiskDeprecated ────────────────────

// TestClassifyPreStandardPQC_Bare covers the bare NIST Round 3 submission
// names that are superseded by an ALREADY-FINAL FIPS standard
// (Kyber/Dilithium/SPHINCS+/SPHINCS). Before this fix these fell through to
// RiskVulnerable/RiskUnknown with an "unrecognized algorithm" message, even
// though the migration-target lookup already knew the correct FIPS
// replacement (review finding A2/F1: self-contradictory output). Falcon is
// covered separately below — it is NOT superseded by a final standard yet,
// so it gets RiskSafe (HQC pattern), not RiskDeprecated.
func TestClassifyPreStandardPQC_Bare(t *testing.T) {
	tests := []struct {
		name      string
		algName   string
		primitive string
		wantTgt   string
	}{
		{"Kyber kem", "Kyber", "kem", "ML-KEM-768"},
		{"Dilithium signature", "Dilithium", "signature", "ML-DSA-65"},
		{"SPHINCS+ signature", "SPHINCS+", "signature", "SLH-DSA-SHA2-128f"},
		{"SPHINCS signature", "SPHINCS", "signature", "SLH-DSA-SHA2-128f"},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			got := ClassifyAlgorithm(tt.algName, tt.primitive, 0)
			if got.Risk != RiskDeprecated {
				t.Errorf("ClassifyAlgorithm(%q, %q, 0).Risk = %q, want %q", tt.algName, tt.primitive, got.Risk, RiskDeprecated)
			}
			if got.Severity != SeverityCritical {
				t.Errorf("ClassifyAlgorithm(%q, %q, 0).Severity = %q, want %q", tt.algName, tt.primitive, got.Severity, SeverityCritical)
			}
			if got.TargetAlgorithm != tt.wantTgt {
				t.Errorf("ClassifyAlgorithm(%q, %q, 0).TargetAlgorithm = %q, want %q", tt.algName, tt.primitive, got.TargetAlgorithm, tt.wantTgt)
			}
			if got.Recommendation == "" {
				t.Errorf("ClassifyAlgorithm(%q, %q, 0).Recommendation is empty, want migration guidance", tt.algName, tt.primitive)
			}
		})
	}
}

// TestClassifyPreStandardPQC_RecommendationHonest verifies the recommendation
// text does not claim the underlying cryptography is broken (unlike MD5/DES) —
// it should say "pre-standard"/"superseded"/"pending", not "broken".
func TestClassifyPreStandardPQC_RecommendationHonest(t *testing.T) {
	for _, alg := range []string{"Kyber", "Dilithium", "SPHINCS+", "SPHINCS"} {
		alg := alg
		t.Run(alg, func(t *testing.T) {
			got := ClassifyAlgorithm(alg, "signature", 0)
			rec := strings.ToLower(got.Recommendation)
			// "not classically broken" is the honest framing we want; only
			// flag claims that the algorithm itself IS broken/exhibits
			// collisions (MD5/SHA-1-style language), not the negated form.
			if strings.Contains(rec, "cryptographically broken") || strings.Contains(rec, "collision") {
				t.Errorf("%q recommendation reads like classically-broken crypto: %q", alg, got.Recommendation)
			}
			if !strings.Contains(rec, "not classically broken") {
				t.Errorf("%q recommendation = %q, want explicit \"not classically broken\" reassurance", alg, got.Recommendation)
			}
		})
	}
}

// TestClassifyFalcon_SafeStandardPending verifies Falcon follows the HQC
// pattern (RiskSafe/SeverityInfo with an informational recommendation)
// rather than RiskDeprecated: unlike Kyber/Dilithium/SPHINCS+, whose
// replacement FIPS standards (203/204/205) are already final, Falcon's
// FN-DSA/FIPS 206 is still pending — there is no finalized name yet for it
// to have been superseded by. Approved doctrine, see fix-g2-report.md
// Concerns section (originally raised, then confirmed, in this fix).
func TestClassifyFalcon_SafeStandardPending(t *testing.T) {
	tests := []struct{ name, algName, primitive string }{
		{"Falcon bare", "Falcon", "signature"},
		{"Falcon-512", "Falcon-512", "signature"},
		{"Falcon-1024", "Falcon-1024", "signature"},
		{"Falcon512 no hyphen", "Falcon512", "signature"},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			got := ClassifyAlgorithm(tt.algName, tt.primitive, 0)
			if got.Risk != RiskSafe {
				t.Errorf("ClassifyAlgorithm(%q, %q, 0).Risk = %q, want %q", tt.algName, tt.primitive, got.Risk, RiskSafe)
			}
			if got.Severity != SeverityInfo {
				t.Errorf("ClassifyAlgorithm(%q, %q, 0).Severity = %q, want %q", tt.algName, tt.primitive, got.Severity, SeverityInfo)
			}
			if !strings.Contains(got.Recommendation, "FIPS 206") || !strings.Contains(strings.ToLower(got.Recommendation), "pending") {
				t.Errorf("ClassifyAlgorithm(%q, %q, 0).Recommendation = %q, want mention of FIPS 206 + pending", tt.algName, tt.primitive, got.Recommendation)
			}
			if got.TargetAlgorithm != "" || got.TargetStandard != "" {
				t.Errorf("ClassifyAlgorithm(%q, %q, 0) TargetAlgorithm/TargetStandard = %q/%q, want empty (HQC pattern — no migration target)",
					tt.algName, tt.primitive, got.TargetAlgorithm, got.TargetStandard)
			}
		})
	}
}

// TestClassifyPreStandardPQC_Parameterized covers liboqs-style parameterized
// forms with NO separator before the digit suffix (Kyber512, Dilithium3) —
// these must resolve via extractBaseName's longest-prefix matching, not the
// exact-name table. Falcon's parameterized forms are covered separately in
// TestClassifyFalcon_SafeStandardPending (different expected Risk).
func TestClassifyPreStandardPQC_Parameterized(t *testing.T) {
	tests := []struct {
		name      string
		algName   string
		primitive string
	}{
		{"Kyber512", "Kyber512", "kem"},
		{"Kyber768", "Kyber768", "kem"},
		{"Kyber1024", "Kyber1024", "kem"},
		{"Dilithium2", "Dilithium2", "signature"},
		{"Dilithium3", "Dilithium3", "signature"},
		{"Dilithium5", "Dilithium5", "signature"},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			got := ClassifyAlgorithm(tt.algName, tt.primitive, 0)
			if got.Risk != RiskDeprecated {
				t.Errorf("ClassifyAlgorithm(%q, %q, 0).Risk = %q, want %q", tt.algName, tt.primitive, got.Risk, RiskDeprecated)
			}
			if got.Severity != SeverityCritical {
				t.Errorf("ClassifyAlgorithm(%q, %q, 0).Severity = %q, want %q", tt.algName, tt.primitive, got.Severity, SeverityCritical)
			}
		})
	}
}

// TestPreStandardPQCPrefixes_AllInDeprecatedAlgorithms guards against drift
// between the longest-prefix-match list used for parameterized forms and the
// exact-match deprecatedAlgorithms table used for bare names — every prefix
// entry must also be a full deprecatedAlgorithms key.
func TestPreStandardPQCPrefixes_AllInDeprecatedAlgorithms(t *testing.T) {
	for _, prefix := range preStandardPQCPrefixes {
		if !deprecatedAlgorithms[prefix] {
			t.Errorf("preStandardPQCPrefixes contains %q, which is not a key in deprecatedAlgorithms", prefix)
		}
	}
}

// ─── Regression: prefix-matching hazards from adding pre-standard PQC names ─

// TestRegression_HybridAndFinalNamesStillSafe verifies that adding
// Kyber/Dilithium/SPHINCS+/SPHINCS to deprecatedAlgorithms (and re-adding
// Falcon to pqcSafeFamilies with its dedicated HQC-style branch) cannot break
// the ALREADY-modeled safe names that sit right next to them:
// curveSM2MLKEM768 (SM2 hybrid — must stay safe even after SM2 is added to
// quantumVulnerableFamilies below), FN-DSA (Falcon's eventual FIPS 206 name),
// and SLH-DSA (SPHINCS+'s FIPS 205 name). See review finding B2 caution note.
func TestRegression_HybridAndFinalNamesStillSafe(t *testing.T) {
	tests := []struct {
		name      string
		algName   string
		primitive string
	}{
		{"curveSM2MLKEM768 kem", "curveSM2MLKEM768", "kem"},
		{"FN-DSA bare", "FN-DSA", "signature"},
		{"FN-DSA-512", "FN-DSA-512", "signature"},
		{"SLH-DSA bare", "SLH-DSA", "signature"},
		{"SLH-DSA-SHA2-128s", "SLH-DSA-SHA2-128s", "signature"},
		{"ML-KEM-768", "ML-KEM-768", "kem"},
		{"ML-DSA-65", "ML-DSA-65", "signature"},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			got := ClassifyAlgorithm(tt.algName, tt.primitive, 0)
			if got.Risk != RiskSafe {
				t.Errorf("ClassifyAlgorithm(%q, %q, 0).Risk = %q, want %q (regression: must stay safe)", tt.algName, tt.primitive, got.Risk, RiskSafe)
			}
		})
	}
}

// ─── B1/F3: HMAC-composite names → inner-hash risk ──────────────────────────

// TestClassifyHMACComposite_DeprecatedInner verifies HMAC wrapping a
// deprecated hash (MD5/SHA-1) correctly returns RiskDeprecated/Critical
// instead of falling into a generic "HMAC" bucket that never reaches the
// hash-family checks (review finding B1/F3).
func TestClassifyHMACComposite_DeprecatedInner(t *testing.T) {
	tests := []string{"HMAC-MD5", "HmacMD5", "HMAC-SHA1", "HmacSHA1"}
	for _, alg := range tests {
		alg := alg
		t.Run(alg, func(t *testing.T) {
			got := ClassifyAlgorithm(alg, "mac", 0)
			if got.Risk != RiskDeprecated {
				t.Errorf("ClassifyAlgorithm(%q, \"mac\", 0).Risk = %q, want %q", alg, got.Risk, RiskDeprecated)
			}
			if got.Severity != SeverityCritical {
				t.Errorf("ClassifyAlgorithm(%q, \"mac\", 0).Severity = %q, want %q", alg, got.Severity, SeverityCritical)
			}
		})
	}
}

// TestClassifyHMACComposite_ResistantInner verifies HMAC wrapping a strong
// hash (SHA-256) returns RiskResistant, matching bare SHA-256's treatment.
func TestClassifyHMACComposite_ResistantInner(t *testing.T) {
	tests := []string{"HMAC-SHA256", "HmacSHA256"}
	for _, alg := range tests {
		alg := alg
		t.Run(alg, func(t *testing.T) {
			got := ClassifyAlgorithm(alg, "mac", 0)
			if got.Risk != RiskResistant {
				t.Errorf("ClassifyAlgorithm(%q, \"mac\", 0).Risk = %q, want %q", alg, got.Risk, RiskResistant)
			}
			if got.Severity != SeverityInfo {
				t.Errorf("ClassifyAlgorithm(%q, \"mac\", 0).Severity = %q, want %q", alg, got.Severity, SeverityInfo)
			}
		})
	}
}

// TestClassifyHMACComposite_UnrecognizedPrimitive verifies the HMAC-inner-hash
// resolution also works when the primitive string is empty/unrecognized (the
// isLikelyHash heuristic fallback path), not just when tagged "mac".
func TestClassifyHMACComposite_UnrecognizedPrimitive(t *testing.T) {
	got := ClassifyAlgorithm("HmacMD5", "", 0)
	if got.Risk != RiskDeprecated {
		t.Errorf(`ClassifyAlgorithm("HmacMD5", "", 0).Risk = %q, want %q`, got.Risk, RiskDeprecated)
	}
}

// TestClassifyHMACBare_Unaffected verifies bare "HMAC" (no inner algorithm
// specified) is unaffected by the new prefix-stripping logic — still resolves
// via the pre-existing isLikelyHash heuristic path to RiskUnknown (key
// strength cannot be inferred without an inner hash name).
func TestClassifyHMACBare_Unaffected(t *testing.T) {
	got := ClassifyAlgorithm("HMAC", "mac", 0)
	if got.Risk != RiskUnknown {
		t.Errorf(`ClassifyAlgorithm("HMAC", "mac", 0).Risk = %q, want %q (unchanged prior behaviour)`, got.Risk, RiskUnknown)
	}
}

// ─── B2/F4/F5: Chinese national crypto (SM2/SM3/SM4) ────────────────────────

// TestClassifySM2_Vulnerable verifies SM2 (Chinese ECC signature/key-exchange
// standard, GM/T 0003-2012) is now classified as quantum-vulnerable instead
// of falling through to RiskUnknown (review finding B2/F4).
func TestClassifySM2_Vulnerable(t *testing.T) {
	tests := []struct {
		name      string
		primitive string
		wantSev   Severity
		wantTgt   string
	}{
		{"signature", "signature", SeverityHigh, "ML-DSA-65"},
		{"kem", "kem", SeverityCritical, "ML-KEM-768"},
		{"key-agree", "key-agree", SeverityCritical, "ML-KEM-768"},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			got := ClassifyAlgorithm("SM2", tt.primitive, 0)
			if got.Risk != RiskVulnerable {
				t.Errorf("ClassifyAlgorithm(\"SM2\", %q, 0).Risk = %q, want %q", tt.primitive, got.Risk, RiskVulnerable)
			}
			if got.Severity != tt.wantSev {
				t.Errorf("ClassifyAlgorithm(\"SM2\", %q, 0).Severity = %q, want %q", tt.primitive, got.Severity, tt.wantSev)
			}
			if got.TargetAlgorithm != tt.wantTgt {
				t.Errorf("ClassifyAlgorithm(\"SM2\", %q, 0).TargetAlgorithm = %q, want %q", tt.primitive, got.TargetAlgorithm, tt.wantTgt)
			}
		})
	}
}

// TestClassifySM2_RecommendationMentionsHybridAndMLDSA verifies the
// unrecognized-primitive fallback recommendation text explicitly names both
// migration paths (hybrid curveSM2MLKEM768 for key exchange, ML-DSA-65 for
// signatures) per the task brief's doctrine.
func TestClassifySM2_RecommendationMentionsHybridAndMLDSA(t *testing.T) {
	got := ClassifyAlgorithm("SM2", "unrecognized-primitive", 0)
	if !strings.Contains(got.Recommendation, "curveSM2MLKEM768") {
		t.Errorf("SM2 recommendation = %q, want mention of curveSM2MLKEM768", got.Recommendation)
	}
	if !strings.Contains(got.Recommendation, "ML-DSA-65") {
		t.Errorf("SM2 recommendation = %q, want mention of ML-DSA-65", got.Recommendation)
	}
}

// TestClassifySM3_Resistant verifies SM3 (Chinese national hash standard,
// 256-bit output) is treated like SHA-256 — RiskResistant, not RiskUnknown
// (review finding B2/F5).
func TestClassifySM3_Resistant(t *testing.T) {
	tests := []struct{ algName, primitive string }{
		{"SM3", "hash"},
		{"SM3", ""}, // unrecognized primitive → isLikelyHash heuristic
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.algName+"/"+tt.primitive, func(t *testing.T) {
			got := ClassifyAlgorithm(tt.algName, tt.primitive, 0)
			if got.Risk != RiskResistant {
				t.Errorf("ClassifyAlgorithm(%q, %q, 0).Risk = %q, want %q", tt.algName, tt.primitive, got.Risk, RiskResistant)
			}
			if got.Severity != SeverityInfo {
				t.Errorf("ClassifyAlgorithm(%q, %q, 0).Severity = %q, want %q", tt.algName, tt.primitive, got.Severity, SeverityInfo)
			}
		})
	}
}

// TestClassifySM4_Weakened verifies SM4 (Chinese national 128-bit symmetric
// cipher, GB/T 32907-2016) is treated like AES-128 — RiskWeakened, not
// RiskUnknown (review finding B2/F5).
func TestClassifySM4_Weakened(t *testing.T) {
	tests := []struct{ algName, primitive string }{
		{"SM4", "symmetric"},
		{"SM4", ""}, // unrecognized primitive → isLikelySymmetric heuristic
		{"SM4-GCM", "ae"},
		{"SM4-CBC", "symmetric"},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.algName+"/"+tt.primitive, func(t *testing.T) {
			got := ClassifyAlgorithm(tt.algName, tt.primitive, 0)
			if got.Risk != RiskWeakened {
				t.Errorf("ClassifyAlgorithm(%q, %q, 0).Risk = %q, want %q", tt.algName, tt.primitive, got.Risk, RiskWeakened)
			}
			if got.TargetAlgorithm != "AES-256" {
				t.Errorf("ClassifyAlgorithm(%q, %q, 0).TargetAlgorithm = %q, want %q", tt.algName, tt.primitive, got.TargetAlgorithm, "AES-256")
			}
		})
	}
}

// ─── B2/F7: GOST (Russian ECC signature standard) ───────────────────────────

// TestClassifyGOST_Vulnerable verifies GOST R 34.10 (Russian ECC-based
// signature standard) is classified as quantum-vulnerable instead of falling
// through to RiskUnknown (review finding B2/F7, scoped to the ECC signature
// variant only — GOST symmetric/hash are out of scope for this fix).
func TestClassifyGOST_Vulnerable(t *testing.T) {
	tests := []string{"GOST", "GOST R 34.10"}
	for _, alg := range tests {
		alg := alg
		t.Run(alg, func(t *testing.T) {
			got := ClassifyAlgorithm(alg, "signature", 0)
			if got.Risk != RiskVulnerable {
				t.Errorf("ClassifyAlgorithm(%q, \"signature\", 0).Risk = %q, want %q", alg, got.Risk, RiskVulnerable)
			}
			if got.TargetAlgorithm != "ML-DSA-65" {
				t.Errorf("ClassifyAlgorithm(%q, \"signature\", 0).TargetAlgorithm = %q, want %q", alg, got.TargetAlgorithm, "ML-DSA-65")
			}
		})
	}
}
