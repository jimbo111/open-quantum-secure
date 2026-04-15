package quantum

import (
	"strings"
	"testing"
)

// TestClassifyPQCSafe covers all NIST PQC standard families and K-PQC Round 4 finalists.
// All of these should return RiskSafe / SeverityInfo with empty Recommendation.
func TestClassifyPQCSafe(t *testing.T) {
	tests := []struct {
		name      string
		algName   string
		primitive string
		keySize   int
	}{
		// --- NIST FIPS 203: ML-KEM ---
		{"ML-KEM-512 kem", "ML-KEM-512", "kem", 0},
		{"ML-KEM-768 kem", "ML-KEM-768", "kem", 0},
		{"ML-KEM-1024 kem", "ML-KEM-1024", "kem", 0},
		{"ML-KEM-512 key-exchange", "ML-KEM-512", "key-exchange", 0},
		{"ML-KEM-768 key-exchange", "ML-KEM-768", "key-exchange", 0},
		{"ML-KEM-1024 key-exchange", "ML-KEM-1024", "key-exchange", 0},

		// --- NIST FIPS 204: ML-DSA ---
		{"ML-DSA-44 signature", "ML-DSA-44", "signature", 0},
		{"ML-DSA-65 signature", "ML-DSA-65", "signature", 0},
		{"ML-DSA-87 signature", "ML-DSA-87", "signature", 0},

		// --- NIST FIPS 205: SLH-DSA ---
		{"SLH-DSA-SHA2-128s signature", "SLH-DSA-SHA2-128s", "signature", 0},
		{"SLH-DSA-SHA2-128f signature", "SLH-DSA-SHA2-128f", "signature", 0},
		{"SLH-DSA-SHA2-192s signature", "SLH-DSA-SHA2-192s", "signature", 0},
		{"SLH-DSA-SHAKE-256f signature", "SLH-DSA-SHAKE-256f", "signature", 0},

		// --- XMSS (stateful hash-based signature) ---
		{"XMSS signature", "XMSS", "signature", 0},
		{"XMSS-SHA2-256 signature", "XMSS-SHA2-256", "signature", 0},

		// --- LMS (stateful hash-based signature) ---
		{"LMS signature", "LMS", "signature", 0},
		{"LMS-SHA256 signature", "LMS-SHA256", "signature", 0},

		// --- K-PQC Round 4 Finalist: SMAUG-T (KEM) ---
		{"SMAUG-T-128 kem", "SMAUG-T-128", "kem", 0},
		{"SMAUG-T-192 kem", "SMAUG-T-192", "kem", 0},
		{"SMAUG-T-256 kem", "SMAUG-T-256", "kem", 0},

		// --- K-PQC Round 4 Finalist: HAETAE (signature) ---
		{"HAETAE-2 signature", "HAETAE-2", "signature", 0},
		{"HAETAE-3 signature", "HAETAE-3", "signature", 0},
		{"HAETAE-5 signature", "HAETAE-5", "signature", 0},

		// --- K-PQC Round 4 Finalist: AIMer (signature) ---
		{"AIMer-128f signature", "AIMer-128f", "signature", 0},
		{"AIMer-128s signature", "AIMer-128s", "signature", 0},
		{"AIMer-192f signature", "AIMer-192f", "signature", 0},
		{"AIMer-256f signature", "AIMer-256f", "signature", 0},

		// --- K-PQC Round 4 Finalist: NTRU+ (KEM) ---
		{"NTRU+-576 kem", "NTRU+-576", "kem", 0},
		{"NTRU+-768 kem", "NTRU+-768", "kem", 0},
		{"NTRU+-864 kem", "NTRU+-864", "kem", 0},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			got := ClassifyAlgorithm(tt.algName, tt.primitive, tt.keySize)
			if got.Risk != RiskSafe {
				t.Errorf("ClassifyAlgorithm(%q, %q, %d).Risk = %q, want %q",
					tt.algName, tt.primitive, tt.keySize, got.Risk, RiskSafe)
			}
			if got.Severity != SeverityInfo {
				t.Errorf("ClassifyAlgorithm(%q, %q, %d).Severity = %q, want %q",
					tt.algName, tt.primitive, tt.keySize, got.Severity, SeverityInfo)
			}
			if got.Recommendation != "" {
				t.Errorf("ClassifyAlgorithm(%q, %q, %d).Recommendation = %q, want empty",
					tt.algName, tt.primitive, tt.keySize, got.Recommendation)
			}
		})
	}
}

// TestClassifyKPQCEliminated covers K-PQC candidates eliminated in earlier rounds.
// All should return RiskVulnerable / SeverityMedium with a recommendation
// mentioning SMAUG-T or HAETAE migration.
func TestClassifyKPQCEliminated(t *testing.T) {
	tests := []struct {
		name      string
		algName   string
		primitive string
		keySize   int
	}{
		{"GCKSign signature", "GCKSign", "signature", 0},
		{"NCC-Sign signature", "NCC-Sign", "signature", 0},
		{"SOLMAE kem", "SOLMAE", "kem", 0},
		{"SOLMAE signature", "SOLMAE", "signature", 0},
		{"TiGER kem", "TiGER", "kem", 0},
		{"TiGER signature", "TiGER", "signature", 0},
		{"PALOMA kem", "PALOMA", "kem", 0},
		{"PALOMA signature", "PALOMA", "signature", 0},
		{"REDOG kem", "REDOG", "kem", 0},
		{"REDOG signature", "REDOG", "signature", 0},
		// Variants with parameter suffixes
		{"NCC-Sign-128 signature", "NCC-Sign-128", "signature", 0},
		{"SOLMAE-512 kem", "SOLMAE-512", "kem", 0},
		{"TiGER-512 kem", "TiGER-512", "kem", 0},
		{"PALOMA-128 kem", "PALOMA-128", "kem", 0},
		{"REDOG-256 kem", "REDOG-256", "kem", 0},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			got := ClassifyAlgorithm(tt.algName, tt.primitive, tt.keySize)
			if got.Risk != RiskVulnerable {
				t.Errorf("ClassifyAlgorithm(%q, %q, %d).Risk = %q, want %q",
					tt.algName, tt.primitive, tt.keySize, got.Risk, RiskVulnerable)
			}
			if got.Severity != SeverityMedium {
				t.Errorf("ClassifyAlgorithm(%q, %q, %d).Severity = %q, want %q",
					tt.algName, tt.primitive, tt.keySize, got.Severity, SeverityMedium)
			}
			rec := strings.ToUpper(got.Recommendation)
			if !strings.Contains(rec, "SMAUG-T") && !strings.Contains(rec, "HAETAE") {
				t.Errorf("ClassifyAlgorithm(%q, %q, %d).Recommendation = %q, want mention of SMAUG-T or HAETAE",
					tt.algName, tt.primitive, tt.keySize, got.Recommendation)
			}
		})
	}
}

// TestClassifyPQCCasing covers PQC algorithm names with non-canonical casing.
// Hyphen-separated variants with different casing should resolve to RiskSafe.
// Underscore-separated variants cannot be matched and fall through to RiskVulnerable.
func TestClassifyPQCCasing(t *testing.T) {
	tests := []struct {
		name      string
		algName   string
		primitive string
		wantRisk  Risk
		wantSev   Severity
	}{
		// All-lowercase hyphen-separated: extractBaseName uppercases for prefix matching → RiskSafe
		{"ml-kem-768 lowercase", "ml-kem-768", "kem", RiskSafe, SeverityInfo},
		{"ml-dsa-65 lowercase", "ml-dsa-65", "signature", RiskSafe, SeverityInfo},
		{"slh-dsa-sha2-128s lowercase", "slh-dsa-sha2-128s", "signature", RiskSafe, SeverityInfo},

		// Mixed-case hyphen-separated → RiskSafe
		{"Ml-Kem-768 mixed case", "Ml-Kem-768", "kem", RiskSafe, SeverityInfo},
		{"mL-DSA-65 mixed case", "mL-DSA-65", "signature", RiskSafe, SeverityInfo},

		// Partial-uppercase hyphen-separated → RiskSafe
		{"ML-kem-768 partial upper", "ML-kem-768", "kem", RiskSafe, SeverityInfo},
		{"ml-KEM-512 partial upper", "ml-KEM-512", "kem", RiskSafe, SeverityInfo},

		// Underscore-separated: FieldsFunc splits on '_', returns first segment "ML" → no map hit
		// Falls into asymmetric primitive path → RiskVulnerable; KEM=Critical (HNDL immediate), Sig=High
		{"ML_KEM_768 underscores kem", "ML_KEM_768", "kem", RiskVulnerable, SeverityCritical},
		{"ML_DSA_65 underscores signature", "ML_DSA_65", "signature", RiskVulnerable, SeverityHigh},
		{"SLH_DSA_SHA2_128s underscores", "SLH_DSA_SHA2_128s", "signature", RiskVulnerable, SeverityHigh},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			got := ClassifyAlgorithm(tt.algName, tt.primitive, 0)
			if got.Risk != tt.wantRisk {
				t.Errorf("ClassifyAlgorithm(%q, %q, 0).Risk = %q, want %q",
					tt.algName, tt.primitive, got.Risk, tt.wantRisk)
			}
			if got.Severity != tt.wantSev {
				t.Errorf("ClassifyAlgorithm(%q, %q, 0).Severity = %q, want %q",
					tt.algName, tt.primitive, got.Severity, tt.wantSev)
			}
		})
	}
}

// TestClassifyPQCFamilyName tests bare PQC family names without parameter suffixes.
// These should all resolve to RiskSafe since extractBaseName prefix-matches the full family.
func TestClassifyPQCFamilyName(t *testing.T) {
	tests := []struct {
		name      string
		algName   string
		primitive string
	}{
		{"ML-KEM bare", "ML-KEM", "kem"},
		{"ML-DSA bare", "ML-DSA", "signature"},
		{"SLH-DSA bare", "SLH-DSA", "signature"},
		{"XMSS bare", "XMSS", "signature"},
		{"LMS bare", "LMS", "signature"},
		{"SMAUG-T bare", "SMAUG-T", "kem"},
		{"HAETAE bare", "HAETAE", "signature"},
		{"AIMer bare", "AIMer", "signature"},
		{"NTRU+ bare", "NTRU+", "kem"},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			got := ClassifyAlgorithm(tt.algName, tt.primitive, 0)
			if got.Risk != RiskSafe {
				t.Errorf("ClassifyAlgorithm(%q, %q, 0).Risk = %q, want %q",
					tt.algName, tt.primitive, got.Risk, RiskSafe)
			}
			if got.Severity != SeverityInfo {
				t.Errorf("ClassifyAlgorithm(%q, %q, 0).Severity = %q, want %q",
					tt.algName, tt.primitive, got.Severity, SeverityInfo)
			}
			if got.Recommendation != "" {
				t.Errorf("ClassifyAlgorithm(%q, %q, 0).Recommendation = %q, want empty",
					tt.algName, tt.primitive, got.Recommendation)
			}
		})
	}
}

// TestClassifyPQCEdgeCases covers invalid/unknown names that should NOT match PQC families,
// and the empty string case.
func TestClassifyPQCEdgeCases(t *testing.T) {
	tests := []struct {
		name      string
		algName   string
		primitive string
		wantRisk  Risk
		wantSev   Severity
	}{
		// Empty string: extractBaseName("") returns "" → no map match → RiskUnknown
		{"empty string no primitive", "", "", RiskUnknown, SeverityLow},
		{"empty string kem primitive", "", "kem", RiskVulnerable, SeverityCritical},

		// PQC-like names that don't match any family
		{"ML-KEM-FAKE unknown", "ML-KEM-FAKE", "kem", RiskSafe, SeverityInfo},   // prefix still matches ML-KEM
		{"MLKEM768 no hyphen", "MLKEM768", "kem", RiskSafe, SeverityInfo}, // added to pqcSafeFamilies (X1 fix)
		{"Kyber-768 old name", "Kyber-768", "kem", RiskVulnerable, SeverityCritical},
		{"Dilithium3 old name", "Dilithium3", "signature", RiskVulnerable, SeverityHigh},
		{"Falcon-512 old name", "Falcon-512", "signature", RiskVulnerable, SeverityHigh},
		{"SPHINCS+ old name", "SPHINCS+", "signature", RiskVulnerable, SeverityHigh},
		{"FrodoKEM unknown kem", "FrodoKEM", "kem", RiskVulnerable, SeverityCritical},
		{"BIKE unknown kem", "BIKE", "kem", RiskVulnerable, SeverityCritical},
		// HQC was added as NIST's 5th PQC standard (March 2025) — now RiskSafe.
		{"HQC nist standard kem", "HQC", "kem", RiskSafe, SeverityInfo},
		{"CRYSTALS-Kyber old", "CRYSTALS-Kyber", "kem", RiskVulnerable, SeverityCritical},
		{"CRYSTALS-Dilithium old", "CRYSTALS-Dilithium", "signature", RiskVulnerable, SeverityHigh},

		// Completely unrelated names
		{"FooBarPQC unknown", "FooBarPQC", "", RiskUnknown, SeverityLow},
		{"PQCAlgo unknown", "PQCAlgo", "", RiskUnknown, SeverityLow},
		{"QuantumSafe unknown", "QuantumSafe", "", RiskUnknown, SeverityLow},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			got := ClassifyAlgorithm(tt.algName, tt.primitive, 0)
			if got.Risk != tt.wantRisk {
				t.Errorf("ClassifyAlgorithm(%q, %q, 0).Risk = %q, want %q",
					tt.algName, tt.primitive, got.Risk, tt.wantRisk)
			}
			if got.Severity != tt.wantSev {
				t.Errorf("ClassifyAlgorithm(%q, %q, 0).Severity = %q, want %q",
					tt.algName, tt.primitive, got.Severity, tt.wantSev)
			}
		})
	}
}

// TestClassifyPQCSafeRecommendationEmpty is a focused assertion that no safe PQC
// algorithm ever carries a non-empty Recommendation field.
func TestClassifyPQCSafeRecommendationEmpty(t *testing.T) {
	safeAlgorithms := []struct{ algName, primitive string }{
		{"ML-KEM-512", "kem"}, {"ML-KEM-768", "kem"}, {"ML-KEM-1024", "kem"},
		{"ML-DSA-44", "signature"}, {"ML-DSA-65", "signature"}, {"ML-DSA-87", "signature"},
		{"SLH-DSA-SHA2-128s", "signature"}, {"SLH-DSA-SHA2-128f", "signature"},
		{"SLH-DSA-SHA2-192s", "signature"}, {"SLH-DSA-SHAKE-256f", "signature"},
		{"XMSS", "signature"}, {"XMSS-SHA2-256", "signature"},
		{"LMS", "signature"}, {"LMS-SHA256", "signature"},
		{"SMAUG-T-128", "kem"}, {"SMAUG-T-192", "kem"}, {"SMAUG-T-256", "kem"},
		{"HAETAE-2", "signature"}, {"HAETAE-3", "signature"}, {"HAETAE-5", "signature"},
		{"AIMer-128f", "signature"}, {"AIMer-128s", "signature"},
		{"AIMer-192f", "signature"}, {"AIMer-256f", "signature"},
		{"NTRU+-576", "kem"}, {"NTRU+-768", "kem"}, {"NTRU+-864", "kem"},
	}

	for _, alg := range safeAlgorithms {
		alg := alg
		t.Run(alg.algName, func(t *testing.T) {
			got := ClassifyAlgorithm(alg.algName, alg.primitive, 0)
			if got.Risk != RiskSafe {
				t.Errorf("%q: Risk = %q, want %q", alg.algName, got.Risk, RiskSafe)
			}
			if got.Recommendation != "" {
				t.Errorf("%q: Recommendation = %q, want empty (safe algorithms carry no recommendation)",
					alg.algName, got.Recommendation)
			}
		})
	}
}

// TestClassifyKPQCEliminatedMigrationTarget verifies the recommendation for every
// K-PQC eliminated candidate explicitly names SMAUG-T or HAETAE as the migration target.
func TestClassifyKPQCEliminatedMigrationTarget(t *testing.T) {
	eliminated := []struct{ algName, primitive string }{
		{"GCKSign", "signature"},
		{"NCC-Sign", "signature"},
		{"SOLMAE", "kem"},
		{"TiGER", "kem"},
		{"PALOMA", "kem"},
		{"REDOG", "kem"},
	}

	for _, alg := range eliminated {
		alg := alg
		t.Run(alg.algName, func(t *testing.T) {
			got := ClassifyAlgorithm(alg.algName, alg.primitive, 0)

			if got.Risk != RiskVulnerable {
				t.Errorf("%q: Risk = %q, want %q", alg.algName, got.Risk, RiskVulnerable)
			}
			if got.Severity != SeverityMedium {
				t.Errorf("%q: Severity = %q, want %q", alg.algName, got.Severity, SeverityMedium)
			}
			if got.Recommendation == "" {
				t.Errorf("%q: Recommendation is empty, want migration guidance", alg.algName)
			}

			rec := got.Recommendation
			upperRec := strings.ToUpper(rec)
			hasSMAUG := strings.Contains(upperRec, "SMAUG-T")
			hasHAETAE := strings.Contains(upperRec, "HAETAE")
			if !hasSMAUG && !hasHAETAE {
				t.Errorf("%q: Recommendation %q does not mention SMAUG-T or HAETAE", alg.algName, rec)
			}
		})
	}
}
