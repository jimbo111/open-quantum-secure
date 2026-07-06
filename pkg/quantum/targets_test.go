package quantum

import (
	"strings"
	"testing"
)

func TestLookupTarget(t *testing.T) {
	tests := []struct {
		name      string
		input     string
		wantAlg   string
		wantStd   string
	}{
		// Asymmetric signing → ML-DSA
		{name: "RSA", input: "RSA", wantAlg: "ML-DSA-65", wantStd: "FIPS 204"},
		// ML-DSA-65 is the floor (review SCANNER_REVIEW_2026-07-05.md finding A1:
		// this used to be ML-DSA-44, contradicting classify.go's recommendation text).
		{name: "ECDSA", input: "ECDSA", wantAlg: "ML-DSA-65", wantStd: "FIPS 204"},
		// Key exchange → ML-KEM
		{name: "ECDH", input: "ECDH", wantAlg: "ML-KEM-768", wantStd: "FIPS 203"},
		{name: "X25519", input: "X25519", wantAlg: "ML-KEM-768", wantStd: "FIPS 203"},
		// Deprecated → modern replacements
		{name: "MD5", input: "MD5", wantAlg: "SHA-256", wantStd: ""},
		{name: "DES", input: "DES", wantAlg: "AES-256-GCM", wantStd: ""},
		// Pre-standard PQC names
		{name: "DILITHIUM", input: "DILITHIUM", wantAlg: "ML-DSA-65", wantStd: "FIPS 204"},
		{name: "KYBER", input: "KYBER", wantAlg: "ML-KEM-768", wantStd: "FIPS 203"},
		// Unknown
		{name: "UNKNOWN-ALG", input: "UNKNOWN-ALG", wantAlg: "", wantStd: ""},
		// Case insensitivity
		{name: "rsa lowercase", input: "rsa", wantAlg: "ML-DSA-65", wantStd: "FIPS 204"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := LookupTarget(tt.input)
			if got.Algorithm != tt.wantAlg {
				t.Errorf("LookupTarget(%q).Algorithm = %q, want %q", tt.input, got.Algorithm, tt.wantAlg)
			}
			if got.Standard != tt.wantStd {
				t.Errorf("LookupTarget(%q).Standard = %q, want %q", tt.input, got.Standard, tt.wantStd)
			}
		})
	}
}

func TestLookupTargetForKeySize(t *testing.T) {
	tests := []struct {
		name    string
		alg     string
		keySize int
		wantAlg string
		wantStd string
	}{
		// RSA key-size ladder. ML-DSA-65 is the floor — RSA-2048 no longer
		// gets ML-DSA-44 (review SCANNER_REVIEW_2026-07-05.md finding A1).
		{name: "RSA-2048", alg: "RSA", keySize: 2048, wantAlg: "ML-DSA-65", wantStd: "FIPS 204"},
		{name: "RSA-3072", alg: "RSA", keySize: 3072, wantAlg: "ML-DSA-65", wantStd: "FIPS 204"},
		{name: "RSA-4096", alg: "RSA", keySize: 4096, wantAlg: "ML-DSA-87", wantStd: "FIPS 204"},
		// ECDSA curve-size ladder. ML-DSA-65 is the floor (same A1 fix).
		{name: "ECDSA-256", alg: "ECDSA", keySize: 256, wantAlg: "ML-DSA-65", wantStd: "FIPS 204"},
		{name: "ECDSA-384", alg: "ECDSA", keySize: 384, wantAlg: "ML-DSA-65", wantStd: "FIPS 204"},
		// ECDSA-521 (P-521, NIST security level 5) steps up to ML-DSA-87 —
		// previously shared the P-384 tier's ML-DSA-65 target.
		{name: "ECDSA-521", alg: "ECDSA", keySize: 521, wantAlg: "ML-DSA-87", wantStd: "FIPS 204"},
		// ECDH curve-size ladder
		{name: "ECDH-256", alg: "ECDH", keySize: 256, wantAlg: "ML-KEM-768", wantStd: "FIPS 203"},
		{name: "ECDH-384", alg: "ECDH", keySize: 384, wantAlg: "ML-KEM-1024", wantStd: "FIPS 203"},
		// AES key-size upgrade
		{name: "AES-128", alg: "AES", keySize: 128, wantAlg: "AES-256", wantStd: ""},
		// AES-256: keySize >= 256 so no AES branch fires; falls through to LookupTarget("AES") which has no entry.
		{name: "AES-256 fallthrough", alg: "AES", keySize: 256, wantAlg: "", wantStd: ""},
		// Unknown algorithm
		{name: "Unknown", alg: "UNKNOWN-ALG", keySize: 128, wantAlg: "", wantStd: ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := LookupTargetForKeySize(tt.alg, tt.keySize)
			if got.Algorithm != tt.wantAlg {
				t.Errorf("LookupTargetForKeySize(%q, %d).Algorithm = %q, want %q", tt.alg, tt.keySize, got.Algorithm, tt.wantAlg)
			}
			if got.Standard != tt.wantStd {
				t.Errorf("LookupTargetForKeySize(%q, %d).Standard = %q, want %q", tt.alg, tt.keySize, got.Standard, tt.wantStd)
			}
		})
	}
}

// TestLookupTarget_EdgeCases exercises boundary and adversarial inputs for
// LookupTarget: empty string, lowercase, completely unknown names, names that
// look like known ones but are not in the map, and very long inputs.
func TestLookupTarget_EdgeCases(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantAlg string
		wantStd string
	}{
		// Empty string: ToUpper("") == "" — not in map → zero value.
		{
			name:    "empty string",
			input:   "",
			wantAlg: "",
			wantStd: "",
		},
		// Lowercase "rsa": ToUpper → "RSA" which is in the map.
		{
			name:    "rsa lowercase maps to ML-DSA-65",
			input:   "rsa",
			wantAlg: "ML-DSA-65",
			wantStd: "FIPS 204",
		},
		// Completely unknown algorithm name.
		{
			name:    "unknown algorithm",
			input:   "UNKNOWN-ALGO",
			wantAlg: "",
			wantStd: "",
		},
		// "RSA-OAEP" is not in the map (only "RSAES-OAEP" is); must return empty.
		{
			name:    "RSA-OAEP not in map",
			input:   "RSA-OAEP",
			wantAlg: "",
			wantStd: "",
		},
		// Very long string (500 chars): must not panic, must return empty.
		{
			name:    "500-char string no panic",
			input:   strings.Repeat("X", 500),
			wantAlg: "",
			wantStd: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("LookupTarget panicked: input=%q panic=%v", tt.input, r)
				}
			}()
			got := LookupTarget(tt.input)
			if got.Algorithm != tt.wantAlg {
				t.Errorf("LookupTarget(%q).Algorithm = %q, want %q", tt.input, got.Algorithm, tt.wantAlg)
			}
			if got.Standard != tt.wantStd {
				t.Errorf("LookupTarget(%q).Standard = %q, want %q", tt.input, got.Standard, tt.wantStd)
			}
		})
	}
}

// TestLookupTargetForKeySize_Boundaries probes the exact threshold values for
// RSA (3072, 4096), ECDSA (384), and AES (256), plus zero and negative keySizes.
func TestLookupTargetForKeySize_Boundaries(t *testing.T) {
	tests := []struct {
		name    string
		alg     string
		keySize int
		wantAlg string
		wantStd string
	}{
		// RSA thresholds at 3072 and 4096 (both are >= comparisons). ML-DSA-65
		// is the floor below 3072 (review SCANNER_REVIEW_2026-07-05.md finding A1:
		// this tier used to be ML-DSA-44).
		{name: "RSA keySize=3071 below 3072 threshold", alg: "RSA", keySize: 3071, wantAlg: "ML-DSA-65", wantStd: "FIPS 204"},
		{name: "RSA keySize=3072 at 3072 threshold", alg: "RSA", keySize: 3072, wantAlg: "ML-DSA-65", wantStd: "FIPS 204"},
		{name: "RSA keySize=3073 above 3072 threshold", alg: "RSA", keySize: 3073, wantAlg: "ML-DSA-65", wantStd: "FIPS 204"},
		{name: "RSA keySize=4095 just below 4096 threshold", alg: "RSA", keySize: 4095, wantAlg: "ML-DSA-65", wantStd: "FIPS 204"},
		{name: "RSA keySize=4096 at 4096 threshold", alg: "RSA", keySize: 4096, wantAlg: "ML-DSA-87", wantStd: "FIPS 204"},
		// RSA at extreme low values: all fall below 3072 → ML-DSA-65 (floor).
		{name: "RSA keySize=0 minimum default", alg: "RSA", keySize: 0, wantAlg: "ML-DSA-65", wantStd: "FIPS 204"},
		{name: "RSA keySize=-1 negative treated as below all thresholds", alg: "RSA", keySize: -1, wantAlg: "ML-DSA-65", wantStd: "FIPS 204"},
		// ECDSA threshold at 384 — both tiers now floor at ML-DSA-65 (same A1 fix).
		{name: "ECDSA keySize=383 below 384 threshold", alg: "ECDSA", keySize: 383, wantAlg: "ML-DSA-65", wantStd: "FIPS 204"},
		{name: "ECDSA keySize=384 at 384 threshold", alg: "ECDSA", keySize: 384, wantAlg: "ML-DSA-65", wantStd: "FIPS 204"},
		// ECDSA threshold at 521 (P-521, NIST security level 5) → ML-DSA-87.
		{name: "ECDSA keySize=520 below 521 threshold", alg: "ECDSA", keySize: 520, wantAlg: "ML-DSA-65", wantStd: "FIPS 204"},
		{name: "ECDSA keySize=521 at 521 threshold", alg: "ECDSA", keySize: 521, wantAlg: "ML-DSA-87", wantStd: "FIPS 204"},
		// AES: upgrade only when keySize > 0 && keySize < 256.
		// keySize=255 satisfies both conditions → AES-256.
		{name: "AES keySize=255 just below 256", alg: "AES", keySize: 255, wantAlg: "AES-256", wantStd: ""},
		// keySize=256 fails the `< 256` guard → falls through to LookupTarget("AES")
		// which has no entry → empty.
		{name: "AES keySize=256 at boundary falls through", alg: "AES", keySize: 256, wantAlg: "", wantStd: ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := LookupTargetForKeySize(tt.alg, tt.keySize)
			if got.Algorithm != tt.wantAlg {
				t.Errorf("LookupTargetForKeySize(%q, %d).Algorithm = %q, want %q",
					tt.alg, tt.keySize, got.Algorithm, tt.wantAlg)
			}
			if got.Standard != tt.wantStd {
				t.Errorf("LookupTargetForKeySize(%q, %d).Standard = %q, want %q",
					tt.alg, tt.keySize, got.Standard, tt.wantStd)
			}
		})
	}
}

func TestClassifyAlgorithmTargetPopulation(t *testing.T) {
	tests := []struct {
		name          string
		alg           string
		primitive     string
		keySize       int
		wantNonEmpty  bool   // true if TargetAlgorithm should be set
		wantTargetAlg string // exact value when wantNonEmpty is true
	}{
		// RSA-2048 signature → vulnerable → ML-DSA-65 (floor; review
		// SCANNER_REVIEW_2026-07-05.md finding A1 — this used to be ML-DSA-44).
		{
			name:          "RSA-2048 signature",
			alg:           "RSA-2048",
			primitive:     "signature",
			keySize:       2048,
			wantNonEmpty:  true,
			wantTargetAlg: "ML-DSA-65",
		},
		// AES-256 symmetric → quantum-resistant → no target
		{
			name:          "AES-256 symmetric resistant",
			alg:           "AES-256",
			primitive:     "symmetric",
			keySize:       256,
			wantNonEmpty:  false,
			wantTargetAlg: "",
		},
		// ML-KEM-768 → PQC safe → no target
		{
			name:          "ML-KEM-768 safe",
			alg:           "ML-KEM-768",
			primitive:     "",
			keySize:       0,
			wantNonEmpty:  false,
			wantTargetAlg: "",
		},
		// MD5 deprecated → target should be SHA-256
		{
			name:          "MD5 deprecated",
			alg:           "MD5",
			primitive:     "hash",
			keySize:       128,
			wantNonEmpty:  true,
			wantTargetAlg: "SHA-256",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ClassifyAlgorithm(tt.alg, tt.primitive, tt.keySize)
			if tt.wantNonEmpty && got.TargetAlgorithm == "" {
				t.Errorf("ClassifyAlgorithm(%q, %q, %d).TargetAlgorithm is empty, want non-empty", tt.alg, tt.primitive, tt.keySize)
			}
			if !tt.wantNonEmpty && got.TargetAlgorithm != "" {
				t.Errorf("ClassifyAlgorithm(%q, %q, %d).TargetAlgorithm = %q, want empty", tt.alg, tt.primitive, tt.keySize, got.TargetAlgorithm)
			}
			if tt.wantTargetAlg != "" && got.TargetAlgorithm != tt.wantTargetAlg {
				t.Errorf("ClassifyAlgorithm(%q, %q, %d).TargetAlgorithm = %q, want %q", tt.alg, tt.primitive, tt.keySize, got.TargetAlgorithm, tt.wantTargetAlg)
			}
		})
	}
}

// TestVulnerableRecommendationMatchesTarget guards against future drift
// between the structured migrationTargets table (surfaced as TargetAlgorithm
// in JSON/SARIF/CBOM) and the free-text vulnerableRecommendation string
// (surfaced as the human-readable Recommendation field). These previously
// disagreed for the exact same finding — ECDSA/Ed25519/RSA<3072 emitted
// ML-DSA-44 in the table while the text said "ML-DSA-65" — see review
// SCANNER_REVIEW_2026-07-05.md finding A1. For every signature entry in
// migrationTargets (Standard == "FIPS 204"), assert vulnerableRecommendation
// mentions the same ML-DSA level. Entries with no dedicated case in
// vulnerableRecommendation (which fall to the generic FIPS 203/204/205 text)
// are skipped — there's nothing to cross-check.
func TestVulnerableRecommendationMatchesTarget(t *testing.T) {
	const noRecommendationCase = "This algorithm is quantum-vulnerable. Migrate to NIST PQC standards (FIPS 203/204/205)."

	for name, target := range migrationTargets {
		if target.Standard != "FIPS 204" {
			continue // not a signature (ML-DSA) entry
		}
		rec := vulnerableRecommendation(name)
		if rec == noRecommendationCase {
			continue // no dedicated case in vulnerableRecommendation — nothing to cross-check
		}
		if !strings.Contains(rec, target.Algorithm) {
			t.Errorf("migrationTargets[%q].Algorithm = %q, but vulnerableRecommendation(%q) = %q — does not mention %q",
				name, target.Algorithm, name, rec, target.Algorithm)
		}
	}
}

// TestExtractBaseName_JWARSAEncryption verifies that JWA (RFC 7518) "alg"
// values for RSA encryption resolve to the RSAES-* base names (which map to
// ML-KEM-768 in migrationTargets) instead of collapsing to bare "RSA" (which
// maps to ML-DSA-65, a signature scheme). See review
// SCANNER_REVIEW_2026-07-05.md finding A3.
func TestExtractBaseName_JWARSAEncryption(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"RSA-OAEP", "RSAES-OAEP"},
		{"RSA-OAEP-256", "RSAES-OAEP"},
		{"RSA1_5", "RSAES-PKCS1"},
		// Case-insensitivity.
		{"rsa-oaep", "RSAES-OAEP"},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := extractBaseName(tt.input)
			if got != tt.want {
				t.Errorf("extractBaseName(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

// TestClassifyAlgorithm_JWARSAEncryption verifies the end-to-end fix for A3:
// a JWA RSA-encryption identifier tagged with an unrecognized primitive
// synonym ("encryption", "jwe", "key-encryption", "enc") gets routed to the
// ML-KEM-768 recommendation, never the ML-DSA signature text.
func TestClassifyAlgorithm_JWARSAEncryption(t *testing.T) {
	primitives := []string{"encryption", "jwe", "key-encryption", "enc"}
	names := []string{"RSA-OAEP", "RSA-OAEP-256", "RSA1_5"}

	for _, name := range names {
		for _, primitive := range primitives {
			t.Run(name+"_"+primitive, func(t *testing.T) {
				got := ClassifyAlgorithm(name, primitive, 2048)
				if got.Risk != RiskVulnerable {
					t.Errorf("ClassifyAlgorithm(%q, %q, 2048).Risk = %q, want %q", name, primitive, got.Risk, RiskVulnerable)
				}
				if got.TargetAlgorithm != "ML-KEM-768" {
					t.Errorf("ClassifyAlgorithm(%q, %q, 2048).TargetAlgorithm = %q, want ML-KEM-768", name, primitive, got.TargetAlgorithm)
				}
				if got.TargetStandard != "FIPS 203" {
					t.Errorf("ClassifyAlgorithm(%q, %q, 2048).TargetStandard = %q, want FIPS 203", name, primitive, got.TargetStandard)
				}
				if strings.Contains(got.Recommendation, "ML-DSA") {
					t.Errorf("ClassifyAlgorithm(%q, %q, 2048).Recommendation = %q, must not mention ML-DSA for an encryption finding",
						name, primitive, got.Recommendation)
				}
				if !strings.Contains(got.Recommendation, "ML-KEM") {
					t.Errorf("ClassifyAlgorithm(%q, %q, 2048).Recommendation = %q, want it to mention ML-KEM", name, primitive, got.Recommendation)
				}
			})
		}
	}
}
