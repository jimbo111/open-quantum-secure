package quantum

import (
	"strings"
	"sync"
	"testing"
)

func TestClassifyAlgorithm(t *testing.T) {
	tests := []struct {
		name      string
		algName   string
		primitive string
		keySize   int
		wantRisk  Risk
		wantSev   Severity
	}{
		// === Deprecated algorithms ===
		{"MD5", "MD5", "hash", 0, RiskDeprecated, SeverityCritical},
		{"SHA-1", "SHA-1", "hash", 0, RiskDeprecated, SeverityCritical},
		{"SHA1 alt", "SHA1", "hash", 0, RiskDeprecated, SeverityCritical},
		{"DES", "DES", "symmetric", 0, RiskDeprecated, SeverityCritical},
		{"3DES", "3DES", "symmetric", 0, RiskDeprecated, SeverityCritical},
		{"RC4", "RC4", "stream-cipher", 0, RiskDeprecated, SeverityCritical},
		{"Blowfish", "Blowfish", "", 0, RiskDeprecated, SeverityCritical},
		{"HAS-160", "HAS-160", "hash", 0, RiskDeprecated, SeverityCritical},

		// === PQC-safe algorithms ===
		{"ML-KEM-768", "ML-KEM-768", "kem", 0, RiskSafe, SeverityInfo},
		{"ML-DSA-65", "ML-DSA-65", "signature", 0, RiskSafe, SeverityInfo},
		{"SLH-DSA", "SLH-DSA-SHA2-128s", "signature", 0, RiskSafe, SeverityInfo},
		{"XMSS", "XMSS", "signature", 0, RiskSafe, SeverityInfo},
		{"LMS", "LMS", "signature", 0, RiskSafe, SeverityInfo},

		// === HQC (NIST 5th PQC standard) ===
		{"HQC bare", "HQC", "kem", 0, RiskSafe, SeverityInfo},
		{"HQC-128", "HQC-128", "kem", 0, RiskSafe, SeverityInfo},
		{"HQC-192", "HQC-192", "kem", 0, RiskSafe, SeverityInfo},
		{"HQC-256", "HQC-256", "kem", 0, RiskSafe, SeverityInfo},

		// === K-PQC Round 4 finalists ===
		{"SMAUG-T-128", "SMAUG-T-128", "kem", 0, RiskSafe, SeverityInfo},
		{"HAETAE-2", "HAETAE-2", "signature", 0, RiskSafe, SeverityInfo},
		{"AIMer-128f", "AIMer-128f", "signature", 0, RiskSafe, SeverityInfo},
		{"NTRU+-576", "NTRU+-576", "kem", 0, RiskSafe, SeverityInfo},

		// === K-PQC eliminated candidates ===
		{"GCKSign eliminated", "GCKSign", "signature", 0, RiskVulnerable, SeverityMedium},
		{"TiGER eliminated", "TiGER", "kem", 0, RiskVulnerable, SeverityMedium},
		{"PALOMA eliminated", "PALOMA", "kem", 0, RiskVulnerable, SeverityMedium},
		{"REDOG eliminated", "REDOG", "kem", 0, RiskVulnerable, SeverityMedium},

		// === Quantum-vulnerable asymmetric ===
		{"RSA-2048 default", "RSA-2048", "", 0, RiskVulnerable, SeverityHigh},
		{"RSA signature", "RSA", "signature", 2048, RiskVulnerable, SeverityHigh},
		{"ECDSA", "ECDSA", "signature", 0, RiskVulnerable, SeverityHigh},
		{"ECDH key-agree", "ECDH", "key-agree", 0, RiskVulnerable, SeverityCritical},
		{"X25519 key-exchange", "X25519", "key-exchange", 0, RiskVulnerable, SeverityCritical},
		{"EdDSA", "EdDSA", "signature", 0, RiskVulnerable, SeverityHigh},
		{"Ed25519", "Ed25519", "", 0, RiskVulnerable, SeverityHigh},
		{"KCDSA", "KCDSA", "signature", 0, RiskVulnerable, SeverityHigh},
		{"EC-KCDSA", "EC-KCDSA", "signature", 0, RiskVulnerable, SeverityHigh},
		{"DH", "DH", "key-agree", 0, RiskVulnerable, SeverityCritical},

		// === Quantum-resistant symmetric ===
		{"AES-256-GCM", "AES-256-GCM", "ae", 256, RiskResistant, SeverityInfo},
		{"AES-256 no mode", "AES-256", "symmetric", 256, RiskResistant, SeverityInfo},
		{"ChaCha20-Poly1305", "ChaCha20-Poly1305", "ae", 256, RiskResistant, SeverityInfo},
		{"ChaCha20 no key", "ChaCha20", "", 0, RiskResistant, SeverityInfo},
		{"ARIA-256", "ARIA-256", "block-cipher", 256, RiskResistant, SeverityInfo},
		{"ARIA no key", "ARIA", "", 0, RiskUnknown, SeverityLow},
		{"LEA-256", "LEA-256", "block-cipher", 256, RiskResistant, SeverityInfo},

		// === Quantum-weakened symmetric ===
		{"AES-128", "AES-128", "symmetric", 128, RiskWeakened, SeverityLow},
		{"ARIA-128", "ARIA", "block-cipher", 128, RiskWeakened, SeverityLow},
		{"LEA-128", "LEA", "block-cipher", 128, RiskWeakened, SeverityLow},

		// === SEED special handling ===
		{"SEED default (128-bit only)", "SEED", "block-cipher", 0, RiskWeakened, SeverityLow},
		{"SEED-128-CBC", "SEED-128-CBC", "block-cipher", 0, RiskWeakened, SeverityLow},
		{"SEED-ECB deprecated", "SEED-ECB", "block-cipher", 0, RiskDeprecated, SeverityCritical},

		// === Quantum-resistant hashes ===
		{"SHA-256", "SHA-256", "hash", 0, RiskResistant, SeverityInfo},
		{"SHA-384", "SHA-384", "hash", 0, RiskResistant, SeverityInfo},
		{"SHA-512", "SHA-512", "hash", 0, RiskResistant, SeverityInfo},
		{"SHA3-256", "SHA3-256", "hash", 0, RiskResistant, SeverityInfo},
		{"BLAKE2b", "BLAKE2b", "hash", 0, RiskResistant, SeverityInfo},

		// === Quantum-weakened hashes ===
		{"SHA-224", "SHA-224", "hash", 0, RiskWeakened, SeverityLow},

		// === LSH variants ===
		{"LSH-512-512 resistant", "LSH-512-512", "hash", 0, RiskResistant, SeverityInfo},
		{"LSH-256-256 weakened", "LSH-256-256", "hash", 0, RiskWeakened, SeverityLow},

		// === CSPRNG / RNG — quantum-resistant (Grover's does not break well-seeded CSPRNGs) ===
		{"CSPRNG", "CSPRNG", "rng", 0, RiskResistant, SeverityInfo},
		{"crypto/rand", "crypto/rand", "rng", 0, RiskResistant, SeverityInfo},
		{"prng primitive", "SomePRNG", "prng", 0, RiskResistant, SeverityInfo},
		{"csprng primitive", "SomeCSPRNG", "csprng", 0, RiskResistant, SeverityInfo},
		{"random primitive", "SomeRandom", "random", 0, RiskResistant, SeverityInfo},

		// === Unknown ===
		{"unknown algo", "FooBar", "", 0, RiskUnknown, SeverityLow},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ClassifyAlgorithm(tt.algName, tt.primitive, tt.keySize)
			if got.Risk != tt.wantRisk {
				t.Errorf("ClassifyAlgorithm(%q, %q, %d).Risk = %q, want %q",
					tt.algName, tt.primitive, tt.keySize, got.Risk, tt.wantRisk)
			}
			if got.Severity != tt.wantSev {
				t.Errorf("ClassifyAlgorithm(%q, %q, %d).Severity = %q, want %q",
					tt.algName, tt.primitive, tt.keySize, got.Severity, tt.wantSev)
			}
		})
	}
}

// TestClassifyAlgorithm_HQC verifies that HQC and its parameter set variants are
// classified as QuantumSafe/SeverityInfo and carry a recommendation noting that
// the standard is not yet finalized and not CNSA 2.0 approved.
func TestClassifyAlgorithm_HQC(t *testing.T) {
	cases := []string{"HQC", "HQC-128", "HQC-192", "HQC-256"}
	for _, alg := range cases {
		t.Run(alg, func(t *testing.T) {
			got := ClassifyAlgorithm(alg, "kem", 0)
			if got.Risk != RiskSafe {
				t.Errorf("ClassifyAlgorithm(%q).Risk = %q, want %q", alg, got.Risk, RiskSafe)
			}
			if got.Severity != SeverityInfo {
				t.Errorf("ClassifyAlgorithm(%q).Severity = %q, want %q", alg, got.Severity, SeverityInfo)
			}
			if got.Recommendation == "" {
				t.Errorf("ClassifyAlgorithm(%q).Recommendation is empty, want non-empty (standard status note)", alg)
			}
			if !strings.Contains(got.Recommendation, "HQC") {
				t.Errorf("ClassifyAlgorithm(%q).Recommendation does not mention HQC: %s", alg, got.Recommendation)
			}
		})
	}
}

// TestClassifyAlgorithm_RNG verifies that the "rng" primitive path returns
// RiskResistant and SeverityInfo and includes the recommendation string.
func TestClassifyAlgorithm_RNG(t *testing.T) {
	cases := []struct {
		alg  string
		prim string
	}{
		{"crypto/rand", "rng"},
		{"CSPRNG", "rng"},
		{"SecureRandom", "csprng"},
		{"rand.Reader", "rng"},
	}
	for _, c := range cases {
		t.Run(c.alg, func(t *testing.T) {
			got := ClassifyAlgorithm(c.alg, c.prim, 0)
			if got.Risk != RiskResistant {
				t.Errorf("ClassifyAlgorithm(%q, %q, 0).Risk = %q, want %q",
					c.alg, c.prim, got.Risk, RiskResistant)
			}
			if got.Severity != SeverityInfo {
				t.Errorf("ClassifyAlgorithm(%q, %q, 0).Severity = %q, want %q",
					c.alg, c.prim, got.Severity, SeverityInfo)
			}
			if got.Recommendation == "" {
				t.Errorf("ClassifyAlgorithm(%q, %q, 0).Recommendation is empty, want non-empty",
					c.alg, c.prim)
			}
		})
	}
}

// TestClassifyAlgorithm_ConcurrentCalls verifies that ClassifyAlgorithm is safe
// to call from multiple goroutines simultaneously (no data races).
// The -race flag will catch any race conditions.
func TestClassifyAlgorithm_ConcurrentCalls(t *testing.T) {
	algorithms := []struct {
		name      string
		primitive string
		keySize   int
	}{
		{"RSA-2048", "signature", 2048},
		{"AES-256-GCM", "ae", 256},
		{"ML-KEM-768", "kem", 0},
		{"SHA-256", "hash", 0},
		{"ECDSA", "signature", 0},
		{"DES", "symmetric", 0},
		{"MD5", "hash", 0},
		{"AES-128", "symmetric", 128},
		{"ChaCha20-Poly1305", "ae", 256},
		{"SMAUG-T-128", "kem", 0},
	}

	const goroutines = 50
	var wg sync.WaitGroup
	wg.Add(goroutines)

	for i := 0; i < goroutines; i++ {
		i := i
		go func() {
			defer wg.Done()
			alg := algorithms[i%len(algorithms)]
			got := ClassifyAlgorithm(alg.name, alg.primitive, alg.keySize)
			// Just ensure it returns a valid risk value (not empty)
			if got.Risk == "" {
				t.Errorf("goroutine %d: ClassifyAlgorithm(%q) returned empty Risk", i, alg.name)
			}
		}()
	}

	wg.Wait()
}

func TestExtractBaseName(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"AES-256-GCM", "AES"},
		{"RSA-2048", "RSA"},
		{"ML-KEM-768", "ML-KEM"},
		{"ML-DSA-65", "ML-DSA"},
		{"SLH-DSA-SHA2-128s", "SLH-DSA"},
		{"SHA-256", "SHA"},   // SHA-256 splits to "SHA" at the hyphen (not in deprecated/pqc maps)
		{"SHA-1", "SHA-1"},
		{"SMAUG-T-128", "SMAUG-T"},
		{"HAETAE-2", "HAETAE"},
		{"AIMer-128f", "AIMer"},
		{"NTRU+-576", "NTRU+"},
		{"EC-KCDSA", "EC-KCDSA"},
		{"HAS-160", "HAS-160"},
		{"ECDSA", "ECDSA"},
		{"ChaCha20", "ChaCha20"},
		{"MD5", "MD5"},
		{"3DES", "3DES"},
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

func TestNormalizePrimitive(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"pke", "pke"},
		{"public-key", "pke"},
		{"kem", "kem"},
		{"key-agree", "key-agree"},
		{"key-exchange", "key-agree"},
		{"dh", "key-agree"},
		{"signature", "signature"},
		{"sign", "signature"},
		{"hash", "hash"},
		{"digest", "hash"},
		{"symmetric", "symmetric"},
		{"block-cipher", "symmetric"},
		{"ae", "ae"},
		{"aead", "ae"},
		{"xof", "xof"},
		// RNG family aliases all normalize to "rng"
		{"rng", "rng"},
		{"prng", "rng"},
		{"csprng", "rng"},
		{"random", "rng"},
		// Unknown passes through lowercased
		{"unknown", "unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := normalizePrimitive(tt.input)
			if got != tt.want {
				t.Errorf("normalizePrimitive(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestHashOutputSize(t *testing.T) {
	tests := []struct {
		baseName string
		upper    string
		keySize  int
		want     int
	}{
		{"SHA-256", "SHA-256", 0, 256},
		{"SHA-512", "SHA-512", 0, 512},
		{"SHA-384", "SHA-384", 0, 384},
		{"MD5", "MD5", 0, 128},
		{"SHA-1", "SHA-1", 0, 160},
		{"HAS-160", "HAS-160", 0, 160},
		{"custom", "CUSTOM-HASH", 512, 512}, // explicit keySize
	}

	for _, tt := range tests {
		t.Run(tt.baseName, func(t *testing.T) {
			got := hashOutputSize(tt.baseName, tt.upper, tt.keySize)
			if got != tt.want {
				t.Errorf("hashOutputSize(%q, %q, %d) = %d, want %d",
					tt.baseName, tt.upper, tt.keySize, got, tt.want)
			}
		})
	}
}

func TestIsLikelySymmetric(t *testing.T) {
	positives := []string{"AES-256", "CHACHA20", "CAMELLIA", "ARIA-128", "SEED", "LEA-256"}
	for _, s := range positives {
		if !isLikelySymmetric(s) {
			t.Errorf("isLikelySymmetric(%q) = false, want true", s)
		}
	}

	negatives := []string{"RSA", "ECDSA", "ML-KEM", "SHA-256"}
	for _, s := range negatives {
		if isLikelySymmetric(s) {
			t.Errorf("isLikelySymmetric(%q) = true, want false", s)
		}
	}
}

func TestIsLikelyHash(t *testing.T) {
	positives := []string{"SHA-256", "SHA3-512", "BLAKE2B", "MD5", "LSH-512", "HMAC-SHA256"}
	for _, s := range positives {
		if !isLikelyHash(s) {
			t.Errorf("isLikelyHash(%q) = false, want true", s)
		}
	}

	negatives := []string{"AES", "RSA", "ECDSA", "ML-KEM"}
	for _, s := range negatives {
		if isLikelyHash(s) {
			t.Errorf("isLikelyHash(%q) = true, want false", s)
		}
	}
}

// TestHybridRecommendations verifies that hybrid transition guidance is present
// in quantum-vulnerable algorithm recommendations and absent from deprecated ones.
func TestHybridRecommendations(t *testing.T) {
	t.Run("key_exchange_contains_hybrid", func(t *testing.T) {
		// RSA key exchange (primitive known) → generic classifyVulnerable path
		c := ClassifyAlgorithm("RSA", "key-exchange", 0)
		if !strings.Contains(c.Recommendation, "hybrid") {
			t.Errorf("RSA key-exchange recommendation should contain 'hybrid', got: %s", c.Recommendation)
		}

		// ECDH key-agree → generic classifyVulnerable path
		c = ClassifyAlgorithm("ECDH", "key-agree", 0)
		if !strings.Contains(c.Recommendation, "hybrid") {
			t.Errorf("ECDH key-agree recommendation should contain 'hybrid', got: %s", c.Recommendation)
		}

		// X25519 default primitive → vulnerableRecommendation with BoringSSL note
		c = ClassifyAlgorithm("X25519", "", 0)
		if !strings.Contains(c.Recommendation, "hybrid") {
			t.Errorf("X25519 default recommendation should contain 'hybrid', got: %s", c.Recommendation)
		}
		if !strings.Contains(c.Recommendation, "BoringSSL") {
			t.Errorf("X25519 recommendation should mention BoringSSL browser support, got: %s", c.Recommendation)
		}
	})

	t.Run("signatures_contain_composite", func(t *testing.T) {
		// RSA signature (primitive known) → generic classifyVulnerable path
		c := ClassifyAlgorithm("RSA", "signature", 0)
		if !strings.Contains(c.Recommendation, "composite") {
			t.Errorf("RSA signature recommendation should contain 'composite', got: %s", c.Recommendation)
		}

		// ECDSA signature → generic classifyVulnerable path
		c = ClassifyAlgorithm("ECDSA", "signature", 0)
		if !strings.Contains(c.Recommendation, "composite") {
			t.Errorf("ECDSA signature recommendation should contain 'composite', got: %s", c.Recommendation)
		}

		// Ed25519 default primitive → vulnerableRecommendation
		c = ClassifyAlgorithm("Ed25519", "", 0)
		if !strings.Contains(c.Recommendation, "composite") {
			t.Errorf("Ed25519 default recommendation should contain 'composite', got: %s", c.Recommendation)
		}

		// DSA signature → generic classifyVulnerable path (has composite from generic text)
		c = ClassifyAlgorithm("DSA", "signature", 0)
		if !strings.Contains(c.Recommendation, "composite") {
			t.Errorf("DSA signature recommendation should contain 'composite', got: %s", c.Recommendation)
		}
	})

	t.Run("DSA_no_hybrid_path_in_default_primitive", func(t *testing.T) {
		// DSA with unknown primitive hits vulnerableRecommendation — explicitly states no hybrid path
		c := ClassifyAlgorithm("DSA", "", 0)
		if !strings.Contains(c.Recommendation, "no hybrid path") {
			t.Errorf("DSA default recommendation should state 'no hybrid path', got: %s", c.Recommendation)
		}
	})

	t.Run("deprecated_no_hybrid", func(t *testing.T) {
		// MD5 — classically broken, no hybrid applicable
		c := ClassifyAlgorithm("MD5", "hash", 0)
		if strings.Contains(c.Recommendation, "hybrid") {
			t.Errorf("MD5 recommendation should not contain 'hybrid', got: %s", c.Recommendation)
		}

		// SHA-1 — classically broken, no hybrid applicable
		c = ClassifyAlgorithm("SHA-1", "hash", 0)
		if strings.Contains(c.Recommendation, "hybrid") {
			t.Errorf("SHA-1 recommendation should not contain 'hybrid', got: %s", c.Recommendation)
		}

		// DES — classically broken, no hybrid applicable
		c = ClassifyAlgorithm("DES", "symmetric", 0)
		if strings.Contains(c.Recommendation, "hybrid") {
			t.Errorf("DES recommendation should not contain 'hybrid', got: %s", c.Recommendation)
		}

		// RC4 — classically broken, no hybrid applicable
		c = ClassifyAlgorithm("RC4", "stream-cipher", 0)
		if strings.Contains(c.Recommendation, "hybrid") {
			t.Errorf("RC4 recommendation should not contain 'hybrid', got: %s", c.Recommendation)
		}

		// Blowfish — classically broken, no hybrid applicable
		c = ClassifyAlgorithm("Blowfish", "", 0)
		if strings.Contains(c.Recommendation, "hybrid") {
			t.Errorf("Blowfish recommendation should not contain 'hybrid', got: %s", c.Recommendation)
		}
	})
}
