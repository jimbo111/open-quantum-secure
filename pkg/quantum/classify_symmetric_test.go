package quantum

import (
	"strings"
	"testing"
)

// TestClassifySymmetricAndHash is a comprehensive table-driven test for
// ClassifyAlgorithm covering all symmetric and hash algorithm categories.
func TestClassifySymmetricAndHash(t *testing.T) {
	type testCase struct {
		name      string
		algName   string
		primitive string
		keySize   int
		wantRisk  Risk
		wantSev   Severity
		wantRecNonEmpty bool // true if Recommendation must be non-empty
	}

	tests := []testCase{
		// =========================================================
		// AES variants
		// =========================================================

		// AES-128: keySize=128 → classifySymmetric → 128 < 256 → weakened/low
		{
			name: "AES-128 weakened by Grover",
			algName: "AES-128", primitive: "symmetric", keySize: 128,
			wantRisk: RiskWeakened, wantSev: SeverityLow, wantRecNonEmpty: true,
		},
		// AES-192: 128 ≤ 192 < 256 → weakened/low
		{
			name: "AES-192 weakened",
			algName: "AES-192", primitive: "symmetric", keySize: 192,
			wantRisk: RiskWeakened, wantSev: SeverityLow, wantRecNonEmpty: true,
		},
		// AES-256: keySize=256 → resistant/info
		{
			name: "AES-256 resistant",
			algName: "AES-256", primitive: "symmetric", keySize: 256,
			wantRisk: RiskResistant, wantSev: SeverityInfo,
		},
		// AES-128-GCM with no explicit keySize: inferred 128 from name →
		// weakened (Grover's halves effective security to ~64-bit)
		{
			name: "AES-128-GCM no explicit keySize (inferred 128)",
			algName: "AES-128-GCM", primitive: "ae", keySize: 0,
			wantRisk: RiskWeakened, wantSev: SeverityLow, wantRecNonEmpty: true,
		},
		// AES-128-GCM with explicit keySize=128 → weakened/low
		{
			name: "AES-128-GCM explicit keySize=128 weakened",
			algName: "AES-128-GCM", primitive: "ae", keySize: 128,
			wantRisk: RiskWeakened, wantSev: SeverityLow, wantRecNonEmpty: true,
		},
		// AES-256-GCM with explicit keySize=256 → resistant
		{
			name: "AES-256-GCM explicit keySize=256 resistant",
			algName: "AES-256-GCM", primitive: "ae", keySize: 256,
			wantRisk: RiskResistant, wantSev: SeverityInfo,
		},
		// AES-256-CBC: keySize=256 → resistant
		{
			name: "AES-256-CBC resistant",
			algName: "AES-256-CBC", primitive: "block-cipher", keySize: 256,
			wantRisk: RiskResistant, wantSev: SeverityInfo,
		},
		// AES-128-CTR: keySize=128 → weakened/low
		{
			name: "AES-128-CTR weakened",
			algName: "AES-128-CTR", primitive: "block-cipher", keySize: 128,
			wantRisk: RiskWeakened, wantSev: SeverityLow, wantRecNonEmpty: true,
		},
		// AES-256-CCM: keySize=256 → resistant
		{
			name: "AES-256-CCM resistant",
			algName: "AES-256-CCM", primitive: "aead", keySize: 256,
			wantRisk: RiskResistant, wantSev: SeverityInfo,
		},
		// AES-128-ECB: keySize=0, inferred 128 from name → weakened
		{
			name: "AES-128-ECB no keySize inferred 128 weakened",
			algName: "AES-128-ECB", primitive: "", keySize: 0,
			wantRisk: RiskWeakened, wantSev: SeverityLow, wantRecNonEmpty: true,
		},
		// AES with explicit keySize parameter (no mode suffix)
		{
			name: "AES explicit keySize=256",
			algName: "AES", primitive: "block-cipher", keySize: 256,
			wantRisk: RiskResistant, wantSev: SeverityInfo,
		},
		{
			name: "AES explicit keySize=128",
			algName: "AES", primitive: "block-cipher", keySize: 128,
			wantRisk: RiskWeakened, wantSev: SeverityLow, wantRecNonEmpty: true,
		},

		// =========================================================
		// ChaCha20 variants
		// =========================================================

		// ChaCha20 with no keySize: baseName=ChaCha20, isLikelySymmetric →
		// quantumResistantSymmetric["CHACHA20"]=true → resistant
		{
			name: "ChaCha20 no keySize name-based resistant",
			algName: "ChaCha20", primitive: "", keySize: 0,
			wantRisk: RiskResistant, wantSev: SeverityInfo,
		},
		// ChaCha20 with explicit 256-bit key
		{
			name: "ChaCha20 keySize=256 resistant",
			algName: "ChaCha20", primitive: "stream-cipher", keySize: 256,
			wantRisk: RiskResistant, wantSev: SeverityInfo,
		},
		// ChaCha20-Poly1305 with no keySize: baseName=ChaCha20, primitive=ae →
		// classifySymmetric → quantumResistantSymmetric["CHACHA20"] → resistant
		{
			name: "ChaCha20-Poly1305 no keySize resistant",
			algName: "ChaCha20-Poly1305", primitive: "ae", keySize: 0,
			wantRisk: RiskResistant, wantSev: SeverityInfo,
		},
		// ChaCha20-Poly1305 with explicit keySize=256
		{
			name: "ChaCha20-Poly1305 keySize=256 resistant",
			algName: "ChaCha20-Poly1305", primitive: "aead", keySize: 256,
			wantRisk: RiskResistant, wantSev: SeverityInfo,
		},

		// =========================================================
		// Camellia variants
		// =========================================================

		// Camellia-128: keySize=128 → weakened/low
		{
			name: "Camellia-128 weakened",
			algName: "Camellia-128", primitive: "block-cipher", keySize: 128,
			wantRisk: RiskWeakened, wantSev: SeverityLow, wantRecNonEmpty: true,
		},
		// Camellia-256: keySize=256 → resistant
		{
			name: "Camellia-256 resistant",
			algName: "Camellia-256", primitive: "block-cipher", keySize: 256,
			wantRisk: RiskResistant, wantSev: SeverityInfo,
		},

		// =========================================================
		// Korean symmetric: ARIA
		// =========================================================

		// ARIA-128: keySize=128 → weakened/low
		{
			name: "ARIA-128 weakened",
			algName: "ARIA-128", primitive: "block-cipher", keySize: 128,
			wantRisk: RiskWeakened, wantSev: SeverityLow, wantRecNonEmpty: true,
		},
		// ARIA-192: keySize=192 < 256 → weakened/low
		{
			name: "ARIA-192 weakened",
			algName: "ARIA-192", primitive: "block-cipher", keySize: 192,
			wantRisk: RiskWeakened, wantSev: SeverityLow, wantRecNonEmpty: true,
		},
		// ARIA-256: keySize=256 → resistant
		{
			name: "ARIA-256 resistant",
			algName: "ARIA-256", primitive: "block-cipher", keySize: 256,
			wantRisk: RiskResistant, wantSev: SeverityInfo,
		},
		// ARIA no keySize: bare name, can't infer key size → conservative RiskUnknown
		{
			name: "ARIA no keySize bare name unknown",
			algName: "ARIA", primitive: "block-cipher", keySize: 0,
			wantRisk: RiskUnknown, wantSev: SeverityLow, wantRecNonEmpty: true,
		},

		// =========================================================
		// Korean symmetric: LEA
		// =========================================================

		// LEA-128: keySize=128 → weakened/low
		{
			name: "LEA-128 weakened",
			algName: "LEA-128", primitive: "block-cipher", keySize: 128,
			wantRisk: RiskWeakened, wantSev: SeverityLow, wantRecNonEmpty: true,
		},
		// LEA-256: keySize=256 → resistant
		{
			name: "LEA-256 resistant",
			algName: "LEA-256", primitive: "block-cipher", keySize: 256,
			wantRisk: RiskResistant, wantSev: SeverityInfo,
		},
		// LEA no keySize: bare name, can't infer key size → conservative RiskUnknown
		{
			name: "LEA no keySize bare name unknown",
			algName: "LEA", primitive: "block-cipher", keySize: 0,
			wantRisk: RiskUnknown, wantSev: SeverityLow, wantRecNonEmpty: true,
		},

		// =========================================================
		// Korean symmetric: SEED
		// =========================================================

		// SEED (128-bit only cipher, no ECB): weakened/low
		{
			name: "SEED default weakened (128-bit only)",
			algName: "SEED", primitive: "block-cipher", keySize: 0,
			wantRisk: RiskWeakened, wantSev: SeverityLow, wantRecNonEmpty: true,
		},
		// SEED-128-CBC: baseName=SEED, not ECB → weakened/low
		{
			name: "SEED-128-CBC weakened",
			algName: "SEED-128-CBC", primitive: "block-cipher", keySize: 0,
			wantRisk: RiskWeakened, wantSev: SeverityLow, wantRecNonEmpty: true,
		},
		// SEED-ECB: deprecated (ECB mode, no authentication)
		{
			name: "SEED-ECB deprecated",
			algName: "SEED-ECB", primitive: "block-cipher", keySize: 0,
			wantRisk: RiskDeprecated, wantSev: SeverityCritical, wantRecNonEmpty: true,
		},

		// =========================================================
		// Hash functions — quantum-resistant
		// =========================================================

		// SHA-256: baseName=SHA (splits at '-'), isLikelyHash prefix SHA → true.
		// hashOutputSize contains "256" → 256. Not < 256.
		// quantumResistantHash["SHA"] → false. effectiveSize=256 >= 256 → resistant.
		{
			name: "SHA-256 resistant",
			algName: "SHA-256", primitive: "hash", keySize: 0,
			wantRisk: RiskResistant, wantSev: SeverityInfo,
		},
		// SHA-384: hashOutputSize → 384, quantumResistantHash["SHA"]=false, 384 >= 256 → resistant
		{
			name: "SHA-384 resistant",
			algName: "SHA-384", primitive: "hash", keySize: 0,
			wantRisk: RiskResistant, wantSev: SeverityInfo,
		},
		// SHA-512: resistant
		{
			name: "SHA-512 resistant",
			algName: "SHA-512", primitive: "hash", keySize: 0,
			wantRisk: RiskResistant, wantSev: SeverityInfo,
		},
		// SHA-256 explicit primitive=hash with keySize=256
		{
			name: "SHA-256 explicit keySize=256 resistant",
			algName: "SHA-256", primitive: "hash", keySize: 256,
			wantRisk: RiskResistant, wantSev: SeverityInfo,
		},
		// SHA3-256: baseName=SHA3, isLikelyHash → true.
		// hashOutputSize: "SHA3-256" contains "256" → 256. Not < 256.
		// quantumResistantHash["SHA3"]=true → resistant
		{
			name: "SHA3-256 resistant",
			algName: "SHA3-256", primitive: "hash", keySize: 0,
			wantRisk: RiskResistant, wantSev: SeverityInfo,
		},
		// SHA3-512: hashOutputSize → 512, quantumResistantHash["SHA3"]=true → resistant
		{
			name: "SHA3-512 resistant",
			algName: "SHA3-512", primitive: "hash", keySize: 0,
			wantRisk: RiskResistant, wantSev: SeverityInfo,
		},
		// BLAKE2b: baseName=BLAKE2b, isLikelyHash → true.
		// hashOutputSize: no numeric suffix → 0. quantumResistantHash["BLAKE2B"]=true → resistant
		{
			name: "BLAKE2b resistant",
			algName: "BLAKE2b", primitive: "hash", keySize: 0,
			wantRisk: RiskResistant, wantSev: SeverityInfo,
		},
		// BLAKE2s: baseName=BLAKE2s, quantumResistantHash["BLAKE2S"]=true → resistant
		{
			name: "BLAKE2s resistant",
			algName: "BLAKE2s", primitive: "hash", keySize: 0,
			wantRisk: RiskResistant, wantSev: SeverityInfo,
		},
		// BLAKE3: baseName=BLAKE3 (no separator), isLikelyHash (prefix BLAKE) → true.
		// hashOutputSize → 0. quantumResistantHash["BLAKE3"]=true → resistant
		{
			name: "BLAKE3 resistant",
			algName: "BLAKE3", primitive: "hash", keySize: 0,
			wantRisk: RiskResistant, wantSev: SeverityInfo,
		},

		// =========================================================
		// Hash functions — quantum-weakened
		// =========================================================

		// SHA-224: hashOutputSize → 224 < 256 → weakened/low
		{
			name: "SHA-224 weakened (< 256 bits output)",
			algName: "SHA-224", primitive: "hash", keySize: 0,
			wantRisk: RiskWeakened, wantSev: SeverityLow, wantRecNonEmpty: true,
		},

		// =========================================================
		// Hash functions — deprecated
		// =========================================================

		// MD5: in deprecatedAlgorithms → deprecated/critical
		{
			name: "MD5 deprecated",
			algName: "MD5", primitive: "hash", keySize: 0,
			wantRisk: RiskDeprecated, wantSev: SeverityCritical, wantRecNonEmpty: true,
		},
		// MD4: in deprecatedAlgorithms → deprecated
		{
			name: "MD4 deprecated",
			algName: "MD4", primitive: "hash", keySize: 0,
			wantRisk: RiskDeprecated, wantSev: SeverityCritical, wantRecNonEmpty: true,
		},
		// SHA-1: in deprecatedAlgorithms → deprecated
		{
			name: "SHA-1 deprecated",
			algName: "SHA-1", primitive: "hash", keySize: 0,
			wantRisk: RiskDeprecated, wantSev: SeverityCritical, wantRecNonEmpty: true,
		},
		// SHA1 (alternate form): in deprecatedAlgorithms → deprecated
		{
			name: "SHA1 alternate form deprecated",
			algName: "SHA1", primitive: "hash", keySize: 0,
			wantRisk: RiskDeprecated, wantSev: SeverityCritical, wantRecNonEmpty: true,
		},

		// =========================================================
		// Korean hash functions
		// =========================================================

		// LSH-256-256: baseName=LSH. LSH prefix branch: hashOutputSize("LSH","LSH-256-256",0)
		// → contains "256" → 256. size==256 → weakened/low
		{
			name: "LSH-256-256 weakened (~128-bit quantum security)",
			algName: "LSH-256-256", primitive: "hash", keySize: 0,
			wantRisk: RiskWeakened, wantSev: SeverityLow, wantRecNonEmpty: true,
		},
		// LSH-512-512: hashOutputSize → 512 >= 512 → resistant
		{
			name: "LSH-512-512 resistant",
			algName: "LSH-512-512", primitive: "hash", keySize: 0,
			wantRisk: RiskResistant, wantSev: SeverityInfo,
		},
		// HAS-160: in deprecatedAlgorithms → deprecated/critical
		{
			name: "HAS-160 deprecated",
			algName: "HAS-160", primitive: "hash", keySize: 0,
			wantRisk: RiskDeprecated, wantSev: SeverityCritical, wantRecNonEmpty: true,
		},

		// =========================================================
		// KDF and MAC
		// =========================================================

		// HMAC-SHA256: baseName=HMAC, isLikelyHash (prefix HMAC) → true.
		// classifySymmetric(isHash=true): hashOutputSize contains "256" → 256.
		// Not < 256. quantumResistantHash["HMAC"]=false. effectiveSize=256 >= 256 → resistant.
		{
			name: "HMAC-SHA256 resistant",
			algName: "HMAC-SHA256", primitive: "mac", keySize: 0,
			wantRisk: RiskResistant, wantSev: SeverityInfo,
		},
		// HKDF: baseName=HKDF, isLikelyHash (prefix HKDF) → true.
		// quantumResistantHash["HKDF"]=true → resistant
		{
			name: "HKDF resistant",
			algName: "HKDF", primitive: "kdf", keySize: 0,
			wantRisk: RiskResistant, wantSev: SeverityInfo,
		},
		// PBKDF2: baseName=PBKDF2, isLikelyHash (prefix PBKDF) → true.
		// quantumResistantHash["PBKDF2"]=true → resistant
		{
			name: "PBKDF2 resistant",
			algName: "PBKDF2", primitive: "kdf", keySize: 0,
			wantRisk: RiskResistant, wantSev: SeverityInfo,
		},
		// Argon2: isLikelyHash (prefix ARGON) → true.
		// hashOutputSize("Argon2","ARGON2",0) → 0. quantumResistantHash["ARGON2"]=true → resistant
		{
			name: "Argon2 resistant",
			algName: "Argon2", primitive: "kdf", keySize: 0,
			wantRisk: RiskResistant, wantSev: SeverityInfo,
		},
		// scrypt: isLikelyHash (prefix SCRYPT) → true.
		// quantumResistantHash["SCRYPT"]=true → resistant
		{
			name: "scrypt resistant",
			algName: "scrypt", primitive: "kdf", keySize: 0,
			wantRisk: RiskResistant, wantSev: SeverityInfo,
		},
		// CMAC: baseName=CMAC. Not deprecated. Not isLikelySymmetric. Not isLikelyHash.
		// → RiskUnknown, SeverityLow
		{
			name: "CMAC unknown (no prefix match)",
			algName: "CMAC", primitive: "", keySize: 0,
			wantRisk: RiskUnknown, wantSev: SeverityLow,
		},

		// =========================================================
		// Deprecated symmetric algorithms
		// =========================================================

		// DES: in deprecatedAlgorithms → deprecated
		{
			name: "DES deprecated",
			algName: "DES", primitive: "block-cipher", keySize: 0,
			wantRisk: RiskDeprecated, wantSev: SeverityCritical, wantRecNonEmpty: true,
		},
		// 3DES: in deprecatedAlgorithms → deprecated
		{
			name: "3DES deprecated",
			algName: "3DES", primitive: "block-cipher", keySize: 0,
			wantRisk: RiskDeprecated, wantSev: SeverityCritical, wantRecNonEmpty: true,
		},
		// Triple-DES: deprecatedAlgorithms["Triple-DES"]=true, checked via name param → deprecated
		{
			name: "Triple-DES deprecated",
			algName: "Triple-DES", primitive: "block-cipher", keySize: 0,
			wantRisk: RiskDeprecated, wantSev: SeverityCritical, wantRecNonEmpty: true,
		},
		// DES-EDE3: baseName=DES → deprecatedAlgorithms["DES"]=true → deprecated
		{
			name: "DES-EDE3 deprecated",
			algName: "DES-EDE3", primitive: "block-cipher", keySize: 0,
			wantRisk: RiskDeprecated, wantSev: SeverityCritical, wantRecNonEmpty: true,
		},
		// TDEA: in deprecatedAlgorithms → deprecated
		{
			name: "TDEA deprecated",
			algName: "TDEA", primitive: "block-cipher", keySize: 0,
			wantRisk: RiskDeprecated, wantSev: SeverityCritical, wantRecNonEmpty: true,
		},
		// RC2: in deprecatedAlgorithms → deprecated
		{
			name: "RC2 deprecated",
			algName: "RC2", primitive: "block-cipher", keySize: 0,
			wantRisk: RiskDeprecated, wantSev: SeverityCritical, wantRecNonEmpty: true,
		},
		// RC4: in deprecatedAlgorithms → deprecated
		{
			name: "RC4 deprecated",
			algName: "RC4", primitive: "stream-cipher", keySize: 0,
			wantRisk: RiskDeprecated, wantSev: SeverityCritical, wantRecNonEmpty: true,
		},
		// RC5: in deprecatedAlgorithms → deprecated
		{
			name: "RC5 deprecated",
			algName: "RC5", primitive: "block-cipher", keySize: 0,
			wantRisk: RiskDeprecated, wantSev: SeverityCritical, wantRecNonEmpty: true,
		},
		// Blowfish: in deprecatedAlgorithms → deprecated
		{
			name: "Blowfish deprecated",
			algName: "Blowfish", primitive: "block-cipher", keySize: 0,
			wantRisk: RiskDeprecated, wantSev: SeverityCritical, wantRecNonEmpty: true,
		},

		// =========================================================
		// Edge cases
		// =========================================================

		// keySize=0 with bare name "AES" (no size in name): conservative RiskUnknown
		{
			name: "AES keySize=0 bare name unknown",
			algName: "AES", primitive: "symmetric", keySize: 0,
			wantRisk: RiskUnknown, wantSev: SeverityLow, wantRecNonEmpty: true,
		},
		// keySize=64 (too small, < 128): weakened/medium
		{
			name: "AES keySize=64 too small weakened medium",
			algName: "AES", primitive: "symmetric", keySize: 64,
			wantRisk: RiskWeakened, wantSev: SeverityMedium, wantRecNonEmpty: true,
		},
		// keySize=192 (128 ≤ 192 < 256): weakened/low
		{
			name: "AES keySize=192 weakened low",
			algName: "AES", primitive: "symmetric", keySize: 192,
			wantRisk: RiskWeakened, wantSev: SeverityLow, wantRecNonEmpty: true,
		},
		// keySize=512 (≥ 256): resistant
		{
			name: "AES keySize=512 resistant",
			algName: "AES", primitive: "symmetric", keySize: 512,
			wantRisk: RiskResistant, wantSev: SeverityInfo,
		},
		// Mixed case input: "aes-256-gcm" → upperName=AES-256-GCM, isLikelySymmetric → true,
		// keySize=256 → resistant
		{
			name: "Mixed case aes-256-gcm resistant",
			algName: "aes-256-gcm", primitive: "ae", keySize: 256,
			wantRisk: RiskResistant, wantSev: SeverityInfo,
		},
		// Underscore separator: "AES_256_GCM" → baseName=AES (split on '_'), keySize=0,
		// quantumResistantSymmetric["AES"] → resistant
		{
			name: "Underscore AES_256_GCM no keySize resistant",
			algName: "AES_256_GCM", primitive: "symmetric", keySize: 0,
			wantRisk: RiskResistant, wantSev: SeverityInfo,
		},
		// Underscore with explicit keySize=128: weakened
		{
			name: "Underscore AES_128_CBC keySize=128 weakened",
			algName: "AES_128_CBC", primitive: "symmetric", keySize: 128,
			wantRisk: RiskWeakened, wantSev: SeverityLow, wantRecNonEmpty: true,
		},
	}

	for _, tt := range tests {
		tt := tt
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
			if tt.wantRecNonEmpty && strings.TrimSpace(got.Recommendation) == "" {
				t.Errorf("ClassifyAlgorithm(%q, %q, %d).Recommendation is empty, want non-empty",
					tt.algName, tt.primitive, tt.keySize)
			}
		})
	}
}

// TestClassifyAES192 verifies that AES-192 with explicit keySize=192 is classified
// as QRWeakened (not Resistant). Grover's algorithm reduces AES-192 to ~96-bit
// effective security, which is below the 128-bit quantum safety threshold.
func TestClassifyAES192(t *testing.T) {
	got := ClassifyAlgorithm("AES-192", "symmetric", 192)

	if got.Risk != RiskWeakened {
		t.Errorf("ClassifyAlgorithm(%q, %q, %d).Risk = %q, want %q",
			"AES-192", "symmetric", 192, got.Risk, RiskWeakened)
	}
	if got.Severity != SeverityLow {
		t.Errorf("ClassifyAlgorithm(%q, %q, %d).Severity = %q, want %q",
			"AES-192", "symmetric", 192, got.Severity, SeverityLow)
	}
	if got.Recommendation == "" {
		t.Errorf("ClassifyAlgorithm(%q, %q, %d).Recommendation is empty, want non-empty",
			"AES-192", "symmetric", 192)
	}
}

// TestClassifySymmetricRecommendationContent verifies recommendation content for
// well-known deprecated and weakened algorithms matches expected migration guidance.
func TestClassifySymmetricRecommendationContent(t *testing.T) {
	tests := []struct {
		algName   string
		primitive string
		keySize   int
		contains  string
	}{
		// Deprecated symmetric recommendations
		{"DES", "block-cipher", 0, "AES-256"},
		{"3DES", "block-cipher", 0, "AES-256"},
		{"Triple-DES", "block-cipher", 0, "AES-256"},
		{"TDEA", "block-cipher", 0, "AES-256"},
		{"RC4", "stream-cipher", 0, "AES-256"},
		{"RC2", "block-cipher", 0, "AES-256"},
		{"RC5", "block-cipher", 0, "AES-256"},
		{"Blowfish", "block-cipher", 0, "AES-256"},
		// Deprecated hash recommendations
		{"MD5", "hash", 0, "SHA-256"},
		{"MD4", "hash", 0, "SHA-256"},
		{"SHA-1", "hash", 0, "SHA-256"},
		{"SHA1", "hash", 0, "SHA-256"},
		{"HAS-160", "hash", 0, "SHA-256"},
		// Weakened symmetric recommendations
		{"AES-128", "symmetric", 128, "256"},
		{"ARIA-128", "block-cipher", 128, "256"},
		{"LEA-128", "block-cipher", 128, "256"},
		// SEED recommendations
		{"SEED", "block-cipher", 0, "ARIA-256"},
		{"SEED-ECB", "block-cipher", 0, "ARIA-256"},
		// Weakened hash recommendations
		{"SHA-224", "hash", 0, "SHA-256"},
		// LSH weakened recommendations
		{"LSH-256-256", "hash", 0, "LSH-512"},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.algName+"_rec_content", func(t *testing.T) {
			got := ClassifyAlgorithm(tt.algName, tt.primitive, tt.keySize)
			if !strings.Contains(got.Recommendation, tt.contains) {
				t.Errorf("ClassifyAlgorithm(%q, %q, %d).Recommendation = %q, want to contain %q",
					tt.algName, tt.primitive, tt.keySize, got.Recommendation, tt.contains)
			}
		})
	}
}

// TestClassifySymmetricKeySizeThresholds verifies the precise key-size boundary
// behaviour for symmetric ciphers: < 128 → weakened/medium, 128–255 → weakened/low,
// ≥ 256 → resistant/info.
func TestClassifySymmetricKeySizeThresholds(t *testing.T) {
	tests := []struct {
		keySize int
		wantRisk Risk
		wantSev  Severity
	}{
		{64,  RiskWeakened,  SeverityMedium},
		{80,  RiskWeakened,  SeverityMedium},
		{112, RiskWeakened,  SeverityMedium},
		{127, RiskWeakened,  SeverityMedium},
		{128, RiskWeakened,  SeverityLow},
		{192, RiskWeakened,  SeverityLow},
		{255, RiskWeakened,  SeverityLow},
		{256, RiskResistant, SeverityInfo},
		{384, RiskResistant, SeverityInfo},
		{512, RiskResistant, SeverityInfo},
	}

	for _, tt := range tests {
		tt := tt
		t.Run("AES_keySize_boundary", func(t *testing.T) {
			got := ClassifyAlgorithm("AES", "symmetric", tt.keySize)
			if got.Risk != tt.wantRisk {
				t.Errorf("keySize=%d: Risk = %q, want %q", tt.keySize, got.Risk, tt.wantRisk)
			}
			if got.Severity != tt.wantSev {
				t.Errorf("keySize=%d: Severity = %q, want %q", tt.keySize, got.Severity, tt.wantSev)
			}
		})
	}
}

// TestClassifyHashOutputSizeThresholds verifies that hash output size < 256 bits
// is classified as weakened, and >= 256 bits as resistant, using the hash primitive.
func TestClassifyHashOutputSizeThresholds(t *testing.T) {
	tests := []struct {
		algName  string
		keySize  int
		wantRisk Risk
		wantSev  Severity
	}{
		// Explicit keySize drives hashOutputSize for unknown hash
		{"UnknownHash", 128, RiskWeakened,  SeverityLow},
		{"UnknownHash", 160, RiskWeakened,  SeverityLow},
		{"UnknownHash", 224, RiskWeakened,  SeverityLow},
		// At 256 and above: resistant (effectiveSize >= 256 path)
		{"UnknownHash", 256, RiskResistant, SeverityInfo},
		{"UnknownHash", 384, RiskResistant, SeverityInfo},
		{"UnknownHash", 512, RiskResistant, SeverityInfo},
	}

	for _, tt := range tests {
		tt := tt
		t.Run("hash_output_boundary", func(t *testing.T) {
			got := ClassifyAlgorithm(tt.algName, "hash", tt.keySize)
			if got.Risk != tt.wantRisk {
				t.Errorf("algName=%q keySize=%d: Risk = %q, want %q",
					tt.algName, tt.keySize, got.Risk, tt.wantRisk)
			}
			if got.Severity != tt.wantSev {
				t.Errorf("algName=%q keySize=%d: Severity = %q, want %q",
					tt.algName, tt.keySize, got.Severity, tt.wantSev)
			}
		})
	}
}
