package quantum

import (
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
		{name: "ECDSA", input: "ECDSA", wantAlg: "ML-DSA-44", wantStd: "FIPS 204"},
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
		// RSA key-size ladder
		{name: "RSA-2048", alg: "RSA", keySize: 2048, wantAlg: "ML-DSA-44", wantStd: "FIPS 204"},
		{name: "RSA-3072", alg: "RSA", keySize: 3072, wantAlg: "ML-DSA-65", wantStd: "FIPS 204"},
		{name: "RSA-4096", alg: "RSA", keySize: 4096, wantAlg: "ML-DSA-87", wantStd: "FIPS 204"},
		// ECDSA curve-size ladder
		{name: "ECDSA-256", alg: "ECDSA", keySize: 256, wantAlg: "ML-DSA-44", wantStd: "FIPS 204"},
		{name: "ECDSA-384", alg: "ECDSA", keySize: 384, wantAlg: "ML-DSA-65", wantStd: "FIPS 204"},
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

func TestClassifyAlgorithmTargetPopulation(t *testing.T) {
	tests := []struct {
		name          string
		alg           string
		primitive     string
		keySize       int
		wantNonEmpty  bool   // true if TargetAlgorithm should be set
		wantTargetAlg string // exact value when wantNonEmpty is true
	}{
		// RSA-2048 signature → vulnerable → TargetAlgorithm must be set
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
