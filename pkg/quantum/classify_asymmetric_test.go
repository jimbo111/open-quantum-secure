package quantum

import (
	"strings"
	"testing"
)

// assertVulnerable is a helper that checks Risk == RiskVulnerable,
// the expected Severity, and that Recommendation contains all wantSubstrings.
func assertVulnerable(t *testing.T, algName, primitive string, keySize int,
	wantSeverity Severity, wantSubstrings ...string) {
	t.Helper()
	got := ClassifyAlgorithm(algName, primitive, keySize)
	if got.Risk != RiskVulnerable {
		t.Errorf("ClassifyAlgorithm(%q, %q, %d).Risk = %q, want %q",
			algName, primitive, keySize, got.Risk, RiskVulnerable)
	}
	if got.Severity != wantSeverity {
		t.Errorf("ClassifyAlgorithm(%q, %q, %d).Severity = %q, want %q",
			algName, primitive, keySize, got.Severity, wantSeverity)
	}
	for _, sub := range wantSubstrings {
		if !strings.Contains(got.Recommendation, sub) {
			t.Errorf("ClassifyAlgorithm(%q, %q, %d).Recommendation = %q, want it to contain %q",
				algName, primitive, keySize, got.Recommendation, sub)
		}
	}
}

// TestClassifyAsymmetric_RSA covers all RSA variants across key sizes and primitives.
func TestClassifyAsymmetric_RSA(t *testing.T) {
	t.Run("RSA_key_sizes", func(t *testing.T) {
		cases := []struct {
			name      string
			algName   string
			primitive string
			keySize   int
			wantSev   Severity
			wantRec   []string
		}{
			{
				name:      "RSA-1024 default primitive",
				algName:   "RSA-1024",
				primitive: "",
				keySize:   1024,
				wantSev:   SeverityHigh,
				wantRec:   []string{"RSA", "quantum-vulnerable", "ML-DSA"},
			},
			{
				name:      "RSA-2048 default primitive",
				algName:   "RSA-2048",
				primitive: "",
				keySize:   2048,
				wantSev:   SeverityHigh,
				wantRec:   []string{"RSA", "ML-DSA"},
			},
			{
				name:      "RSA-4096 default primitive",
				algName:   "RSA-4096",
				primitive: "",
				keySize:   4096,
				wantSev:   SeverityHigh,
				wantRec:   []string{"RSA", "ML-DSA"},
			},
			{
				name:      "RSA-8192 default primitive",
				algName:   "RSA-8192",
				primitive: "",
				keySize:   8192,
				wantSev:   SeverityHigh,
				wantRec:   []string{"RSA", "ML-DSA"},
			},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				assertVulnerable(t, tc.algName, tc.primitive, tc.keySize, tc.wantSev, tc.wantRec...)
			})
		}
	})

	t.Run("RSA_signature_primitive", func(t *testing.T) {
		cases := []struct {
			algName string
			keySize int
		}{
			{"RSA", 2048},
			{"RSA-2048", 2048},
			{"RSA-4096", 4096},
		}
		for _, tc := range cases {
			t.Run(tc.algName, func(t *testing.T) {
				assertVulnerable(t, tc.algName, "signature", tc.keySize,
					SeverityHigh, "ML-DSA", "SLH-DSA")
			})
		}
	})

	t.Run("RSA_key_exchange_primitive", func(t *testing.T) {
		cases := []struct {
			algName   string
			primitive string
		}{
			{"RSA", "key-exchange"},
			{"RSA-2048", "key-agree"},
			{"RSA-4096", "kem"},
		}
		for _, tc := range cases {
			t.Run(tc.algName+"_"+tc.primitive, func(t *testing.T) {
				assertVulnerable(t, tc.algName, tc.primitive, 0,
					SeverityCritical, "ML-KEM")
			})
		}
	})

	t.Run("RSA_pke_primitive", func(t *testing.T) {
		// pke now routes to key-agree/kem/pke case → SeverityCritical (HNDL immediate)
		assertVulnerable(t, "RSA-2048", "pke", 2048, SeverityCritical,
			"ML-KEM")
	})

	t.Run("RSASSA-PKCS1_variants", func(t *testing.T) {
		cases := []struct {
			algName   string
			primitive string
			wantSev   Severity
			wantRec   []string
		}{
			{
				algName:   "RSASSA-PKCS1",
				primitive: "signature",
				wantSev:   SeverityHigh,
				wantRec:   []string{"ML-DSA", "SLH-DSA"},
			},
			{
				algName:   "RSASSA-PKCS1-v1_5",
				primitive: "signature",
				wantSev:   SeverityHigh,
				wantRec:   []string{"ML-DSA", "SLH-DSA"},
			},
			{
				algName:   "RSASSA-PKCS1",
				primitive: "",
				wantSev:   SeverityHigh,
				wantRec:   []string{"RSA"},
			},
		}
		for _, tc := range cases {
			t.Run(tc.algName+"_"+tc.primitive, func(t *testing.T) {
				assertVulnerable(t, tc.algName, tc.primitive, 0, tc.wantSev, tc.wantRec...)
			})
		}
	})

	t.Run("RSASSA-PSS_variants", func(t *testing.T) {
		cases := []struct {
			algName   string
			primitive string
			keySize   int
			wantSev   Severity
			wantRec   []string
		}{
			{
				algName:   "RSASSA-PSS",
				primitive: "signature",
				keySize:   2048,
				wantSev:   SeverityHigh,
				wantRec:   []string{"ML-DSA", "SLH-DSA"},
			},
			{
				algName:   "RSASSA-PSS",
				primitive: "",
				keySize:   0,
				wantSev:   SeverityHigh,
				wantRec:   []string{"RSA"},
			},
		}
		for _, tc := range cases {
			t.Run(tc.algName+"_"+tc.primitive, func(t *testing.T) {
				assertVulnerable(t, tc.algName, tc.primitive, tc.keySize, tc.wantSev, tc.wantRec...)
			})
		}
	})

	t.Run("RSAES-PKCS1_variants", func(t *testing.T) {
		cases := []struct {
			algName   string
			primitive string
			wantSev   Severity
			wantRec   []string
		}{
			{
				algName:   "RSAES-PKCS1",
				primitive: "pke",
				wantSev:   SeverityCritical,
				wantRec:   []string{"ML-KEM"},
			},
			{
				algName:   "RSAES-PKCS1",
				primitive: "key-exchange",
				wantSev:   SeverityCritical,
				wantRec:   []string{"ML-KEM"},
			},
			{
				algName:   "RSAES-PKCS1-v1_5",
				primitive: "",
				wantSev:   SeverityHigh,
				wantRec:   []string{"RSA"},
			},
		}
		for _, tc := range cases {
			t.Run(tc.algName+"_"+tc.primitive, func(t *testing.T) {
				assertVulnerable(t, tc.algName, tc.primitive, 0, tc.wantSev, tc.wantRec...)
			})
		}
	})

	t.Run("RSAES-OAEP_variants", func(t *testing.T) {
		cases := []struct {
			algName   string
			primitive string
			wantSev   Severity
			wantRec   []string
		}{
			{
				algName:   "RSAES-OAEP",
				primitive: "pke",
				wantSev:   SeverityCritical,
				wantRec:   []string{"ML-KEM"},
			},
			{
				algName:   "RSAES-OAEP",
				primitive: "key-exchange",
				wantSev:   SeverityCritical,
				wantRec:   []string{"ML-KEM"},
			},
			{
				algName:   "RSAES-OAEP",
				primitive: "signature",
				wantSev:   SeverityHigh,
				wantRec:   []string{"ML-DSA", "SLH-DSA"},
			},
			{
				algName:   "RSAES-OAEP",
				primitive: "",
				wantSev:   SeverityHigh,
				wantRec:   []string{"RSA"},
			},
		}
		for _, tc := range cases {
			t.Run(tc.algName+"_"+tc.primitive, func(t *testing.T) {
				assertVulnerable(t, tc.algName, tc.primitive, 0, tc.wantSev, tc.wantRec...)
			})
		}
	})
}

// TestClassifyAsymmetric_ECDSA covers ECDSA variants with different curves.
func TestClassifyAsymmetric_ECDSA(t *testing.T) {
	cases := []struct {
		name      string
		algName   string
		primitive string
		keySize   int
		wantSev   Severity
		wantRec   []string
	}{
		{
			name:      "ECDSA no curve",
			algName:   "ECDSA",
			primitive: "signature",
			keySize:   0,
			wantSev:   SeverityHigh,
			wantRec:   []string{"ML-DSA", "SLH-DSA"},
		},
		{
			name:      "ECDSA P-256",
			algName:   "ECDSA",
			primitive: "signature",
			keySize:   256,
			wantSev:   SeverityHigh,
			wantRec:   []string{"ML-DSA", "SLH-DSA"},
		},
		{
			name:      "ECDSA P-384",
			algName:   "ECDSA",
			primitive: "signature",
			keySize:   384,
			wantSev:   SeverityHigh,
			wantRec:   []string{"ML-DSA", "SLH-DSA"},
		},
		{
			name:      "ECDSA P-521",
			algName:   "ECDSA",
			primitive: "signature",
			keySize:   521,
			wantSev:   SeverityHigh,
			wantRec:   []string{"ML-DSA", "SLH-DSA"},
		},
		{
			name:      "ECDSA with curve suffix P256",
			algName:   "ECDSA-P256",
			primitive: "signature",
			keySize:   256,
			wantSev:   SeverityHigh,
			wantRec:   []string{"ML-DSA", "SLH-DSA"},
		},
		{
			name:      "ECDSA with curve suffix P384",
			algName:   "ECDSA-P384",
			primitive: "signature",
			keySize:   384,
			wantSev:   SeverityHigh,
			wantRec:   []string{"ML-DSA", "SLH-DSA"},
		},
		{
			name:      "ECDSA with curve suffix P521",
			algName:   "ECDSA-P521",
			primitive: "signature",
			keySize:   521,
			wantSev:   SeverityHigh,
			wantRec:   []string{"ML-DSA", "SLH-DSA"},
		},
		{
			name:      "ECDSA default primitive",
			algName:   "ECDSA",
			primitive: "",
			keySize:   0,
			wantSev:   SeverityHigh,
			wantRec:   []string{"ECDSA", "ML-DSA"},
		},
		{
			name:      "ECDSA key-exchange primitive",
			algName:   "ECDSA",
			primitive: "key-exchange",
			keySize:   256,
			wantSev:   SeverityCritical,
			wantRec:   []string{"ML-KEM"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assertVulnerable(t, tc.algName, tc.primitive, tc.keySize, tc.wantSev, tc.wantRec...)
		})
	}
}

// TestClassifyAsymmetric_ECDH_ECDHE covers ECDH and ECDHE key agreement variants.
func TestClassifyAsymmetric_ECDH_ECDHE(t *testing.T) {
	cases := []struct {
		name      string
		algName   string
		primitive string
		keySize   int
		wantSev   Severity
		wantRec   []string
	}{
		{
			name:      "ECDH key-agree",
			algName:   "ECDH",
			primitive: "key-agree",
			keySize:   0,
			wantSev:   SeverityCritical,
			wantRec:   []string{"ML-KEM"},
		},
		{
			name:      "ECDH key-exchange",
			algName:   "ECDH",
			primitive: "key-exchange",
			keySize:   0,
			wantSev:   SeverityCritical,
			wantRec:   []string{"ML-KEM"},
		},
		{
			name:      "ECDH kem",
			algName:   "ECDH",
			primitive: "kem",
			keySize:   0,
			wantSev:   SeverityCritical,
			wantRec:   []string{"ML-KEM"},
		},
		{
			name:      "ECDH P-256",
			algName:   "ECDH",
			primitive: "key-agree",
			keySize:   256,
			wantSev:   SeverityCritical,
			wantRec:   []string{"ML-KEM"},
		},
		{
			name:      "ECDH P-384",
			algName:   "ECDH",
			primitive: "key-agree",
			keySize:   384,
			wantSev:   SeverityCritical,
			wantRec:   []string{"ML-KEM"},
		},
		{
			name:      "ECDH P-521",
			algName:   "ECDH",
			primitive: "key-agree",
			keySize:   521,
			wantSev:   SeverityCritical,
			wantRec:   []string{"ML-KEM"},
		},
		{
			name:      "ECDH default primitive",
			algName:   "ECDH",
			primitive: "",
			keySize:   0,
			wantSev:   SeverityHigh,
			wantRec:   []string{"ML-KEM"},
		},
		{
			name:      "ECDHE key-agree",
			algName:   "ECDHE",
			primitive: "key-agree",
			keySize:   0,
			wantSev:   SeverityCritical,
			wantRec:   []string{"ML-KEM"},
		},
		{
			name:      "ECDHE key-exchange",
			algName:   "ECDHE",
			primitive: "key-exchange",
			keySize:   256,
			wantSev:   SeverityCritical,
			wantRec:   []string{"ML-KEM"},
		},
		{
			name:      "ECDHE kem",
			algName:   "ECDHE",
			primitive: "kem",
			keySize:   0,
			wantSev:   SeverityCritical,
			wantRec:   []string{"ML-KEM"},
		},
		{
			name:      "ECDHE default primitive",
			algName:   "ECDHE",
			primitive: "",
			keySize:   0,
			wantSev:   SeverityHigh,
			wantRec:   []string{"ML-KEM"},
		},
		{
			name:      "ECDH with curve suffix P256",
			algName:   "ECDH-P256",
			primitive: "key-exchange",
			keySize:   256,
			wantSev:   SeverityCritical,
			wantRec:   []string{"ML-KEM"},
		},
		{
			name:      "ECDHE with curve suffix secp384r1",
			algName:   "ECDHE-secp384r1",
			primitive: "key-agree",
			keySize:   384,
			wantSev:   SeverityCritical,
			wantRec:   []string{"ML-KEM"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assertVulnerable(t, tc.algName, tc.primitive, tc.keySize, tc.wantSev, tc.wantRec...)
		})
	}
}

// TestClassifyAsymmetric_EdDSA covers EdDSA, Ed25519, and Ed448.
func TestClassifyAsymmetric_EdDSA(t *testing.T) {
	cases := []struct {
		name      string
		algName   string
		primitive string
		keySize   int
		wantSev   Severity
		wantRec   []string
	}{
		{
			name:      "EdDSA signature",
			algName:   "EdDSA",
			primitive: "signature",
			keySize:   0,
			wantSev:   SeverityHigh,
			wantRec:   []string{"ML-DSA", "SLH-DSA"},
		},
		{
			name:      "EdDSA default primitive",
			algName:   "EdDSA",
			primitive: "",
			keySize:   0,
			wantSev:   SeverityHigh,
			wantRec:   []string{"EdDSA", "ML-DSA"},
		},
		{
			name:      "EdDSA key-exchange",
			algName:   "EdDSA",
			primitive: "key-exchange",
			keySize:   0,
			wantSev:   SeverityCritical,
			wantRec:   []string{"ML-KEM"},
		},
		{
			name:      "Ed25519 signature",
			algName:   "Ed25519",
			primitive: "signature",
			keySize:   256,
			wantSev:   SeverityHigh,
			wantRec:   []string{"ML-DSA", "SLH-DSA"},
		},
		{
			name:      "Ed25519 default primitive",
			algName:   "Ed25519",
			primitive: "",
			keySize:   0,
			wantSev:   SeverityHigh,
			wantRec:   []string{"EdDSA", "ML-DSA"},
		},
		{
			name:      "Ed448 signature",
			algName:   "Ed448",
			primitive: "signature",
			keySize:   448,
			wantSev:   SeverityHigh,
			wantRec:   []string{"ML-DSA", "SLH-DSA"},
		},
		{
			name:      "Ed448 default primitive",
			algName:   "Ed448",
			primitive: "",
			keySize:   0,
			wantSev:   SeverityHigh,
			wantRec:   []string{"EdDSA", "ML-DSA"},
		},
		{
			name:      "Ed448 key-exchange",
			algName:   "Ed448",
			primitive: "key-exchange",
			keySize:   0,
			wantSev:   SeverityCritical,
			wantRec:   []string{"ML-KEM"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assertVulnerable(t, tc.algName, tc.primitive, tc.keySize, tc.wantSev, tc.wantRec...)
		})
	}
}

// TestClassifyAsymmetric_DH covers DH, FFDH, and Diffie-Hellman variants.
func TestClassifyAsymmetric_DH(t *testing.T) {
	cases := []struct {
		name      string
		algName   string
		primitive string
		keySize   int
		wantSev   Severity
		wantRec   []string
	}{
		{
			name:      "DH key-agree",
			algName:   "DH",
			primitive: "key-agree",
			keySize:   0,
			wantSev:   SeverityCritical,
			wantRec:   []string{"ML-KEM"},
		},
		{
			name:      "DH key-exchange",
			algName:   "DH",
			primitive: "key-exchange",
			keySize:   0,
			wantSev:   SeverityCritical,
			wantRec:   []string{"ML-KEM"},
		},
		{
			name:      "DH kem",
			algName:   "DH",
			primitive: "kem",
			keySize:   0,
			wantSev:   SeverityCritical,
			wantRec:   []string{"ML-KEM"},
		},
		{
			name:      "DH-2048 key-agree",
			algName:   "DH-2048",
			primitive: "key-agree",
			keySize:   2048,
			wantSev:   SeverityCritical,
			wantRec:   []string{"ML-KEM"},
		},
		{
			name:      "DH-4096 key-agree",
			algName:   "DH-4096",
			primitive: "key-agree",
			keySize:   4096,
			wantSev:   SeverityCritical,
			wantRec:   []string{"ML-KEM"},
		},
		{
			name:      "DH default primitive",
			algName:   "DH",
			primitive: "",
			keySize:   0,
			wantSev:   SeverityHigh,
			wantRec:   []string{"ML-KEM"},
		},
		{
			name:      "DH signature primitive",
			algName:   "DH",
			primitive: "signature",
			keySize:   0,
			wantSev:   SeverityHigh,
			wantRec:   []string{"ML-DSA", "SLH-DSA"},
		},
		{
			name:      "FFDH key-agree",
			algName:   "FFDH",
			primitive: "key-agree",
			keySize:   2048,
			wantSev:   SeverityCritical,
			wantRec:   []string{"ML-KEM"},
		},
		{
			name:      "FFDH key-exchange",
			algName:   "FFDH",
			primitive: "key-exchange",
			keySize:   3072,
			wantSev:   SeverityCritical,
			wantRec:   []string{"ML-KEM"},
		},
		{
			name:      "FFDH default primitive",
			algName:   "FFDH",
			primitive: "",
			keySize:   0,
			wantSev:   SeverityHigh,
			wantRec:   []string{"ML-KEM"},
		},
		{
			name:      "Diffie-Hellman key-agree",
			algName:   "Diffie-Hellman",
			primitive: "key-agree",
			keySize:   2048,
			wantSev:   SeverityCritical,
			wantRec:   []string{"ML-KEM"},
		},
		{
			name:      "Diffie-Hellman key-exchange",
			algName:   "Diffie-Hellman",
			primitive: "key-exchange",
			keySize:   0,
			wantSev:   SeverityCritical,
			wantRec:   []string{"ML-KEM"},
		},
		{
			name:      "Diffie-Hellman default primitive",
			algName:   "Diffie-Hellman",
			primitive: "",
			keySize:   0,
			wantSev:   SeverityHigh,
			wantRec:   []string{"ML-KEM"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assertVulnerable(t, tc.algName, tc.primitive, tc.keySize, tc.wantSev, tc.wantRec...)
		})
	}
}

// TestClassifyAsymmetric_CurveBased covers X25519 and X448.
func TestClassifyAsymmetric_CurveBased(t *testing.T) {
	cases := []struct {
		name      string
		algName   string
		primitive string
		keySize   int
		wantSev   Severity
		wantRec   []string
	}{
		{
			name:      "X25519 key-exchange",
			algName:   "X25519",
			primitive: "key-exchange",
			keySize:   256,
			wantSev:   SeverityCritical,
			wantRec:   []string{"ML-KEM"},
		},
		{
			name:      "X25519 key-agree",
			algName:   "X25519",
			primitive: "key-agree",
			keySize:   0,
			wantSev:   SeverityCritical,
			wantRec:   []string{"ML-KEM"},
		},
		{
			name:      "X25519 kem",
			algName:   "X25519",
			primitive: "kem",
			keySize:   0,
			wantSev:   SeverityCritical,
			wantRec:   []string{"ML-KEM"},
		},
		{
			name:      "X25519 default primitive",
			algName:   "X25519",
			primitive: "",
			keySize:   0,
			wantSev:   SeverityHigh,
			wantRec:   []string{"ML-KEM"},
		},
		{
			name:      "X448 key-exchange",
			algName:   "X448",
			primitive: "key-exchange",
			keySize:   448,
			wantSev:   SeverityCritical,
			wantRec:   []string{"ML-KEM"},
		},
		{
			name:      "X448 key-agree",
			algName:   "X448",
			primitive: "key-agree",
			keySize:   0,
			wantSev:   SeverityCritical,
			wantRec:   []string{"ML-KEM"},
		},
		{
			name:      "X448 kem",
			algName:   "X448",
			primitive: "kem",
			keySize:   0,
			wantSev:   SeverityCritical,
			wantRec:   []string{"ML-KEM"},
		},
		{
			name:      "X448 default primitive",
			algName:   "X448",
			primitive: "",
			keySize:   0,
			wantSev:   SeverityHigh,
			wantRec:   []string{"ML-KEM"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assertVulnerable(t, tc.algName, tc.primitive, tc.keySize, tc.wantSev, tc.wantRec...)
		})
	}
}

// TestClassifyAsymmetric_Other covers ElGamal, ECIES, MQV, ECMQV, DSA.
func TestClassifyAsymmetric_Other(t *testing.T) {
	cases := []struct {
		name      string
		algName   string
		primitive string
		keySize   int
		wantSev   Severity
		wantRec   []string
	}{
		// ElGamal
		{
			name:      "ElGamal key-exchange",
			algName:   "ElGamal",
			primitive: "key-exchange",
			keySize:   2048,
			wantSev:   SeverityCritical,
			wantRec:   []string{"ML-KEM"},
		},
		{
			name:      "ElGamal pke",
			algName:   "ElGamal",
			primitive: "pke",
			keySize:   2048,
			wantSev:   SeverityCritical,
			wantRec:   []string{"ML-KEM"},
		},
		{
			name:      "ElGamal default primitive",
			algName:   "ElGamal",
			primitive: "",
			keySize:   0,
			wantSev:   SeverityHigh,
			wantRec:   []string{"NIST PQC"},
		},

		// ECIES
		{
			name:      "ECIES pke",
			algName:   "ECIES",
			primitive: "pke",
			keySize:   256,
			wantSev:   SeverityCritical,
			wantRec:   []string{"ML-KEM"},
		},
		{
			name:      "ECIES key-exchange",
			algName:   "ECIES",
			primitive: "key-exchange",
			keySize:   256,
			wantSev:   SeverityCritical,
			wantRec:   []string{"ML-KEM"},
		},
		{
			name:      "ECIES default primitive",
			algName:   "ECIES",
			primitive: "",
			keySize:   0,
			wantSev:   SeverityHigh,
			wantRec:   []string{"NIST PQC"},
		},

		// MQV
		{
			name:      "MQV key-agree",
			algName:   "MQV",
			primitive: "key-agree",
			keySize:   2048,
			wantSev:   SeverityCritical,
			wantRec:   []string{"ML-KEM"},
		},
		{
			name:      "MQV key-exchange",
			algName:   "MQV",
			primitive: "key-exchange",
			keySize:   0,
			wantSev:   SeverityCritical,
			wantRec:   []string{"ML-KEM"},
		},
		{
			name:      "MQV default primitive",
			algName:   "MQV",
			primitive: "",
			keySize:   0,
			wantSev:   SeverityHigh,
			wantRec:   []string{"NIST PQC"},
		},

		// ECMQV
		{
			name:      "ECMQV key-agree",
			algName:   "ECMQV",
			primitive: "key-agree",
			keySize:   256,
			wantSev:   SeverityCritical,
			wantRec:   []string{"ML-KEM"},
		},
		{
			name:      "ECMQV key-exchange",
			algName:   "ECMQV",
			primitive: "key-exchange",
			keySize:   384,
			wantSev:   SeverityCritical,
			wantRec:   []string{"ML-KEM"},
		},
		{
			name:      "ECMQV default primitive",
			algName:   "ECMQV",
			primitive: "",
			keySize:   0,
			wantSev:   SeverityHigh,
			wantRec:   []string{"NIST PQC"},
		},

		// DSA
		{
			name:      "DSA signature",
			algName:   "DSA",
			primitive: "signature",
			keySize:   2048,
			wantSev:   SeverityHigh,
			wantRec:   []string{"ML-DSA", "SLH-DSA"},
		},
		{
			name:      "DSA default primitive",
			algName:   "DSA",
			primitive: "",
			keySize:   0,
			wantSev:   SeverityHigh,
			wantRec:   []string{"NIST PQC"},
		},
		{
			name:      "DSA key-exchange",
			algName:   "DSA",
			primitive: "key-exchange",
			keySize:   0,
			wantSev:   SeverityCritical,
			wantRec:   []string{"ML-KEM"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assertVulnerable(t, tc.algName, tc.primitive, tc.keySize, tc.wantSev, tc.wantRec...)
		})
	}
}

// TestClassifyAsymmetric_Korean covers KCDSA and EC-KCDSA Korean standards.
func TestClassifyAsymmetric_Korean(t *testing.T) {
	cases := []struct {
		name      string
		algName   string
		primitive string
		keySize   int
		wantSev   Severity
		wantRec   []string
	}{
		{
			name:      "KCDSA signature",
			algName:   "KCDSA",
			primitive: "signature",
			keySize:   2048,
			wantSev:   SeverityHigh,
			wantRec:   []string{"ML-DSA", "SLH-DSA"},
		},
		{
			name:      "KCDSA default primitive",
			algName:   "KCDSA",
			primitive: "",
			keySize:   0,
			wantSev:   SeverityHigh,
			wantRec:   []string{"HAETAE", "ML-DSA"},
		},
		{
			name:      "KCDSA key-exchange",
			algName:   "KCDSA",
			primitive: "key-exchange",
			keySize:   0,
			wantSev:   SeverityCritical,
			wantRec:   []string{"ML-KEM"},
		},
		{
			name:      "KCDSA with key size 3072",
			algName:   "KCDSA",
			primitive: "signature",
			keySize:   3072,
			wantSev:   SeverityHigh,
			wantRec:   []string{"ML-DSA", "SLH-DSA"},
		},
		{
			name:      "EC-KCDSA signature",
			algName:   "EC-KCDSA",
			primitive: "signature",
			keySize:   256,
			wantSev:   SeverityHigh,
			wantRec:   []string{"ML-DSA", "SLH-DSA"},
		},
		{
			name:      "EC-KCDSA default primitive",
			algName:   "EC-KCDSA",
			primitive: "",
			keySize:   0,
			wantSev:   SeverityHigh,
			wantRec:   []string{"HAETAE", "ML-DSA"},
		},
		{
			name:      "EC-KCDSA key-exchange",
			algName:   "EC-KCDSA",
			primitive: "key-exchange",
			keySize:   0,
			wantSev:   SeverityCritical,
			wantRec:   []string{"ML-KEM"},
		},
		{
			name:      "EC-KCDSA P-256",
			algName:   "EC-KCDSA-P256",
			primitive: "signature",
			keySize:   256,
			wantSev:   SeverityHigh,
			wantRec:   []string{"ML-DSA", "SLH-DSA"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assertVulnerable(t, tc.algName, tc.primitive, tc.keySize, tc.wantSev, tc.wantRec...)
		})
	}
}

// TestClassifyAsymmetric_RecommendationContent verifies specific PQC migration
// guidance is present in recommendations for each algorithm family.
func TestClassifyAsymmetric_RecommendationContent(t *testing.T) {
	t.Run("RSA_default_mentions_MLDSA", func(t *testing.T) {
		got := ClassifyAlgorithm("RSA-2048", "", 2048)
		// RSA default (no primitive) routes to signing recommendation
		if !strings.Contains(got.Recommendation, "ML-DSA") {
			t.Errorf("RSA recommendation missing ML-DSA: %q", got.Recommendation)
		}
	})

	t.Run("ECDSA_default_mentions_MLDSA_and_SLHDSA", func(t *testing.T) {
		got := ClassifyAlgorithm("ECDSA", "", 0)
		if !strings.Contains(got.Recommendation, "ML-DSA") {
			t.Errorf("ECDSA recommendation missing ML-DSA: %q", got.Recommendation)
		}
	})

	t.Run("KCDSA_default_mentions_HAETAE", func(t *testing.T) {
		got := ClassifyAlgorithm("KCDSA", "", 0)
		if !strings.Contains(got.Recommendation, "HAETAE") {
			t.Errorf("KCDSA recommendation missing HAETAE: %q", got.Recommendation)
		}
	})

	t.Run("EC-KCDSA_default_mentions_HAETAE", func(t *testing.T) {
		got := ClassifyAlgorithm("EC-KCDSA", "", 0)
		if !strings.Contains(got.Recommendation, "HAETAE") {
			t.Errorf("EC-KCDSA recommendation missing HAETAE: %q", got.Recommendation)
		}
	})

	t.Run("EdDSA_default_mentions_MLDSA", func(t *testing.T) {
		got := ClassifyAlgorithm("EdDSA", "", 0)
		if !strings.Contains(got.Recommendation, "ML-DSA") {
			t.Errorf("EdDSA recommendation missing ML-DSA: %q", got.Recommendation)
		}
	})

	t.Run("ECDH_key_exchange_mentions_CNSA_deadline", func(t *testing.T) {
		got := ClassifyAlgorithm("ECDH", "key-exchange", 0)
		if !strings.Contains(got.Recommendation, "2030") {
			t.Errorf("ECDH key-exchange recommendation missing CNSA 2.0 deadline: %q", got.Recommendation)
		}
	})

	t.Run("RSA_signature_mentions_CNSA_deadline", func(t *testing.T) {
		got := ClassifyAlgorithm("RSA", "signature", 2048)
		if !strings.Contains(got.Recommendation, "2035") {
			t.Errorf("RSA signature recommendation missing CNSA 2.0 deadline: %q", got.Recommendation)
		}
	})

	t.Run("X25519_default_mentions_MLKEM", func(t *testing.T) {
		got := ClassifyAlgorithm("X25519", "", 0)
		if !strings.Contains(got.Recommendation, "ML-KEM") {
			t.Errorf("X25519 recommendation missing ML-KEM: %q", got.Recommendation)
		}
	})

	t.Run("DH_key_agree_mentions_CNSA_deadline", func(t *testing.T) {
		got := ClassifyAlgorithm("DH", "key-agree", 2048)
		if !strings.Contains(got.Recommendation, "2030") {
			t.Errorf("DH key-agree recommendation missing CNSA 2.0 deadline: %q", got.Recommendation)
		}
	})
}

// TestClassifyAsymmetric_PrimitiveSeverityMatrix verifies the severity mapping
// for each primitive type on a representative algorithm.
func TestClassifyAsymmetric_PrimitiveSeverityMatrix(t *testing.T) {
	primitiveToSeverity := []struct {
		primitive string
		wantSev   Severity
	}{
		{"key-exchange", SeverityCritical},
		{"key-agree", SeverityCritical},
		{"kem", SeverityCritical},
		{"signature", SeverityHigh},
		{"sign", SeverityHigh},           // normalizePrimitive("sign") → "signature"
		{"digital-signature", SeverityHigh}, // normalizePrimitive → "signature"
		{"pke", SeverityCritical},            // pke now routes to key-agree/kem/pke case
		{"public-key", SeverityCritical},     // normalizePrimitive → "pke" → Critical
		{"", SeverityHigh},               // default branch
	}

	// Use ECDH as the representative vulnerable algorithm
	for _, tc := range primitiveToSeverity {
		t.Run("ECDH_primitive_"+tc.primitive, func(t *testing.T) {
			got := ClassifyAlgorithm("ECDH", tc.primitive, 0)
			if got.Risk != RiskVulnerable {
				t.Errorf("ClassifyAlgorithm(ECDH, %q, 0).Risk = %q, want %q",
					tc.primitive, got.Risk, RiskVulnerable)
			}
			if got.Severity != tc.wantSev {
				t.Errorf("ClassifyAlgorithm(ECDH, %q, 0).Severity = %q, want %q",
					tc.primitive, got.Severity, tc.wantSev)
			}
		})
	}
}

// TestClassifyAsymmetric_EdgeCases covers boundary conditions.
func TestClassifyAsymmetric_EdgeCases(t *testing.T) {
	t.Run("empty_name_and_empty_primitive", func(t *testing.T) {
		got := ClassifyAlgorithm("", "", 0)
		// Empty name should not match any vulnerable family; falls to unknown
		if got.Risk != RiskUnknown {
			t.Errorf("ClassifyAlgorithm(\"\", \"\", 0).Risk = %q, want %q", got.Risk, RiskUnknown)
		}
		if got.Severity != SeverityLow {
			t.Errorf("ClassifyAlgorithm(\"\", \"\", 0).Severity = %q, want %q", got.Severity, SeverityLow)
		}
	})

	t.Run("empty_name_with_signature_primitive", func(t *testing.T) {
		// Unrecognized name + asymmetric primitive → RiskVulnerable per step 4
		got := ClassifyAlgorithm("", "signature", 0)
		if got.Risk != RiskVulnerable {
			t.Errorf("ClassifyAlgorithm(\"\", \"signature\", 0).Risk = %q, want %q", got.Risk, RiskVulnerable)
		}
		if got.Severity != SeverityHigh {
			t.Errorf("ClassifyAlgorithm(\"\", \"signature\", 0).Severity = %q, want %q", got.Severity, SeverityHigh)
		}
	})

	t.Run("zero_keySize_RSA", func(t *testing.T) {
		got := ClassifyAlgorithm("RSA", "", 0)
		if got.Risk != RiskVulnerable {
			t.Errorf("RSA with zero keySize Risk = %q, want %q", got.Risk, RiskVulnerable)
		}
	})

	t.Run("very_large_keySize_RSA", func(t *testing.T) {
		// Extremely large key size should not change the vulnerability classification
		got := ClassifyAlgorithm("RSA", "signature", 1<<20)
		if got.Risk != RiskVulnerable {
			t.Errorf("RSA with 1M keySize Risk = %q, want %q", got.Risk, RiskVulnerable)
		}
		if got.Severity != SeverityHigh {
			t.Errorf("RSA with 1M keySize Severity = %q, want %q", got.Severity, SeverityHigh)
		}
	})

	t.Run("very_large_keySize_ECDH", func(t *testing.T) {
		got := ClassifyAlgorithm("ECDH", "key-exchange", 1<<20)
		if got.Risk != RiskVulnerable {
			t.Errorf("ECDH with 1M keySize Risk = %q, want %q", got.Risk, RiskVulnerable)
		}
		if got.Severity != SeverityCritical {
			t.Errorf("ECDH with 1M keySize Severity = %q, want %q", got.Severity, SeverityCritical)
		}
	})

	t.Run("mixed_case_RSA", func(t *testing.T) {
		// extractBaseName uses ToUpper internally, so case-insensitive matching applies
		got := ClassifyAlgorithm("rsa-2048", "", 2048)
		if got.Risk != RiskVulnerable {
			t.Errorf("lowercase rsa-2048 Risk = %q, want %q", got.Risk, RiskVulnerable)
		}
	})

	t.Run("mixed_case_ECDSA", func(t *testing.T) {
		got := ClassifyAlgorithm("ecdsa", "signature", 256)
		if got.Risk != RiskVulnerable {
			t.Errorf("lowercase ecdsa Risk = %q, want %q", got.Risk, RiskVulnerable)
		}
	})

	t.Run("mixed_case_EdDSA", func(t *testing.T) {
		got := ClassifyAlgorithm("EDDSA", "signature", 0)
		if got.Risk != RiskVulnerable {
			t.Errorf("uppercase EDDSA Risk = %q, want %q", got.Risk, RiskVulnerable)
		}
	})

	t.Run("mixed_case_diffie-hellman", func(t *testing.T) {
		got := ClassifyAlgorithm("diffie-hellman", "key-agree", 2048)
		if got.Risk != RiskVulnerable {
			t.Errorf("lowercase diffie-hellman Risk = %q, want %q", got.Risk, RiskVulnerable)
		}
		if got.Severity != SeverityCritical {
			t.Errorf("lowercase diffie-hellman Severity = %q, want %q", got.Severity, SeverityCritical)
		}
	})

	t.Run("RSA_with_underscore_variant", func(t *testing.T) {
		// RSAES-PKCS1 with underscore separator in the suffix
		got := ClassifyAlgorithm("RSAES-PKCS1-v1_5", "pke", 2048)
		if got.Risk != RiskVulnerable {
			t.Errorf("RSAES-PKCS1-v1_5 Risk = %q, want %q", got.Risk, RiskVulnerable)
		}
	})

	t.Run("recommendation_not_empty_for_vulnerable", func(t *testing.T) {
		vulnerableAlgs := []struct {
			name      string
			primitive string
		}{
			{"RSA-2048", ""},
			{"ECDSA", "signature"},
			{"ECDH", "key-exchange"},
			{"EdDSA", ""},
			{"Ed25519", ""},
			{"Ed448", ""},
			{"X25519", "key-exchange"},
			{"X448", "key-agree"},
			{"DH", "key-agree"},
			{"FFDH", "key-exchange"},
			{"Diffie-Hellman", ""},
			{"ElGamal", ""},
			{"ECIES", ""},
			{"MQV", "key-agree"},
			{"ECMQV", "key-exchange"},
			{"DSA", "signature"},
			{"KCDSA", ""},
			{"EC-KCDSA", ""},
		}
		for _, tc := range vulnerableAlgs {
			t.Run(tc.name, func(t *testing.T) {
				got := ClassifyAlgorithm(tc.name, tc.primitive, 0)
				if got.Risk == RiskVulnerable && got.Recommendation == "" {
					t.Errorf("ClassifyAlgorithm(%q, %q, 0) is RiskVulnerable but has empty Recommendation",
						tc.name, tc.primitive)
				}
			})
		}
	})
}

// TestClassifyAsymmetric_NormalizePrimitiveVariants verifies that all synonymous
// primitives produce the same severity outcomes on a known vulnerable algorithm.
func TestClassifyAsymmetric_NormalizePrimitiveVariants(t *testing.T) {
	// All of these should normalize to key-agree → SeverityCritical
	criticalPrimitives := []string{
		"key-exchange",
		"key_exchange",
		"keyexchange",
		"key-agree",
		"dh",
		"kem",
		"key-encapsulation",
	}
	for _, p := range criticalPrimitives {
		t.Run("RSA_"+p, func(t *testing.T) {
			got := ClassifyAlgorithm("RSA", p, 2048)
			if got.Severity != SeverityCritical {
				t.Errorf("ClassifyAlgorithm(RSA, %q, 2048).Severity = %q, want %q",
					p, got.Severity, SeverityCritical)
			}
		})
	}

	// All of these should normalize to signature → SeverityHigh
	signaturePrimitives := []string{
		"signature",
		"sign",
		"digital-signature",
	}
	for _, p := range signaturePrimitives {
		t.Run("ECDSA_"+p, func(t *testing.T) {
			got := ClassifyAlgorithm("ECDSA", p, 256)
			if got.Severity != SeverityHigh {
				t.Errorf("ClassifyAlgorithm(ECDSA, %q, 256).Severity = %q, want %q",
					p, got.Severity, SeverityHigh)
			}
		})
	}

	// public-key normalizes to pke → SeverityCritical (key-agree/kem/pke case)
	got := ClassifyAlgorithm("ECDSA", "public-key", 256)
	if got.Severity != SeverityCritical {
		t.Errorf("ClassifyAlgorithm(ECDSA, \"public-key\", 256).Severity = %q, want %q",
			got.Severity, SeverityCritical)
	}
}
