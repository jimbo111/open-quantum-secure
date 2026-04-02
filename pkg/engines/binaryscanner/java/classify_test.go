package java

import (
	"testing"
)

func TestClassifyAlgorithmString(t *testing.T) {
	tests := []struct {
		name      string
		input     string
		wantNil   bool
		primitive string
		algName   string
		mode      string
	}{
		// --- AES transforms ---
		{
			name: "AES/GCM/NoPadding",
			input: "AES/GCM/NoPadding",
			primitive: "ae", algName: "AES", mode: "GCM",
		},
		{
			name: "AES/CBC/PKCS5Padding",
			input: "AES/CBC/PKCS5Padding",
			primitive: "symmetric", algName: "AES", mode: "CBC",
		},
		{
			name: "AES/CTR/NoPadding",
			input: "AES/CTR/NoPadding",
			primitive: "symmetric", algName: "AES", mode: "CTR",
		},
		{
			name: "AES/CCM/NoPadding",
			input: "AES/CCM/NoPadding",
			primitive: "ae", algName: "AES", mode: "CCM",
		},
		{
			name:      "AES alone",
			input:     "AES",
			primitive: "symmetric", algName: "AES",
		},

		// --- RSA ---
		{
			name: "RSA/ECB/PKCS1Padding",
			input: "RSA/ECB/PKCS1Padding",
			primitive: "pke", algName: "RSA", mode: "ECB",
		},
		{
			name:      "RSA alone",
			input:     "RSA",
			primitive: "pke", algName: "RSA",
		},

		// --- Hash algorithms ---
		{
			name:      "SHA-256",
			input:     "SHA-256",
			primitive: "hash", algName: "SHA-256",
		},
		{
			name:      "SHA-512",
			input:     "SHA-512",
			primitive: "hash", algName: "SHA-512",
		},
		{
			name:      "SHA-1",
			input:     "SHA-1",
			primitive: "hash", algName: "SHA-1",
		},
		{
			name:      "MD5",
			input:     "MD5",
			primitive: "hash", algName: "MD5",
		},
		{
			name:      "MD2",
			input:     "MD2",
			primitive: "hash", algName: "MD2",
		},
		{
			name:      "SHA3-256",
			input:     "SHA3-256",
			primitive: "hash", algName: "SHA3-256",
		},

		// --- HMAC ---
		{
			name:      "HmacSHA256",
			input:     "HmacSHA256",
			primitive: "mac", algName: "HMAC", mode: "SHA-256",
		},
		{
			name:      "HmacSHA512",
			input:     "HmacSHA512",
			primitive: "mac", algName: "HMAC", mode: "SHA-512",
		},
		{
			name:      "HmacSHA1",
			input:     "HmacSHA1",
			primitive: "mac", algName: "HMAC", mode: "SHA-1",
		},
		{
			name:      "HMACSHA384",
			input:     "HMACSHA384",
			primitive: "mac", algName: "HMAC", mode: "SHA-384",
		},

		// --- KDF ---
		{
			name:      "PBKDF2WithHmacSHA256",
			input:     "PBKDF2WithHmacSHA256",
			primitive: "kdf",
		},
		{
			name:      "PBKDF2WithHmacSHA1",
			input:     "PBKDF2WithHmacSHA1",
			primitive: "kdf",
		},
		{
			name:      "HKDF",
			input:     "HKDF",
			primitive: "kdf",
		},
		{
			name:      "scrypt",
			input:     "scrypt",
			primitive: "kdf",
		},
		{
			name:      "bcrypt",
			input:     "bcrypt",
			primitive: "kdf",
		},

		// --- TLS/SSL protocols ---
		{
			name:      "TLSv1.3",
			input:     "TLSv1.3",
			primitive: "protocol", algName: "TLS", mode: "1.3",
		},
		{
			name:      "TLSv1.2",
			input:     "TLSv1.2",
			primitive: "protocol", algName: "TLS", mode: "1.2",
		},
		{
			name:      "TLS",
			input:     "TLS",
			primitive: "protocol", algName: "TLS",
		},
		{
			name:      "SSLv3",
			input:     "SSLv3",
			primitive: "protocol", algName: "TLS", mode: "3",
		},

		// --- Key exchange ---
		{
			name:      "DH",
			input:     "DH",
			primitive: "key-exchange", algName: "DH",
		},
		{
			name:      "ECDH",
			input:     "ECDH",
			primitive: "key-exchange", algName: "ECDH",
		},
		{
			name:      "X25519",
			input:     "X25519",
			primitive: "key-exchange", algName: "X25519",
		},
		{
			name:      "X448",
			input:     "X448",
			primitive: "key-exchange", algName: "X448",
		},

		// --- Signatures ---
		{
			name:      "EC",
			input:     "EC",
			primitive: "signature", algName: "EC",
		},
		{
			name:      "ECDSA",
			input:     "ECDSA",
			primitive: "signature", algName: "ECDSA",
		},
		{
			name:      "EdDSA",
			input:     "EdDSA",
			primitive: "signature", algName: "EdDSA",
		},
		{
			name:      "Ed25519",
			input:     "Ed25519",
			primitive: "signature", algName: "Ed25519",
		},
		{
			name:      "Ed448",
			input:     "Ed448",
			primitive: "signature", algName: "Ed448",
		},
		{
			name:      "SHA256withECDSA",
			input:     "SHA256withECDSA",
			primitive: "signature",
		},

		// --- ChaCha20 (AEAD) ---
		{
			name:      "ChaCha20-Poly1305",
			input:     "ChaCha20-Poly1305",
			primitive: "ae", algName: "ChaCha20-Poly1305",
		},
		{
			name:      "ChaCha20",
			input:     "ChaCha20",
			primitive: "ae",
		},

		// --- Legacy symmetric ---
		{
			name:      "DES",
			input:     "DES",
			primitive: "symmetric", algName: "DES",
		},
		{
			name:      "DESede",
			input:     "DESede",
			primitive: "symmetric", algName: "DESede",
		},
		{
			name:      "3DES",
			input:     "3DES",
			primitive: "symmetric", algName: "3DES",
		},
		{
			name:      "Blowfish",
			input:     "Blowfish",
			primitive: "symmetric", algName: "Blowfish",
		},
		{
			name:      "RC4",
			input:     "RC4",
			primitive: "symmetric", algName: "RC4",
		},
		{
			name:      "RC2",
			input:     "RC2",
			primitive: "symmetric", algName: "RC2",
		},

		// --- Non-crypto strings that must return nil ---
		{name: "UTF-8", input: "UTF-8", wantNil: true},
		{name: "main", input: "main", wantNil: true},
		{name: "java/lang/Object", input: "java/lang/Object", wantNil: true},
		{name: "empty", input: "", wantNil: true},
		{name: "single char X", input: "X", wantNil: true},
		{name: "two chars AB", input: "AB", wantNil: true},
		{name: "package path", input: "com/example/foo/bar", wantNil: true},
		{name: "string with space", input: "AES 256", wantNil: true},
		{name: "java class path", input: "java.lang.String", wantNil: true},
		{name: "void", input: "void", wantNil: true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := classifyAlgorithmString(tc.input)

			if tc.wantNil {
				if got != nil {
					t.Errorf("classifyAlgorithmString(%q) = %+v, want nil", tc.input, got)
				}
				return
			}

			if got == nil {
				t.Fatalf("classifyAlgorithmString(%q) = nil, want non-nil", tc.input)
			}
			if got.Primitive != tc.primitive {
				t.Errorf("classifyAlgorithmString(%q).Primitive = %q, want %q", tc.input, got.Primitive, tc.primitive)
			}
			if tc.algName != "" && got.Name != tc.algName {
				t.Errorf("classifyAlgorithmString(%q).Name = %q, want %q", tc.input, got.Name, tc.algName)
			}
			if tc.mode != "" && got.Mode != tc.mode {
				t.Errorf("classifyAlgorithmString(%q).Mode = %q, want %q", tc.input, got.Mode, tc.mode)
			}
		})
	}
}

func TestKnownCryptoClassesMap(t *testing.T) {
	// Ensure minimum required entries are present.
	required := []string{
		"Cipher", "KeyGenerator", "Mac", "KeyAgreement", "MessageDigest",
		"Signature", "KeyPairGenerator", "KeyFactory", "SecretKeyFactory",
		"SSLContext", "SecureRandom", "AlgorithmParameters",
		"AlgorithmParameterGenerator", "CertificateFactory",
		"CertPathValidator", "TrustManagerFactory", "KeyManagerFactory",
		"KeyStore",
	}
	for _, name := range required {
		if !knownCryptoClasses[name] {
			t.Errorf("knownCryptoClasses missing required entry %q", name)
		}
	}
	if len(knownCryptoClasses) < 18 {
		t.Errorf("knownCryptoClasses has %d entries, want >= 18", len(knownCryptoClasses))
	}
}
