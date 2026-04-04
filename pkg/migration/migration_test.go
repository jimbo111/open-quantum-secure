package migration

import (
	"strings"
	"testing"
)

// TestGenerateSnippet covers the eight required cases plus a handful of
// additional edge cases derived from the double-check checklist.
func TestGenerateSnippet(t *testing.T) {
	tests := []struct {
		name         string
		filePath     string
		classicalAlg string
		primitive    string
		targetAlg    string
		wantNil      bool
		wantLang     string
		wantBefore   string // substring expected in Before field
		wantAfter    string // substring expected in After field
	}{
		// 1. Go file + RSA → Go ML-DSA snippet
		{
			name:         "go RSA signing",
			filePath:     "internal/auth/signer.go",
			classicalAlg: "RSA",
			primitive:    "signature",
			targetAlg:    "ML-DSA-65",
			wantLang:     "go",
			wantBefore:   "rsa",
			wantAfter:    "liboqs-go",
		},
		// 2. Python file + ECDSA → Python ML-DSA snippet
		{
			name:         "python ECDSA signing",
			filePath:     "crypto/sign.py",
			classicalAlg: "ECDSA",
			primitive:    "signature",
			targetAlg:    "ML-DSA-44",
			wantLang:     "python",
			wantBefore:   "cryptography",
			wantAfter:    "liboqs-python",
		},
		// 3. Java file + ECDH → Java Bouncy Castle ML-KEM snippet
		{
			name:         "java ECDH key agreement",
			filePath:     "src/main/java/KeyExchange.java",
			classicalAlg: "ECDH",
			primitive:    "key-agree",
			targetAlg:    "ML-KEM-768",
			wantLang:     "java",
			wantBefore:   "ECDH",
			wantAfter:    "BCPQC",
		},
		// 4. Rust file + X25519 → Rust KEM snippet
		{
			name:         "rust X25519 key exchange",
			filePath:     "src/transport/handshake.rs",
			classicalAlg: "X25519",
			primitive:    "key-exchange",
			targetAlg:    "ML-KEM-768",
			wantLang:     "rust",
			wantBefore:   "x25519",
			wantAfter:    "oqs::kem",
		},
		// 5. YAML config + RSA → config snippet
		{
			name:         "yaml config RSA certificate",
			filePath:     "deploy/nginx.yaml",
			classicalAlg: "RSA",
			primitive:    "signature",
			targetAlg:    "ML-DSA-65",
			wantLang:     "config",
			wantBefore:   "ssl_certificate",
			wantAfter:    "ML-DSA",
		},
		// 6. Unknown extension → nil
		{
			name:         "unknown extension",
			filePath:     "src/crypto/sign.swift",
			classicalAlg: "RSA",
			primitive:    "signature",
			targetAlg:    "ML-DSA-65",
			wantNil:      true,
		},
		// 7. Unknown / unrecognised algorithm + no primitive hint → nil
		{
			name:         "unknown algorithm no primitive",
			filePath:     "internal/hash.go",
			classicalAlg: "ARIA",
			primitive:    "",
			targetAlg:    "",
			wantNil:      true,
		},
		// 8. Already-safe PQC algorithm → nil
		{
			name:         "safe algorithm ML-KEM",
			filePath:     "internal/kem.go",
			classicalAlg: "ML-KEM-768",
			primitive:    "kem",
			targetAlg:    "",
			wantNil:      true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := GenerateSnippet(tc.filePath, tc.classicalAlg, tc.primitive, tc.targetAlg)

			if tc.wantNil {
				if got != nil {
					t.Fatalf("want nil, got snippet with Language=%q", got.Language)
				}
				return
			}

			if got == nil {
				t.Fatal("want non-nil snippet, got nil")
			}

			if got.Language != tc.wantLang {
				t.Errorf("Language: want %q, got %q", tc.wantLang, got.Language)
			}

			if tc.wantBefore != "" && !strings.Contains(got.Before, tc.wantBefore) {
				t.Errorf("Before: want substring %q in:\n%s", tc.wantBefore, got.Before)
			}

			if tc.wantAfter != "" && !strings.Contains(got.After, tc.wantAfter) {
				t.Errorf("After: want substring %q in:\n%s", tc.wantAfter, got.After)
			}

			if got.Explanation == "" {
				t.Error("Explanation must not be empty")
			}
		})
	}
}

// TestLangFromExt verifies that every documented extension resolves correctly,
// including all config variants and the unknown/empty cases.
func TestLangFromExt(t *testing.T) {
	tests := []struct {
		ext  string
		want string
	}{
		{".go", "go"},
		{".py", "python"},
		{".java", "java"},
		{".rs", "rust"},
		// config group
		{".yml", "config"},
		{".yaml", "config"},
		{".conf", "config"},
		{".nginx", "config"},
		{".cnf", "config"},
		{".cfg", "config"},
		{".properties", "config"},
		{".toml", "config"},
		{".json", "config"},
		{".xml", "config"},
		{".ini", "config"},
		{".hcl", "config"},
		{".env", "config"},
		// unknown
		{".swift", ""},
		{".kt", ""},
		{".ts", ""},
		{"", ""},
	}

	for _, tc := range tests {
		t.Run(tc.ext, func(t *testing.T) {
			if got := langFromExt(tc.ext); got != tc.want {
				t.Errorf("langFromExt(%q): want %q, got %q", tc.ext, tc.want, got)
			}
		})
	}
}

// TestClassicalAlgFamily verifies the sign/kem/empty classification for every
// algorithm in targets.go that matters for snippet generation.
func TestClassicalAlgFamily(t *testing.T) {
	sign := []string{
		"RSA", "RSASSA-PKCS1", "RSASSA-PSS",
		"DSA", "ECDSA", "EDDSA", "ED25519", "ED448",
		"KCDSA", "EC-KCDSA",
	}
	kem := []string{
		"ECDH", "ECDHE", "X25519", "X448",
		"DH", "FFDH", "DIFFIE-HELLMAN",
		"RSAES-PKCS1", "RSAES-OAEP",
		"ELGAMAL", "ECIES", "MQV", "ECMQV",
	}
	unknown := []string{
		// PQC-safe → no migration family
		"ML-DSA-65", "ML-KEM-768", "DILITHIUM", "KYBER",
		// Hash / symmetric — no snippet generated
		"AES", "SHA-256", "MD5",
		// Truly unknown
		"ARIA", "CAMELLIA",
	}

	for _, alg := range sign {
		t.Run("sign/"+alg, func(t *testing.T) {
			if got := classicalAlgFamily(alg); got != "sign" {
				t.Errorf("classicalAlgFamily(%q) = %q, want %q", alg, got, "sign")
			}
		})
	}

	for _, alg := range kem {
		t.Run("kem/"+alg, func(t *testing.T) {
			if got := classicalAlgFamily(alg); got != "kem" {
				t.Errorf("classicalAlgFamily(%q) = %q, want %q", alg, got, "kem")
			}
		})
	}

	for _, alg := range unknown {
		t.Run("unknown/"+alg, func(t *testing.T) {
			if got := classicalAlgFamily(alg); got != "" {
				t.Errorf("classicalAlgFamily(%q) = %q, want %q (empty)", alg, got, "")
			}
		})
	}
}

// TestToOQSVariant verifies the PascalCase conversion used in Rust snippets.
func TestToOQSVariant(t *testing.T) {
	tests := []struct {
		alg  string
		want string
	}{
		{"ML-DSA-44", "MlDsa44"},
		{"ML-DSA-65", "MlDsa65"},
		{"ML-DSA-87", "MlDsa87"},
		{"ML-KEM-512", "MlKem512"},
		{"ML-KEM-768", "MlKem768"},
		{"ML-KEM-1024", "MlKem1024"},
		{"SLH-DSA-SHA2-128f", "SlhDsaSha2128f"},
	}

	for _, tc := range tests {
		t.Run(tc.alg, func(t *testing.T) {
			if got := toOQSVariant(tc.alg); got != tc.want {
				t.Errorf("toOQSVariant(%q) = %q, want %q", tc.alg, got, tc.want)
			}
		})
	}
}

// TestGoSnippetTLSHint verifies that X25519/ECDHE Go snippets mention the
// Go 1.24 crypto/tls native support note.
func TestGoSnippetTLSHint(t *testing.T) {
	for _, alg := range []string{"X25519", "ECDHE"} {
		t.Run(alg, func(t *testing.T) {
			s := GenerateSnippet("internal/tls/handshake.go", alg, "key-exchange", "ML-KEM-768")
			if s == nil {
				t.Fatal("want snippet, got nil")
			}
			if !strings.Contains(s.After, "crypto/tls") {
				t.Errorf("expected crypto/tls TLS hint in After for %s, got:\n%s", alg, s.After)
			}
		})
	}
}

// TestEmptyTargetAlgFallback ensures that an empty targetAlg argument falls
// back to sensible defaults and still produces a valid snippet.
func TestEmptyTargetAlgFallback(t *testing.T) {
	tests := []struct {
		name         string
		filePath     string
		classicalAlg string
		primitive    string
		wantContains string // substring in Explanation
	}{
		{"go sign fallback", "main.go", "RSA", "signature", "ML-DSA-65"},
		{"py kem fallback", "keys.py", "ECDH", "key-agree", "ML-KEM-768"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			s := GenerateSnippet(tc.filePath, tc.classicalAlg, tc.primitive, "")
			if s == nil {
				t.Fatal("want snippet, got nil")
			}
			if !strings.Contains(s.Explanation, tc.wantContains) {
				t.Errorf("Explanation %q does not contain %q", s.Explanation, tc.wantContains)
			}
		})
	}
}

// TestCaseInsensitiveAlg ensures algorithm names are matched
// case-insensitively so callers don't need to normalise first.
func TestCaseInsensitiveAlg(t *testing.T) {
	variants := []string{"rsa", "Rsa", "RSA"}
	for _, v := range variants {
		t.Run(v, func(t *testing.T) {
			s := GenerateSnippet("main.go", v, "signature", "ML-DSA-65")
			if s == nil {
				t.Fatalf("GenerateSnippet with alg=%q returned nil, want snippet", v)
			}
		})
	}
}

// TestConfigExtensions verifies that every config extension produces a snippet
// for a known algorithm, exercising both KEM and sign paths.
func TestConfigExtensions(t *testing.T) {
	extensions := []string{
		".yml", ".yaml", ".conf", ".nginx", ".cnf", ".cfg",
		".properties", ".toml", ".json", ".xml", ".ini", ".hcl", ".env",
	}

	for _, ext := range extensions {
		t.Run(ext, func(t *testing.T) {
			s := GenerateSnippet("server"+ext, "RSA", "signature", "ML-DSA-65")
			if s == nil {
				t.Fatalf("GenerateSnippet(%q, RSA) returned nil, want config snippet", ext)
			}
			if s.Language != "config" {
				t.Errorf("Language: want %q, got %q", "config", s.Language)
			}
		})
	}
}

// TestJavaBCAlgStrip verifies that numeric variant suffixes are stripped for
// Bouncy Castle's getInstance call (ML-KEM-768 → ML-KEM, ML-DSA-65 → ML-DSA).
func TestJavaBCAlgStrip(t *testing.T) {
	tests := []struct {
		alg      string
		family   string
		wantAlg  string // expected in After snippet
	}{
		{"ML-KEM-768", "kem", "ML-KEM"},
		{"ML-DSA-65", "sign", "ML-DSA"},
		{"ML-KEM-1024", "kem", "ML-KEM"},
		{"ML-DSA-87", "sign", "ML-DSA"},
	}

	for _, tc := range tests {
		t.Run(tc.alg, func(t *testing.T) {
			primitive := "signature"
			classicalAlg := "RSA"
			if tc.family == "kem" {
				primitive = "key-agree"
				classicalAlg = "ECDH"
			}
			s := GenerateSnippet("Crypto.java", classicalAlg, primitive, tc.alg)
			if s == nil {
				t.Fatal("want snippet, got nil")
			}
			if !strings.Contains(s.After, `"`+tc.wantAlg+`"`) {
				t.Errorf("After does not contain %q:\n%s", tc.wantAlg, s.After)
			}
		})
	}
}
