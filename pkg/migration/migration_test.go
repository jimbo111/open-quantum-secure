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
		// 6. Swift file + RSA → Swift signing snippet
		{
			name:         "swift RSA signing",
			filePath:     "src/crypto/sign.swift",
			classicalAlg: "RSA",
			primitive:    "signature",
			targetAlg:    "ML-DSA-65",
			wantNil:      false,
			wantLang:     "swift",
			wantBefore:   "Curve25519.Signing",
			wantAfter:    "ML-DSA-65",
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
		// 9. JS file + RSA → JavaScript snippet
		{
			name:         "js RSA signing",
			filePath:     "src/auth/signer.js",
			classicalAlg: "RSA",
			primitive:    "signature",
			targetAlg:    "ML-DSA-65",
			wantLang:     "javascript",
			wantBefore:   "createSign",
			wantAfter:    "liboqs-node",
		},
		// 10. TS file + ECDH → TypeScript snippet
		{
			name:         "ts ECDH key exchange",
			filePath:     "src/transport/exchange.ts",
			classicalAlg: "ECDH",
			primitive:    "key-exchange",
			targetAlg:    "ML-KEM-768",
			wantLang:     "typescript",
			wantBefore:   "createECDH",
			wantAfter:    "liboqs-node",
		},
		// 11. C file + ECDSA → C snippet
		{
			name:         "c ECDSA signing",
			filePath:     "src/crypto/sign.c",
			classicalAlg: "ECDSA",
			primitive:    "signature",
			targetAlg:    "ML-DSA-65",
			wantLang:     "c",
			wantBefore:   "EVP_PKEY_RSA",
			wantAfter:    "EVP_PKEY_CTX_new_from_name",
		},
		// 12. CPP file + X25519 → C++ snippet
		{
			name:         "cpp X25519 key exchange",
			filePath:     "src/tls/handshake.cpp",
			classicalAlg: "X25519",
			primitive:    "key-exchange",
			targetAlg:    "ML-KEM-768",
			wantLang:     "cpp",
			wantBefore:   "EVP_PKEY_EC",
			wantAfter:    "EVP_PKEY_CTX_new_from_name",
		},
		// 13. CS file + RSA → C# snippet
		{
			name:         "csharp RSA signing",
			filePath:     "Crypto/Signer.cs",
			classicalAlg: "RSA",
			primitive:    "signature",
			targetAlg:    "ML-DSA-65",
			wantLang:     "csharp",
			wantBefore:   "RSA.Create",
			wantAfter:    "BouncyCastle",
		},
		// 14. Swift file + Ed25519 → Swift signing snippet
		{
			name:         "swift_Ed25519_signing",
			filePath:     "Sources/Crypto/Signer.swift",
			classicalAlg: "Ed25519",
			primitive:    "signature",
			targetAlg:    "ML-DSA-44",
			wantNil:      false,
			wantLang:     "swift",
			wantBefore:   "Curve25519.Signing",
			wantAfter:    "ML-DSA-44",
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
		// new languages added
		{".js", "javascript"},
		{".ts", "typescript"},
		{".tsx", "typescript"},
		{".c", "c"},
		{".h", "c"},
		{".cpp", "cpp"},
		{".cc", "cpp"},
		{".cxx", "cpp"},
		{".hpp", "cpp"},
		{".cs", "csharp"},
		// swift
		{".swift", "swift"},
		// unknown
		{".kt", ""},
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

// TestConfigServerTypeSnippets verifies that configSnippet detects nginx,
// Apache (httpd), and HAProxy paths and emits the appropriate directives.
func TestConfigServerTypeSnippets(t *testing.T) {
	tests := []struct {
		name         string
		filePath     string
		classicalAlg string
		primitive    string
		wantBefore   string // substring expected in Before field
		wantAfter    string // substring expected in After field
	}{
		{
			name:         "nginx.conf ECDH -> nginx KEM snippet",
			filePath:     "/etc/nginx/nginx.conf",
			classicalAlg: "ECDH",
			primitive:    "key-exchange",
			wantBefore:   "ssl_ecdh_curve",
			wantAfter:    "X25519MLKEM768",
		},
		{
			name:         "httpd.conf RSA -> Apache sign snippet",
			filePath:     "/etc/httpd/conf/httpd.conf",
			classicalAlg: "RSA",
			primitive:    "signature",
			wantBefore:   "SSLCertificateFile",
			wantAfter:    "server-mldsa.crt",
		},
		{
			name:         "haproxy.cfg ECDH -> HAProxy KEM snippet",
			filePath:     "/etc/haproxy/haproxy.cfg",
			classicalAlg: "ECDH",
			primitive:    "key-exchange",
			wantBefore:   "bind *:443",
			wantAfter:    "X25519MLKEM768",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			s := GenerateSnippet(tc.filePath, tc.classicalAlg, tc.primitive, "")
			if s == nil {
				t.Fatal("want non-nil snippet, got nil")
			}
			if s.Language != "config" {
				t.Errorf("Language: want %q, got %q", "config", s.Language)
			}
			if !strings.Contains(s.Before, tc.wantBefore) {
				t.Errorf("Before: want substring %q in:\n%s", tc.wantBefore, s.Before)
			}
			if !strings.Contains(s.After, tc.wantAfter) {
				t.Errorf("After: want substring %q in:\n%s", tc.wantAfter, s.After)
			}
		})
	}
}

// TestGoKEMNoStrayBlankLine verifies that a non-TLS Go KEM snippet does not
// contain a triple newline (\n\n\n) caused by an empty note prefix.
func TestGoKEMNoStrayBlankLine(t *testing.T) {
	// ECDH without any TLS primitive hint → note is empty, so the template
	// must not produce an extra blank line.
	s := GenerateSnippet("internal/crypto/exchange.go", "ECDH", "key-agree", "ML-KEM-768")
	if s == nil {
		t.Fatal("want snippet, got nil")
	}
	if strings.Contains(s.After, "\n\n\n") {
		t.Errorf("After contains stray triple newline:\n%q", s.After)
	}
}

// TestJavaBCAlgStrip verifies that numeric variant suffixes are stripped for
// Bouncy Castle's getInstance call (ML-KEM-768 → ML-KEM, ML-DSA-65 → ML-DSA).
func TestJavaBCAlgStrip(t *testing.T) {
	tests := []struct {
		alg     string
		family  string
		wantAlg string // expected in After snippet
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

// TestGenerateSnippet_EdgeCases covers boundary and adversarial inputs for
// GenerateSnippet, verifying nil-safety and correct nil/non-nil returns.
func TestGenerateSnippet_EdgeCases(t *testing.T) {
	tests := []struct {
		name         string
		filePath     string
		classicalAlg string
		primitive    string
		targetAlg    string
		wantNil      bool
		// When wantNil is false, these must be non-empty in the returned snippet.
		wantLang string
	}{
		// Empty filePath: filepath.Ext("") == "" → langFromExt("") == "" → nil.
		{
			name:         "empty filePath",
			filePath:     "",
			classicalAlg: "RSA",
			primitive:    "signature",
			targetAlg:    "ML-DSA-65",
			wantNil:      true,
		},
		// Empty classicalAlg + empty primitive: classicalAlgFamily("") == "" and
		// neither isSigning nor isKEM matches "" → nil.
		{
			name:         "empty classicalAlg and primitive",
			filePath:     "internal/auth.go",
			classicalAlg: "",
			primitive:    "",
			targetAlg:    "ML-DSA-65",
			wantNil:      true,
		},
		// Empty targetAlg with a recognized sign algorithm: falls back to ML-DSA-65.
		{
			name:         "empty targetAlg defaults for signing",
			filePath:     "internal/auth.go",
			classicalAlg: "RSA",
			primitive:    "signature",
			targetAlg:    "",
			wantNil:      false,
			wantLang:     "go",
		},
		// Empty targetAlg with a recognized KEM algorithm: falls back to ML-KEM-768.
		{
			name:         "empty targetAlg defaults for kem",
			filePath:     "transport/exchange.go",
			classicalAlg: "ECDH",
			primitive:    "key-exchange",
			targetAlg:    "",
			wantNil:      false,
			wantLang:     "go",
		},
		// Special chars in algorithm name: extractBaseAlg("RSA/OAEP") finds no
		// hyphen-digit boundary, so baseAlg is "RSA/OAEP".
		// classicalAlgFamily("RSA/OAEP") returns "" (no match).
		// primitive "signature" → family "sign" via isSigning → snippet produced.
		// Must not panic.
		{
			name:         "special chars RSA/OAEP with primitive hint",
			filePath:     "internal/crypto.go",
			classicalAlg: "RSA/OAEP",
			primitive:    "signature",
			targetAlg:    "ML-DSA-65",
			wantNil:      false,
			wantLang:     "go",
		},
		// Very long algorithm name (200 chars): must not panic.
		// The 200-char 'A' name: isSafePQC → false, extractBaseAlg returns it
		// unchanged (no hyphens), classicalAlgFamily → "", but isSigning("signature")
		// resolves family to "sign" → snippet IS produced.
		{
			name:         "very long algorithm name",
			filePath:     "internal/crypto.go",
			classicalAlg: strings.Repeat("A", 200),
			primitive:    "signature",
			targetAlg:    "ML-DSA-65",
			wantNil:      false,
			wantLang:     "go",
		},
		// File path with spaces: filepath.Ext resolves correctly; must work.
		{
			name:         "file path with spaces",
			filePath:     "/path to/my file.go",
			classicalAlg: "RSA",
			primitive:    "signature",
			targetAlg:    "ML-DSA-65",
			wantNil:      false,
			wantLang:     "go",
		},
		// File with no extension: langFromExt("") returns "" → nil.
		{
			name:         "file with no extension Makefile",
			filePath:     "/Makefile",
			classicalAlg: "RSA",
			primitive:    "signature",
			targetAlg:    "ML-DSA-65",
			wantNil:      true,
		},
		// Compound name "ECDSA-P256-SHA256": extractBaseAlg finds "-P256" (hyphen-P-digit)
		// in the second loop → returns "ECDSA". classicalAlgFamily("ECDSA") == "sign".
		{
			name:         "compound ECDSA-P256-SHA256 resolves to ECDSA",
			filePath:     "internal/sign.go",
			classicalAlg: "ECDSA-P256-SHA256",
			primitive:    "signature",
			targetAlg:    "ML-DSA-44",
			wantNil:      false,
			wantLang:     "go",
		},
		// Compound name "AES-256-GCM": extractBaseAlg finds "-2" (hyphen-digit) → "AES".
		// classicalAlgFamily("AES") returns "" and no primitive hint → nil.
		{
			name:         "compound AES-256-GCM no family and no primitive",
			filePath:     "internal/crypto.go",
			classicalAlg: "AES-256-GCM",
			primitive:    "",
			targetAlg:    "",
			wantNil:      true,
		},
		// PQC algorithm "ML-DSA-44": isSafePQC fires → nil.
		{
			name:         "PQC name ML-DSA-44 is safe",
			filePath:     "internal/pqc.go",
			classicalAlg: "ML-DSA-44",
			primitive:    "signature",
			targetAlg:    "",
			wantNil:      true,
		},
		// Pre-standard "DILITHIUM-2": isSafePQC checks HasPrefix("DILITHIUM-2", "DILITHIUM-") → true → nil.
		{
			name:         "pre-standard DILITHIUM-2 is safe",
			filePath:     "internal/pqc.go",
			classicalAlg: "DILITHIUM-2",
			primitive:    "signature",
			targetAlg:    "",
			wantNil:      true,
		},
		// Pre-standard "KYBER-768": isSafePQC checks HasPrefix("KYBER-768", "KYBER-") → true → nil.
		{
			name:         "pre-standard KYBER-768 is safe",
			filePath:     "internal/pqc.go",
			classicalAlg: "KYBER-768",
			primitive:    "kem",
			targetAlg:    "",
			wantNil:      true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// Wrap in a deferred recover so a panic fails the test cleanly
			// instead of crashing the whole suite.
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("GenerateSnippet panicked: %v", r)
				}
			}()

			got := GenerateSnippet(tc.filePath, tc.classicalAlg, tc.primitive, tc.targetAlg)

			if tc.wantNil {
				if got != nil {
					t.Fatalf("want nil, got snippet{Language:%q}", got.Language)
				}
				return
			}

			if got == nil {
				t.Fatal("want non-nil snippet, got nil")
			}
			if tc.wantLang != "" && got.Language != tc.wantLang {
				t.Errorf("Language: want %q, got %q", tc.wantLang, got.Language)
			}
			if got.Before == "" {
				t.Error("Before must not be empty for a valid snippet")
			}
			if got.After == "" {
				t.Error("After must not be empty for a valid snippet")
			}
			if got.Explanation == "" {
				t.Error("Explanation must not be empty for a valid snippet")
			}
		})
	}
}

// TestGenerateSnippet_EdgeCases_LongAlg re-checks the 200-char case with a
// primitive hint so we confirm the snippet IS produced (covers the sign family
// resolution path through isSigning, not classicalAlgFamily).
func TestGenerateSnippet_EdgeCases_LongAlg(t *testing.T) {
	longAlg := strings.Repeat("A", 200)
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("GenerateSnippet panicked on 200-char alg: %v", r)
		}
	}()
	// The 200-char name passes isSafePQC (none of the PQC prefixes match),
	// extractBaseAlg returns the full 200-char string (no hyphen-digit boundary),
	// classicalAlgFamily returns "" because the name is not in the switch,
	// but isSigning("signature") → family "sign" → snippet is produced.
	got := GenerateSnippet("internal/crypto.go", longAlg, "signature", "ML-DSA-65")
	if got == nil {
		t.Fatal("want snippet for long alg with primitive hint, got nil")
	}
	if got.Language != "go" {
		t.Errorf("Language: want %q, got %q", "go", got.Language)
	}
}

// TestExtractBaseAlg is a dedicated table-driven test for extractBaseAlg.
func TestExtractBaseAlg(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		// Hyphen followed immediately by a digit — first loop fires.
		{"RSA-2048", "RSA"},
		{"AES-256-GCM", "AES"},   // first hyphen+digit wins; "GCM" is never reached
		{"SHA-256", "SHA"},        // hyphen at 3, next char '2' (digit)
		{"ML-DSA-44", "ML-DSA"},   // hyphen at 2 is before 'D' (not digit); hyphen at 6 before '4' (digit) → "ML-DSA"
		{"3DES", "3DES"},          // no hyphen at all
		{"RSA", "RSA"},            // no hyphen at all
		// Hyphen followed by P+digit — second loop fires.
		{"ECDSA-P256", "ECDSA"},
		{"ECDSA-P256-SHA256", "ECDSA"}, // first loop finds no hyphen+digit in "ECDSA-P256"; second loop finds "-P2" → "ECDSA"
		// No hyphen-digit boundary of either kind.
		{"X25519", "X25519"},      // '2' is part of the name with no preceding hyphen
		{"Ed25519", "Ed25519"},    // same: no hyphen before any digit
		// Empty input must not panic and returns itself.
		{"", ""},
	}

	for _, tc := range tests {
		t.Run(tc.input, func(t *testing.T) {
			got := extractBaseAlg(tc.input)
			if got != tc.want {
				t.Errorf("extractBaseAlg(%q) = %q, want %q", tc.input, got, tc.want)
			}
		})
	}
}

// FuzzGenerateSnippet verifies that GenerateSnippet never panics on arbitrary
// inputs and that any non-nil result has all three text fields populated.
func FuzzGenerateSnippet(f *testing.F) {
	// Seed corpus: known-good inputs that exercise all major code paths.
	type seed struct {
		filePath, classicalAlg, primitive, targetAlg string
	}
	seeds := []seed{
		{"internal/auth/signer.go", "RSA", "signature", "ML-DSA-65"},
		{"keys.py", "ECDH", "key-agree", "ML-KEM-768"},
		{"Crypto.java", "ECDSA", "signature", "ML-DSA-44"},
		{"src/transport/handshake.rs", "X25519", "key-exchange", "ML-KEM-768"},
		{"deploy/nginx.yaml", "RSA", "signature", ""},
		{"internal/pqc.go", "ML-DSA-65", "signature", ""},
		{"internal/pqc.go", "KYBER-768", "kem", ""},
		{"", "RSA", "signature", "ML-DSA-65"},
		{"/Makefile", "RSA", "signature", "ML-DSA-65"},
		{"internal/crypto.go", "AES-256-GCM", "", ""},
	}
	for _, s := range seeds {
		f.Add(s.filePath, s.classicalAlg, s.primitive, s.targetAlg)
	}

	f.Fuzz(func(t *testing.T, filePath, classicalAlg, primitive, targetAlg string) {
		// Must never panic.
		var got *Snippet
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("GenerateSnippet panicked: filePath=%q classicalAlg=%q primitive=%q targetAlg=%q panic=%v",
						filePath, classicalAlg, primitive, targetAlg, r)
				}
			}()
			got = GenerateSnippet(filePath, classicalAlg, primitive, targetAlg)
		}()

		// When a snippet is returned all three text fields must be non-empty.
		if got != nil {
			if got.Language == "" {
				t.Errorf("non-nil snippet has empty Language: filePath=%q classicalAlg=%q", filePath, classicalAlg)
			}
			if got.Before == "" {
				t.Errorf("non-nil snippet has empty Before: filePath=%q classicalAlg=%q", filePath, classicalAlg)
			}
			if got.After == "" {
				t.Errorf("non-nil snippet has empty After: filePath=%q classicalAlg=%q", filePath, classicalAlg)
			}
		}
	})
}
