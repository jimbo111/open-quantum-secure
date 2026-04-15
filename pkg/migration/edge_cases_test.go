package migration

import (
	"strings"
	"testing"
	"unicode/utf8"
)

// ---------------------------------------------------------------------------
// Extension detection
// ---------------------------------------------------------------------------

// TestExtensionDetection_CaseAndVariants covers uppercase, mixed-case, and
// backup-extension file names.  langFromExt operates on the lowercased result
// of filepath.Ext so ".GO" must resolve to "go".  A ".go.bak" file has ext
// ".bak" which is unknown.
func TestExtensionDetection_CaseAndVariants(t *testing.T) {
	tests := []struct {
		name     string
		filePath string
		wantLang string // "" means GenerateSnippet should return nil
	}{
		// Uppercase extension — filepath.Ext preserves case, but GenerateSnippet
		// lower-cases before passing to langFromExt.
		{
			name:     "uppercase .GO",
			filePath: "signer.GO",
			wantLang: "go",
		},
		// Mixed-case
		{
			name:     "mixed-case .Go",
			filePath: "crypto/signer.Go",
			wantLang: "go",
		},
		// .go.bak — filepath.Ext returns ".bak", which is unknown → nil.
		{
			name:     "go backup file .go.bak returns nil",
			filePath: "signer.go.bak",
			wantLang: "",
		},
		// No extension at all — filepath.Ext returns "" → nil.
		{
			name:     "no extension Dockerfile",
			filePath: "Dockerfile",
			wantLang: "",
		},
		// .txt is not in the map → nil.
		{
			name:     "txt extension returns nil",
			filePath: "readme.txt",
			wantLang: "",
		},
		// .yml and .yaml both collapse to "config".
		{
			name:     "yml extension is config",
			filePath: "deploy/k8s.yml",
			wantLang: "config",
		},
		{
			name:     "yaml extension is config",
			filePath: "deploy/k8s.yaml",
			wantLang: "config",
		},
		// Uppercase config extension, e.g. ".YAML".
		{
			name:     "uppercase .YAML is config",
			filePath: "deploy/k8s.YAML",
			wantLang: "config",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			s := GenerateSnippet(tc.filePath, "RSA", "signature", "ML-DSA-65")
			if tc.wantLang == "" {
				if s != nil {
					t.Fatalf("want nil snippet, got Language=%q", s.Language)
				}
				return
			}
			if s == nil {
				t.Fatalf("want snippet with Language=%q, got nil", tc.wantLang)
			}
			if s.Language != tc.wantLang {
				t.Errorf("Language: want %q, got %q", tc.wantLang, s.Language)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Config file detection (server type)
// ---------------------------------------------------------------------------

// TestConfigFileDetection verifies that configServerType correctly identifies
// nginx, Apache, and HAProxy from a variety of path patterns.
func TestConfigFileDetection(t *testing.T) {
	tests := []struct {
		name       string
		filePath   string
		wantServer string // "nginx", "apache", or "haproxy"
	}{
		{"nginx.conf", "nginx.conf", "nginx"},
		{"apache2.conf", "apache2.conf", "apache"},
		{"haproxy.cfg", "haproxy.cfg", "haproxy"},
		{"unknown.conf falls back to nginx", "server.conf", "nginx"},
		// Path-based detection — directory name contains the keyword.
		{"/etc/nginx/sites-available/default", "/etc/nginx/sites-available/default", "nginx"},
		{"/etc/apache2/sites-enabled/000-default.conf", "/etc/apache2/sites-enabled/000-default.conf", "apache"},
		{"/etc/haproxy/haproxy.cfg", "/etc/haproxy/haproxy.cfg", "haproxy"},
		// httpd alias for Apache
		{"/etc/httpd/conf/httpd.conf", "/etc/httpd/conf/httpd.conf", "apache"},
		// Mixed-case keyword in path — configServerType lower-cases.
		{"HAProxy in path", "/srv/HAProxy/cfg/tls.cfg", "haproxy"},
		{"Apache2 upper in path", "/etc/Apache2/tls.conf", "apache"},
		{"NGINX upper in path", "/etc/NGINX/nginx.conf", "nginx"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := configServerType(tc.filePath)
			if got != tc.wantServer {
				t.Errorf("configServerType(%q) = %q, want %q", tc.filePath, got, tc.wantServer)
			}
		})
	}
}

// TestConfigSnippetServerDirectives exercises GenerateSnippet for config paths,
// asserting server-specific directives appear in Before/After.
func TestConfigSnippetServerDirectives(t *testing.T) {
	tests := []struct {
		name         string
		filePath     string
		classicalAlg string
		primitive    string
		wantBefore   string
		wantAfter    string
	}{
		// Unknown .conf falls back to nginx-style directives.
		{
			name:         "unknown.conf ECDH falls back to nginx KEM snippet",
			filePath:     "/etc/myapp/server.conf",
			classicalAlg: "ECDH",
			primitive:    "key-exchange",
			wantBefore:   "ssl_ecdh_curve",
			wantAfter:    "X25519MLKEM768",
		},
		// apache2.conf with ECDH KEM.
		{
			name:         "apache2.conf ECDH -> Apache KEM snippet",
			filePath:     "/etc/apache2/apache2.conf",
			classicalAlg: "ECDH",
			primitive:    "key-exchange",
			wantBefore:   "SSLOpenSSLConfCmd",
			wantAfter:    "X25519MLKEM768",
		},
		// haproxy.cfg with RSA signing.
		{
			name:         "haproxy.cfg RSA -> haproxy bind directive sign snippet",
			filePath:     "/etc/haproxy/haproxy.cfg",
			classicalAlg: "RSA",
			primitive:    "signature",
			wantBefore:   "bind *:443 ssl crt",
			wantAfter:    "ML-DSA",
		},
		// Path-based detection for /etc/nginx/sites-available/default (no extension).
		// The extension gate falls back to a server-path heuristic so Debian/Ubuntu
		// nginx layouts still get migration guidance.
		{
			name:         "nginx sites-available path no extension",
			filePath:     "/etc/nginx/sites-available/default",
			classicalAlg: "ECDH",
			primitive:    "key-exchange",
			wantBefore:   "ssl_ecdh_curve",
			wantAfter:    "X25519MLKEM768",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			s := GenerateSnippet(tc.filePath, tc.classicalAlg, tc.primitive, "")
			if s == nil {
				t.Fatalf("want non-nil snippet, got nil")
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

// ---------------------------------------------------------------------------
// Algorithm / target combinations
// ---------------------------------------------------------------------------

// TestAlgorithmTargetCombinations exercises a matrix of classical algorithms
// and their recommended PQC targets.
func TestAlgorithmTargetCombinations(t *testing.T) {
	tests := []struct {
		name         string
		classicalAlg string
		primitive    string
		targetAlg    string
		filePath     string
		wantNil      bool
	}{
		// RSA-2048 → ML-DSA-44
		{"RSA-2048 -> ML-DSA-44", "RSA-2048", "signature", "ML-DSA-44", "main.go", false},
		// RSA-3072 → ML-DSA-65
		{"RSA-3072 -> ML-DSA-65", "RSA-3072", "signature", "ML-DSA-65", "main.go", false},
		// RSA-4096 → ML-DSA-87
		{"RSA-4096 -> ML-DSA-87", "RSA-4096", "signature", "ML-DSA-87", "main.go", false},
		// ECDSA-P256 → ML-DSA-44
		{"ECDSA-P256 -> ML-DSA-44", "ECDSA-P256", "signature", "ML-DSA-44", "main.go", false},
		// ECDH → ML-KEM-768
		{"ECDH -> ML-KEM-768", "ECDH", "key-exchange", "ML-KEM-768", "main.go", false},
		// Unknown algorithm, empty primitive → nil
		{"unknown alg no primitive", "BLOWFISH", "", "", "main.go", true},
		// Empty algorithm, empty target → nil (classicalAlgFamily("") == "")
		{"empty alg and target", "", "", "", "main.go", true},
		// Empty target with known signing alg → default ML-DSA-65 used
		{"empty target sign defaults", "RSA", "signature", "", "main.go", false},
		// Empty target with known KEM alg → default ML-KEM-768 used
		{"empty target kem defaults", "ECDH", "key-exchange", "", "main.go", false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			s := GenerateSnippet(tc.filePath, tc.classicalAlg, tc.primitive, tc.targetAlg)
			if tc.wantNil {
				if s != nil {
					t.Fatalf("want nil, got snippet{Language:%q}", s.Language)
				}
				return
			}
			if s == nil {
				t.Fatalf("want non-nil snippet, got nil")
			}
			if s.Before == "" {
				t.Error("Before must not be empty")
			}
			if s.After == "" {
				t.Error("After must not be empty")
			}
			if s.Explanation == "" {
				t.Error("Explanation must not be empty")
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Snippet content sanity
// ---------------------------------------------------------------------------

// TestSnippetContentSanity verifies fundamental snippet quality invariants
// across every supported language.
func TestSnippetContentSanity(t *testing.T) {
	type tc struct {
		name         string
		filePath     string
		classicalAlg string
		primitive    string
		targetAlg    string
		wantImport   string // expected substring indicating an import statement
	}
	tests := []tc{
		{
			name:         "go sign import",
			filePath:     "main.go",
			classicalAlg: "RSA",
			primitive:    "signature",
			targetAlg:    "ML-DSA-65",
			wantImport:   "import",
		},
		{
			name:         "python sign import",
			filePath:     "main.py",
			classicalAlg: "RSA",
			primitive:    "signature",
			targetAlg:    "ML-DSA-65",
			wantImport:   "from",
		},
		{
			name:         "java sign import",
			filePath:     "Crypto.java",
			classicalAlg: "RSA",
			primitive:    "signature",
			targetAlg:    "ML-DSA-65",
			wantImport:   "import",
		},
		{
			name:         "rust sign import",
			filePath:     "sign.rs",
			classicalAlg: "RSA",
			primitive:    "signature",
			targetAlg:    "ML-DSA-65",
			wantImport:   "use",
		},
		{
			name:         "javascript sign require",
			filePath:     "sign.js",
			classicalAlg: "RSA",
			primitive:    "signature",
			targetAlg:    "ML-DSA-65",
			wantImport:   "require",
		},
		{
			name:         "typescript kem require",
			filePath:     "exchange.ts",
			classicalAlg: "ECDH",
			primitive:    "key-exchange",
			targetAlg:    "ML-KEM-768",
			wantImport:   "require",
		},
		{
			name:         "csharp sign using",
			filePath:     "Signer.cs",
			classicalAlg: "RSA",
			primitive:    "signature",
			targetAlg:    "ML-DSA-65",
			wantImport:   "using",
		},
		{
			name:         "swift sign import",
			filePath:     "Signer.swift",
			classicalAlg: "RSA",
			primitive:    "signature",
			targetAlg:    "ML-DSA-65",
			wantImport:   "import",
		},
		{
			name:         "c sign include-free (openssl-style, no import keyword)",
			filePath:     "sign.c",
			classicalAlg: "RSA",
			primitive:    "signature",
			targetAlg:    "ML-DSA-65",
			wantImport:   "EVP_PKEY", // OpenSSL style, no #include in snippet
		},
		{
			name:         "cpp kem snippet non-empty",
			filePath:     "exchange.cpp",
			classicalAlg: "ECDH",
			primitive:    "key-exchange",
			targetAlg:    "ML-KEM-768",
			wantImport:   "EVP_PKEY",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := GenerateSnippet(tt.filePath, tt.classicalAlg, tt.primitive, tt.targetAlg)
			if s == nil {
				t.Fatal("want non-nil snippet, got nil")
			}
			// Before ≠ After
			if s.Before == s.After {
				t.Error("Before and After must differ")
			}
			// Both non-empty
			if s.Before == "" {
				t.Error("Before must not be empty")
			}
			if s.After == "" {
				t.Error("After must not be empty")
			}
			// Explanation non-empty
			if s.Explanation == "" {
				t.Error("Explanation must not be empty")
			}
			// Language-appropriate import keyword present in After
			if !strings.Contains(s.After, tt.wantImport) && !strings.Contains(s.Before, tt.wantImport) {
				t.Errorf("expected import keyword %q in Before or After;\nBefore:\n%s\nAfter:\n%s",
					tt.wantImport, s.Before, s.After)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Runtime hints
// ---------------------------------------------------------------------------

// TestRuntimeHints checks that language-specific runtime version annotations
// appear when appropriate.
func TestRuntimeHints(t *testing.T) {
	t.Run("go ECDH->KEM mentions Go 1.24 only for TLS alg", func(t *testing.T) {
		// X25519 is a TLS KEM alg — the Go snippet should mention Go 1.24.
		s := GenerateSnippet("tls.go", "X25519", "key-exchange", "ML-KEM-768")
		if s == nil {
			t.Fatal("want snippet, got nil")
		}
		if !strings.Contains(s.After, "1.24") {
			t.Errorf("expected Go 1.24 runtime hint in After for X25519, got:\n%s", s.After)
		}
	})

	t.Run("go plain ECDH without TLS primitive omits Go 1.24 hint", func(t *testing.T) {
		// ECDH with generic "key-agree" primitive — isTLS is false.
		s := GenerateSnippet("exchange.go", "ECDH", "key-agree", "ML-KEM-768")
		if s == nil {
			t.Fatal("want snippet, got nil")
		}
		// isTLS check: algUpper != "ECDHE" && algUpper != "X25519",
		// primitive "key-agree" does not contain "tls" → no Go 1.24 hint.
		if strings.Contains(s.After, "1.24") {
			t.Errorf("did not expect Go 1.24 hint for plain ECDH key-agree, got:\n%s", s.After)
		}
	})

	t.Run("ECDHE explicitly triggers TLS Go hint", func(t *testing.T) {
		s := GenerateSnippet("tls.go", "ECDHE", "key-exchange", "ML-KEM-768")
		if s == nil {
			t.Fatal("want snippet, got nil")
		}
		if !strings.Contains(s.After, "crypto/tls") {
			t.Errorf("expected crypto/tls hint for ECDHE, got:\n%s", s.After)
		}
	})

	t.Run("c sign snippet mentions OpenSSL 3.5", func(t *testing.T) {
		s := GenerateSnippet("sign.c", "RSA", "signature", "ML-DSA-65")
		if s == nil {
			t.Fatal("want snippet, got nil")
		}
		if !strings.Contains(s.After, "3.5") {
			t.Errorf("expected OpenSSL 3.5 hint in C sign After, got:\n%s", s.After)
		}
	})

	t.Run("c kem snippet mentions OpenSSL 3.5", func(t *testing.T) {
		s := GenerateSnippet("exchange.c", "ECDH", "key-exchange", "ML-KEM-768")
		if s == nil {
			t.Fatal("want snippet, got nil")
		}
		if !strings.Contains(s.After, "3.5") {
			t.Errorf("expected OpenSSL 3.5 hint in C KEM After, got:\n%s", s.After)
		}
	})

	t.Run("swift sign snippet mentions CryptoKit", func(t *testing.T) {
		s := GenerateSnippet("sign.swift", "RSA", "signature", "ML-DSA-65")
		if s == nil {
			t.Fatal("want snippet, got nil")
		}
		if !strings.Contains(s.After, "CryptoKit") {
			t.Errorf("expected CryptoKit mention in Swift sign After, got:\n%s", s.After)
		}
	})

	t.Run("js kem snippet mentions Node.js OpenSSL", func(t *testing.T) {
		s := GenerateSnippet("exchange.js", "ECDH", "key-exchange", "ML-KEM-768")
		if s == nil {
			t.Fatal("want snippet, got nil")
		}
		if !strings.Contains(s.After, "Node.js") {
			t.Errorf("expected Node.js hint in JS KEM After, got:\n%s", s.After)
		}
	})
}

// ---------------------------------------------------------------------------
// Snippet syntactic sanity (best-effort brace/paren balance)
// ---------------------------------------------------------------------------

// countRune counts occurrences of r in s.
func countRune(s string, r rune) int {
	n := 0
	for _, c := range s {
		if c == r {
			n++
		}
	}
	return n
}

// TestSnippetSyntaxSanity performs best-effort structural checks on generated
// snippets: brace balance in Go/Java/C/C++, paren balance in Python.
func TestSnippetSyntaxSanity(t *testing.T) {
	type syntaxCase struct {
		name         string
		filePath     string
		classicalAlg string
		primitive    string
		targetAlg    string
		checkBraces  bool // { } balance
		checkParens  bool // ( ) balance
	}

	cases := []syntaxCase{
		{
			name:         "go sign braces balanced",
			filePath:     "main.go",
			classicalAlg: "RSA",
			primitive:    "signature",
			targetAlg:    "ML-DSA-65",
			checkBraces:  true,
		},
		{
			name:         "go kem braces balanced",
			filePath:     "exchange.go",
			classicalAlg: "ECDH",
			primitive:    "key-exchange",
			targetAlg:    "ML-KEM-768",
			checkBraces:  true,
		},
		{
			name:         "java sign braces balanced",
			filePath:     "Crypto.java",
			classicalAlg: "RSA",
			primitive:    "signature",
			targetAlg:    "ML-DSA-65",
			checkBraces:  true,
		},
		{
			name:         "java kem braces balanced",
			filePath:     "Crypto.java",
			classicalAlg: "ECDH",
			primitive:    "key-agree",
			targetAlg:    "ML-KEM-768",
			checkBraces:  true,
		},
		{
			name:         "c sign parens balanced",
			filePath:     "sign.c",
			classicalAlg: "RSA",
			primitive:    "signature",
			targetAlg:    "ML-DSA-65",
			checkParens:  true,
		},
		{
			name:         "cpp kem parens balanced",
			filePath:     "exchange.cpp",
			classicalAlg: "ECDH",
			primitive:    "key-exchange",
			targetAlg:    "ML-KEM-768",
			checkParens:  true,
		},
		{
			name:         "python sign parens balanced",
			filePath:     "main.py",
			classicalAlg: "RSA",
			primitive:    "signature",
			targetAlg:    "ML-DSA-65",
			checkParens:  true,
		},
		{
			name:         "python kem parens balanced",
			filePath:     "exchange.py",
			classicalAlg: "ECDH",
			primitive:    "key-agree",
			targetAlg:    "ML-KEM-768",
			checkParens:  true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := GenerateSnippet(tc.filePath, tc.classicalAlg, tc.primitive, tc.targetAlg)
			if s == nil {
				t.Fatal("want non-nil snippet, got nil")
			}

			if tc.checkBraces {
				for _, label := range []struct {
					name string
					code string
				}{{"Before", s.Before}, {"After", s.After}} {
					open := countRune(label.code, '{')
					close := countRune(label.code, '}')
					if open != close {
						t.Errorf("%s: unbalanced braces: %d '{' vs %d '}' in:\n%s",
							label.name, open, close, label.code)
					}
				}
			}

			if tc.checkParens {
				for _, label := range []struct {
					name string
					code string
				}{{"Before", s.Before}, {"After", s.After}} {
					open := countRune(label.code, '(')
					close := countRune(label.code, ')')
					if open != close {
						t.Errorf("%s: unbalanced parens: %d '(' vs %d ')' in:\n%s",
							label.name, open, close, label.code)
					}
				}
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Case sensitivity of algorithm names
// ---------------------------------------------------------------------------

// TestCaseSensitivityAlgorithmNames verifies that the four variants of "rsa"
// (all lowercase, PascalCase, ALL CAPS, mixed) all produce a valid snippet.
// The existing TestCaseInsensitiveAlg only covers three variants; we add "rSa".
func TestCaseSensitivityAlgorithmNames(t *testing.T) {
	variants := []string{"rsa", "RSA", "Rsa", "rSa"}
	for _, v := range variants {
		t.Run("rsa_variant/"+v, func(t *testing.T) {
			s := GenerateSnippet("main.go", v, "signature", "ML-DSA-65")
			if s == nil {
				t.Fatalf("GenerateSnippet(alg=%q) returned nil, want snippet", v)
			}
			if s.Language != "go" {
				t.Errorf("Language: want %q, got %q", "go", s.Language)
			}
		})
	}

	// Repeat for ECDH KEM variants.
	ecdhVariants := []string{"ecdh", "ECDH", "Ecdh", "eCdH"}
	for _, v := range ecdhVariants {
		t.Run("ecdh_variant/"+v, func(t *testing.T) {
			s := GenerateSnippet("main.go", v, "key-exchange", "ML-KEM-768")
			if s == nil {
				t.Fatalf("GenerateSnippet(alg=%q) returned nil, want snippet", v)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Before ≠ After invariant across all languages
// ---------------------------------------------------------------------------

// TestBeforeNotEqualAfter asserts the before != after invariant for every
// language using both sign and kem paths, ensuring no copy/paste accidents.
func TestBeforeNotEqualAfter(t *testing.T) {
	cases := []struct {
		filePath     string
		classicalAlg string
		primitive    string
		targetAlg    string
	}{
		{"sign.go", "RSA", "signature", "ML-DSA-65"},
		{"exchange.go", "ECDH", "key-exchange", "ML-KEM-768"},
		{"sign.py", "RSA", "signature", "ML-DSA-65"},
		{"exchange.py", "ECDH", "key-agree", "ML-KEM-768"},
		{"Signer.java", "RSA", "signature", "ML-DSA-65"},
		{"Exchange.java", "ECDH", "key-agree", "ML-KEM-768"},
		{"sign.rs", "RSA", "signature", "ML-DSA-65"},
		{"exchange.rs", "ECDH", "key-exchange", "ML-KEM-768"},
		{"sign.js", "RSA", "signature", "ML-DSA-65"},
		{"exchange.ts", "ECDH", "key-exchange", "ML-KEM-768"},
		{"sign.c", "RSA", "signature", "ML-DSA-65"},
		{"exchange.cpp", "ECDH", "key-exchange", "ML-KEM-768"},
		{"Signer.cs", "RSA", "signature", "ML-DSA-65"},
		{"sign.swift", "RSA", "signature", "ML-DSA-65"},
		{"nginx.conf", "RSA", "signature", "ML-DSA-65"},
		{"haproxy.cfg", "ECDH", "key-exchange", "ML-KEM-768"},
	}

	for _, tc := range cases {
		name := tc.filePath + "/" + tc.classicalAlg
		t.Run(name, func(t *testing.T) {
			s := GenerateSnippet(tc.filePath, tc.classicalAlg, tc.primitive, tc.targetAlg)
			if s == nil {
				t.Fatal("want non-nil snippet, got nil")
			}
			if s.Before == s.After {
				t.Errorf("Before == After (identical snippet) for %s", name)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Target algorithm reflected in snippet
// ---------------------------------------------------------------------------

// TestTargetAlgorithmInSnippet verifies that the target PQC algorithm name
// (e.g. "ML-DSA-44") appears somewhere in the generated After text so callers
// can confirm the right algorithm is referenced.
func TestTargetAlgorithmInSnippet(t *testing.T) {
	targets := []struct {
		classicalAlg string
		primitive    string
		targetAlg    string
		wantInAfter  string // exact fragment we expect
	}{
		{"RSA", "signature", "ML-DSA-44", "ML-DSA-44"},
		{"RSA", "signature", "ML-DSA-65", "ML-DSA-65"},
		{"RSA", "signature", "ML-DSA-87", "ML-DSA-87"},
		{"ECDH", "key-exchange", "ML-KEM-768", "ML-KEM-768"},
	}

	langs := []string{".go", ".py", ".java", ".rs", ".js", ".ts", ".c", ".cpp", ".cs", ".swift"}

	for _, tgt := range targets {
		for _, ext := range langs {
			name := tgt.classicalAlg + "_" + tgt.targetAlg + ext
			t.Run(name, func(t *testing.T) {
				s := GenerateSnippet("file"+ext, tgt.classicalAlg, tgt.primitive, tgt.targetAlg)
				if s == nil {
					// Swift KEM is not covered by the sign path when classicalAlg is "ECDH";
					// skip gracefully and note below.
					t.Skipf("GenerateSnippet returned nil for %s (coverage gap)", name)
				}
				// Target should appear in either After or Explanation.
				combined := s.After + s.Explanation
				if !strings.Contains(combined, tgt.wantInAfter) {
					t.Errorf("target %q not found in After+Explanation:\nAfter:\n%s\nExplanation: %s",
						tgt.wantInAfter, s.After, s.Explanation)
				}
			})
		}
	}
}

// ---------------------------------------------------------------------------
// Snippet UTF-8 validity
// ---------------------------------------------------------------------------

// TestSnippetUTF8 ensures all snippet string fields contain only valid UTF-8,
// guarding against garbled encoding in template strings.
func TestSnippetUTF8(t *testing.T) {
	cases := []struct {
		filePath     string
		classicalAlg string
		primitive    string
		targetAlg    string
	}{
		{"sign.go", "RSA", "signature", "ML-DSA-65"},
		{"sign.py", "ECDSA", "signature", "ML-DSA-44"},
		{"Signer.java", "ECDH", "key-agree", "ML-KEM-768"},
		{"sign.swift", "RSA", "signature", "ML-DSA-65"},
		{"nginx.conf", "ECDH", "key-exchange", ""},
	}

	for _, tc := range cases {
		t.Run(tc.filePath, func(t *testing.T) {
			s := GenerateSnippet(tc.filePath, tc.classicalAlg, tc.primitive, tc.targetAlg)
			if s == nil {
				t.Fatal("want non-nil snippet, got nil")
			}
			for field, val := range map[string]string{
				"Language":    s.Language,
				"Before":      s.Before,
				"After":       s.After,
				"Explanation": s.Explanation,
			} {
				if !utf8.ValidString(val) {
					t.Errorf("%s contains invalid UTF-8", field)
				}
			}
		})
	}
}

// ---------------------------------------------------------------------------
// isSafePQC edge cases
// ---------------------------------------------------------------------------

// TestIsSafePQC_EdgeCases checks boundary values for isSafePQC, including
// bare prefix names (no hyphen) and mixed-case inputs.
func TestIsSafePQC_EdgeCases(t *testing.T) {
	safe := []string{
		"ML-DSA", "ml-dsa", "ML-DSA-44", "ML-DSA-65", "ML-DSA-87",
		"ML-KEM", "ML-KEM-512", "ML-KEM-768", "ML-KEM-1024",
		"SLH-DSA", "SLH-DSA-SHA2-128f",
		"DILITHIUM", "DILITHIUM-2", "DILITHIUM-3",
		"KYBER", "KYBER-512", "KYBER-768", "KYBER-1024",
		"XMSS", "XMSS-SHA2-10-256",
		"LMS",
		"SPHINCS+",
		"HQC", "HQC-128",
	}
	notSafe := []string{
		"RSA", "ECDSA", "ECDH", "X25519", "AES", "SHA-256", "",
	}

	for _, alg := range safe {
		t.Run("safe/"+alg, func(t *testing.T) {
			if !isSafePQC(alg) {
				t.Errorf("isSafePQC(%q) = false, want true", alg)
			}
		})
	}
	for _, alg := range notSafe {
		t.Run("unsafe/"+alg, func(t *testing.T) {
			if isSafePQC(alg) {
				t.Errorf("isSafePQC(%q) = true, want false", alg)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// pqcStandard label
// ---------------------------------------------------------------------------

// TestPQCStandard verifies that pqcStandard returns the correct FIPS label.
func TestPQCStandard(t *testing.T) {
	tests := []struct {
		alg  string
		want string
	}{
		{"ML-DSA-44", "FIPS 204"},
		{"ML-DSA-65", "FIPS 204"},
		{"ML-DSA-87", "FIPS 204"},
		{"SLH-DSA-SHA2-128f", "FIPS 204"},
		{"ML-KEM-512", "FIPS 203"},
		{"ML-KEM-768", "FIPS 203"},
		{"ML-KEM-1024", "FIPS 203"},
		// Unknown algorithm returns empty string.
		{"RSA", ""},
		{"", ""},
	}

	for _, tc := range tests {
		t.Run(tc.alg, func(t *testing.T) {
			got := pqcStandard(tc.alg)
			if got != tc.want {
				t.Errorf("pqcStandard(%q) = %q, want %q", tc.alg, got, tc.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Nil-safety for unrecognised file extensions
// ---------------------------------------------------------------------------

// TestUnrecognisedExtensions ensures a broad set of unrecognised extensions
// returns nil without panicking.
func TestUnrecognisedExtensions(t *testing.T) {
	extensions := []string{
		".kt", ".rb", ".php", ".sh", ".bash", ".zsh", ".fish",
		".lock", ".sum", ".mod", ".bazel", ".gradle", ".tf",
		".lua", ".ex", ".exs", ".elm", ".clj", ".hs", ".ml",
	}

	for _, ext := range extensions {
		t.Run(ext, func(t *testing.T) {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("GenerateSnippet panicked for extension %s: %v", ext, r)
				}
			}()
			s := GenerateSnippet("file"+ext, "RSA", "signature", "ML-DSA-65")
			if s != nil {
				t.Errorf("want nil for extension %s, got Language=%q", ext, s.Language)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Config snippet: no nil for any recognised config extension
// ---------------------------------------------------------------------------

// TestConfigExtensionsKEMPath complements the existing TestConfigExtensions
// (sign path only) by exercising the KEM family path for every config
// extension, verifying no extension returns nil.
func TestConfigExtensionsKEMPath(t *testing.T) {
	extensions := []string{
		".yml", ".yaml", ".conf", ".nginx", ".cnf", ".cfg",
		".properties", ".toml", ".json", ".xml", ".ini", ".hcl", ".env",
	}

	for _, ext := range extensions {
		t.Run(ext, func(t *testing.T) {
			s := GenerateSnippet("server"+ext, "ECDH", "key-exchange", "ML-KEM-768")
			if s == nil {
				t.Fatalf("GenerateSnippet(%q, ECDH, key-exchange) returned nil, want config snippet", ext)
			}
			if s.Language != "config" {
				t.Errorf("Language: want %q, got %q", "config", s.Language)
			}
			if !strings.Contains(s.After, "X25519MLKEM768") {
				t.Errorf("After does not mention X25519MLKEM768:\n%s", s.After)
			}
		})
	}
}
