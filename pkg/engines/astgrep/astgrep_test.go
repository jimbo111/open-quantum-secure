package astgrep

import (
	"os"
	"testing"

	"github.com/jimbo111/open-quantum-secure/pkg/findings"
)

func TestNormalize(t *testing.T) {
	tests := []struct {
		name        string
		match       rawMatch
		wantFile    string
		wantLine    int
		wantColumn  int
		wantAlg     string
		wantPrim    string
		wantConf    findings.Confidence
		wantEngine  string
	}{
		{
			name: "java cipher with ALGO metavar",
			match: rawMatch{
				Text:     `Cipher.getInstance("AES/CBC/PKCS5Padding")`,
				File:     "src/Crypto.java",
				Language: "java",
				RuleID:   "crypto-java-cipher",
				Message:  `Java Cipher.getInstance: "AES/CBC/PKCS5Padding"`,
				Severity: "warning",
				Range: rawRange{
					Start: rawPosition{Line: 9, Column: 4},
					End:   rawPosition{Line: 9, Column: 45},
				},
				MetaVars: rawMetaVars{
					"ALGO": {Text: `"AES/CBC/PKCS5Padding"`},
				},
			},
			wantFile:   "src/Crypto.java",
			wantLine:   10, // 0-indexed → 1-indexed
			wantColumn: 5,
			wantAlg:    "AES/CBC/PKCS5Padding",
			wantPrim:   "symmetric",
			wantConf:   findings.ConfidenceMedium,
			wantEngine: "astgrep",
		},
		{
			name: "openssl evp encrypt init no metavar",
			match: rawMatch{
				Text:     "EVP_EncryptInit(ctx, EVP_aes_256_cbc(), key, iv)",
				File:     "lib/crypto.c",
				Language: "c",
				RuleID:   "crypto-openssl-evp-encrypt-init",
				Message:  "OpenSSL EVP_EncryptInit usage: EVP_aes_256_cbc()",
				Severity: "warning",
				Range: rawRange{
					Start: rawPosition{Line: 0, Column: 0},
				},
				MetaVars: rawMetaVars{},
			},
			wantFile:   "lib/crypto.c",
			wantLine:   1,
			wantColumn: 1,
			wantAlg:    "EVP_aes_256_cbc()",
			wantPrim:   "symmetric",
			wantConf:   findings.ConfidenceMedium,
			wantEngine: "astgrep",
		},
		{
			name: "go rsa generate key error severity",
			match: rawMatch{
				Text:     "rsa.GenerateKey(rand.Reader, 2048)",
				File:     "internal/keys.go",
				Language: "go",
				RuleID:   "crypto-go-rsa-generate-key",
				Message:  "Go crypto/rsa GenerateKey: 2048-bit",
				Severity: "error",
				Range: rawRange{
					Start: rawPosition{Line: 19, Column: 1},
				},
				MetaVars: rawMetaVars{
					"BITS": {Text: "2048"},
				},
			},
			wantFile:   "internal/keys.go",
			wantLine:   20,
			wantColumn: 2,
			wantAlg:    "2048-bit",
			wantPrim:   "asymmetric",
			wantConf:   findings.ConfidenceHigh,
			wantEngine: "astgrep",
		},
		{
			name: "python hashlib md5 info severity fallback ruleId",
			match: rawMatch{
				Text:     "hashlib.md5(data)",
				File:     "utils/hash.py",
				Language: "python",
				RuleID:   "crypto-python-hashlib-md5",
				Message:  "Python hashlib.md5 usage",
				Severity: "info",
				Range: rawRange{
					Start: rawPosition{Line: 4, Column: 0},
				},
				MetaVars: rawMetaVars{},
			},
			wantFile:   "utils/hash.py",
			wantLine:   5,
			wantColumn: 1,
			wantAlg:    "MD5", // ruleId last segment uppercased
			wantPrim:   "hash",
			wantConf:   findings.ConfidenceLow,
			wantEngine: "astgrep",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			uf := normalize(tc.match)

			if uf.Location.File != tc.wantFile {
				t.Errorf("File: got %q, want %q", uf.Location.File, tc.wantFile)
			}
			if uf.Location.Line != tc.wantLine {
				t.Errorf("Line: got %d, want %d", uf.Location.Line, tc.wantLine)
			}
			if uf.Location.Column != tc.wantColumn {
				t.Errorf("Column: got %d, want %d", uf.Location.Column, tc.wantColumn)
			}
			if uf.Confidence != tc.wantConf {
				t.Errorf("Confidence: got %q, want %q", uf.Confidence, tc.wantConf)
			}
			if uf.SourceEngine != tc.wantEngine {
				t.Errorf("SourceEngine: got %q, want %q", uf.SourceEngine, tc.wantEngine)
			}
			if tc.wantAlg != "" {
				if uf.Algorithm == nil {
					t.Fatalf("Algorithm: got nil, want %q", tc.wantAlg)
				}
				if uf.Algorithm.Name != tc.wantAlg {
					t.Errorf("Algorithm.Name: got %q, want %q", uf.Algorithm.Name, tc.wantAlg)
				}
				if uf.Algorithm.Primitive != tc.wantPrim {
					t.Errorf("Algorithm.Primitive: got %q, want %q", uf.Algorithm.Primitive, tc.wantPrim)
				}
			}
		})
	}
}

func TestExtractAlgorithm(t *testing.T) {
	tests := []struct {
		name  string
		match rawMatch
		want  string
	}{
		{
			name: "ALGO metavar wins",
			match: rawMatch{
				RuleID:  "crypto-java-cipher",
				Message: "Java Cipher.getInstance: RSA",
				MetaVars: rawMetaVars{
					"ALGO": {Text: "RSA"},
				},
			},
			want: "RSA",
		},
		{
			name: "quoted ALGO metavar stripped",
			match: rawMatch{
				RuleID:  "crypto-java-cipher",
				Message: `Java Cipher.getInstance: "AES/GCM/NoPadding"`,
				MetaVars: rawMetaVars{
					"ALGO": {Text: `"AES/GCM/NoPadding"`},
				},
			},
			want: "AES/GCM/NoPadding",
		},
		{
			name: "message colon extraction fallback",
			match: rawMatch{
				RuleID:   "crypto-openssl-evp-encrypt-init",
				Message:  "OpenSSL EVP_EncryptInit usage: EVP_aes_128_cbc",
				MetaVars: rawMetaVars{},
			},
			want: "EVP_aes_128_cbc",
		},
		{
			name: "ruleId last segment fallback",
			match: rawMatch{
				RuleID:   "crypto-python-hashlib-sha256",
				Message:  "Python hashlib.sha256 usage",
				MetaVars: rawMetaVars{},
			},
			want: "SHA256",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := extractAlgorithm(tc.match)
			if got != tc.want {
				t.Errorf("extractAlgorithm: got %q, want %q", got, tc.want)
			}
		})
	}
}

func TestConfidenceFromSeverity(t *testing.T) {
	tests := []struct {
		sev  string
		want findings.Confidence
	}{
		{"error", findings.ConfidenceHigh},
		{"ERROR", findings.ConfidenceHigh},
		{"warning", findings.ConfidenceMedium},
		{"Warning", findings.ConfidenceMedium},
		{"info", findings.ConfidenceLow},
		{"hint", findings.ConfidenceLow},
		{"", findings.ConfidenceLow},
	}

	for _, tc := range tests {
		t.Run(tc.sev, func(t *testing.T) {
			got := confidenceFromSeverity(tc.sev)
			if got != tc.want {
				t.Errorf("confidenceFromSeverity(%q): got %q, want %q", tc.sev, got, tc.want)
			}
		})
	}
}

func TestPrimitiveFromRuleID(t *testing.T) {
	tests := []struct {
		ruleID string
		want   string
	}{
		{"crypto-java-cipher", "symmetric"},
		{"crypto-go-rsa-generate-key", "asymmetric"},
		{"crypto-go-ecdsa-sign", "asymmetric"},
		{"crypto-go-sha256-new", "hash"},
		{"crypto-python-hashlib-md5", "hash"},
		{"crypto-openssl-evp-decrypt-init", "symmetric"},
		{"crypto-openssl-evp-decrypt-init-ex", "symmetric"},
		{"crypto-openssl-evp-encrypt-init", "symmetric"},
		{"crypto-java-secret-key-factory", "symmetric"},
		{"crypto-openssl-evp-digest-init", "hash"},
		{"crypto-go-hmac-new", "mac"},
		{"crypto-go-tls-config", "protocol"},
		{"crypto-openssl-ssl-ctx-new", "protocol"},
		{"crypto-python-cryptography-hazmat-ec", "asymmetric"},
		{"crypto-go-ecdh-generate-key", "asymmetric"},
		{"crypto-unknown", ""},
	}

	for _, tc := range tests {
		t.Run(tc.ruleID, func(t *testing.T) {
			got := primitiveFromRuleID(tc.ruleID)
			if got != tc.want {
				t.Errorf("primitiveFromRuleID(%q): got %q, want %q", tc.ruleID, got, tc.want)
			}
		})
	}
}

func TestFindBinary_NotFound(t *testing.T) {
	e := &Engine{}
	// Provide a non-existent directory; binary should not be found.
	result := e.findBinary([]string{"/nonexistent/path"})
	// Only fail if both PATH lookups also found something — unlikely in CI,
	// but we just check the function doesn't panic.
	_ = result
}

func TestAvailableFalseWhenNoBinary(t *testing.T) {
	e := &Engine{binaryPath: ""}
	if e.Available() {
		t.Error("Available() should return false when binaryPath is empty")
	}
}

func TestEngineMetadata(t *testing.T) {
	e := &Engine{}

	if e.Name() != "astgrep" {
		t.Errorf("Name(): got %q, want %q", e.Name(), "astgrep")
	}
	if e.Tier() != 1 { // Tier1Pattern = 1
		t.Errorf("Tier(): got %d, want 1", e.Tier())
	}

	langs := e.SupportedLanguages()
	if len(langs) == 0 {
		t.Error("SupportedLanguages() returned empty slice")
	}
	langSet := make(map[string]bool, len(langs))
	for _, l := range langs {
		langSet[l] = true
	}
	for _, expected := range []string{"go", "java", "python", "c", "cpp"} {
		if !langSet[expected] {
			t.Errorf("SupportedLanguages() missing %q", expected)
		}
	}
}

func TestEmbeddedRulesExtract(t *testing.T) {
	dir, cleanup, err := extractEmbeddedRules()
	if err != nil {
		t.Fatalf("extractEmbeddedRules: %v", err)
	}
	defer cleanup()

	if dir == "" {
		t.Fatal("extractEmbeddedRules returned empty dir")
	}

	// Expect at least one .yml file in the temp dir.
	entries, err := readDir(dir)
	if err != nil {
		t.Fatalf("read temp dir: %v", err)
	}
	if len(entries) == 0 {
		t.Error("extractEmbeddedRules: no rule files written")
	}
	for _, name := range entries {
		if !hasYMLSuffix(name) {
			t.Errorf("unexpected file in rules dir: %s", name)
		}
	}
}

// readDir lists file names in a directory using os.ReadDir.
func readDir(path string) ([]string, error) {
	entries, err := os.ReadDir(path)
	if err != nil {
		return nil, err
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		if !e.IsDir() {
			names = append(names, e.Name())
		}
	}
	return names, nil
}

func hasYMLSuffix(name string) bool {
	return len(name) > 4 && name[len(name)-4:] == ".yml"
}
