package astgrep

import (
	"os"
	"path/filepath"
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
		wantKeySize int
		wantMode    string
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
			name: "openssl evp encrypt init parses CIPHER selector",
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
				MetaVars: rawMetaVars{
					"CIPHER": {Text: "EVP_aes_256_cbc()"},
				},
			},
			wantFile:    "lib/crypto.c",
			wantLine:    1,
			wantColumn:  1,
			wantAlg:     "AES",
			wantPrim:    "symmetric",
			wantKeySize: 256,
			wantMode:    "CBC",
			wantConf:    findings.ConfidenceMedium,
			wantEngine:  "astgrep",
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
			wantFile:    "internal/keys.go",
			wantLine:    20,
			wantColumn:  2,
			wantAlg:     "RSA", // curated name — NOT the poisoned "2048-bit" message suffix
			wantPrim:    "pke",
			wantKeySize: 2048,
			wantConf:    findings.ConfidenceHigh,
			wantEngine:  "astgrep",
		},
		{
			name: "python hashlib md5 info severity curated name",
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
			wantAlg:    "MD5",
			wantPrim:   "hash",
			wantConf:   findings.ConfidenceLow,
			wantEngine: "astgrep",
		},
		{
			name: "go ecdh generate key curated name",
			match: rawMatch{
				Text:     "ecdh.P256().GenerateKey(rand.Reader)",
				File:     "internal/kex.go",
				Language: "go",
				RuleID:   "crypto-go-ecdh-generate-key",
				Message:  "Go crypto/ecdh P-256 key generation",
				Severity: "warning",
				Range: rawRange{
					Start: rawPosition{Line: 7, Column: 0},
				},
				MetaVars: rawMetaVars{},
			},
			wantFile:   "internal/kex.go",
			wantLine:   8,
			wantColumn: 1,
			wantAlg:    "ECDH",
			wantPrim:   "key-agree",
			wantConf:   findings.ConfidenceMedium,
			wantEngine: "astgrep",
		},
		{
			name: "node generateKeyPairSync rsa with modulusLength",
			match: rawMatch{
				Text:     "crypto.generateKeyPairSync('rsa', { modulusLength: 2048 })",
				File:     "src/keys.js",
				Language: "javascript",
				RuleID:   "crypto-node-generate-key-pair-sync-modulus",
				Message:  "Node crypto.generateKeyPairSync: 'rsa' 2048-bit",
				Severity: "warning",
				Range: rawRange{
					Start: rawPosition{Line: 2, Column: 0},
				},
				MetaVars: rawMetaVars{
					"TYPE": {Text: "'rsa'"},
					"BITS": {Text: "2048"},
				},
			},
			wantFile:    "src/keys.js",
			wantLine:    3,
			wantColumn:  1,
			wantAlg:     "RSA",
			wantPrim:    "pke",
			wantKeySize: 2048,
			wantConf:    findings.ConfidenceMedium,
			wantEngine:  "astgrep",
		},
		{
			name: "jwt sign RS256 maps to RSA",
			match: rawMatch{
				Text:     "jwt.sign(payload, key, { algorithm: 'RS256' })",
				File:     "src/auth.ts",
				Language: "typescript",
				RuleID:   "crypto-node-jwt-sign-ts",
				Message:  "jsonwebtoken jwt.sign: 'RS256'",
				Severity: "warning",
				Range: rawRange{
					Start: rawPosition{Line: 11, Column: 0},
				},
				MetaVars: rawMetaVars{
					"ALGO": {Text: "'RS256'"},
				},
			},
			wantFile:   "src/auth.ts",
			wantLine:   12,
			wantColumn: 1,
			wantAlg:    "RSA",
			wantPrim:   "signature",
			wantConf:   findings.ConfidenceMedium,
			wantEngine: "astgrep",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			uf := normalize(tc.match, nil)

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
				if uf.Algorithm.KeySize != tc.wantKeySize {
					t.Errorf("Algorithm.KeySize: got %d, want %d", uf.Algorithm.KeySize, tc.wantKeySize)
				}
				if uf.Algorithm.Mode != tc.wantMode {
					t.Errorf("Algorithm.Mode: got %q, want %q", uf.Algorithm.Mode, tc.wantMode)
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
			name: "openssl CIPHER selector parsed to family name",
			match: rawMatch{
				RuleID:  "crypto-openssl-evp-encrypt-init",
				Message: "OpenSSL EVP_EncryptInit usage: EVP_aes_128_cbc()",
				MetaVars: rawMetaVars{
					"CIPHER": {Text: "EVP_aes_128_cbc()"},
				},
			},
			want: "AES",
		},
		{
			name: "curated ruleID name beats old last-segment fallback",
			match: rawMatch{
				RuleID:   "crypto-python-hashlib-sha256",
				Message:  "Python hashlib.sha256 usage",
				MetaVars: rawMetaVars{},
			},
			want: "SHA-256",
		},
		{
			name: "message suffix is never consulted (no 2048-bit poisoning)",
			match: rawMatch{
				RuleID:   "crypto-go-rsa-generate-key",
				Message:  "Go crypto/rsa GenerateKey: 2048-bit",
				MetaVars: rawMetaVars{"BITS": {Text: "2048"}},
			},
			want: "RSA",
		},
		{
			name: "node keygen type token canonicalized",
			match: rawMatch{
				RuleID:   "crypto-node-generate-key-pair",
				Message:  "Node crypto.generateKeyPair: 'ec'",
				MetaVars: rawMetaVars{"TYPE": {Text: "'ec'"}},
			},
			want: "ECDSA",
		},
		{
			name: "unquoted variable capture falls back to metadata not garbage",
			match: rawMatch{
				RuleID:   "crypto-java-cipher",
				Message:  "Java Cipher.getInstance: transform",
				MetaVars: rawMetaVars{"ALGO": {Text: "transform"}},
			},
			want: "", // value-generic rule + unresolvable capture → no algorithm
		},
		{
			name: "java signature transform maps to base algorithm",
			match: rawMatch{
				RuleID:   "crypto-java-signature",
				Message:  `Java Signature.getInstance: "SHA256withRSA"`,
				MetaVars: rawMetaVars{"ALGO": {Text: `"SHA256withRSA"`}},
			},
			want: "RSA",
		},
		{
			name: "unknown external rule infers from ruleID token",
			match: rawMatch{
				RuleID:   "custom-md5-usage-check",
				MetaVars: rawMetaVars{},
			},
			want: "MD5",
		},
		{
			name: "unknown external rule with no algorithm token yields empty (no NEW/CONFIG)",
			match: rawMatch{
				RuleID:   "custom-thing-new",
				MetaVars: rawMetaVars{},
			},
			want: "",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := extractAlgorithm(tc.match, nil)
			if got != tc.want {
				t.Errorf("extractAlgorithm: got %q, want %q", got, tc.want)
			}
		})
	}
}

// TestExtractAlgorithm_LoadedMetadataWins verifies that metadata harvested from
// rule files (the map returned by resolveRulesFile) takes precedence over the
// builtin table and ruleID inference for static names.
func TestExtractAlgorithm_LoadedMetadataWins(t *testing.T) {
	meta := map[string]ruleMeta{
		"external-custom-keygen": {Algorithm: "DSA", Primitive: "signature"},
	}
	m := rawMatch{RuleID: "external-custom-keygen", MetaVars: rawMetaVars{}}
	if got := extractAlgorithm(m, meta); got != "DSA" {
		t.Errorf("extractAlgorithm with loaded metadata: got %q, want %q", got, "DSA")
	}
	uf := normalize(m, meta)
	if uf.Algorithm == nil || uf.Algorithm.Primitive != "signature" {
		t.Errorf("normalize should take primitive from loaded metadata, got %+v", uf.Algorithm)
	}
}

// TestMetaVarsUnmarshal_NestedSingle pins the real ast-grep CLI JSON contract:
// metaVariables nests single captures under "single". The flat legacy shape
// must keep working for old fixtures.
func TestMetaVarsUnmarshal_NestedSingle(t *testing.T) {
	nested := []byte(`{"single":{"BITS":{"text":"2048"},"ALGO":{"text":"'rsa'"}},"multi":{},"transformed":{}}`)
	var mv rawMetaVars
	if err := mv.UnmarshalJSON(nested); err != nil {
		t.Fatalf("nested unmarshal: %v", err)
	}
	if mv["BITS"].Text != "2048" || mv["ALGO"].Text != "'rsa'" {
		t.Errorf("nested metaVariables not decoded: %+v", mv)
	}

	flat := []byte(`{"BITS":{"text":"4096"}}`)
	mv = nil
	if err := mv.UnmarshalJSON(flat); err != nil {
		t.Fatalf("flat unmarshal: %v", err)
	}
	if mv["BITS"].Text != "4096" {
		t.Errorf("flat metaVariables not decoded: %+v", mv)
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

// readDir lists file names in a directory using os.ReadDir.
// Retained for use by other tests; the legacy TestEmbeddedRulesExtract
// covered the dir-extract path, but extractEmbeddedRules was replaced with
// concatEmbeddedRules → see rules_transform_test.go for the new coverage.
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

// TestFindBinary_RejectsSystemSGCommand guards against a real, observed CI
// failure: "sg" is also the Unix substitute-group-ID command (shadow-utils),
// present on virtually every Linux box including bare GitHub Actions runners
// that never installed ast-grep. Blindly trusting exec.LookPath("sg") makes
// Available() a false positive, and Scan() then invokes the wrong binary
// entirely — observed as "sg: group 'scan' does not exist" in CI, because
// astgrep's first CLI arg ("scan") gets interpreted as a Unix group name.
func TestFindBinary_RejectsSystemSGCommand(t *testing.T) {
	dir := t.TempDir()
	fakeSG := filepath.Join(dir, "sg")
	// Mimics the real coreutils/shadow-utils sg: errors on an unrecognized
	// "group", says nothing about ast-grep.
	script := "#!/bin/sh\necho \"sg: group '$1' does not exist\" >&2\nexit 1\n"
	if err := os.WriteFile(fakeSG, []byte(script), 0755); err != nil {
		t.Fatalf("write fake sg: %v", err)
	}
	// Isolate PATH so a real ast-grep/sg installed on the dev/CI machine
	// running this test suite can't mask the fake — this test exists
	// specifically because a real "sg" (the Unix command) sits on PATH in
	// bare CI environments.
	t.Setenv("PATH", dir)

	e := &Engine{}
	got := e.findBinary(nil)
	if got != "" {
		t.Errorf("findBinary resolved the system sg command as ast-grep: %q", got)
	}
}

// TestFindBinary_AcceptsRealAstGrepNamedSG is the positive control: a
// genuine ast-grep binary invoked under its short "sg" alias must still be
// recognized.
func TestFindBinary_AcceptsRealAstGrepNamedSG(t *testing.T) {
	dir := t.TempDir()
	fakeSG := filepath.Join(dir, "sg")
	script := "#!/bin/sh\necho 'ast-grep 0.38.6'\n"
	if err := os.WriteFile(fakeSG, []byte(script), 0755); err != nil {
		t.Fatalf("write fake ast-grep-as-sg: %v", err)
	}
	t.Setenv("PATH", dir)

	e := &Engine{}
	got := e.findBinary(nil)
	if got != fakeSG {
		t.Errorf("findBinary(nil) = %q, want %q (real ast-grep under the sg alias)", got, fakeSG)
	}
}
