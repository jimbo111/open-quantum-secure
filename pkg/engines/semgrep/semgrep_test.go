package semgrep

import (
	"testing"

	"github.com/jimbo111/open-quantum-secure/pkg/engines"
	"github.com/jimbo111/open-quantum-secure/pkg/findings"
)

// --- Engine metadata tests ---

func TestName(t *testing.T) {
	e := New()
	if got := e.Name(); got != "semgrep" {
		t.Errorf("Name() = %q, want %q", got, "semgrep")
	}
}

func TestTier(t *testing.T) {
	e := New()
	if got := e.Tier(); got != engines.Tier2Flow {
		t.Errorf("Tier() = %v, want Tier2Flow", got)
	}
}

func TestSupportedLanguages(t *testing.T) {
	e := New()
	langs := e.SupportedLanguages()
	want := []string{"java", "python", "go", "javascript", "typescript", "c", "cpp", "ruby", "rust", "php"}
	if len(langs) != len(want) {
		t.Fatalf("SupportedLanguages() len = %d, want %d", len(langs), len(want))
	}
	set := make(map[string]bool, len(want))
	for _, l := range langs {
		set[l] = true
	}
	for _, l := range want {
		if !set[l] {
			t.Errorf("SupportedLanguages() missing %q", l)
		}
	}
}

func TestAvailable_NoBinary(t *testing.T) {
	e := &Engine{binaryPath: ""}
	if e.Available() {
		t.Error("Available() = true, want false when binaryPath is empty")
	}
}

func TestAvailable_WithBinary(t *testing.T) {
	e := &Engine{binaryPath: "/usr/bin/semgrep"}
	if !e.Available() {
		t.Error("Available() = false, want true when binaryPath is set")
	}
}

// --- parseSARIF tests ---

func TestParseSARIF_EmptyInput(t *testing.T) {
	result, err := parseSARIF([]byte(`{"runs":[]}`))
	if err != nil {
		t.Fatalf("parseSARIF empty runs: unexpected error: %v", err)
	}
	if len(result) != 0 {
		t.Errorf("parseSARIF empty runs: got %d findings, want 0", len(result))
	}
}

func TestParseSARIF_MalformedJSON(t *testing.T) {
	_, err := parseSARIF([]byte(`{invalid json`))
	if err == nil {
		t.Error("parseSARIF malformed: expected error, got nil")
	}
}

func TestParseSARIF_NoCodeFlows_ConfidenceMedium(t *testing.T) {
	input := `{
		"runs": [{
			"tool": {"driver": {"rules": [
				{"id": "java-rsa-keysize", "properties": {"algorithm": "RSA", "primitive": "asymmetric"}}
			]}},
			"results": [{
				"ruleId": "java-rsa-keysize",
				"message": {"text": "RSA key pair generation detected"},
				"level": "warning",
				"locations": [{
					"physicalLocation": {
						"artifactLocation": {"uri": "src/Crypto.java"},
						"region": {"startLine": 42, "startColumn": 5}
					}
				}]
			}]
		}]
	}`

	results, err := parseSARIF([]byte(input))
	if err != nil {
		t.Fatalf("parseSARIF: unexpected error: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("got %d findings, want 1", len(results))
	}

	f := results[0]
	if f.Confidence != findings.ConfidenceMedium {
		t.Errorf("Confidence = %q, want %q", f.Confidence, findings.ConfidenceMedium)
	}
	if len(f.DataFlowPath) != 0 {
		t.Errorf("DataFlowPath len = %d, want 0", len(f.DataFlowPath))
	}
}

func TestParseSARIF_WithCodeFlows_ConfidenceHigh(t *testing.T) {
	input := `{
		"runs": [{
			"tool": {"driver": {"rules": [
				{"id": "java-rsa-keysize", "properties": {"algorithm": "RSA", "primitive": "asymmetric"}}
			]}},
			"results": [{
				"ruleId": "java-rsa-keysize",
				"message": {"text": "RSA key pair generation detected"},
				"level": "warning",
				"locations": [{
					"physicalLocation": {
						"artifactLocation": {"uri": "src/Crypto.java"},
						"region": {"startLine": 42, "startColumn": 5}
					}
				}],
				"codeFlows": [{
					"threadFlows": [{
						"locations": [
							{
								"location": {
									"physicalLocation": {
										"artifactLocation": {"uri": "src/Crypto.java"},
										"region": {"startLine": 10, "startColumn": 1}
									}
								},
								"message": {"text": "source"}
							},
							{
								"location": {
									"physicalLocation": {
										"artifactLocation": {"uri": "src/Crypto.java"},
										"region": {"startLine": 42, "startColumn": 5}
									}
								},
								"message": {"text": "sink"}
							}
						]
					}]
				}]
			}]
		}]
	}`

	results, err := parseSARIF([]byte(input))
	if err != nil {
		t.Fatalf("parseSARIF: unexpected error: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("got %d findings, want 1", len(results))
	}

	f := results[0]
	if f.Confidence != findings.ConfidenceHigh {
		t.Errorf("Confidence = %q, want %q", f.Confidence, findings.ConfidenceHigh)
	}
	if len(f.DataFlowPath) != 2 {
		t.Fatalf("DataFlowPath len = %d, want 2", len(f.DataFlowPath))
	}
	if f.DataFlowPath[0].Message != "source" {
		t.Errorf("DataFlowPath[0].Message = %q, want %q", f.DataFlowPath[0].Message, "source")
	}
	if f.DataFlowPath[1].Message != "sink" {
		t.Errorf("DataFlowPath[1].Message = %q, want %q", f.DataFlowPath[1].Message, "sink")
	}
}

func TestParseSARIF_AlgorithmFromMetadata(t *testing.T) {
	input := `{
		"runs": [{
			"tool": {"driver": {"rules": [
				{"id": "java-rsa-keysize", "properties": {"algorithm": "RSA", "primitive": "asymmetric"}}
			]}},
			"results": [{
				"ruleId": "java-rsa-keysize",
				"message": {"text": "RSA detected"},
				"level": "warning",
				"locations": [{
					"physicalLocation": {
						"artifactLocation": {"uri": "Main.java"},
						"region": {"startLine": 5, "startColumn": 1}
					}
				}]
			}]
		}]
	}`

	results, err := parseSARIF([]byte(input))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("got %d findings, want 1", len(results))
	}
	f := results[0]
	if f.Algorithm == nil {
		t.Fatal("Algorithm is nil")
	}
	if f.Algorithm.Name != "RSA" {
		t.Errorf("Algorithm.Name = %q, want %q", f.Algorithm.Name, "RSA")
	}
	if f.Algorithm.Primitive != "asymmetric" {
		t.Errorf("Algorithm.Primitive = %q, want %q", f.Algorithm.Primitive, "asymmetric")
	}
}

func TestParseSARIF_AlgorithmFallbackFromRuleID(t *testing.T) {
	// No rule metadata in driver — should fall back to ruleID inference.
	input := `{
		"runs": [{
			"tool": {"driver": {"rules": []}},
			"results": [{
				"ruleId": "go-crypto-rsa-usage",
				"message": {"text": "RSA detected"},
				"level": "warning",
				"locations": [{
					"physicalLocation": {
						"artifactLocation": {"uri": "main.go"},
						"region": {"startLine": 15, "startColumn": 2}
					}
				}]
			}]
		}]
	}`

	results, err := parseSARIF([]byte(input))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("got %d findings, want 1", len(results))
	}
	f := results[0]
	if f.Algorithm == nil {
		t.Fatal("Algorithm is nil, want RSA from ruleID inference")
	}
	if f.Algorithm.Name != "RSA" {
		t.Errorf("Algorithm.Name = %q, want RSA (inferred from ruleID)", f.Algorithm.Name)
	}
}

func TestParseSARIF_LocationMapping(t *testing.T) {
	input := `{
		"runs": [{
			"tool": {"driver": {"rules": []}},
			"results": [{
				"ruleId": "test-rule",
				"message": {"text": "test"},
				"level": "warning",
				"locations": [{
					"physicalLocation": {
						"artifactLocation": {"uri": "pkg/foo/bar.go"},
						"region": {"startLine": 99, "startColumn": 12}
					}
				}]
			}]
		}]
	}`

	results, err := parseSARIF([]byte(input))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("got %d findings, want 1", len(results))
	}
	f := results[0]
	if f.Location.File != "pkg/foo/bar.go" {
		t.Errorf("Location.File = %q, want %q", f.Location.File, "pkg/foo/bar.go")
	}
	if f.Location.Line != 99 {
		t.Errorf("Location.Line = %d, want 99", f.Location.Line)
	}
	if f.Location.Column != 12 {
		t.Errorf("Location.Column = %d, want 12", f.Location.Column)
	}
}

func TestParseSARIF_MultipleResults(t *testing.T) {
	input := `{
		"runs": [{
			"tool": {"driver": {"rules": [
				{"id": "rule-a", "properties": {"algorithm": "RSA", "primitive": "asymmetric"}},
				{"id": "rule-b", "properties": {"algorithm": "AES", "primitive": "symmetric"}}
			]}},
			"results": [
				{
					"ruleId": "rule-a",
					"message": {"text": "RSA detected"},
					"level": "warning",
					"locations": [{"physicalLocation": {"artifactLocation": {"uri": "A.java"}, "region": {"startLine": 1, "startColumn": 1}}}]
				},
				{
					"ruleId": "rule-b",
					"message": {"text": "AES detected"},
					"level": "warning",
					"locations": [{"physicalLocation": {"artifactLocation": {"uri": "B.java"}, "region": {"startLine": 2, "startColumn": 1}}}]
				}
			]
		}]
	}`

	results, err := parseSARIF([]byte(input))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(results) != 2 {
		t.Fatalf("got %d findings, want 2", len(results))
	}
	if results[0].Algorithm == nil || results[0].Algorithm.Name != "RSA" {
		t.Errorf("results[0].Algorithm.Name = %v, want RSA", results[0].Algorithm)
	}
	if results[1].Algorithm == nil || results[1].Algorithm.Name != "AES" {
		t.Errorf("results[1].Algorithm.Name = %v, want AES", results[1].Algorithm)
	}
}

func TestParseSARIF_SourceEngine(t *testing.T) {
	input := `{
		"runs": [{
			"tool": {"driver": {"rules": []}},
			"results": [{
				"ruleId": "x",
				"message": {"text": "x"},
				"level": "warning",
				"locations": [{"physicalLocation": {"artifactLocation": {"uri": "f.go"}}}]
			}]
		}]
	}`

	results, err := parseSARIF([]byte(input))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("got %d findings, want 1", len(results))
	}
	if results[0].SourceEngine != "semgrep" {
		t.Errorf("SourceEngine = %q, want %q", results[0].SourceEngine, "semgrep")
	}
}

func TestParseSARIF_ReachableUnknown(t *testing.T) {
	input := `{
		"runs": [{
			"tool": {"driver": {"rules": []}},
			"results": [{
				"ruleId": "x",
				"message": {"text": "x"},
				"level": "warning",
				"locations": [{"physicalLocation": {"artifactLocation": {"uri": "f.go"}}}]
			}]
		}]
	}`

	results, err := parseSARIF([]byte(input))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if results[0].Reachable != findings.ReachableUnknown {
		t.Errorf("Reachable = %q, want %q", results[0].Reachable, findings.ReachableUnknown)
	}
}

func TestParseSARIF_NoRegion_ZeroLocation(t *testing.T) {
	input := `{
		"runs": [{
			"tool": {"driver": {"rules": []}},
			"results": [{
				"ruleId": "x",
				"message": {"text": "x"},
				"level": "warning",
				"locations": [{"physicalLocation": {"artifactLocation": {"uri": "f.go"}}}]
			}]
		}]
	}`

	results, err := parseSARIF([]byte(input))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if results[0].Location.Line != 0 {
		t.Errorf("Line = %d, want 0 when region is absent", results[0].Location.Line)
	}
}

// --- inferAlgorithmFromRuleID tests ---

func TestInferAlgorithmFromRuleID(t *testing.T) {
	tests := []struct {
		ruleID string
		want   string
	}{
		{"java-rsa-keysize", "RSA"},
		{"python-ecdsa-sign", "ECDSA"},
		{"go-ecdh-key", "ECDH"},
		{"python-aes-key", "AES"},
		{"detect-sha256-hash", "SHA-256"},
		{"detect-sha512-hash", "SHA-512"},
		{"detect-sha1-usage", "SHA-1"},
		{"detect-sha-generic", "SHA"},
		{"md5-weak-hash", "MD5"},
		{"hmac-sha256", "HMAC"},
		{"tls-version-check", "TLS"},
		{"des-usage", "DES"},
		{"unknown-rule-id", ""},
	}

	for _, tt := range tests {
		t.Run(tt.ruleID, func(t *testing.T) {
			got := inferAlgorithmFromRuleID(tt.ruleID)
			if got != tt.want {
				t.Errorf("inferAlgorithmFromRuleID(%q) = %q, want %q", tt.ruleID, got, tt.want)
			}
		})
	}
}

// --- primitiveFromRuleID tests ---

func TestPrimitiveFromRuleID(t *testing.T) {
	tests := []struct {
		ruleID string
		want   string
	}{
		{"java-rsa-keysize", "asymmetric"},
		{"python-ecdsa-sign", "asymmetric"},
		{"go-ecdh-exchange", "asymmetric"},
		{"detect-ec-key", "asymmetric"},
		{"python-aes-encrypt", "symmetric"},
		{"cipher-usage", "symmetric"},
		{"sha256-digest", "hash"},
		{"md5-hash", "hash"},
		{"hmac-sha1", "mac"},
		{"tls-config-check", "protocol"},
		{"detect-ssl-version", "protocol"},
		{"pbkdf2-kdf", "kdf"},
		{"unknown-rule", ""},
	}

	for _, tt := range tests {
		t.Run(tt.ruleID, func(t *testing.T) {
			got := primitiveFromRuleID(tt.ruleID)
			if got != tt.want {
				t.Errorf("primitiveFromRuleID(%q) = %q, want %q", tt.ruleID, got, tt.want)
			}
		})
	}
}

// --- buildRuleMetaLookup tests ---

// --- cleanURI tests ---

func TestCleanURI(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{
			name:  "Unix absolute path with file:/// prefix",
			input: "file:///home/user/path",
			want:  "/home/user/path",
		},
		{
			name:  "Windows-style path with file:/// prefix",
			input: "file:///C:/path",
			want:  "/C:/path",
		},
		{
			name:  "relative path with file:// prefix",
			input: "file://relative/path",
			want:  "relative/path",
		},
		{
			name:  "no prefix passthrough",
			input: "src/main.go",
			want:  "src/main.go",
		},
		{
			name:  "empty string passthrough",
			input: "",
			want:  "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := cleanURI(tt.input)
			if got != tt.want {
				t.Errorf("cleanURI(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

// --- Additional parseSARIF edge case tests ---

func TestParseSARIF_EmptyResultsArray(t *testing.T) {
	input := `{
		"runs": [{
			"tool": {"driver": {"rules": []}},
			"results": []
		}]
	}`

	results, err := parseSARIF([]byte(input))
	if err != nil {
		t.Fatalf("parseSARIF with empty results array: unexpected error: %v", err)
	}
	if len(results) != 0 {
		t.Errorf("parseSARIF with empty results array: got %d findings, want 0", len(results))
	}
}

func TestParseSARIF_MissingResultsKey(t *testing.T) {
	// SARIF run with no "results" key at all — the struct zero-value is nil slice.
	input := `{"runs": [{"tool": {"driver": {"rules": []}}}]}`

	results, err := parseSARIF([]byte(input))
	if err != nil {
		t.Fatalf("parseSARIF with missing results key: unexpected error: %v", err)
	}
	if len(results) != 0 {
		t.Errorf("parseSARIF with missing results key: got %d findings, want 0", len(results))
	}
}

// --- DES word-boundary tests ---

func TestInferAlgorithmFromRuleID_DESWordBoundary(t *testing.T) {
	tests := []struct {
		ruleID string
		want   string
	}{
		// Should match DES
		{"crypto-des-usage", "DES"},
		{"crypto-3des", "DES"},
		{"triple-des-check", "DES"},
		{"des-encryption", "DES"},
		// Should NOT match DES (word boundary protection)
		{"describes-method", ""},
		{"address-handler", ""},
	}

	for _, tt := range tests {
		t.Run(tt.ruleID, func(t *testing.T) {
			got := inferAlgorithmFromRuleID(tt.ruleID)
			if got != tt.want {
				t.Errorf("inferAlgorithmFromRuleID(%q) = %q, want %q", tt.ruleID, got, tt.want)
			}
		})
	}
}

func TestBuildRuleMetaLookup(t *testing.T) {
	rules := []sarifInputRule{
		{
			ID: "java-rsa-keysize",
			Properties: map[string]interface{}{
				"algorithm": "RSA",
				"primitive": "asymmetric",
			},
		},
		{
			ID: "python-aes-key",
			Properties: map[string]interface{}{
				"algorithm": "AES",
				"primitive": "symmetric",
			},
		},
		{
			ID:         "no-props",
			Properties: nil,
		},
	}

	lookup := buildRuleMetaLookup(rules)

	if m := lookup["java-rsa-keysize"]; m.Algorithm != "RSA" || m.Primitive != "asymmetric" {
		t.Errorf("java-rsa-keysize: got {%q,%q}, want {RSA,asymmetric}", m.Algorithm, m.Primitive)
	}
	if m := lookup["python-aes-key"]; m.Algorithm != "AES" || m.Primitive != "symmetric" {
		t.Errorf("python-aes-key: got {%q,%q}, want {AES,symmetric}", m.Algorithm, m.Primitive)
	}
	if m := lookup["no-props"]; m.Algorithm != "" || m.Primitive != "" {
		t.Errorf("no-props: got {%q,%q}, want empty", m.Algorithm, m.Primitive)
	}
}
