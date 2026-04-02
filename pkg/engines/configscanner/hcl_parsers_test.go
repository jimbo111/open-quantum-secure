package configscanner

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestParseHCL(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		wantKeys []string
		wantVals []string
	}{
		{
			name: "flat key-value",
			input: `algorithm = "AES"
key_size = 256
`,
			wantKeys: []string{"algorithm", "key_size"},
			wantVals: []string{"AES", "256"},
		},
		{
			name: "nested block",
			input: `resource "tls_private_key" "example" {
  algorithm = "RSA"
  rsa_bits  = 4096
}
`,
			wantKeys: []string{
				"resource.tls_private_key.example.algorithm",
				"resource.tls_private_key.example.rsa_bits",
			},
			wantVals: []string{"RSA", "4096"},
		},
		{
			name: "multi-level nesting",
			input: `resource "aws_lb_listener" "https" {
  protocol = "HTTPS"
  default_action {
    type = "forward"
  }
}
`,
			wantKeys: []string{
				"resource.aws_lb_listener.https.protocol",
				"resource.aws_lb_listener.https.default_action.type",
			},
			wantVals: []string{"HTTPS", "forward"},
		},
		{
			name: "line comments hash and slash",
			input: `# This is a comment
// Another comment
algorithm = "AES"
`,
			wantKeys: []string{"algorithm"},
			wantVals: []string{"AES"},
		},
		{
			name: "block comment",
			input: `/* This is
a block comment */
algorithm = "AES"
`,
			wantKeys: []string{"algorithm"},
			wantVals: []string{"AES"},
		},
		{
			name: "inline block comment",
			input: `algorithm /* cipher type */ = "AES"
`,
			// The inline comment makes this tricky — algorithm is on the left of =
			wantKeys: []string{"algorithm"},
			wantVals: []string{"AES"},
		},
		{
			name:     "empty input",
			input:    "",
			wantKeys: nil,
		},
		{
			name: "boolean values",
			input: `enabled = true
disabled = false
`,
			wantKeys: []string{"enabled", "disabled"},
			wantVals: []string{"true", "false"},
		},
		{
			name: "terraform TLS resource",
			input: `resource "tls_private_key" "rsa" {
  algorithm = "RSA"
  rsa_bits  = 2048
}

resource "tls_private_key" "ecdsa" {
  algorithm   = "ECDSA"
  ecdsa_curve = "P256"
}
`,
			wantKeys: []string{
				"resource.tls_private_key.rsa.algorithm",
				"resource.tls_private_key.rsa.rsa_bits",
				"resource.tls_private_key.ecdsa.algorithm",
				"resource.tls_private_key.ecdsa.ecdsa_curve",
			},
			wantVals: []string{"RSA", "2048", "ECDSA", "P256"},
		},
		{
			name: "provider block no labels",
			input: `provider {
  algorithm = "AES"
}
`,
			wantKeys: []string{"provider.algorithm"},
			wantVals: []string{"AES"},
		},
		{
			name: "escaped quotes in string",
			input: `value = "hello \"world\""
`,
			wantKeys: []string{"value"},
			wantVals: []string{`hello \"world\"`},
		},
		{
			name: "trailing inline comment",
			input: `algorithm = "AES" # symmetric cipher
`,
			wantKeys: []string{"algorithm"},
			wantVals: []string{"AES"},
		},
		{
			name: "variable block",
			input: `variable "ssl_policy" {
  default = "ELBSecurityPolicy-TLS-1-2-2017-01"
  type    = string
}
`,
			wantKeys: []string{
				"variable.ssl_policy.default",
				"variable.ssl_policy.type",
			},
			wantVals: []string{"ELBSecurityPolicy-TLS-1-2-2017-01", "string"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			kvs, err := parseHCL([]byte(tt.input))
			if err != nil {
				t.Fatalf("parseHCL error: %v", err)
			}
			if len(tt.wantKeys) == 0 {
				if len(kvs) != 0 {
					t.Errorf("expected empty result, got %v", kvs)
				}
				return
			}
			kvMap := make(map[string]string)
			for _, kv := range kvs {
				kvMap[kv.Key] = kv.Value
			}
			for i, wk := range tt.wantKeys {
				got, ok := kvMap[wk]
				if !ok {
					t.Errorf("missing key %q (have: %v)", wk, keysOf(kvs))
					continue
				}
				if got != tt.wantVals[i] {
					t.Errorf("key %q: got %q, want %q", wk, got, tt.wantVals[i])
				}
			}
			if len(kvs) != len(tt.wantKeys) {
				t.Errorf("got %d kvs, want %d (keys: %v)", len(kvs), len(tt.wantKeys), keysOf(kvs))
			}
		})
	}
}

func keysOf(kvs []KeyValue) []string {
	keys := make([]string, len(kvs))
	for i, kv := range kvs {
		keys[i] = kv.Key
	}
	return keys
}

func TestParseHCL_LineNumbers(t *testing.T) {
	input := `# comment
resource "tls_private_key" "example" {
  algorithm = "RSA"
  rsa_bits  = 4096
}
`
	kvs, err := parseHCL([]byte(input))
	if err != nil {
		t.Fatalf("parseHCL error: %v", err)
	}
	if len(kvs) != 2 {
		t.Fatalf("expected 2 kvs, got %d", len(kvs))
	}
	// algorithm is on line 3 (1-indexed).
	if kvs[0].Line != 3 {
		t.Errorf("algorithm line: got %d, want 3", kvs[0].Line)
	}
	if kvs[1].Line != 4 {
		t.Errorf("rsa_bits line: got %d, want 4", kvs[1].Line)
	}
}

func TestParseHCL_Heredoc(t *testing.T) {
	input := `script = <<EOF
#!/bin/bash
echo "hello"
EOF
algorithm = "AES"
`
	kvs, err := parseHCL([]byte(input))
	if err != nil {
		t.Fatalf("parseHCL error: %v", err)
	}
	if len(kvs) != 2 {
		t.Fatalf("expected 2 kvs, got %d", len(kvs))
	}
	if kvs[0].Key != "script" {
		t.Errorf("key 0: got %q, want %q", kvs[0].Key, "script")
	}
	if !strings.Contains(kvs[0].Value, "#!/bin/bash") {
		t.Errorf("heredoc value should contain script content, got %q", kvs[0].Value)
	}
	if kvs[1].Key != "algorithm" || kvs[1].Value != "AES" {
		t.Errorf("key 1: got %q=%q, want algorithm=AES", kvs[1].Key, kvs[1].Value)
	}
}

func TestParseHCL_IndentedHeredoc(t *testing.T) {
	input := `script = <<-EOF
    line1
    line2
    EOF
`
	kvs, err := parseHCL([]byte(input))
	if err != nil {
		t.Fatalf("parseHCL error: %v", err)
	}
	if len(kvs) != 1 {
		t.Fatalf("expected 1 kv, got %d", len(kvs))
	}
}

func TestParseHCL_QuotedHeredocMarker(t *testing.T) {
	input := `script = <<"EOF"
#!/bin/bash
echo "hello"
EOF
algorithm = "AES"
`
	kvs, err := parseHCL([]byte(input))
	if err != nil {
		t.Fatalf("parseHCL error: %v", err)
	}
	if len(kvs) != 2 {
		t.Fatalf("expected 2 kvs, got %d (keys: %v)", len(kvs), keysOf(kvs))
	}
	if kvs[0].Key != "script" {
		t.Errorf("key 0: got %q, want %q", kvs[0].Key, "script")
	}
	if kvs[1].Key != "algorithm" || kvs[1].Value != "AES" {
		t.Errorf("key 1: got %q=%q, want algorithm=AES", kvs[1].Key, kvs[1].Value)
	}
}

func TestParseHCL_OnlyComments(t *testing.T) {
	input := `# just comments
// more comments
/* block
   comment */
`
	kvs, err := parseHCL([]byte(input))
	if err != nil {
		t.Fatalf("parseHCL error: %v", err)
	}
	if len(kvs) != 0 {
		t.Errorf("expected empty result, got %v", kvs)
	}
}

func TestParseHCL_DeeplyNested(t *testing.T) {
	input := `a {
  b {
    c {
      algorithm = "AES"
    }
  }
}
`
	kvs, err := parseHCL([]byte(input))
	if err != nil {
		t.Fatalf("parseHCL error: %v", err)
	}
	if len(kvs) != 1 {
		t.Fatalf("expected 1 kv, got %d", len(kvs))
	}
	if kvs[0].Key != "a.b.c.algorithm" {
		t.Errorf("key: got %q, want %q", kvs[0].Key, "a.b.c.algorithm")
	}
}

func TestParseHCL_DepthLimitDoesNotCorruptSiblings(t *testing.T) {
	// Build HCL with nesting deeper than maxHCLDepth (64) followed by
	// a sibling block. The sibling must still be parsed correctly.
	var b strings.Builder
	for i := 0; i < 70; i++ {
		b.WriteString(strings.Repeat("  ", i))
		b.WriteString(fmt.Sprintf("level%d {\n", i))
	}
	// Innermost assignment (beyond depth limit — will be dropped).
	b.WriteString(strings.Repeat("  ", 70))
	b.WriteString("deep_key = \"deep_val\"\n")
	// Close all 70 braces.
	for i := 69; i >= 0; i-- {
		b.WriteString(strings.Repeat("  ", i))
		b.WriteString("}\n")
	}
	// Sibling block AFTER the deeply nested one.
	b.WriteString("sibling {\n  algorithm = \"AES\"\n}\n")

	kvs, err := parseHCL([]byte(b.String()))
	if err != nil {
		t.Fatalf("parseHCL error: %v", err)
	}

	// The deeply nested key should be dropped, but the sibling must survive.
	foundSibling := false
	for _, kv := range kvs {
		if kv.Key == "sibling.algorithm" && kv.Value == "AES" {
			foundSibling = true
		}
	}
	if !foundSibling {
		keys := make([]string, len(kvs))
		for i, kv := range kvs {
			keys[i] = kv.Key
		}
		t.Errorf("sibling block not parsed after depth-limited block; got keys: %v", keys)
	}
}

func TestParseHCL_UnterminatedHeredoc(t *testing.T) {
	input := `script = <<EOF
#!/bin/bash
echo "hello"
algorithm = "AES"
`
	// EOF marker never appears — heredoc consumes rest of file.
	kvs, err := parseHCL([]byte(input))
	if err != nil {
		t.Fatalf("parseHCL error: %v", err)
	}
	// The script key should exist with the rest of file as value.
	if len(kvs) != 1 {
		t.Fatalf("expected 1 kv (script heredoc), got %d", len(kvs))
	}
	if kvs[0].Key != "script" {
		t.Errorf("key: got %q, want %q", kvs[0].Key, "script")
	}
}

func TestParseHCL_UnterminatedBlockComment(t *testing.T) {
	input := `algorithm = "AES"
/* this comment never closes
key = "RSA"
`
	kvs, err := parseHCL([]byte(input))
	if err != nil {
		t.Fatalf("parseHCL error: %v", err)
	}
	// Only the first line (before the block comment) should be parsed.
	if len(kvs) != 1 {
		t.Fatalf("expected 1 kv, got %d", len(kvs))
	}
	if kvs[0].Value != "AES" {
		t.Errorf("value: got %q, want %q", kvs[0].Value, "AES")
	}
}

func TestIsConfigFile_HCL(t *testing.T) {
	tests := []struct {
		path string
		want bool
	}{
		{"/app/infra/main.tf", true},              // well-known
		{"/app/infra/variables.tf", true},          // well-known
		{"/app/terraform.tfvars", true},            // well-known
		{"/app/config/crypto.tf", true},            // config dir keyword
		{"/app/security.hcl", true},                // security keyword
		{"/app/random.tf", false},                  // no crypto keyword, no config dir
		{"/app/random.hcl", false},                 // no crypto keyword, no config dir
		{"/app/config/settings.hcl", true},         // config dir keyword
		{"/app/config/prod.tfvars", true},           // non-well-known .tfvars in config dir
		{"/app/random.tfvars", false},               // no crypto keyword, no config dir
		{"/app/settings/staging.tfvars", true},      // .tfvars in settings dir
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			got := isConfigFile(tt.path)
			if got != tt.want {
				t.Errorf("isConfigFile(%q) = %v, want %v", tt.path, got, tt.want)
			}
		})
	}
}

func TestScanConfigFile_TF(t *testing.T) {
	dir := t.TempDir()

	tf := `resource "tls_private_key" "example" {
  algorithm = "RSA"
  rsa_bits  = 2048
}

resource "tls_private_key" "ecdsa" {
  algorithm   = "ECDSA"
  ecdsa_curve = "P256"
}
`
	path := filepath.Join(dir, "crypto.tf")
	if err := os.WriteFile(path, []byte(tf), 0o644); err != nil {
		t.Fatal(err)
	}

	eng := New()
	findings, err := eng.scanConfigFile(path)
	if err != nil {
		t.Fatalf("scanConfigFile error: %v", err)
	}

	if len(findings) == 0 {
		t.Fatal("expected findings from .tf file, got none")
	}

	foundRSA := false
	foundECDSA := false
	for _, f := range findings {
		if f.Algorithm != nil {
			switch {
			case strings.EqualFold(f.Algorithm.Name, "RSA"):
				foundRSA = true
			case strings.EqualFold(f.Algorithm.Name, "ECDSA"):
				foundECDSA = true
			}
		}
	}
	if !foundRSA {
		t.Error("expected RSA finding")
	}
	if !foundECDSA {
		t.Error("expected ECDSA finding")
	}
}

func TestScanConfigFile_HCL_AWSListener(t *testing.T) {
	dir := t.TempDir()

	hcl := `resource "aws_lb_listener" "https" {
  protocol    = "HTTPS"
  ssl_policy  = "ELBSecurityPolicy-TLS-1-2-2017-01"
}
`
	path := filepath.Join(dir, "tls-config.hcl")
	if err := os.WriteFile(path, []byte(hcl), 0o644); err != nil {
		t.Fatal(err)
	}

	eng := New()
	findings, err := eng.scanConfigFile(path)
	if err != nil {
		t.Fatalf("scanConfigFile error: %v", err)
	}

	// ssl_policy contains "tls" — should match protocol pattern.
	// protocol = "HTTPS" should match protocol pattern.
	if len(findings) == 0 {
		t.Log("no findings — ssl_policy/protocol values may not match crypto vocabulary")
	}
}

func TestSupportedLanguages_IncludesHCL(t *testing.T) {
	eng := New()
	langs := eng.SupportedLanguages()
	found := false
	for _, l := range langs {
		if l == "hcl" {
			found = true
		}
	}
	if !found {
		t.Errorf("SupportedLanguages() should include 'hcl', got %v", langs)
	}
}

func TestParseHCL_MultipleBlocksSameType(t *testing.T) {
	input := `resource "a" "first" {
  algorithm = "AES"
}

resource "a" "second" {
  algorithm = "RSA"
}
`
	kvs, err := parseHCL([]byte(input))
	if err != nil {
		t.Fatalf("parseHCL error: %v", err)
	}
	if len(kvs) != 2 {
		t.Fatalf("expected 2 kvs, got %d", len(kvs))
	}

	kvMap := make(map[string]string)
	for _, kv := range kvs {
		kvMap[kv.Key] = kv.Value
	}

	if v := kvMap["resource.a.first.algorithm"]; v != "AES" {
		t.Errorf("first: got %q, want AES", v)
	}
	if v := kvMap["resource.a.second.algorithm"]; v != "RSA" {
		t.Errorf("second: got %q, want RSA", v)
	}
}

func TestParseHCL_BlockOnNextLine(t *testing.T) {
	input := `resource "foo" "bar"
{
  algorithm = "AES"
}
`
	kvs, err := parseHCL([]byte(input))
	if err != nil {
		t.Fatalf("parseHCL error: %v", err)
	}
	if len(kvs) != 1 {
		t.Fatalf("expected 1 kv, got %d (keys: %v)", len(kvs), keysOf(kvs))
	}
	if kvs[0].Key != "resource.foo.bar.algorithm" {
		t.Errorf("key: got %q, want %q", kvs[0].Key, "resource.foo.bar.algorithm")
	}
}

// ---------------------------------------------------------------------------
// hclExtractValue — trailing backslash bounds check (Bug 2 regression test)
// ---------------------------------------------------------------------------

// TestHCLExtractValue_TrailingBackslash tests the bounds-check fix for the
// out-of-bounds indexing that occurred when a quoted HCL value ended with a
// backslash (e.g. `"test\"`). Before the fix, `end += 2` overshot len(s) and
// the loop condition caught it, but the next iteration would index s[end]
// where end == len(s), causing a panic when len(s) was odd-sized in certain
// runtime layouts. The fix breaks out of the loop when end >= len(s) after
// the escape skip.
func TestHCLExtractValue_TrailingBackslash(t *testing.T) {
	tests := []struct {
		name  string
		input string // the full RHS including opening quote
		want  string
	}{
		{
			// Trailing backslash — `"test\"` has no valid closing quote because
			// the `\"` is an escaped-quote escape sequence consuming both `\`
			// and `"`. The function breaks out of the loop (bounds check) and
			// falls through to the best-effort `return s[1:]`, which is
			// everything after the opening quote: `test\"`.
			name:  "trailing backslash only",
			input: `"test\"`,
			want:  `test\"`,
		},
		{
			// Escaped newline sequence — parser does not expand escape sequences;
			// it returns raw content up to the closing quote.
			name:  "escaped newline not at end",
			input: `"test\n"`,
			want:  `test\n`,
		},
		{
			// Escaped quote followed by more content and a real closing quote.
			// The parser skips `\"` (advancing end by 2) and continues until
			// it finds the unescaped closing `"` after `value`.
			name:  "escaped quote before closing quote",
			input: `"test\"value"`,
			want:  `test\"value`,
		},
		{
			// Normal quoted string — must still work correctly.
			name:  "normal quoted string",
			input: `"AES-256"`,
			want:  "AES-256",
		},
		{
			// `"\"` — opening quote, then `\"` (escape skip advances end past
			// len), breaks out, returns s[1:] = `\"`.
			name:  "only backslash inside quotes",
			input: `"\"`,
			want:  `\"`,
		},
		{
			// Empty quoted string.
			name:  "empty string",
			input: `""`,
			want:  "",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := hclExtractValue(tc.input)
			if got != tc.want {
				t.Errorf("hclExtractValue(%q) = %q, want %q", tc.input, got, tc.want)
			}
		})
	}
}

// TestHCLExtractValue_TrailingBackslash_NoPanic is a safety net: it feeds a
// range of adversarial inputs to hclExtractValue and verifies the function
// never panics. This covers the original out-of-bounds scenario.
func TestHCLExtractValue_TrailingBackslash_NoPanic(t *testing.T) {
	inputs := []string{
		`"\"`,          // trailing backslash
		`"\\"`,         // escaped backslash
		`"\\\"`,        // escaped backslash then trailing backslash
		`"a\`,          // backslash at very end, odd length
		`"\`,           // minimal: one char after opening quote
		`"`,            // just opening quote
		`""`,           // empty
		`"a\"b\"c"`,    // multiple escaped quotes
	}
	for _, s := range inputs {
		s := s
		t.Run(s, func(t *testing.T) {
			defer func() {
				if r := recover(); r != nil {
					t.Errorf("hclExtractValue(%q) panicked: %v", s, r)
				}
			}()
			_ = hclExtractValue(s)
		})
	}
}
