package configscanner

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestParseINI(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		wantKeys []string
		wantVals []string
	}{
		{
			name: "flat key-value with equals",
			input: `algorithm=AES
keySize=256
`,
			wantKeys: []string{"algorithm", "keySize"},
			wantVals: []string{"AES", "256"},
		},
		{
			name: "key-value with colon separator",
			input: `algorithm: RSA
key-size: 2048
`,
			wantKeys: []string{"algorithm", "key-size"},
			wantVals: []string{"RSA", "2048"},
		},
		{
			name: "section headers produce dotted keys",
			input: `[server]
host=localhost
port=8443

[server.ssl]
protocol=TLSv1.2
cipher=AES-256-GCM
`,
			wantKeys: []string{"server.host", "server.port", "server.ssl.protocol", "server.ssl.cipher"},
			wantVals: []string{"localhost", "8443", "TLSv1.2", "AES-256-GCM"},
		},
		{
			name: "comments with semicolon and hash",
			input: `; This is a comment
# This is also a comment
algorithm=AES
`,
			wantKeys: []string{"algorithm"},
			wantVals: []string{"AES"},
		},
		{
			name:     "empty input",
			input:    "",
			wantKeys: nil,
		},
		{
			name: "inline comments stripped",
			input: `algorithm=AES ; this is a comment
hash=SHA-256 # another comment
`,
			wantKeys: []string{"algorithm", "hash"},
			wantVals: []string{"AES", "SHA-256"},
		},
		{
			name: "quoted values preserve inline comment chars",
			input: `description="AES ; with comment"
note='SHA-256 # secure'
`,
			wantKeys: []string{"description", "note"},
			wantVals: []string{"AES ; with comment", "SHA-256 # secure"},
		},
		{
			name: "continuation lines",
			input: `long_value=first \
second \
third
`,
			wantKeys: []string{"long_value"},
			wantVals: []string{"first second third"},
		},
		{
			name:     "only comments and blanks",
			input:    "; comment\n# comment\n\n",
			wantKeys: nil,
		},
		{
			name: "multiple sections",
			input: `[crypto]
algorithm=RSA

[tls]
protocol=TLSv1.3
`,
			wantKeys: []string{"crypto.algorithm", "tls.protocol"},
			wantVals: []string{"RSA", "TLSv1.3"},
		},
		{
			name: "quoted value with trailing inline comment",
			input: `cipher="AES-256-GCM" ; symmetric cipher
protocol='TLSv1.3' # latest
`,
			wantKeys: []string{"cipher", "protocol"},
			wantVals: []string{"AES-256-GCM", "TLSv1.3"},
		},
		{
			name: "whitespace around key and value",
			input: `  algorithm  =  AES
  key-size  :  256
`,
			wantKeys: []string{"algorithm", "key-size"},
			wantVals: []string{"AES", "256"},
		},
		{
			name: "no value after separator",
			input: `algorithm=
`,
			wantKeys: []string{"algorithm"},
			wantVals: []string{""},
		},
		{
			name: "windows line endings",
			input: "[ssl]\r\nprotocol=TLSv1.2\r\ncipher=AES\r\n",
			wantKeys: []string{"ssl.protocol", "ssl.cipher"},
			wantVals: []string{"TLSv1.2", "AES"},
		},
		{
			name: "section with spaces in bracket",
			input: `[ security  ]
algorithm=AES
`,
			wantKeys: []string{"security.algorithm"},
			wantVals: []string{"AES"},
		},
		{
			name: "empty key from equals-only line skipped",
			input: "=\nalgorithm=AES\n",
			wantKeys: []string{"algorithm"},
			wantVals: []string{"AES"},
		},
		{
			name: "empty section header degrades to flat keys",
			input: "[]\nalgorithm=AES\n",
			wantKeys: []string{"algorithm"},
			wantVals: []string{"AES"},
		},
		{
			name: "openssl style config",
			input: `[req]
default_bits = 2048
default_md = sha256
distinguished_name = req_dn

[req_dn]
CN = example.com
`,
			wantKeys: []string{"req.default_bits", "req.default_md", "req.distinguished_name", "req_dn.CN"},
			wantVals: []string{"2048", "sha256", "req_dn", "example.com"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			kvs, err := parseINI([]byte(tt.input))
			if err != nil {
				t.Fatalf("parseINI error: %v", err)
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
					t.Errorf("missing key %q", wk)
					continue
				}
				if got != tt.wantVals[i] {
					t.Errorf("key %q: got %q, want %q", wk, got, tt.wantVals[i])
				}
			}
			if len(kvs) != len(tt.wantKeys) {
				t.Errorf("got %d kvs, want %d", len(kvs), len(tt.wantKeys))
			}
		})
	}
}

func TestParseINI_LineNumbers(t *testing.T) {
	input := `; comment
[section]
key1=val1
key2=val2
`
	kvs, err := parseINI([]byte(input))
	if err != nil {
		t.Fatalf("parseINI error: %v", err)
	}
	if len(kvs) != 2 {
		t.Fatalf("expected 2 kvs, got %d", len(kvs))
	}

	// key1 is on line 3 (after comment on line 1, section on line 2).
	if kvs[0].Line != 3 {
		t.Errorf("key1 line: got %d, want 3", kvs[0].Line)
	}
	if kvs[1].Line != 4 {
		t.Errorf("key2 line: got %d, want 4", kvs[1].Line)
	}
}

func TestParseINI_NoSeparator(t *testing.T) {
	input := "no_separator_here\nalgorithm=AES\n"
	kvs, err := parseINI([]byte(input))
	if err != nil {
		t.Fatalf("parseINI error: %v", err)
	}
	// Lines without = or : are skipped.
	if len(kvs) != 1 {
		t.Fatalf("expected 1 kv, got %d", len(kvs))
	}
	if kvs[0].Key != "algorithm" {
		t.Errorf("unexpected key: %s", kvs[0].Key)
	}
}

func TestParseINI_ContinuationLineNumbers(t *testing.T) {
	input := `key1=first \
second
key2=val2
`
	kvs, err := parseINI([]byte(input))
	if err != nil {
		t.Fatalf("parseINI error: %v", err)
	}
	if len(kvs) != 2 {
		t.Fatalf("expected 2 kvs, got %d", len(kvs))
	}
	// key1 starts on line 1 (continuation doesn't change start line).
	if kvs[0].Line != 1 {
		t.Errorf("key1 line: got %d, want 1", kvs[0].Line)
	}
	// key2 is on line 3.
	if kvs[1].Line != 3 {
		t.Errorf("key2 line: got %d, want 3", kvs[1].Line)
	}
}

func TestIsConfigFile_INI(t *testing.T) {
	tests := []struct {
		path string
		want bool
	}{
		{"/etc/crypto.ini", true},          // crypto keyword in name
		{"/app/config/settings.ini", true}, // config dir keyword
		{"/etc/ssl/openssl.cnf", true},     // well-known filename
		{"/app/php.ini", true},             // well-known filename
		{"/app/my.cnf", true},              // well-known filename
		{"/app/security.cfg", true},        // security keyword
		{"/app/random.ini", false},         // no crypto keyword, no config dir
		{"/app/random.cfg", false},         // no crypto keyword, no config dir
		{"/app/config/mariadb.cnf", true},  // non-well-known .cnf in config dir
		{"/app/random.cnf", false},         // no crypto keyword, no config dir
		{"/app/conf/custom.cnf", true},     // .cnf in conf dir
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

func TestScanConfigFile_INI(t *testing.T) {
	dir := t.TempDir()

	// Write an INI file with crypto parameters.
	ini := `[security]
algorithm=AES
key-size=256

[tls]
protocol=TLSv1.2
cipher=DES
`
	path := filepath.Join(dir, "crypto.ini")
	if err := os.WriteFile(path, []byte(ini), 0o644); err != nil {
		t.Fatal(err)
	}

	eng := New()
	findings, err := eng.scanConfigFile(path)
	if err != nil {
		t.Fatalf("scanConfigFile error: %v", err)
	}

	// Expect at least AES, DES, and possibly key-size and TLSv1.2 findings.
	if len(findings) == 0 {
		t.Fatal("expected findings, got none")
	}

	foundAES := false
	foundDES := false
	for _, f := range findings {
		if f.Algorithm != nil {
			switch {
			case strings.EqualFold(f.Algorithm.Name, "AES"):
				foundAES = true
			case strings.EqualFold(f.Algorithm.Name, "DES"):
				foundDES = true
			}
		}
	}
	if !foundAES {
		t.Error("expected AES finding")
	}
	if !foundDES {
		t.Error("expected DES finding")
	}
}

func TestScanConfigFile_CFG(t *testing.T) {
	dir := t.TempDir()

	cfg := `[ssl]
cipher = AES-256-GCM
protocol = TLSv1.2
key-size = 2048
`
	path := filepath.Join(dir, "openssl.cfg")
	if err := os.WriteFile(path, []byte(cfg), 0o644); err != nil {
		t.Fatal(err)
	}

	eng := New()
	findings, err := eng.scanConfigFile(path)
	if err != nil {
		t.Fatalf("scanConfigFile error: %v", err)
	}

	if len(findings) == 0 {
		t.Fatal("expected findings from .cfg file, got none")
	}

	// Should find AES from cipher key.
	foundAES := false
	for _, f := range findings {
		if f.Algorithm != nil && strings.EqualFold(f.Algorithm.Name, "AES") {
			foundAES = true
		}
	}
	if !foundAES {
		t.Error("expected AES finding from cipher=AES-256-GCM")
	}
}

func TestParseINI_MySQLConfig(t *testing.T) {
	// Real-world MySQL my.cnf snippet.
	input := `[mysqld]
ssl-ca=/etc/mysql/ca.pem
ssl-cert=/etc/mysql/server-cert.pem
ssl-key=/etc/mysql/server-key.pem
ssl-cipher=DHE-RSA-AES256-SHA

[client]
ssl-mode=REQUIRED
`
	kvs, err := parseINI([]byte(input))
	if err != nil {
		t.Fatalf("parseINI error: %v", err)
	}

	kvMap := make(map[string]string)
	for _, kv := range kvs {
		kvMap[kv.Key] = kv.Value
	}

	if v := kvMap["mysqld.ssl-cipher"]; v != "DHE-RSA-AES256-SHA" {
		t.Errorf("ssl-cipher: got %q, want %q", v, "DHE-RSA-AES256-SHA")
	}
	if v := kvMap["client.ssl-mode"]; v != "REQUIRED" {
		t.Errorf("ssl-mode: got %q, want %q", v, "REQUIRED")
	}
}

func TestParseINI_PHPConfig(t *testing.T) {
	// PHP php.ini crypto-related settings.
	input := `[openssl]
openssl.cafile=/etc/ssl/certs/ca-certificates.crt
openssl.capath=/etc/ssl/certs

[session]
session.hash_function = sha256
session.hash_bits_per_character = 5
`
	kvs, err := parseINI([]byte(input))
	if err != nil {
		t.Fatalf("parseINI error: %v", err)
	}

	kvMap := make(map[string]string)
	for _, kv := range kvs {
		kvMap[kv.Key] = kv.Value
	}

	if v := kvMap["session.session.hash_function"]; v != "sha256" {
		t.Errorf("hash_function: got %q, want %q", v, "sha256")
	}
}

func TestSupportedLanguages_IncludesINI(t *testing.T) {
	eng := New()
	langs := eng.SupportedLanguages()
	found := false
	for _, l := range langs {
		if l == "ini" {
			found = true
		}
	}
	if !found {
		t.Errorf("SupportedLanguages() should include 'ini', got %v", langs)
	}
}
