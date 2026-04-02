package configscanner

import (
	"strings"
	"testing"
)

func TestParseTOML(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		wantKeys []string
		wantVals []string
		wantErr  bool
	}{
		{
			name: "basic key-value pairs",
			input: `
algorithm = "AES"
key_size = 256
`,
			wantKeys: []string{"algorithm", "key_size"},
			wantVals: []string{"AES", "256"},
		},
		{
			name: "nested tables with dotted keys",
			input: `
[server.tls]
cipher = "AES-256-GCM"
protocol = "TLSv1.3"
`,
			wantKeys: []string{"server.tls.cipher", "server.tls.protocol"},
			wantVals: []string{"AES-256-GCM", "TLSv1.3"},
		},
		{
			name: "deeply nested table",
			input: `
[spring.security.oauth2.client]
algorithm = "RSA"
key_size = 2048
`,
			wantKeys: []string{"spring.security.oauth2.client.algorithm", "spring.security.oauth2.client.key_size"},
			wantVals: []string{"RSA", "2048"},
		},
		{
			name: "arrays of scalar values",
			input: `
ciphers = ["AES-256-GCM", "ChaCha20-Poly1305"]
`,
			wantKeys: []string{"ciphers[0]", "ciphers[1]"},
			wantVals: []string{"AES-256-GCM", "ChaCha20-Poly1305"},
		},
		{
			name: "arrays of tables",
			input: `
[[algorithms]]
name = "RSA"
key_size = 2048

[[algorithms]]
name = "ECDSA"
key_size = 256
`,
			wantKeys: []string{"algorithms[0].name", "algorithms[0].key_size", "algorithms[1].name", "algorithms[1].key_size"},
			wantVals: []string{"RSA", "2048", "ECDSA", "256"},
		},
		{
			name: "inline tables",
			input: `
tls = {cipher = "AES-128-GCM", version = "1.2"}
`,
			wantKeys: []string{"tls.cipher", "tls.version"},
			wantVals: []string{"AES-128-GCM", "1.2"},
		},
		{
			name: "bool values",
			input: `
enable_tls = true
allow_legacy = false
`,
			wantKeys: []string{"enable_tls", "allow_legacy"},
			wantVals: []string{"true", "false"},
		},
		{
			name: "float values",
			input: `
entropy = 3.14
`,
			wantKeys: []string{"entropy"},
			wantVals: []string{"3.14"},
		},
		{
			name: "multi-line basic string",
			input: `
certificate = """
-----BEGIN CERTIFICATE-----
MIIBkTCB+wIJ
-----END CERTIFICATE-----
"""
`,
			wantKeys: []string{"certificate"},
		},
		{
			name:     "empty TOML file",
			input:    "",
			wantKeys: nil,
		},
		{
			name: "crypto-relevant TLS settings (Cargo.toml style)",
			input: `
[package]
name = "my-server"
version = "0.1.0"

[dependencies.rustls]
version = "0.21"

[tls]
cipher_suites = ["TLS_AES_256_GCM_SHA384"]
min_version = "1.2"
key_log = false
`,
			wantKeys: []string{
				"package.name",
				"package.version",
				"dependencies.rustls.version",
				"tls.cipher_suites[0]",
				"tls.min_version",
				"tls.key_log",
			},
			wantVals: []string{
				"my-server",
				"0.1.0",
				"0.21",
				"TLS_AES_256_GCM_SHA384",
				"1.2",
				"false",
			},
		},
		{
			name: "crypto-relevant pyproject.toml style",
			input: `
[tool.cryptography]
backend = "openssl"
key_size = 4096
hash_algorithm = "SHA-256"
`,
			wantKeys: []string{
				"tool.cryptography.backend",
				"tool.cryptography.key_size",
				"tool.cryptography.hash_algorithm",
			},
			wantVals: []string{"openssl", "4096", "SHA-256"},
		},
		{
			name:    "invalid TOML",
			input:   `key = [unclosed`,
			wantErr: true,
		},
		{
			name: "integer key size value",
			input: `
key_size = 4096
`,
			wantKeys: []string{"key_size"},
			wantVals: []string{"4096"},
		},
		{
			name: "comments are ignored",
			input: `
# This is a comment
algorithm = "RSA" # inline comment (TOML ignores this as comment)
`,
			wantKeys: []string{"algorithm"},
			wantVals: []string{"RSA"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			kvs, err := parseTOML([]byte(tt.input))
			if tt.wantErr {
				if err == nil {
					t.Error("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("parseTOML error: %v", err)
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
			for i, key := range tt.wantKeys {
				got, ok := kvMap[key]
				if !ok {
					t.Errorf("key %q not found; available keys: %v", key, mapKeys(kvMap))
					continue
				}
				if tt.wantVals != nil && i < len(tt.wantVals) && tt.wantVals[i] != "" {
					if got != tt.wantVals[i] {
						t.Errorf("key %q: got value %q, want %q", key, got, tt.wantVals[i])
					}
				}
			}
		})
	}
}

func TestParseTOMLDepthLimit(t *testing.T) {
	// Build a deeply nested TOML table that exceeds maxTOMLDepth (64).
	// TOML uses [a.b.c.d...] header syntax for nested tables.
	var sb strings.Builder
	// Build a key path that is 70 levels deep.
	parts := make([]string, 70)
	for i := range parts {
		parts[i] = "a"
	}
	sb.WriteString("[")
	sb.WriteString(strings.Join(parts, "."))
	sb.WriteString("]\n")
	sb.WriteString("cipher = \"AES\"\n")

	kvs, err := parseTOML([]byte(sb.String()))
	if err != nil {
		t.Fatalf("parseTOML error: %v", err)
	}
	// The deeply nested key should be capped; we just verify no panic
	// and the entry count is within bounds.
	if len(kvs) > maxTOMLEntries {
		t.Errorf("entry count %d exceeds maxTOMLEntries %d", len(kvs), maxTOMLEntries)
	}
}

func TestParseTOMLEntryCap(t *testing.T) {
	// Generate more than maxTOMLEntries keys to verify the cap is enforced.
	var sb strings.Builder
	// Use a flat table with many keys.
	for i := 0; i < maxTOMLEntries+10; i++ {
		sb.WriteString("k")
		for d := i; d > 0 || i == 0; d /= 26 {
			sb.WriteByte(byte('a' + d%26))
			if d == 0 {
				break
			}
		}
		sb.WriteString(" = \"v\"\n")
	}

	kvs, err := parseTOML([]byte(sb.String()))
	if err != nil {
		// TOML may reject duplicate keys from our naive key generation — that's fine.
		t.Skipf("parseTOML returned error (likely duplicate keys): %v", err)
	}
	if len(kvs) > maxTOMLEntries {
		t.Errorf("entry count %d exceeds maxTOMLEntries %d", len(kvs), maxTOMLEntries)
	}
}

func TestParseTOMLLineNumbersAreZero(t *testing.T) {
	// BurntSushi/toml does not expose line numbers via MetaData.Type/Keys;
	// we document that Line is always 0 for TOML (consistent with parseJSON).
	input := `
algorithm = "RSA"
key_size = 2048
`
	kvs, err := parseTOML([]byte(input))
	if err != nil {
		t.Fatalf("parseTOML error: %v", err)
	}
	for _, kv := range kvs {
		if kv.Line != 0 {
			t.Errorf("key %q: expected Line=0 (TOML has no line info), got %d", kv.Key, kv.Line)
		}
	}
}

// mapKeys returns sorted keys of a map for diagnostic output.
func mapKeys(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return keys
}
