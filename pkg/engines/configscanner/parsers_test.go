package configscanner

import (
	"strings"
	"testing"
)

func TestParseYAML(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		wantKeys []string
		wantVals []string
	}{
		{
			name: "flat map",
			input: `
algorithm: AES
keySize: 256
`,
			wantKeys: []string{"algorithm", "keySize"},
			wantVals: []string{"AES", "256"},
		},
		{
			name: "nested map",
			input: `
spring:
  security:
    algorithm: RSA
`,
			wantKeys: []string{"spring.security.algorithm"},
			wantVals: []string{"RSA"},
		},
		{
			name: "sequence values",
			input: `
ciphers:
  - AES-256-GCM
  - ChaCha20-Poly1305
`,
			wantKeys: []string{"ciphers[0]", "ciphers[1]"},
			wantVals: []string{"AES-256-GCM", "ChaCha20-Poly1305"},
		},
		{
			name:     "empty document",
			input:    "",
			wantKeys: nil,
		},
		{
			name: "anchor and alias",
			input: `
defaults: &defaults
  algorithm: AES-256-GCM

production:
  <<: *defaults
`,
			// Only defaults.algorithm should appear; the merge key alias
			// is resolved as a mapping node.
			wantKeys: []string{"defaults.algorithm"},
			wantVals: []string{"AES-256-GCM"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			kvs, err := parseYAML([]byte(tt.input))
			if err != nil {
				t.Fatalf("parseYAML error: %v", err)
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
					t.Errorf("key %q not found in result", key)
					continue
				}
				if tt.wantVals != nil && i < len(tt.wantVals) && got != tt.wantVals[i] {
					t.Errorf("key %q: got value %q, want %q", key, got, tt.wantVals[i])
				}
			}
		})
	}
}

func TestParseYAMLLineNumbers(t *testing.T) {
	input := `algorithm: AES
keySize: 256
`
	kvs, err := parseYAML([]byte(input))
	if err != nil {
		t.Fatalf("parseYAML error: %v", err)
	}
	kvMap := make(map[string]KeyValue)
	for _, kv := range kvs {
		kvMap[kv.Key] = kv
	}
	if kv, ok := kvMap["algorithm"]; !ok || kv.Line != 1 {
		t.Errorf("algorithm: want line 1, got %d", kvMap["algorithm"].Line)
	}
	if kv, ok := kvMap["keySize"]; !ok || kv.Line != 2 {
		t.Errorf("keySize: want line 2, got %d", kv.Line)
	}
}

func TestParseJSON(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		wantKeys []string
		wantVals []string
	}{
		{
			name:     "flat object",
			input:    `{"algorithm":"AES","keySize":"256"}`,
			wantKeys: []string{"algorithm", "keySize"},
			wantVals: []string{"AES", "256"},
		},
		{
			name:     "nested object",
			input:    `{"spring":{"security":{"algorithm":"RSA"}}}`,
			wantKeys: []string{"spring.security.algorithm"},
			wantVals: []string{"RSA"},
		},
		{
			name:     "array values",
			input:    `{"ciphers":["AES-256-GCM","ChaCha20-Poly1305"]}`,
			wantKeys: []string{"ciphers[0]", "ciphers[1]"},
			wantVals: []string{"AES-256-GCM", "ChaCha20-Poly1305"},
		},
		{
			name:     "numeric value",
			input:    `{"keySize":256}`,
			wantKeys: []string{"keySize"},
			wantVals: []string{"256"},
		},
		{
			name:  "invalid json",
			input: `{bad json`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			kvs, err := parseJSON([]byte(tt.input))
			if tt.name == "invalid json" {
				if err == nil {
					t.Error("expected error for invalid JSON, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("parseJSON error: %v", err)
			}
			if len(tt.wantKeys) == 0 {
				return
			}
			kvMap := make(map[string]string)
			for _, kv := range kvs {
				kvMap[kv.Key] = kv.Value
			}
			for i, key := range tt.wantKeys {
				got, ok := kvMap[key]
				if !ok {
					t.Errorf("key %q not found in result", key)
					continue
				}
				if tt.wantVals != nil && i < len(tt.wantVals) && got != tt.wantVals[i] {
					t.Errorf("key %q: got value %q, want %q", key, got, tt.wantVals[i])
				}
			}
		})
	}
}

func TestParseProperties(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		wantKVs  []KeyValue
	}{
		{
			name:  "basic equals",
			input: "algorithm=AES\nkeySize=256\n",
			wantKVs: []KeyValue{
				{Key: "algorithm", Value: "AES", Line: 1},
				{Key: "keySize", Value: "256", Line: 2},
			},
		},
		{
			name:  "colon separator",
			input: "algorithm: AES\n",
			wantKVs: []KeyValue{
				{Key: "algorithm", Value: "AES", Line: 1},
			},
		},
		{
			name:  "skip comments",
			input: "# comment\n! also comment\nalgorithm=AES\n",
			wantKVs: []KeyValue{
				{Key: "algorithm", Value: "AES", Line: 3},
			},
		},
		{
			name:  "skip blank lines",
			input: "\n\nalgorithm=AES\n",
			wantKVs: []KeyValue{
				{Key: "algorithm", Value: "AES", Line: 3},
			},
		},
		{
			name:  "whitespace trimming",
			input: "  algorithm  =  AES  \n",
			wantKVs: []KeyValue{
				{Key: "algorithm", Value: "AES", Line: 1},
			},
		},
		{
			name:  "continuation line",
			input: "long.value=AES\\\n  -256-GCM\n",
			wantKVs: []KeyValue{
				{Key: "long.value", Value: "AES-256-GCM", Line: 1},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			kvs, err := parseProperties([]byte(tt.input))
			if err != nil {
				t.Fatalf("parseProperties error: %v", err)
			}
			if len(kvs) != len(tt.wantKVs) {
				t.Fatalf("got %d pairs, want %d; got: %v", len(kvs), len(tt.wantKVs), kvs)
			}
			for i, want := range tt.wantKVs {
				got := kvs[i]
				if got.Key != want.Key || got.Value != want.Value || got.Line != want.Line {
					t.Errorf("[%d] got {%q,%q,%d}, want {%q,%q,%d}",
						i, got.Key, got.Value, got.Line,
						want.Key, want.Value, want.Line)
				}
			}
		})
	}
}

func TestParseEnv(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantKVs []KeyValue
	}{
		{
			name:  "plain key=value",
			input: "ALGORITHM=AES\n",
			wantKVs: []KeyValue{
				{Key: "ALGORITHM", Value: "AES", Line: 1},
			},
		},
		{
			name:  "double-quoted value",
			input: `CIPHER="AES-256-GCM"` + "\n",
			wantKVs: []KeyValue{
				{Key: "CIPHER", Value: "AES-256-GCM", Line: 1},
			},
		},
		{
			name:  "single-quoted value",
			input: "CIPHER='AES-256-GCM'\n",
			wantKVs: []KeyValue{
				{Key: "CIPHER", Value: "AES-256-GCM", Line: 1},
			},
		},
		{
			name:  "export prefix",
			input: "export ALGORITHM=RSA\n",
			wantKVs: []KeyValue{
				{Key: "ALGORITHM", Value: "RSA", Line: 1},
			},
		},
		{
			name:  "skip comments and blank lines",
			input: "# comment\n\nALGORITHM=AES\n",
			wantKVs: []KeyValue{
				{Key: "ALGORITHM", Value: "AES", Line: 3},
			},
		},
		{
			name:  "multiple entries",
			input: "CIPHER=AES\nKEY_SIZE=256\nHASH=SHA-256\n",
			wantKVs: []KeyValue{
				{Key: "CIPHER", Value: "AES", Line: 1},
				{Key: "KEY_SIZE", Value: "256", Line: 2},
				{Key: "HASH", Value: "SHA-256", Line: 3},
			},
		},
		{
			name:  "double-quoted value with trailing inline comment",
			input: `KEY="value with # hash" # real comment` + "\n",
			wantKVs: []KeyValue{
				{Key: "KEY", Value: "value with # hash", Line: 1},
			},
		},
		{
			name:  "single-quoted value with trailing inline comment",
			input: "KEY='value with # hash' # real comment\n",
			wantKVs: []KeyValue{
				{Key: "KEY", Value: "value with # hash", Line: 1},
			},
		},
		{
			name:  "double-quoted simple value",
			input: `KEY="simple"` + "\n",
			wantKVs: []KeyValue{
				{Key: "KEY", Value: "simple", Line: 1},
			},
		},
		{
			name:  "unquoted value with inline comment",
			input: "KEY=unquoted # comment\n",
			wantKVs: []KeyValue{
				{Key: "KEY", Value: "unquoted", Line: 1},
			},
		},
		{
			name:  "unquoted value hash without space is not a comment",
			input: "KEY=value#nospace\n",
			wantKVs: []KeyValue{
				{Key: "KEY", Value: "value#nospace", Line: 1},
			},
		},
		{
			name:  "double-quoted value no closing quote best effort",
			input: `KEY="no closing quote` + "\n",
			wantKVs: []KeyValue{
				{Key: "KEY", Value: "no closing quote", Line: 1},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			kvs, err := parseEnv([]byte(tt.input))
			if err != nil {
				t.Fatalf("parseEnv error: %v", err)
			}
			if len(kvs) != len(tt.wantKVs) {
				t.Fatalf("got %d pairs, want %d; got: %v", len(kvs), len(tt.wantKVs), kvs)
			}
			for i, want := range tt.wantKVs {
				got := kvs[i]
				if got.Key != want.Key || got.Value != want.Value || got.Line != want.Line {
					t.Errorf("[%d] got {%q,%q,%d}, want {%q,%q,%d}",
						i, got.Key, got.Value, got.Line,
						want.Key, want.Value, want.Line)
				}
			}
		})
	}
}

// --- XML tests ---

func TestParseXML(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		wantKeys []string
		wantVals []string
		wantErr  bool
	}{
		{
			name: "basic nested elements",
			input: `<config>
  <server>
    <ssl>
      <protocol>TLS 1.2</protocol>
    </ssl>
  </server>
</config>`,
			wantKeys: []string{"config.server.ssl.protocol"},
			wantVals: []string{"TLS 1.2"},
		},
		{
			name:     "attributes",
			input:    `<ssl enabled="true" version="TLSv1.3"/>`,
			wantKeys: []string{"ssl[@enabled]", "ssl[@version]"},
			wantVals: []string{"true", "TLSv1.3"},
		},
		{
			name: "mixed elements and attributes",
			input: `<security>
  <ssl enabled="true">
    <protocol>TLS 1.3</protocol>
    <keySize>256</keySize>
  </ssl>
</security>`,
			wantKeys: []string{
				"security.ssl[@enabled]",
				"security.ssl.protocol",
				"security.ssl.keySize",
			},
			wantVals: []string{"true", "TLS 1.3", "256"},
		},
		{
			name: "CDATA section",
			input: `<config>
  <algorithm><![CDATA[AES-256-GCM]]></algorithm>
</config>`,
			wantKeys: []string{"config.algorithm"},
			wantVals: []string{"AES-256-GCM"},
		},
		{
			name:     "self-closing element with attribute",
			input:    `<keystore type="PKCS12" path="/etc/ssl/keystore.p12"/>`,
			wantKeys: []string{"keystore[@type]", "keystore[@path]"},
			wantVals: []string{"PKCS12", "/etc/ssl/keystore.p12"},
		},
		{
			name: "namespaced elements — namespace prefix stripped",
			input: `<beans xmlns:sec="http://www.springframework.org/schema/security">
  <sec:http>
    <sec:algorithm>AES</sec:algorithm>
  </sec:http>
</beans>`,
			wantKeys: []string{"beans.http.algorithm"},
			wantVals: []string{"AES"},
		},
		{
			name: "Tomcat SSL connector config",
			input: `<server>
  <Connector SSLEnabled="true" keystoreType="PKCS12" sslProtocol="TLS" ciphers="TLS_AES_256_GCM_SHA384"/>
</server>`,
			wantKeys: []string{
				"server.Connector[@SSLEnabled]",
				"server.Connector[@keystoreType]",
				"server.Connector[@sslProtocol]",
				"server.Connector[@ciphers]",
			},
			wantVals: []string{"true", "PKCS12", "TLS", "TLS_AES_256_GCM_SHA384"},
		},
		{
			name: "WS-Security SignatureMethod",
			input: `<wsse:Security>
  <ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>
</wsse:Security>`,
			wantKeys: []string{"Security.SignatureMethod[@Algorithm]"},
			wantVals: []string{"http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"},
		},
		{
			name:     "empty self-closing root",
			input:    `<config/>`,
			wantKeys: nil,
		},
		{
			name:     "root with text value",
			input:    `<algorithm>AES-256-GCM</algorithm>`,
			wantKeys: []string{"algorithm"},
			wantVals: []string{"AES-256-GCM"},
		},
		{
			name:    "invalid XML — unclosed tag",
			input:   `<unclosed>`,
			wantErr: true,
		},
		{
			name: "processing instruction and comment skipped",
			input: `<?xml version="1.0" encoding="UTF-8"?>
<!-- This is a comment -->
<config>
  <algorithm>AES</algorithm>
</config>`,
			wantKeys: []string{"config.algorithm"},
			wantVals: []string{"AES"},
		},
		{
			name: "whitespace-only text nodes skipped",
			input: `<config>
  <cipher>
    AES-256-GCM
  </cipher>
</config>`,
			wantKeys: []string{"config.cipher"},
			wantVals: []string{"AES-256-GCM"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			kvs, err := parseXML([]byte(tt.input))
			if tt.wantErr {
				if err == nil {
					t.Error("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("parseXML error: %v", err)
			}
			if len(tt.wantKeys) == 0 {
				if tt.name == "empty self-closing root" && len(kvs) != 0 {
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
					t.Errorf("key %q not found; all keys: %v", key, xmlAllKeys(kvs))
					continue
				}
				if tt.wantVals != nil && i < len(tt.wantVals) && got != tt.wantVals[i] {
					t.Errorf("key %q: got value %q, want %q", key, got, tt.wantVals[i])
				}
			}
		})
	}
}

func TestParseXMLDepthLimit(t *testing.T) {
	var sb strings.Builder
	depth := maxXMLDepth + 10
	for i := 0; i < depth; i++ {
		sb.WriteString("<a>")
	}
	sb.WriteString("value")
	for i := 0; i < depth; i++ {
		sb.WriteString("</a>")
	}

	kvs, err := parseXML([]byte(sb.String()))
	if err != nil {
		t.Fatalf("unexpected error on deep XML: %v", err)
	}
	for _, kv := range kvs {
		parts := strings.Split(kv.Key, ".")
		if len(parts) > maxXMLDepth {
			t.Errorf("key depth %d exceeds limit %d: %q", len(parts), maxXMLDepth, kv.Key)
		}
	}
}

func TestParseXMLEntryCapEnforced(t *testing.T) {
	var sb strings.Builder
	sb.WriteString("<root>")
	for i := 0; i < maxXMLEntries+100; i++ {
		sb.WriteString("<item>val</item>")
	}
	sb.WriteString("</root>")

	kvs, err := parseXML([]byte(sb.String()))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(kvs) > maxXMLEntries {
		t.Errorf("entry cap not enforced: got %d entries, want <= %d", len(kvs), maxXMLEntries)
	}
}

func TestParseXMLXXEPrevention(t *testing.T) {
	// Attempt XXE via SYSTEM entity — Go's xml.Decoder never fetches external resources.
	// Strict=true causes an error on undefined entity references (entity not defined in inline DTD).
	xxePayload := `<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ELEMENT foo ANY>
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<foo>&xxe;</foo>`

	kvs, err := parseXML([]byte(xxePayload))
	if err != nil {
		// Expected: strict mode rejects the entity — test passes.
		return
	}
	// No error path: ensure no file system content leaked.
	for _, kv := range kvs {
		if strings.Contains(kv.Value, "root:") || strings.Contains(kv.Value, "/bin/bash") {
			t.Errorf("XXE may have succeeded — suspicious value: %q", kv.Value)
		}
	}
}

func TestParseXMLLineNumbersAreZero(t *testing.T) {
	kvs, err := parseXML([]byte(`<config><algorithm>AES</algorithm></config>`))
	if err != nil {
		t.Fatalf("parseXML error: %v", err)
	}
	for _, kv := range kvs {
		if kv.Line != 0 {
			t.Errorf("expected Line=0 for XML KVs, got %d for key %q", kv.Line, kv.Key)
		}
	}
}

// xmlAllKeys returns key names from a KeyValue slice for diagnostic output.
func xmlAllKeys(kvs []KeyValue) []string {
	out := make([]string, len(kvs))
	for i, kv := range kvs {
		out[i] = kv.Key
	}
	return out
}
