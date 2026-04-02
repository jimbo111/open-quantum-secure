package configscanner

import (
	"testing"

	"github.com/jimbo111/open-quantum-secure/pkg/findings"
)

func TestMatchCryptoParams(t *testing.T) {
	tests := []struct {
		name      string
		kv        KeyValue
		wantAlg   string
		wantPrim  string
		wantSize  int
		wantMode  string
		wantMatch bool
	}{
		// algorithm key variants
		{
			name:      "algorithm=AES",
			kv:        KeyValue{Key: "algorithm", Value: "AES", Line: 1},
			wantAlg:   "AES",
			wantPrim:  "symmetric",
			wantMatch: true,
		},
		{
			name:      "algorithm=RSA",
			kv:        KeyValue{Key: "algorithm", Value: "RSA", Line: 1},
			wantAlg:   "RSA",
			wantPrim:  "asymmetric",
			wantMatch: true,
		},
		{
			name:      "algorithm=DES",
			kv:        KeyValue{Key: "algorithm", Value: "DES", Line: 5},
			wantAlg:   "DES",
			wantPrim:  "symmetric",
			wantMatch: true,
		},
		{
			name:      "algorithm=3DES (desede)",
			kv:        KeyValue{Key: "algorithm", Value: "DESede", Line: 1},
			wantAlg:   "3DES",
			wantPrim:  "symmetric",
			wantMatch: true,
		},
		{
			name:      "algorithm=Blowfish",
			kv:        KeyValue{Key: "algorithm", Value: "Blowfish", Line: 1},
			wantAlg:   "Blowfish",
			wantPrim:  "symmetric",
			wantMatch: true,
		},
		{
			name:      "algorithm=ChaCha20",
			kv:        KeyValue{Key: "algorithm", Value: "ChaCha20", Line: 1},
			wantAlg:   "ChaCha20",
			wantPrim:  "symmetric",
			wantMatch: true,
		},
		{
			name:      "algorithm=SHA-256",
			kv:        KeyValue{Key: "algorithm", Value: "SHA-256", Line: 1},
			wantAlg:   "SHA-256",
			wantPrim:  "hash",
			wantMatch: true,
		},
		{
			name:      "algorithm=SHA-512",
			kv:        KeyValue{Key: "algorithm", Value: "SHA-512", Line: 1},
			wantAlg:   "SHA-512",
			wantPrim:  "hash",
			wantMatch: true,
		},
		{
			name:      "algorithm=SHA-1",
			kv:        KeyValue{Key: "algorithm", Value: "SHA-1", Line: 1},
			wantAlg:   "SHA-1",
			wantPrim:  "hash",
			wantMatch: true,
		},
		{
			name:      "algorithm=MD5",
			kv:        KeyValue{Key: "algorithm", Value: "MD5", Line: 1},
			wantAlg:   "MD5",
			wantPrim:  "hash",
			wantMatch: true,
		},
		{
			name:      "algorithm=HMAC",
			kv:        KeyValue{Key: "algorithm", Value: "HMAC", Line: 1},
			wantAlg:   "HMAC",
			wantPrim:  "mac",
			wantMatch: true,
		},
		{
			name:      "algorithm=ECDSA",
			kv:        KeyValue{Key: "algorithm", Value: "ECDSA", Line: 1},
			wantAlg:   "ECDSA",
			wantPrim:  "signature",
			wantMatch: true,
		},
		{
			name:      "algorithm=ECDH",
			kv:        KeyValue{Key: "algorithm", Value: "ECDH", Line: 1},
			wantAlg:   "ECDH",
			wantPrim:  "key-exchange",
			wantMatch: true,
		},
		{
			name:      "algorithm=Ed25519",
			kv:        KeyValue{Key: "algorithm", Value: "Ed25519", Line: 1},
			wantAlg:   "Ed25519",
			wantPrim:  "signature",
			wantMatch: true,
		},

		// cipher key with full cipher string
		{
			name:      "cipher=AES-256-GCM",
			kv:        KeyValue{Key: "cipher", Value: "AES-256-GCM", Line: 3},
			wantAlg:   "AES",
			wantPrim:  "symmetric",
			wantSize:  256,
			wantMode:  "GCM",
			wantMatch: true,
		},
		{
			name:      "cipher=AES-128-CBC",
			kv:        KeyValue{Key: "cipher", Value: "AES-128-CBC", Line: 3},
			wantAlg:   "AES",
			wantPrim:  "symmetric",
			wantSize:  128,
			wantMode:  "CBC",
			wantMatch: true,
		},
		{
			name:      "cipher=ChaCha20-Poly1305",
			kv:        KeyValue{Key: "cipher", Value: "ChaCha20-Poly1305", Line: 1},
			wantAlg:   "ChaCha20-Poly1305",
			wantPrim:  "ae",
			wantMatch: true,
		},
		{
			name:      "cipher=RC4",
			kv:        KeyValue{Key: "cipher", Value: "RC4", Line: 1},
			wantAlg:   "RC4",
			wantPrim:  "stream-cipher",
			wantMatch: true,
		},

		// TLS protocol
		{
			name:      "protocol=TLSv1.0",
			kv:        KeyValue{Key: "protocol", Value: "TLSv1.0", Line: 2},
			wantAlg:   "TLS",
			wantPrim:  "protocol",
			wantMatch: true,
		},
		{
			name:      "protocol=SSLv3",
			kv:        KeyValue{Key: "protocol", Value: "SSLv3", Line: 2},
			wantAlg:   "SSLv3",
			wantPrim:  "protocol",
			wantMatch: true,
		},

		// Key size patterns
		{
			name:      "keySize=256",
			kv:        KeyValue{Key: "keySize", Value: "256", Line: 4},
			wantAlg:   "AES",
			wantPrim:  "symmetric",
			wantSize:  256,
			wantMatch: true,
		},
		{
			name:      "key_length=128",
			kv:        KeyValue{Key: "key_length", Value: "128", Line: 4},
			wantAlg:   "AES",
			wantPrim:  "symmetric",
			wantSize:  128,
			wantMatch: true,
		},
		{
			name:      "key-size with bits suffix",
			kv:        KeyValue{Key: "key-size", Value: "256bits", Line: 4},
			wantAlg:   "AES",
			wantPrim:  "symmetric",
			wantSize:  256,
			wantMatch: true,
		},

		// Cipher suite
		{
			name:      "cipherSuite contains RSA",
			kv:        KeyValue{Key: "ciphersuite", Value: "TLS_RSA_WITH_AES_128_CBC_SHA", Line: 1},
			wantAlg:   "RSA",
			wantPrim:  "asymmetric",
			wantMatch: true,
		},
		{
			name:      "cipherSuite contains ECDHE",
			kv:        KeyValue{Key: "ciphersuite", Value: "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384", Line: 1},
			wantAlg:   "ECDHE",
			wantPrim:  "key-exchange",
			wantMatch: true,
		},

		// Encryption key
		{
			name:      "encryption=AES",
			kv:        KeyValue{Key: "encryption", Value: "AES", Line: 1},
			wantAlg:   "AES",
			wantPrim:  "symmetric",
			wantMatch: true,
		},

		// Hash key
		{
			name:      "hash=SHA256",
			kv:        KeyValue{Key: "hash", Value: "SHA256", Line: 1},
			wantAlg:   "SHA-256",
			wantPrim:  "hash",
			wantMatch: true,
		},
		{
			name:      "digest=MD5",
			kv:        KeyValue{Key: "digest", Value: "MD5", Line: 1},
			wantAlg:   "MD5",
			wantPrim:  "hash",
			wantMatch: true,
		},

		// Nested key (dotted)
		{
			name:      "spring.security.algorithm=AES",
			kv:        KeyValue{Key: "spring.security.algorithm", Value: "AES", Line: 7},
			wantAlg:   "AES",
			wantPrim:  "symmetric",
			wantMatch: true,
		},

		// Non-matching entries
		{
			name:      "unrelated key",
			kv:        KeyValue{Key: "database.host", Value: "localhost", Line: 1},
			wantMatch: false,
		},
		{
			name:      "algorithm with unknown value",
			kv:        KeyValue{Key: "algorithm", Value: "UNKNOWN_ALGO", Line: 1},
			wantMatch: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fds := matchCryptoParams("test.yml", []KeyValue{tt.kv})
			if !tt.wantMatch {
				if len(fds) != 0 {
					t.Errorf("expected no match, got %d findings: %+v", len(fds), fds)
				}
				return
			}
			if len(fds) == 0 {
				t.Fatal("expected a finding but got none")
			}
			f := fds[0]
			if f.Algorithm == nil {
				t.Fatal("finding has nil Algorithm")
			}
			if f.Algorithm.Name != tt.wantAlg {
				t.Errorf("Algorithm.Name = %q, want %q", f.Algorithm.Name, tt.wantAlg)
			}
			if f.Algorithm.Primitive != tt.wantPrim {
				t.Errorf("Algorithm.Primitive = %q, want %q", f.Algorithm.Primitive, tt.wantPrim)
			}
			if tt.wantSize != 0 && f.Algorithm.KeySize != tt.wantSize {
				t.Errorf("Algorithm.KeySize = %d, want %d", f.Algorithm.KeySize, tt.wantSize)
			}
			if tt.wantMode != "" && f.Algorithm.Mode != tt.wantMode {
				t.Errorf("Algorithm.Mode = %q, want %q", f.Algorithm.Mode, tt.wantMode)
			}
			if f.Confidence != findings.ConfidenceMedium {
				t.Errorf("Confidence = %q, want %q", f.Confidence, findings.ConfidenceMedium)
			}
			if f.SourceEngine != "config-scanner" {
				t.Errorf("SourceEngine = %q, want %q", f.SourceEngine, "config-scanner")
			}
			if f.Reachable != findings.ReachableUnknown {
				t.Errorf("Reachable = %q, want %q", f.Reachable, findings.ReachableUnknown)
			}
			if f.Location.Line != tt.kv.Line {
				t.Errorf("Location.Line = %d, want %d", f.Location.Line, tt.kv.Line)
			}
		})
	}
}

func TestParseIntValue(t *testing.T) {
	tests := []struct {
		input string
		want  int
	}{
		{"256", 256},
		{"128", 128},
		{"256bits", 256},
		{"256 bits", 256},
		{"256bit", 256},
		{"256b", 256},
		{"  256  ", 256},
		{"abc", 0},
		{"-1", 0},
		{"0", 0},
		{"", 0},
	}
	for _, tt := range tests {
		got := parseIntValue(tt.input)
		if got != tt.want {
			t.Errorf("parseIntValue(%q) = %d, want %d", tt.input, got, tt.want)
		}
	}
}

func TestMatchCryptoParamsLinePreservation(t *testing.T) {
	kvs := []KeyValue{
		{Key: "algorithm", Value: "AES", Line: 10},
		{Key: "cipher", Value: "AES-256-GCM", Line: 25},
	}
	fds := matchCryptoParams("/some/config.yml", kvs)
	if len(fds) != 2 {
		t.Fatalf("expected 2 findings, got %d", len(fds))
	}
	if fds[0].Location.Line != 10 {
		t.Errorf("first finding line = %d, want 10", fds[0].Location.Line)
	}
	if fds[1].Location.Line != 25 {
		t.Errorf("second finding line = %d, want 25", fds[1].Location.Line)
	}
}

func TestFirstMatchWins(t *testing.T) {
	// A key containing "algorithm" and matching two patterns — should only
	// produce one finding.
	kv := KeyValue{Key: "algorithm", Value: "AES-256-GCM", Line: 1}
	fds := matchCryptoParams("config.yml", []KeyValue{kv})
	if len(fds) != 1 {
		t.Errorf("expected 1 finding (first match wins), got %d", len(fds))
	}
}
