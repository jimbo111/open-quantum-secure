package zeeklog

import "testing"

func TestNormalizeTLSVersion(t *testing.T) {
	tests := []struct {
		in   string
		want string
	}{
		{"TLSv13", "1.3"},
		{"TLSv12", "1.2"},
		{"TLSv11", "1.1"},
		{"TLSv10", "1.0"},
		{"TLS1.3", "1.3"},
		{"TLS13", "1.3"},
		{"tlsv13", "1.3"},
		{"SSLv3", "SSLv3"}, // passthrough
		{"", ""},
	}
	for _, tt := range tests {
		got := normalizeTLSVersion(tt.in)
		if got != tt.want {
			t.Errorf("normalizeTLSVersion(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestCurveNameToGroup(t *testing.T) {
	tests := []struct {
		in   string
		want string
	}{
		{"secp256r1", "secp256r1"},
		{"prime256v1", "secp256r1"},
		{"secp384r1", "secp384r1"},
		{"x25519", "X25519"},
		{"X25519", "X25519"},
		{"x25519mlkem768", "X25519MLKEM768"},
		{"X25519MLKEM768", "X25519MLKEM768"},
		{"secp256r1mlkem768", "SecP256r1MLKEM768"},
		{"mlkem768", "MLKEM768"},
		{"mlkem1024", "MLKEM1024"},
		{"-", ""},
		{"", ""},
		{"unknown_curve", "unknown_curve"}, // passthrough
	}
	for _, tt := range tests {
		got := curveNameToGroup(tt.in)
		if got != tt.want {
			t.Errorf("curveNameToGroup(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestResolveOIDAlgorithm(t *testing.T) {
	tests := []struct {
		in      string
		want    string
		wantOK  bool
	}{
		{"2.16.840.1.101.3.4.3.17", "ML-DSA-44", true},
		{"2.16.840.1.101.3.4.3.18", "ML-DSA-65", true},
		{"2.16.840.1.101.3.4.3.19", "ML-DSA-87", true},
		{"unknown 2.16.840.1.101.3.4.3.18", "ML-DSA-65", true},
		{"2.16.840.1.101.3.4.4.2", "ML-KEM-768", true},
		{"unknown 2.16.840.1.101.3.4.4.3", "ML-KEM-1024", true},
		{"sha256WithRSAEncryption", "", false},
		{"", "", false},
	}
	for _, tt := range tests {
		got, ok := resolveOIDAlgorithm(tt.in)
		if ok != tt.wantOK {
			t.Errorf("resolveOIDAlgorithm(%q) ok = %v, want %v", tt.in, ok, tt.wantOK)
		}
		if got != tt.want {
			t.Errorf("resolveOIDAlgorithm(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestCipherPrimitive(t *testing.T) {
	tests := []struct {
		cipher string
		want   string
	}{
		{"TLS_AES_256_GCM_SHA384", "ae"},
		{"TLS_CHACHA20_POLY1305_SHA256", "ae"},
		{"TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384", "key-agree"},
		{"TLS_DHE_RSA_WITH_AES_128_GCM_SHA256", "key-agree"},
		{"TLS_RSA_WITH_AES_256_GCM_SHA384", "asymmetric"},
		{"UNKNOWN_CIPHER", ""},
	}
	for _, tt := range tests {
		got := cipherPrimitive(tt.cipher)
		if got != tt.want {
			t.Errorf("cipherPrimitive(%q) = %q, want %q", tt.cipher, got, tt.want)
		}
	}
}
