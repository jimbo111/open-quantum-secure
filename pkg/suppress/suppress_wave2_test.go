package suppress

import "testing"

// Wave-2 review V14: `// oqs:ignore[TLS]` must keep suppressing findings
// after the G7 rename gave them versioned names ("TLSv1.2").
func TestGenericCoversVersioned(t *testing.T) {
	for _, tc := range []struct {
		directive, algorithm string
		want                 bool
	}{
		{"TLS", "TLSv1.2", true},
		{"tls", "TLS 1.3", true},
		{"SSL", "SSLv3", true},
		{"TLS", "TLS_RSA_WITH_AES_128", false},
		{"TLS", "TLS", false}, // exact match handled by EqualFold path
		{"RSA", "RSAv2", false},
	} {
		if got := genericCoversVersioned(tc.directive, tc.algorithm); got != tc.want {
			t.Errorf("genericCoversVersioned(%q, %q) = %v, want %v", tc.directive, tc.algorithm, got, tc.want)
		}
	}
}
