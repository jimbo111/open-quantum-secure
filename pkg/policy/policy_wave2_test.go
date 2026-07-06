package policy

import "testing"

// Wave-2 review V13: config-scanner protocol findings were renamed from
// generic "TLS" to versioned "TLSv1.x". Policy allow/block entries written
// as "tls"/"ssl" (pre-rename convention, no glob) must keep matching the
// versioned forms — a generic protocol pattern covers its versions.
func TestMatchesPattern_GenericProtocolCoversVersions(t *testing.T) {
	for _, tc := range []struct {
		pattern, alg string
		want         bool
	}{
		{"tls", "tlsv1.2", true},
		{"tls", "tlsv1.0", true},
		{"ssl", "sslv3", true},
		{"tls", "tls 1.3", true},   // target-style name
		{"tls", "tls_rsa_with_aes", false}, // cipher-suite-ish names are NOT versions
		{"tls", "atlas", false},
		{"tlsv1.2", "tlsv1.2", true},
	} {
		if got := matchesAnyPattern(tc.alg, []string{tc.pattern}); got != tc.want {
			t.Errorf("matchesAnyPattern(%q, [%q]) = %v, want %v", tc.alg, tc.pattern, got, tc.want)
		}
	}
}
