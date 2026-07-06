package configscanner

import "testing"

// Wave-2 review V6+V12: acronym-run camelCase keys and glued compound
// patterns regressed relative to the pre-G7 substring matcher.
func TestKeyMatchesPattern_AcronymAndGlued(t *testing.T) {
	cases := []struct {
		key, pattern string
		want         bool
	}{
		// V6: acronym runs — upper→upper transitions need a boundary
		// before the last upper when followed by lower.
		{"SSLProtocol", "protocol", true},
		{"Connector[@SSLProtocol]", "protocol", true},
		{"TLSCipherSuite", "ciphersuite", true},
		// V12: glued patterns vs camelCase segment splits.
		{"cipherSuite", "ciphersuite", true},
		{"cipherSuites", "ciphersuite", true}, // plural via n-gram join
		{"keyLength", "keylength", true},
		// The B7 fix must hold: single-segment plural never matches.
		{"expectedAlgorithms[0]", "algorithm", false},
		{"algorithms", "algorithm", false},
		{"tls_algorithms", "algorithm", false},
		// Existing behavior unchanged.
		{"encryption_algorithm", "algorithm", true},
		{"spring.ssl.algorithm", "algorithm", true},
		{"cipher-suites", "cipher-suite", true},
	}
	for _, tc := range cases {
		if got := keyMatchesPattern(tc.key, tc.pattern); got != tc.want {
			t.Errorf("keyMatchesPattern(%q, %q) = %v, want %v", tc.key, tc.pattern, got, tc.want)
		}
	}
}
