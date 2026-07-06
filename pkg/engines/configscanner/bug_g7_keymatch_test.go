package configscanner

import (
	"testing"
)

// TestBugG7_KeyMatchingSegmentBoundary is the RED test for review finding B7:
// matchCryptoParams used a bare strings.Contains(lowerKey, param.KeyPattern)
// check, so the flattened JSON key "expectedAlgorithms[0]" (from
// {"expectedAlgorithms": ["AES"]} -- the ground-truth manifest's OWN schema)
// false-positived against the "algorithm" vocabulary entry, because
// "expectedAlgorithms" contains "algorithm" as a substring.
//
// After the fix, key matching must be segment-boundary-aware: a KeyPattern
// only matches a whole segment (bounded by ./[/]/_/- or a camelCase
// transition), not an arbitrary substring.
func TestBugG7_KeyMatchingSegmentBoundary(t *testing.T) {
	tests := []struct {
		name      string
		key       string
		value     string
		wantMatch bool
	}{
		{
			name:      "expectedAlgorithms[0] must NOT match algorithm vocab (ground-truth manifest self-FP)",
			key:       "expectedAlgorithms[0]",
			value:     "AES",
			wantMatch: false,
		},
		{
			name:      "encryption_algorithm must still match",
			key:       "encryption_algorithm",
			value:     "AES",
			wantMatch: true,
		},
		{
			name:      "spring.ssl.algorithm must still match",
			key:       "spring.ssl.algorithm",
			value:     "AES",
			wantMatch: true,
		},
		{
			name:      "camelCase sslProtocol must still match protocol vocab",
			key:       "sslProtocol",
			value:     "TLSv1.2",
			wantMatch: true,
		},
		{
			name:      "plural cipher-suites still matches cipher-suite vocab",
			key:       "cipher-suites",
			value:     "TLS_RSA_WITH_AES_128_CBC_SHA",
			wantMatch: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fds := matchCryptoParams("test.json", []KeyValue{{Key: tt.key, Value: tt.value, Line: 1}})
			gotMatch := len(fds) > 0
			if gotMatch != tt.wantMatch {
				t.Errorf("key=%q value=%q: match = %v, want %v (findings: %+v)",
					tt.key, tt.value, gotMatch, tt.wantMatch, fds)
			}
		})
	}
}

// TestBugG7_JWTAlgClaim proves the new "alg" vocabulary entry (safe to add
// now that key matching is segment-bounded -- previously "alg" would have
// been a substring of "algorithm" and matched everything) recognizes the
// JWT/JWS "alg" claim without colliding with the unrelated "algorithm" key.
func TestBugG7_JWTAlgClaim(t *testing.T) {
	fds := matchCryptoParams("test.json", []KeyValue{{Key: "jwt.alg", Value: "RS256", Line: 1}})
	if len(fds) == 0 || fds[0].Algorithm == nil {
		t.Fatal(`expected jwt.alg=RS256 to match a vocabulary entry`)
	}
	if fds[0].Algorithm.Name != "RSA" {
		t.Errorf("jwt.alg=RS256: Algorithm.Name = %q, want RSA", fds[0].Algorithm.Name)
	}
}
