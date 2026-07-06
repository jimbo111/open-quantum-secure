package registry

import "testing"

// Wave-2 review C9: separator-less HMAC composites (Java "HmacSHA1") hit
// the family-prefix path and collapsed to bare "HMAC", hiding the inner
// (possibly deprecated) digest from classification.
func TestNormalize_HMACCompositePreservesInnerHash(t *testing.T) {
	reg := Load()
	for _, tc := range []struct{ in, wantCanonical string }{
		{"HmacSHA1", "HMAC-SHA1"},
		{"HmacMD5", "HMAC-MD5"},
		{"HMACSHA256", "HMAC-SHA256"},
		{"HMAC-SHA256", "HMAC-SHA256"}, // exact variant match, unchanged
		{"HMAC", "HMAC"},               // bare family stays bare
	} {
		got := reg.Normalize(tc.in, 0, "")
		if got.CanonicalName != tc.wantCanonical {
			t.Errorf("Normalize(%q).CanonicalName = %q, want %q (match=%v)", tc.in, got.CanonicalName, tc.wantCanonical, got.MatchType)
		}
	}
}
