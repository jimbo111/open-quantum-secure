package output

import (
	"testing"
)

// TestMapToCDXPrimitive_RNG verifies that the "rng" primitive family maps to
// the CycloneDX 1.7 dedicated "drbg" primitive. Earlier versions of this code
// returned "other" because the prior CycloneDX revision had no RNG-specific
// value, but CycloneDX 1.7 added "drbg" to algorithmProperties.primitive's
// enum. Strict schema validators reject "other" when "drbg" is appropriate.
func TestMapToCDXPrimitive_RNG(t *testing.T) {
	cases := []struct {
		input string
		want  string
	}{
		// All RNG aliases must map to "drbg" (CycloneDX 1.7 enum value).
		{"rng", "drbg"},
		{"RNG", "drbg"},
		{"prng", "drbg"},
		{"PRNG", "drbg"},
		{"csprng", "drbg"},
		{"CSPRNG", "drbg"},
		{"random", "drbg"},
		{"RANDOM", "drbg"},
		{"drbg", "drbg"}, // explicit drbg passes through.
		// Existing mappings must remain unaffected.
		{"hash", "hash"},
		{"kem", "kem"},
		{"symmetric", "block-cipher"},
		{"block-cipher", "block-cipher"},
		{"ae", "ae"},
		{"aead", "ae"},
		{"signature", "signature"},
		{"xof", "xof"},
	}

	for _, c := range cases {
		t.Run(c.input, func(t *testing.T) {
			got := mapToCDXPrimitive(c.input)
			if got != c.want {
				t.Errorf("mapToCDXPrimitive(%q) = %q, want %q", c.input, got, c.want)
			}
		})
	}
}
