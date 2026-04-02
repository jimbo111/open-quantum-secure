package output

import (
	"testing"
)

// TestMapToCDXPrimitive_RNG verifies that the "rng" primitive family maps to
// "other" in CycloneDX 1.7 output. CycloneDX 1.7 has no native "rng" primitive
// in its taxonomy, so all rng/prng/csprng/random variants fall back to "other".
func TestMapToCDXPrimitive_RNG(t *testing.T) {
	cases := []struct {
		input string
		want  string
	}{
		// All RNG aliases must map to "other"
		{"rng", "other"},
		{"RNG", "other"},
		{"prng", "other"},
		{"PRNG", "other"},
		{"csprng", "other"},
		{"CSPRNG", "other"},
		{"random", "other"},
		{"RANDOM", "other"},
		// Existing mappings must remain unaffected
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
