package configscanner

import (
	"testing"

	"github.com/jimbo111/open-quantum-secure/pkg/quantum"
)

// TestBugG7_TLSVersionDistinguishable is the RED test for review finding B6:
// configscanner's TLS protocol vocabulary computed the SSLv3/TLSv1.0-1.3
// distinction via ValueHints but then discarded it, emitting Algorithm:"TLS"
// for every TLS version. Downstream classification could not tell a legacy
// TLSv1.0 config from a TLSv1.3 one -- both classified as "unknown".
//
// This test scans the same fixture shape as the ground-truth
// config-crypto/application.yml (ssl.protocol=TLSv1.2) plus a TLSv1.0 and a
// TLSv1.3 variant, and asserts:
//  1. The three versions produce distinguishable Algorithm.Name values.
//  2. Feeding each finding's Algorithm through quantum.ClassifyAlgorithm
//     yields three DIFFERENT risk verdicts: TLSv1.0 deprecated,
//     TLSv1.2 quantum-vulnerable (conditional/note-level), TLSv1.3 resistant.
func TestBugG7_TLSVersionDistinguishable(t *testing.T) {
	versions := []struct {
		value    string
		wantRisk quantum.Risk
	}{
		{"TLSv1.0", quantum.RiskDeprecated},
		{"TLSv1.1", quantum.RiskDeprecated},
		{"TLSv1.2", quantum.RiskVulnerable},
		{"TLSv1.3", quantum.RiskResistant},
	}

	names := make(map[string]string, len(versions)) // value -> Algorithm.Name
	for _, v := range versions {
		fds := matchCryptoParams("application.yml", []KeyValue{{Key: "ssl.protocol", Value: v.value, Line: 7}})
		if len(fds) == 0 || fds[0].Algorithm == nil {
			t.Fatalf("protocol=%s: expected a finding, got none", v.value)
		}
		alg := fds[0].Algorithm
		names[v.value] = alg.Name

		got := quantum.ClassifyAlgorithm(alg.Name, alg.Primitive, alg.KeySize)
		if got.Risk != v.wantRisk {
			t.Errorf("protocol=%s: ClassifyAlgorithm(%q, %q, %d).Risk = %q, want %q",
				v.value, alg.Name, alg.Primitive, alg.KeySize, got.Risk, v.wantRisk)
		}
	}

	// Every version must produce a distinct Algorithm.Name -- the whole point
	// of the fix is that TLSv1.0 is no longer indistinguishable from TLSv1.3.
	seen := make(map[string]string) // Algorithm.Name -> first value that produced it
	for value, name := range names {
		if prior, ok := seen[name]; ok {
			t.Errorf("protocol=%s and protocol=%s both produced Algorithm.Name=%q -- versions must be distinguishable",
				value, prior, name)
		}
		seen[name] = value
	}
}
