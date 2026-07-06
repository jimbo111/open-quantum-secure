package configscanner

import (
	"testing"

	"github.com/jimbo111/open-quantum-secure/pkg/quantum"
)

// TestBugG7Followup_SSLv3Deprecated is the RED test for the G7 code-review
// follow-up: SSLv3 already got a distinct Algorithm.Name ("SSLv3", vocabulary.go
// line ~186) before the B6 fix, but classify.go never had a corresponding
// deprecatedAlgorithms entry, so it fell through to RiskUnknown/SeverityLow --
// the same undifferentiated-risk bug as TLSv1.0/1.1 had, just not called out
// in the original B6 finding because SSLv3 wasn't one of the four TLS entries
// that collapsed to Algorithm:"TLS". SSLv3 is classically broken (POODLE) and
// must classify the same way TLSv1.0/1.1 now do: RiskDeprecated/SeverityCritical.
//
// Covers both paths: the config-scanner vocabulary/classify path (a real
// ssl_protocol: SSLv3-style config value) and a direct ClassifyAlgorithm call
// (the shape other engines -- or a future SSLv3 vocabulary entry with a
// different ValueHint spelling -- would use).
func TestBugG7Followup_SSLv3Deprecated(t *testing.T) {
	// Vocabulary/classify path: three real-world value spellings all
	// normalize to the same canonical Algorithm.Name="SSLv3" at the
	// vocabulary layer (see the "protocol" ValueHints entry), so a single
	// config-value shape suffices to exercise the full pipeline once; the
	// direct ClassifyAlgorithm cases below cover the name-shape question
	// (SSLv2, "SSLv3") independent of configscanner's own value normalization.
	fds := matchCryptoParams("application.yml", []KeyValue{{Key: "ssl.protocol", Value: "SSLv3", Line: 6}})
	if len(fds) == 0 || fds[0].Algorithm == nil {
		t.Fatal("protocol=SSLv3: expected a finding, got none")
	}
	alg := fds[0].Algorithm
	if alg.Name != "SSLv3" {
		t.Fatalf("protocol=SSLv3: Algorithm.Name = %q, want SSLv3", alg.Name)
	}
	got := quantum.ClassifyAlgorithm(alg.Name, alg.Primitive, alg.KeySize)
	if got.Risk != quantum.RiskDeprecated {
		t.Errorf("protocol=SSLv3 (via vocabulary): ClassifyAlgorithm(%q, %q, %d).Risk = %q, want %q",
			alg.Name, alg.Primitive, alg.KeySize, got.Risk, quantum.RiskDeprecated)
	}
	if got.Severity != quantum.SeverityCritical {
		t.Errorf("protocol=SSLv3 (via vocabulary): Severity = %q, want %q", got.Severity, quantum.SeverityCritical)
	}
	if got.Recommendation == "" {
		t.Error("protocol=SSLv3: expected a non-empty Recommendation")
	}

	// Direct ClassifyAlgorithm path -- SSLv3 and SSLv2 as literal names, the
	// shape another engine (or a future vocabulary entry) would pass in.
	// Scoped to these two literal names only: configscanner's vocabulary
	// already normalizes every SSLv3 value spelling ("sslv3"/"ssl3"/"ssl 3")
	// to the single canonical Algorithm.Name="SSLv3" before classification
	// ever sees it, so there is no real path that produces a literal
	// "SSL 3.0" Algorithm name for ClassifyAlgorithm to need to handle.
	for _, name := range []string{"SSLv3", "SSLv2"} {
		c := quantum.ClassifyAlgorithm(name, "protocol", 0)
		if c.Risk != quantum.RiskDeprecated {
			t.Errorf("ClassifyAlgorithm(%q, protocol, 0).Risk = %q, want %q", name, c.Risk, quantum.RiskDeprecated)
		}
		if c.Severity != quantum.SeverityCritical {
			t.Errorf("ClassifyAlgorithm(%q, protocol, 0).Severity = %q, want %q", name, c.Severity, quantum.SeverityCritical)
		}
	}
}
