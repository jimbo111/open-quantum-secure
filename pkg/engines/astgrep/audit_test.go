package astgrep

// AUDIT: adversarial fixtures authored for the 2026-04-20 Tier-1 scanner audit.
// See docs/audits/2026-04-20-scanner-layer-audit/01-t1-source.md for the report.

import (
	"strings"
	"testing"

	"github.com/jimbo111/open-quantum-secure/pkg/findings"
)

// -----------------------------------------------------------------------------
// F-ASTGREP-1 — primitiveFromRuleID returns "hash" for HMAC rule IDs when the
// rule name also contains "sha" (e.g. "hmac-sha256").  The SHA arm of the
// switch is evaluated before the HMAC arm so MAC rules get mislabeled.
// -----------------------------------------------------------------------------

func TestAudit_PrimitiveFromRuleID_HMACMisclassifiedAsHash(t *testing.T) {
	// Each of these rule IDs describes an HMAC primitive but also contains
	// "sha" (because HMAC is typically paired with a hash).  Expected: "mac".
	cases := []string{
		"crypto-hmac-sha256-new",
		"crypto-go-hmac-sha256",
		"crypto-hmac-sha1",
		"crypto-hmac-sha512-verify",
	}

	for _, id := range cases {
		id := id
		t.Run(id, func(t *testing.T) {
			got := primitiveFromRuleID(id)
			if got != "mac" {
				t.Errorf("primitiveFromRuleID(%q) = %q, want \"mac\"", id, got)
			}
		})
	}
}

// -----------------------------------------------------------------------------
// F-ASTGREP-2 — a pathological capture containing ONLY quote characters must
// not surface quote chars as an algorithm name. With the metadata-based
// resolution the empty capture falls through to the rule's static resolution;
// crypto-java-cipher is value-generic (no static name), so the finding
// honestly carries no Algorithm instead of a poisoned one.
// -----------------------------------------------------------------------------

func TestAudit_ExtractAlgorithm_EmptyAfterTrimFallsThrough(t *testing.T) {
	m := rawMatch{
		RuleID:  "crypto-java-cipher",
		Message: "Java Cipher.getInstance: AES-256",
		MetaVars: rawMetaVars{
			// Pathological capture: parser grabbed only the quote chars.
			"ALGO": {Text: `""`},
		},
	}

	got := extractAlgorithm(m, nil)
	if got != "" {
		t.Errorf("extractAlgorithm = %q, want \"\" for quote-only capture on a value-generic rule", got)
	}

	uf := normalize(m, nil)
	if uf.Algorithm != nil {
		t.Errorf("normalize should emit no Algorithm for unresolvable capture, got %+v", uf.Algorithm)
	}
}

// -----------------------------------------------------------------------------
// F-ASTGREP-3 (superseded) — the message-suffix extractor (extractQuoted) was
// removed: it poisoned Algorithm.Name with message fragments ("2048-bit",
// "elliptic.P256()"). This regression test pins that the message text is
// never consulted for algorithm naming anymore.
// -----------------------------------------------------------------------------

func TestAudit_MessageSuffixNeverConsulted(t *testing.T) {
	cases := []struct {
		ruleID  string
		message string
		want    string
	}{
		{"crypto-go-rsa-generate-key", "Go crypto/rsa GenerateKey: 2048-bit", "RSA"},
		{"crypto-go-ecdsa-generate-key", "Go crypto/ecdsa GenerateKey: elliptic.P256()", "ECDSA"},
		{"crypto-go-tls-config", "Go crypto/tls Config usage", "TLS"},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.ruleID, func(t *testing.T) {
			got := extractAlgorithm(rawMatch{RuleID: tc.ruleID, Message: tc.message}, nil)
			if got != tc.want {
				t.Errorf("extractAlgorithm(%q) = %q, want %q (message suffix must not leak into name)", tc.ruleID, got, tc.want)
			}
		})
	}
}

// -----------------------------------------------------------------------------
// F-ASTGREP-4 — normalize keeps a UnifiedFinding even when the rule ID is
// entirely empty, producing a finding with zero Location and ruleId fallback
// returning "".  In practice this would be filtered by dedup but is still
// surfaced in raw scanner output.  Low severity; invariants check.
// -----------------------------------------------------------------------------

func TestAudit_Normalize_EmptyRuleIDEmitsNakedFinding(t *testing.T) {
	m := rawMatch{
		RuleID:   "",
		File:     "src/foo.go",
		Severity: "",
		Range: rawRange{
			Start: rawPosition{Line: 0, Column: 0},
		},
	}
	uf := normalize(m, nil)
	if uf.SourceEngine != "astgrep" {
		t.Errorf("SourceEngine: got %q, want %q", uf.SourceEngine, "astgrep")
	}
	if uf.Reachable != findings.ReachableUnknown {
		t.Errorf("Reachable: got %v, want ReachableUnknown", uf.Reachable)
	}
	// Algorithm is dropped because extractAlgorithm returns "" when RuleID=="".
	if uf.Algorithm != nil {
		t.Errorf("expected no Algorithm for empty RuleID, got %+v", uf.Algorithm)
	}
}

// -----------------------------------------------------------------------------
// F-ASTGREP-5 (updated) — token-based ruleID inference resolves PQC / hybrid
// names to their canonical classifier-recognized spellings instead of the old
// last-segment uppercase ("768", "MLKEM768"). Hybrid ids resolve to the full
// hybrid name so they are not misclassified via the classical component.
// -----------------------------------------------------------------------------

func TestAudit_ExtractAlgorithm_HybridPQCTokens(t *testing.T) {
	cases := []struct {
		ruleID  string
		wantAlg string
	}{
		{"crypto-go-x25519-mlkem-768", "X25519MLKEM768"},
		{"crypto-go-kyber768", "Kyber768"},
		{"crypto-hybrid-x25519-mlkem768", "X25519MLKEM768"},
		{"crypto-mlkem", "ML-KEM"},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.ruleID, func(t *testing.T) {
			m := rawMatch{RuleID: tc.ruleID}
			got := extractAlgorithm(m, nil)
			if got != tc.wantAlg {
				t.Errorf("extractAlgorithm(%q) = %q, want %q", tc.ruleID, got, tc.wantAlg)
			}
		})
	}
}

// -----------------------------------------------------------------------------
// F-ASTGREP-6 — quote-only ALGO captures must never surface quote characters
// as an algorithm name. Distilled from F-ASTGREP-2 as a standalone property
// test.
// -----------------------------------------------------------------------------

func TestAudit_ExtractAlgorithm_AlgoOnlyQuotes(t *testing.T) {
	quoteStrings := []string{`""`, `''`, `"'`, `''`, `""""`}
	for _, q := range quoteStrings {
		q := q
		t.Run(q, func(t *testing.T) {
			m := rawMatch{
				RuleID:  "crypto-java-cipher",
				Message: "", // no fallback available
				MetaVars: rawMetaVars{
					"ALGO": {Text: q},
				},
			}
			got := extractAlgorithm(m, nil)
			if strings.ContainsAny(got, `"'`) {
				t.Errorf("extractAlgorithm kept quote chars in %q", got)
			}
		})
	}
}
