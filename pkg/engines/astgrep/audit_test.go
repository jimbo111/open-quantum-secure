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
// F-ASTGREP-2 — extractAlgorithm loses the algorithm when the ALGO metavariable
// contains ONLY quote characters (Trim reduces to empty) but the code returns
// the empty trimmed value instead of falling through to message/ruleId
// extraction.
// -----------------------------------------------------------------------------

func TestAudit_ExtractAlgorithm_EmptyAfterTrimBreaksFallback(t *testing.T) {
	m := rawMatch{
		RuleID:  "crypto-java-cipher",
		Message: "Java Cipher.getInstance: AES-256",
		MetaVars: rawMetaVars{
			// Pathological capture: parser grabbed only the quote chars.
			"ALGO": {Text: `""`},
		},
	}

	got := extractAlgorithm(m)
	// AUDIT BUG: Expected fallback to yield "AES-256" (from message) but the
	// function returns "" because Trim(`""`, `"'`) == "".
	if got == "" {
		t.Logf("AUDIT: extractAlgorithm returned \"\" for ALGO=%q — message/ruleId fallback skipped", m.MetaVars["ALGO"].Text)
	}

	// Normalize consumes the empty value and emits a finding with NO Algorithm.
	uf := normalize(m)
	if uf.Algorithm == nil {
		t.Logf("AUDIT: normalize produced finding with nil Algorithm; downstream dedup keyed on RawIdentifier only")
	}
}

// -----------------------------------------------------------------------------
// F-ASTGREP-3 — extractAlgorithm message fallback bails whenever the extracted
// candidate contains whitespace.  This drops legitimate multi-word algorithm
// captures (e.g. "AES 256 GCM").  Low severity; just a fallback gap.
// -----------------------------------------------------------------------------

func TestAudit_ExtractQuoted_WhitespaceRejected(t *testing.T) {
	candidates := []struct {
		msg    string
		expect string
	}{
		// Space inside the candidate — current behaviour drops it.
		{"Cipher.getInstance: AES 256 GCM", ""},
		// Tab inside candidate.
		{"Digest: SHA\t256", ""},
		// Single-token candidate survives.
		{"Digest: SHA256", "SHA256"},
	}
	for _, tc := range candidates {
		tc := tc
		t.Run(tc.msg, func(t *testing.T) {
			got := extractQuoted(tc.msg)
			if got != tc.expect {
				t.Errorf("extractQuoted(%q) = %q, want %q (current behaviour)", tc.msg, got, tc.expect)
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
	uf := normalize(m)
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
// F-ASTGREP-5 — inferAlgorithm for PQC / hybrid names is not covered.  The
// ruleId last-segment path uppercases the raw token, which is fine for
// MLKEM-768 but silently loses semantic information that the algorithm is
// quantum-safe.  Property check to document behaviour.
// -----------------------------------------------------------------------------

func TestAudit_ExtractAlgorithm_HybridPQCUppercaseOnly(t *testing.T) {
	cases := []struct {
		ruleID  string
		wantAlg string
	}{
		{"crypto-go-x25519-mlkem-768", "768"},           // only last segment
		{"crypto-go-kyber768", "KYBER768"},              // single token uppercases
		{"crypto-hybrid-x25519-mlkem768", "MLKEM768"},   // last segment preserved
		{"crypto-mlkem", "MLKEM"},                       // last segment preserved
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.ruleID, func(t *testing.T) {
			m := rawMatch{RuleID: tc.ruleID}
			got := extractAlgorithm(m)
			if got != tc.wantAlg {
				t.Errorf("extractAlgorithm(%q) = %q, want %q", tc.ruleID, got, tc.wantAlg)
			}
		})
	}
}

// -----------------------------------------------------------------------------
// F-ASTGREP-6 — extractAlgorithm returns the trimmed ALGO metavariable even
// when Trim reduces the input to the empty string because the early check
// `mv.Text != ""` does not re-check after Trim.  Distilled from F-ASTGREP-2 as
// a standalone property test.
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
			got := extractAlgorithm(m)
			// Current behaviour: empty string returned; finding loses algorithm.
			if strings.ContainsAny(got, `"'`) {
				t.Errorf("extractAlgorithm kept quote chars in %q", got)
			}
		})
	}
}
