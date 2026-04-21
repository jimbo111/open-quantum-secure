package semgrep

// AUDIT: adversarial fixtures authored for the 2026-04-20 Tier-1 scanner audit.
// See docs/audits/2026-04-20-scanner-layer-audit/01-t1-source.md for the report.

import (
	"testing"
)

// -----------------------------------------------------------------------------
// F-SEMGREP-1 — inferAlgorithmFromRuleID substring matching is too liberal.
// Any rule ID containing the substring "rsa" returns "RSA", including words
// like "persaepe" or "parse-errors" (the latter contains "rsae" ≠ "rsa" so
// it's fine, but words like "persaepe" DO contain "rsa" as a substring).
// -----------------------------------------------------------------------------

func TestAudit_InferAlgorithm_SubstringFalsePositives(t *testing.T) {
	// 2026-04-21: after token-boundary fix, substring "rsa" inside an
	// unrelated word (persaepe, parser) must NOT match.
	cases := []struct {
		ruleID string
		want   string
	}{
		{"persaepe-latin-word", ""},   // "rsa" inside "persaepe" — no match
		{"detect-parser-ssl-frag", ""}, // "parser" does not tokenise to "rsa"
		{"parse-errors", ""},
		{"hmac-ecdh", "ECDH"},          // priority order: ECDH checked before HMAC
		{"rsa-key-generation", "RSA"},  // legitimate token match
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.ruleID, func(t *testing.T) {
			got := inferAlgorithmFromRuleID(tc.ruleID)
			if got != tc.want {
				t.Errorf("inferAlgorithmFromRuleID(%q) = %q, want %q",
					tc.ruleID, got, tc.want)
			}
		})
	}
}

// -----------------------------------------------------------------------------
// F-SEMGREP-2 — primitiveFromRuleID is order-sensitive.  Rule IDs that mix
// multiple crypto keywords match only the first arm encountered.  Documents
// current behaviour so any reordering is noticed.
// -----------------------------------------------------------------------------

func TestAudit_PrimitiveFromRuleID_OrderSensitive(t *testing.T) {
	cases := []struct {
		ruleID string
		want   string
	}{
		// RSA appears first in switch, wins over TLS.
		{"tls-rsa-handshake", "asymmetric"},
		// HMAC branch comes before SHA — correct for semgrep.
		{"hmac-sha256", "mac"},
		// "ecdh" wins over "aes" — asymmetric (correct).
		{"ecdh-aes-wrap", "asymmetric"},
		// "aes" before "hmac" in same id — symmetric wins because switch short-circuits.
		{"aes-hmac-compose", "symmetric"},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.ruleID, func(t *testing.T) {
			got := primitiveFromRuleID(tc.ruleID)
			if got != tc.want {
				t.Errorf("primitiveFromRuleID(%q) = %q, want %q",
					tc.ruleID, got, tc.want)
			}
		})
	}
}

// -----------------------------------------------------------------------------
// F-SEMGREP-3 — inferAlgorithmFromRuleID + primitiveFromRuleID can produce
// logically inconsistent pairs.  Rule "hmac-sha256" maps algorithm to "HMAC"
// but primitive to "mac" (OK); however "sha256-hmac" maps algorithm to
// "SHA-256" AND primitive to "mac" — the algorithm should be HMAC-SHA256 or
// SHA-256 with primitive "hash".  Documents inconsistency.
// -----------------------------------------------------------------------------

func TestAudit_HMACvsSHA_InconsistentPair(t *testing.T) {
	// In semgrep, HMAC arm precedes SHA in inferAlgorithmFromRuleID, so
	// "sha256-hmac" returns algorithm=HMAC.  Primitive returns "mac".
	alg := inferAlgorithmFromRuleID("sha256-hmac")
	prim := primitiveFromRuleID("sha256-hmac")
	if alg != "HMAC" {
		t.Errorf("alg: got %q, want %q", alg, "HMAC")
	}
	if prim != "mac" {
		t.Errorf("prim: got %q, want %q", prim, "mac")
	}

	// However, a rule that leads with a HASH keyword but names an HMAC
	// primitive anywhere after — e.g. "sha-digest-for-hmac" — can diverge.
	// Document the ordering interaction.
	alg2 := inferAlgorithmFromRuleID("md5-mac-compose")
	prim2 := primitiveFromRuleID("md5-mac-compose")
	if alg2 != "MD5" {
		t.Errorf("alg2: got %q, want %q", alg2, "MD5")
	}
	if prim2 != "symmetric" && prim2 != "mac" && prim2 != "hash" {
		t.Errorf("prim2: got %q, want mac/symmetric/hash", prim2)
	}
}

// -----------------------------------------------------------------------------
// F-SEMGREP-4 — cleanURI only strips a literal "file://" prefix.  It does
// not decode percent-encoded characters, handle Windows drive letters in the
// form "file:///C:/..." (which leaves "/C:/..." with the leading slash — may
// confuse filepath logic on Windows), or reject non-file schemes.
// -----------------------------------------------------------------------------

func TestAudit_CleanURI_EdgeCases(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		// Percent-encoded space not decoded.
		{"file:///path/with%20space.go", "/path/with%20space.go"},
		// Windows-style path retains leading slash — caller must handle.
		{"file:///C:/src/x.go", "/C:/src/x.go"},
		// Non-file schemes pass through unchanged (not flagged).
		{"https://example.com/x.go", "https://example.com/x.go"},
		// jar: URI (semgrep occasionally emits these) passes through.
		{"jar:file:///tmp/a.jar!/b.class", "jar:file:///tmp/a.jar!/b.class"},
		// Empty.
		{"", ""},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.in, func(t *testing.T) {
			got := cleanURI(tc.in)
			if got != tc.want {
				t.Errorf("cleanURI(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

// -----------------------------------------------------------------------------
// F-SEMGREP-5 — parseSARIF panics-safety: handle SARIF where threadFlows are
// present but Locations is empty.  Exercise the defensive path in
// extractDataFlowPath.
// -----------------------------------------------------------------------------

func TestAudit_ParseSARIF_EmptyThreadFlowLocations(t *testing.T) {
	input := `{
        "runs": [{
            "tool": {"driver": {"rules": []}},
            "results": [{
                "ruleId": "java-rsa",
                "message": {"text": "x"},
                "level": "warning",
                "locations": [{"physicalLocation": {"artifactLocation": {"uri": "f.java"}, "region": {"startLine": 1, "startColumn": 1}}}],
                "codeFlows": [{"threadFlows": [{"locations": []}]}]
            }]
        }]
    }`
	results, err := parseSARIF([]byte(input))
	if err != nil {
		t.Fatalf("parseSARIF: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("want 1 result, got %d", len(results))
	}
	// codeFlows present with empty locations → DataFlowPath is non-nil empty slice.
	// Current code takes the "len(flowPath) > 0" branch as false, so we get
	// ConfidenceMedium, not High.  Verify.
	if len(results[0].DataFlowPath) != 0 {
		t.Errorf("DataFlowPath: got %d steps, want 0", len(results[0].DataFlowPath))
	}
	// Note: extractDataFlowPath returns an empty non-nil slice when threadFlow
	// is present but Locations is empty.  Callers that distinguish nil from
	// empty may misbehave.
}

// -----------------------------------------------------------------------------
// F-SEMGREP-6 — parseSARIF strips rule metadata silently when Properties is
// non-map (e.g. array or string).  Uses buildRuleMetaLookup's type assertion.
// -----------------------------------------------------------------------------

func TestAudit_BuildRuleMetaLookup_NonStringAlgProperty(t *testing.T) {
	rules := []sarifInputRule{
		{
			ID: "java-rsa-keysize",
			Properties: map[string]interface{}{
				"algorithm": 42, // numeric, not string
				"primitive": []string{"asymmetric"},
			},
		},
	}
	m := buildRuleMetaLookup(rules)
	meta := m["java-rsa-keysize"]
	// Non-string values are silently discarded.
	if meta.Algorithm != "" {
		t.Errorf("Algorithm: got %q, want empty", meta.Algorithm)
	}
	if meta.Primitive != "" {
		t.Errorf("Primitive: got %q, want empty", meta.Primitive)
	}
}

// -----------------------------------------------------------------------------
// F-SEMGREP-7 — DES word-boundary regex: "predestined-token" contains "des" as
// a substring but NOT as "des-" or "-des-" or "-des" or "3des" or "triple-des".
// Verify it is NOT classified as DES.  Property test.
// -----------------------------------------------------------------------------

func TestAudit_InferAlgorithm_DESWordBoundaryAdversarial(t *testing.T) {
	cases := []struct {
		ruleID string
		wantIsDES bool
	}{
		{"predestined-rule", false},   // "des" inside word
		{"destroyer-rule", false},     // "des" at start of word but not as whole token
		{"addresses-rule", false},     // "des" in middle
		{"des", true},                 // exact match
		{"des-cbc", true},             // prefix
		{"crypto-des-usage", true},    // middle
		{"use-des", true},             // suffix
		{"3des-mode", true},           // 3des
		{"triple-des-config", true},   // triple-des
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.ruleID, func(t *testing.T) {
			got := inferAlgorithmFromRuleID(tc.ruleID)
			isDES := got == "DES"
			if isDES != tc.wantIsDES {
				t.Errorf("inferAlgorithmFromRuleID(%q) = %q; isDES=%v, want isDES=%v",
					tc.ruleID, got, isDES, tc.wantIsDES)
			}
		})
	}
}
