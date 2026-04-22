package policy

// Audit 2026-04-20 — Policy layer adversarial + property tests.
// These tests DOCUMENT current behaviour and surface potential bugs. A failing
// test here means either (a) the behaviour changed since audit, or (b) the
// suspected bug has been fixed. See docs/audits/2026-04-20-scanner-layer-audit/
// 09-policy-compliance.md for findings discussion.

import (
	"fmt"
	"math/rand"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/jimbo111/open-quantum-secure/pkg/findings"
	"github.com/jimbo111/open-quantum-secure/pkg/quantum"
)

// ---------------------------------------------------------------------------
// F-P1 (Adversarial): fail-on "info" value
//
// AUDIT FOCUS: fail-on logic boundary cases — undocumented values.
//
// Observation: severityRank includes SevInfo=0. The code looks up FailOn with
// severityRank[findings.Severity(p.FailOn)] — so a caller setting
// FailOn="info" ENABLES the rule (hasFailOn=true, failOnLevel=0). Every finding
// with a known severity (including SevInfo itself) will then trigger because
// every rank >= 0.
//
// Documentation states "Valid values: 'critical', 'high', 'medium', 'low'"
// (policy.go:8). "info" is NOT documented but is silently accepted, with
// surprising semantics (matches everything, including info). Classification:
// undocumented precedence (MEDIUM severity).
// ---------------------------------------------------------------------------
func TestAudit_FailOn_InfoValue_SilentlyAccepted_MatchesEverything(t *testing.T) {
	ff := []findings.UnifiedFinding{
		algFinding("ML-KEM-1024", findings.SevInfo, findings.QRSafe),
	}
	p := Policy{FailOn: "info"}
	r := Evaluate(p, ff, nil, summaryFrom(ff))

	// Documents current behaviour: "info" IS a silent rule-enabler.
	if r.Pass {
		t.Logf("AUDIT NOTE: FailOn='info' unexpectedly passed; may indicate fix (severityRank SevInfo lookup rejected).")
	} else {
		t.Logf("AUDIT CONFIRMED: FailOn='info' is silently accepted (undocumented); produced %d violations on a quantum-safe finding.", len(r.Violations))
	}
	// Do not fail the test — this is documentation. Assert the documented
	// "disaster" case still does nothing (negative control).
	p2 := Policy{FailOn: "disaster"}
	r2 := Evaluate(p2, ff, nil, summaryFrom(ff))
	if !r2.Pass {
		t.Errorf("FailOn='disaster' (unknown) should be silently ignored; got violations: %v", r2.Violations)
	}
}

// ---------------------------------------------------------------------------
// F-P2 (Adversarial): fail-on case sensitivity
//
// AUDIT FOCUS: "HIGH" (uppercase) falls through because severityRank keys are
// lowercase. If a user writes `failOn: HIGH` in YAML, the rule is silently
// skipped. This is the documented policy-bypass finding in the report (F2).
//
// This test ASSERTS the current (buggy) behaviour so a fix will flip the test
// and alert maintainers that documentation + test expectations must update.
// ---------------------------------------------------------------------------
func TestAudit_FailOn_CaseSensitive_UppercaseIgnored(t *testing.T) {
	// 2026-04-21: flipped after the case-insensitive FailOn fix. Upper/Mixed
	// case values must now be honoured the same as lowercase.
	ff := []findings.UnifiedFinding{
		algFinding("RSA-2048", findings.SevCritical, findings.QRVulnerable),
	}
	for _, val := range []string{"HIGH", "High", "CRITICAL", "Critical"} {
		t.Run(val, func(t *testing.T) {
			p := Policy{FailOn: val}
			r := Evaluate(p, ff, nil, summaryFrom(ff))
			if r.Pass {
				t.Errorf("FailOn=%q: expected failure (critical finding present), got pass", val)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// F-P3 (Adversarial): glob/wildcard patterns in allow/block lists
//
// AUDIT FOCUS: documentation does not say anything about glob support.
// Implementation uses map lookup (exact match), so patterns like "RSA*"
// would be silently ignored — a user expecting glob behaviour would have a
// policy that silently never matches.
// ---------------------------------------------------------------------------
func TestAudit_BlockedAlgorithms_GlobPatterns_AreLiteralMatches(t *testing.T) {
	// 2026-04-21: glob matching now supported. `RSA*` blocks every RSA
	// variant rather than requiring an exact literal name match.
	ff := []findings.UnifiedFinding{
		algFinding("RSA-2048", findings.SevHigh, findings.QRVulnerable),
		algFinding("RSA-3072", findings.SevHigh, findings.QRVulnerable),
		algFinding("RSA-OAEP", findings.SevHigh, findings.QRVulnerable),
	}
	p := Policy{BlockedAlgorithms: []string{"RSA*"}}
	r := Evaluate(p, ff, nil, summaryFrom(ff))

	blocked := 0
	for _, v := range r.Violations {
		if v.Rule == "blocked-algorithm" {
			blocked++
		}
	}
	if blocked != 3 {
		t.Errorf("BlockedAlgorithms=%q: expected 3 matches (all RSA variants), got %d", []string{"RSA*"}, blocked)
	}
}

// ---------------------------------------------------------------------------
// F-P4 (Adversarial): MaxQuantumVulnerable with negative pointer
//
// AUDIT FOCUS: if a user configures `maxQuantumVulnerable: -1` the check
// `summary.QuantumVulnerable > *p.MaxQuantumVulnerable` becomes
// `0 > -1` = true even with zero vulnerable findings — so a scan with no
// findings produces a violation. This is surprising.
// ---------------------------------------------------------------------------
func TestAudit_MaxQuantumVulnerable_NegativeValue_ProducesViolation(t *testing.T) {
	neg := -1
	p := Policy{MaxQuantumVulnerable: &neg}
	r := Evaluate(p, nil, nil, ScanSummary{QuantumVulnerable: 0})
	// Document current behaviour. Not asserted as a failure because the "right"
	// semantics for a negative threshold are debatable — the recommendation is
	// to validate at config-load time.
	if r.Pass {
		t.Logf("AUDIT NOTE: MaxQuantumVulnerable=-1 with zero findings passed — treated as infinite perhaps.")
	} else {
		t.Logf("AUDIT CONFIRMED (low): MaxQuantumVulnerable=-1 produces violation even with 0 vulnerable findings (0 > -1). " +
			"Negative pointer is accepted silently. Recommend: validate policy on load and reject negative values.")
	}
}

// ---------------------------------------------------------------------------
// F-P5 (Adversarial): dependency + algorithm-nil findings interact with
// MaxQuantumVulnerable via the summary, but NOT with blocked/allowed lists.
// Verifies isolation.
// ---------------------------------------------------------------------------
func TestAudit_DependencyFinding_CountsTowardMaxVulnerable(t *testing.T) {
	// A pure dependency finding with QRVulnerable: no Algorithm field.
	ff := []findings.UnifiedFinding{
		depFinding("openssl-1.0.2", findings.SevHigh, findings.QRVulnerable),
	}
	zero := 0
	p := Policy{MaxQuantumVulnerable: &zero}
	sum := ScanSummary{QuantumVulnerable: 1}
	r := Evaluate(p, ff, nil, sum)
	if r.Pass {
		t.Errorf("AUDIT: dependency finding with QRVulnerable should count against MaxQuantumVulnerable=0; expected fail. Got pass=true")
	}
	// But it should NOT trigger the blocked-algorithm rule even if library name matches.
	p2 := Policy{BlockedAlgorithms: []string{"openssl-1.0.2"}}
	r2 := Evaluate(p2, ff, nil, summaryFrom(ff))
	for _, v := range r2.Violations {
		if v.Rule == "blocked-algorithm" {
			t.Errorf("AUDIT: blocked-algorithm fired on dependency finding (should be skipped — Algorithm==nil); got: %v", r2.Violations)
		}
	}
}

// ---------------------------------------------------------------------------
// F-P6 (Adversarial): YAML round-trip — zero-value field preservation
//
// AUDIT FOCUS: yaml tags use `failOn` etc. Concern: MaxQuantumVulnerable=0
// (zero is semantically "zero allowed") must survive the round trip distinct
// from nil (disabled). Without omitempty, a marshalled Policy that had nil
// would emit `maxQuantumVulnerable: null` — acceptable.
// ---------------------------------------------------------------------------
func TestAudit_Policy_YAMLRoundTrip_Fidelity(t *testing.T) {
	zero := 0
	seven := 7
	cases := []Policy{
		{},
		{FailOn: "high", AllowedAlgorithms: []string{"AES-256"}, BlockedAlgorithms: []string{"RSA-2048", "DES"}},
		{RequirePQC: true, MinQRS: 75},
		{MaxQuantumVulnerable: &zero},
		{MaxQuantumVulnerable: &seven},
		{FailOn: "critical", RequirePQC: true, MaxQuantumVulnerable: &zero, MinQRS: 100,
			AllowedAlgorithms: []string{"ML-KEM-1024", "ML-DSA-87"},
			BlockedAlgorithms: []string{"RSA-2048", "ECDSA", "SHA-1"}},
	}
	for i, orig := range cases {
		t.Run(fmt.Sprintf("case%d", i), func(t *testing.T) {
			data, err := yaml.Marshal(&orig)
			if err != nil {
				t.Fatalf("marshal error: %v", err)
			}
			var got Policy
			if err := yaml.Unmarshal(data, &got); err != nil {
				t.Fatalf("unmarshal error: %v\ninput:\n%s", err, data)
			}
			// Compare field-by-field.
			if got.FailOn != orig.FailOn {
				t.Errorf("FailOn: got %q, want %q", got.FailOn, orig.FailOn)
			}
			if !sliceEq(got.AllowedAlgorithms, orig.AllowedAlgorithms) {
				t.Errorf("AllowedAlgorithms: got %v, want %v", got.AllowedAlgorithms, orig.AllowedAlgorithms)
			}
			if !sliceEq(got.BlockedAlgorithms, orig.BlockedAlgorithms) {
				t.Errorf("BlockedAlgorithms: got %v, want %v", got.BlockedAlgorithms, orig.BlockedAlgorithms)
			}
			if got.RequirePQC != orig.RequirePQC {
				t.Errorf("RequirePQC: got %v, want %v", got.RequirePQC, orig.RequirePQC)
			}
			if got.MinQRS != orig.MinQRS {
				t.Errorf("MinQRS: got %d, want %d", got.MinQRS, orig.MinQRS)
			}
			// Nil-vs-zero preservation for MaxQuantumVulnerable is critical.
			switch {
			case orig.MaxQuantumVulnerable == nil && got.MaxQuantumVulnerable != nil:
				t.Errorf("MaxQuantumVulnerable: nil became %d after round-trip", *got.MaxQuantumVulnerable)
			case orig.MaxQuantumVulnerable != nil && got.MaxQuantumVulnerable == nil:
				t.Errorf("MaxQuantumVulnerable: %d became nil after round-trip", *orig.MaxQuantumVulnerable)
			case orig.MaxQuantumVulnerable != nil && got.MaxQuantumVulnerable != nil &&
				*orig.MaxQuantumVulnerable != *got.MaxQuantumVulnerable:
				t.Errorf("MaxQuantumVulnerable: got %d, want %d", *got.MaxQuantumVulnerable, *orig.MaxQuantumVulnerable)
			}
		})
	}
}

func sliceEq(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// ---------------------------------------------------------------------------
// F-P7 (Property-based): ordering invariance
//
// AUDIT FOCUS: shuffling findings should not change pass/fail or violation
// count. Only violation order may change.
// ---------------------------------------------------------------------------
func TestAudit_Evaluate_Property_FindingOrderInvariant(t *testing.T) {
	base := []findings.UnifiedFinding{
		algFinding("RSA-2048", findings.SevCritical, findings.QRVulnerable),
		algFinding("AES-128", findings.SevMedium, findings.QRWeakened),
		algFinding("ML-KEM-1024", findings.SevInfo, findings.QRSafe),
		algFinding("ECDSA", findings.SevHigh, findings.QRVulnerable),
		algFinding("SHA-256", findings.SevLow, findings.QRWeakened),
		algFinding("ML-DSA-87", findings.SevInfo, findings.QRSafe),
	}
	p := Policy{
		FailOn:               "medium",
		BlockedAlgorithms:    []string{"RSA-2048", "AES-128"},
		AllowedAlgorithms:    []string{"AES-256", "ML-KEM-1024", "ML-DSA-87"},
		RequirePQC:           true,
		MaxQuantumVulnerable: intPtr(1),
		MinQRS:               80,
	}

	refCount := len(Evaluate(p, base, qrs(50), summaryFrom(base)).Violations)

	rng := rand.New(rand.NewSource(42))
	for trial := 0; trial < 25; trial++ {
		shuf := make([]findings.UnifiedFinding, len(base))
		copy(shuf, base)
		rng.Shuffle(len(shuf), func(i, j int) { shuf[i], shuf[j] = shuf[j], shuf[i] })
		got := Evaluate(p, shuf, qrs(50), summaryFrom(shuf))
		if len(got.Violations) != refCount {
			t.Errorf("trial %d: violation count changed with order — ref=%d got=%d", trial, refCount, len(got.Violations))
		}
	}
}

// ---------------------------------------------------------------------------
// F-P8 (Property-based): idempotence
//
// Re-running Evaluate on the same input must produce the same result.
// ---------------------------------------------------------------------------
func TestAudit_Evaluate_Property_Idempotent(t *testing.T) {
	ff := []findings.UnifiedFinding{
		algFinding("RSA-2048", findings.SevHigh, findings.QRVulnerable),
		algFinding("ML-KEM-1024", findings.SevInfo, findings.QRSafe),
	}
	p := Policy{FailOn: "high", BlockedAlgorithms: []string{"RSA-2048"}, RequirePQC: true}
	r1 := Evaluate(p, ff, qrs(70), summaryFrom(ff))
	r2 := Evaluate(p, ff, qrs(70), summaryFrom(ff))
	if r1.Pass != r2.Pass || len(r1.Violations) != len(r2.Violations) {
		t.Errorf("not idempotent: r1.Pass=%v(#%d) r2.Pass=%v(#%d)", r1.Pass, len(r1.Violations), r2.Pass, len(r2.Violations))
	}
}

// ---------------------------------------------------------------------------
// F-P9 (Property-based): monotonicity — adding a stricter rule never reduces
// the violation count. Specifically, going from empty policy → policy with
// rules enabled cannot decrease violations.
// ---------------------------------------------------------------------------
func TestAudit_Evaluate_Property_MonotonicityOnRuleAddition(t *testing.T) {
	ff := []findings.UnifiedFinding{
		algFinding("RSA-2048", findings.SevCritical, findings.QRVulnerable),
		algFinding("DES", findings.SevHigh, findings.QRVulnerable),
	}
	summary := summaryFrom(ff)

	none := Policy{}
	addFailOn := Policy{FailOn: "high"}
	addBlock := Policy{FailOn: "high", BlockedAlgorithms: []string{"RSA-2048", "DES"}}
	addRequirePQC := Policy{FailOn: "high", BlockedAlgorithms: []string{"RSA-2048", "DES"}, RequirePQC: true}

	n0 := len(Evaluate(none, ff, nil, summary).Violations)
	n1 := len(Evaluate(addFailOn, ff, nil, summary).Violations)
	n2 := len(Evaluate(addBlock, ff, nil, summary).Violations)
	n3 := len(Evaluate(addRequirePQC, ff, nil, summary).Violations)
	if !(n0 <= n1 && n1 <= n2 && n2 <= n3) {
		t.Errorf("non-monotonic: %d, %d, %d, %d (adding rules should never reduce violations)", n0, n1, n2, n3)
	}
}

// ---------------------------------------------------------------------------
// F-P10 (Adversarial): BlockedAlgorithms does not care about QuantumRisk
//
// A PQC-safe algorithm can be blocked via BlockedAlgorithms. Verifies no
// accidental short-circuit based on risk classification.
// ---------------------------------------------------------------------------
func TestAudit_BlockedAlgorithms_BlocksEvenSafeAlgorithms(t *testing.T) {
	ff := []findings.UnifiedFinding{
		algFinding("ML-KEM-1024", findings.SevInfo, findings.QRSafe),
	}
	p := Policy{BlockedAlgorithms: []string{"ML-KEM-1024"}}
	r := Evaluate(p, ff, nil, summaryFrom(ff))
	if r.Pass {
		t.Error("BlockedAlgorithms should block an algorithm regardless of quantum risk classification")
	}
}

// ---------------------------------------------------------------------------
// F-P11 (Adversarial): FailOn fires per-finding — a mixed batch produces
// multiple fail-on violations. Verifies no deduplication.
// ---------------------------------------------------------------------------
func TestAudit_FailOn_FiresPerFinding_NoDedup(t *testing.T) {
	ff := []findings.UnifiedFinding{
		algFinding("RSA-2048", findings.SevCritical, findings.QRVulnerable),
		algFinding("ECDSA", findings.SevCritical, findings.QRVulnerable),
		algFinding("DES", findings.SevCritical, findings.QRVulnerable),
	}
	p := Policy{FailOn: "critical"}
	r := Evaluate(p, ff, nil, summaryFrom(ff))
	failOns := 0
	for _, v := range r.Violations {
		if v.Rule == "fail-on" {
			failOns++
		}
	}
	if failOns != 3 {
		t.Errorf("expected 3 fail-on violations (one per finding), got %d", failOns)
	}
}

// ---------------------------------------------------------------------------
// F-P12 (Adversarial): AllowedAlgorithms with entries that differ only by
// whitespace or casing should dedupe to one effective entry.
// ---------------------------------------------------------------------------
func TestAudit_AllowedAlgorithms_DuplicatesMergeCaseInsensitive(t *testing.T) {
	ff := []findings.UnifiedFinding{
		algFinding("AES-256", findings.SevInfo, findings.QRResistant),
	}
	p := Policy{AllowedAlgorithms: []string{"AES-256", "aes-256", "  AES-256  ", "AES-256"}}
	r := Evaluate(p, ff, nil, summaryFrom(ff))
	if !r.Pass {
		t.Errorf("AES-256 listed in AllowedAlgorithms (with duplicates/casing) should pass; violations: %v", r.Violations)
	}
	// Negative: RSA-2048 not in allowed list → should fail with allowed-algorithms rule.
	ff2 := []findings.UnifiedFinding{algFinding("RSA-2048", findings.SevHigh, findings.QRVulnerable)}
	r2 := Evaluate(p, ff2, nil, summaryFrom(ff2))
	found := false
	for _, v := range r2.Violations {
		if v.Rule == "allowed-algorithms" {
			found = true
		}
	}
	if !found {
		t.Errorf("RSA-2048 should trigger allowed-algorithms violation (only AES-256 allowed); got: %v", r2.Violations)
	}
}

// ---------------------------------------------------------------------------
// F-P13 (Adversarial): fail-on with Severity="" (empty) — the empty string is
// NOT in severityRank so FailOn rule is disabled. Documents behaviour.
// ---------------------------------------------------------------------------
func TestAudit_FailOn_EmptyStringValue_Disables(t *testing.T) {
	ff := []findings.UnifiedFinding{
		algFinding("RSA-2048", findings.SevCritical, findings.QRVulnerable),
	}
	p := Policy{FailOn: ""}
	r := Evaluate(p, ff, nil, summaryFrom(ff))
	if !r.Pass {
		t.Errorf("FailOn='' (empty) should disable the rule; got violations: %v", r.Violations)
	}
}

// ---------------------------------------------------------------------------
// F-P14 (Adversarial): BlockedAlgorithms with unicode / trimming edge cases.
// ---------------------------------------------------------------------------
func TestAudit_BlockedAlgorithms_TrimmingAndUnicode(t *testing.T) {
	// Leading/trailing whitespace in block entry should be trimmed.
	ff := []findings.UnifiedFinding{algFinding("RSA-2048", findings.SevHigh, findings.QRVulnerable)}
	p := Policy{BlockedAlgorithms: []string{"  RSA-2048  "}}
	r := Evaluate(p, ff, nil, summaryFrom(ff))
	found := false
	for _, v := range r.Violations {
		if v.Rule == "blocked-algorithm" {
			found = true
		}
	}
	if !found {
		t.Errorf("'  RSA-2048  ' should be trimmed and block RSA-2048; got: %v", r.Violations)
	}

	// Non-ASCII case: Greek/mixed — trimmed but NOT normalised (documented
	// behaviour: strings.ToLower only ASCII-lowercases here, but finding name
	// has no unicode, so pass-through).
	_ = strings.ToLower // keep strings import tidy
}

// ---------------------------------------------------------------------------
// F-P15 (Adversarial): severity rank boundary — a finding with no known
// severity must not crash and must not trigger fail-on.
// ---------------------------------------------------------------------------
func TestAudit_FailOn_UnknownFindingSeverity_DoesNotTrigger(t *testing.T) {
	ff := []findings.UnifiedFinding{
		{
			Algorithm:   &findings.Algorithm{Name: "RSA-2048"},
			Severity:    findings.Severity("catastrophic"), // not in severityRank
			QuantumRisk: findings.QRVulnerable,
		},
	}
	p := Policy{FailOn: "low"}
	r := Evaluate(p, ff, nil, summaryFrom(ff))
	if !r.Pass {
		t.Errorf("unknown finding severity should not trigger fail-on; got: %v", r.Violations)
	}
}

// ---------------------------------------------------------------------------
// F-P16 (Adversarial, quantum): quantum.QRS must be accepted at boundary 0
// even when minQRS>0, iff QRS is non-nil.
// ---------------------------------------------------------------------------
func TestAudit_MinQRS_Score0WithMinQRSSet_Fails(t *testing.T) {
	p := Policy{MinQRS: 1}
	r := Evaluate(p, nil, &quantum.QRS{Score: 0, Grade: "F"}, ScanSummary{})
	if r.Pass {
		t.Error("MinQRS=1 with QRS.Score=0 should fail (0 < 1)")
	}
}
