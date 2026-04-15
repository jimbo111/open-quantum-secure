package policy

import (
	"testing"

	"github.com/jimbo111/open-quantum-secure/pkg/findings"
)

// ---------------------------------------------------------------------------
// AllowedAlgorithms overriding BlockedAlgorithms interaction
// ---------------------------------------------------------------------------

// TestEvaluate_AllowedOverridesBlocked verifies that when the same algorithm is
// in both AllowedAlgorithms and BlockedAlgorithms, both rules fire independently.
// The policy engine doesn't short-circuit: a blocked finding also fails the
// allowed-algorithms check, producing two violations.
func TestEvaluate_AllowedAndBlockedBothSet_BothFire(t *testing.T) {
	ff := []findings.UnifiedFinding{
		algFinding("RSA-2048", findings.SevHigh, findings.QRVulnerable),
	}
	p := Policy{
		AllowedAlgorithms: []string{"AES-256"},      // RSA-2048 not allowed
		BlockedAlgorithms: []string{"RSA-2048"},      // RSA-2048 explicitly blocked
	}
	result := Evaluate(p, ff, nil, summaryFrom(ff))
	if result.Pass {
		t.Error("should fail: RSA-2048 is both blocked and not in allowed list")
	}
	rulesSeen := make(map[string]bool)
	for _, v := range result.Violations {
		rulesSeen[v.Rule] = true
	}
	if !rulesSeen["blocked-algorithm"] {
		t.Error("expected blocked-algorithm violation")
	}
	if !rulesSeen["allowed-algorithms"] {
		t.Error("expected allowed-algorithms violation")
	}
}

// TestEvaluate_AllowedAlgorithms_EmptyListIsNoOp verifies that an empty
// AllowedAlgorithms list (nil) does not trigger violations for any algorithm.
func TestEvaluate_AllowedAlgorithms_EmptyListIsNoOp(t *testing.T) {
	ff := []findings.UnifiedFinding{
		algFinding("RSA-2048", findings.SevHigh, findings.QRVulnerable),
		algFinding("DES", findings.SevHigh, findings.QRDeprecated),
	}
	p := Policy{AllowedAlgorithms: nil}
	result := Evaluate(p, ff, nil, summaryFrom(ff))
	if !result.Pass {
		t.Errorf("empty AllowedAlgorithms should be no-op; violations: %v", result.Violations)
	}
}

// TestEvaluate_BlockedAlgorithms_EmptyListIsNoOp verifies that an empty
// BlockedAlgorithms list (nil) does not trigger violations.
func TestEvaluate_BlockedAlgorithms_EmptyListIsNoOp(t *testing.T) {
	ff := []findings.UnifiedFinding{
		algFinding("RSA-2048", findings.SevHigh, findings.QRVulnerable),
	}
	p := Policy{BlockedAlgorithms: nil}
	result := Evaluate(p, ff, nil, summaryFrom(ff))
	if !result.Pass {
		t.Errorf("empty BlockedAlgorithms should be no-op; violations: %v", result.Violations)
	}
}

// ---------------------------------------------------------------------------
// FailOn severity boundary exhaustion
// ---------------------------------------------------------------------------

// TestEvaluate_FailOn_InfoDoesNotTriggerAnyThreshold verifies that an info-
// severity finding does not trip any threshold including "info" (which is not
// a valid FailOn value — only critical/high/medium/low are documented).
func TestEvaluate_FailOn_InfoFindingBelowLowThreshold(t *testing.T) {
	ff := []findings.UnifiedFinding{
		algFinding("AES-128", findings.SevInfo, findings.QRWeakened),
	}
	p := Policy{FailOn: "low"}
	result := Evaluate(p, ff, nil, summaryFrom(ff))
	if !result.Pass {
		t.Errorf("info severity should not trigger 'low' threshold; violations: %v", result.Violations)
	}
}

// TestEvaluate_FailOn_HighFindingTriggersMediumThreshold verifies that high
// severity findings trigger medium-and-above threshold.
func TestEvaluate_FailOn_HighFindingTriggersMediumThreshold(t *testing.T) {
	ff := []findings.UnifiedFinding{
		algFinding("RSA-2048", findings.SevHigh, findings.QRVulnerable),
	}
	p := Policy{FailOn: "medium"}
	result := Evaluate(p, ff, nil, summaryFrom(ff))
	if result.Pass {
		t.Error("high finding should trigger medium threshold (high >= medium)")
	}
}

// TestEvaluate_FailOn_CriticalTriggersMediumThreshold tests upward triggering.
func TestEvaluate_FailOn_CriticalTriggersMediumThreshold(t *testing.T) {
	ff := []findings.UnifiedFinding{
		algFinding("RSA-2048", findings.SevCritical, findings.QRVulnerable),
	}
	p := Policy{FailOn: "medium"}
	result := Evaluate(p, ff, nil, summaryFrom(ff))
	if result.Pass {
		t.Error("critical finding should trigger medium threshold")
	}
	if len(result.Violations) != 1 || result.Violations[0].Rule != "fail-on" {
		t.Errorf("unexpected violations: %v", result.Violations)
	}
}

// TestEvaluate_FailOn_FindingWithNoSeveritySkipped verifies that a finding
// with empty Severity does not trigger the fail-on rule (no rank in the map).
func TestEvaluate_FailOn_FindingWithNoSeveritySkipped(t *testing.T) {
	ff := []findings.UnifiedFinding{
		{
			Algorithm:   &findings.Algorithm{Name: "RSA-2048"},
			QuantumRisk: findings.QRVulnerable,
			// Severity intentionally empty
		},
	}
	p := Policy{FailOn: "low"}
	result := Evaluate(p, ff, nil, summaryFrom(ff))
	if !result.Pass {
		t.Errorf("finding with no severity should not trigger fail-on; violations: %v", result.Violations)
	}
}

// ---------------------------------------------------------------------------
// MinQRS edge cases
// ---------------------------------------------------------------------------

// TestEvaluate_MinQRS100_Score100_Passes verifies the exact boundary case.
func TestEvaluate_MinQRS100_Score100_Passes(t *testing.T) {
	p := Policy{MinQRS: 100}
	result := Evaluate(p, nil, qrs(100), ScanSummary{})
	if !result.Pass {
		t.Errorf("minQRS=100 with score=100 should pass; violations: %v", result.Violations)
	}
}

// TestEvaluate_MinQRS100_Score99_Fails verifies off-by-one boundary.
func TestEvaluate_MinQRS100_Score99_Fails(t *testing.T) {
	p := Policy{MinQRS: 100}
	result := Evaluate(p, nil, qrs(99), ScanSummary{})
	if result.Pass {
		t.Error("minQRS=100 with score=99 should fail")
	}
	if len(result.Violations) == 0 || result.Violations[0].Rule != "min-qrs" {
		t.Errorf("expected min-qrs violation; got: %v", result.Violations)
	}
}

// TestEvaluate_MinQRS_ZeroDisabled verifies that MinQRS=0 never triggers a
// violation regardless of QRS score (including nil).
func TestEvaluate_MinQRS_ZeroIsDisabled(t *testing.T) {
	p := Policy{MinQRS: 0}
	// nil QRS with MinQRS=0 must not produce a violation
	result := Evaluate(p, nil, nil, ScanSummary{})
	if !result.Pass {
		t.Errorf("MinQRS=0 (disabled) with nil QRS should pass; violations: %v", result.Violations)
	}
}

// ---------------------------------------------------------------------------
// RequirePQC edge cases
// ---------------------------------------------------------------------------

// TestEvaluate_RequirePQC_OnlySafeFindings_Passes verifies that a codebase
// with all-safe findings satisfies the RequirePQC requirement.
func TestEvaluate_RequirePQC_OnlySafeFindings_Passes(t *testing.T) {
	ff := []findings.UnifiedFinding{
		algFinding("ML-KEM-768", findings.SevInfo, findings.QRSafe),
		algFinding("ML-DSA-65", findings.SevInfo, findings.QRSafe),
	}
	p := Policy{RequirePQC: true}
	result := Evaluate(p, ff, nil, summaryFrom(ff))
	if !result.Pass {
		t.Errorf("all-safe findings should satisfy RequirePQC; violations: %v", result.Violations)
	}
}

// TestEvaluate_RequirePQC_DepFindingWithSafeSummary verifies that when the
// summary already counts safe entries (from algo findings), RequirePQC passes
// even if this particular finding is a dependency (not algo).
func TestEvaluate_RequirePQC_SummaryWithSafeCount_Passes(t *testing.T) {
	ff := []findings.UnifiedFinding{
		{Dependency: &findings.Dependency{Library: "openssl"}, QuantumRisk: findings.QRVulnerable},
	}
	p := Policy{RequirePQC: true}
	// Manually provide summary indicating 1 safe (e.g. from another algo finding)
	summary := ScanSummary{QuantumSafe: 1}
	result := Evaluate(p, ff, nil, summary)
	if !result.Pass {
		t.Errorf("RequirePQC should pass when summary.QuantumSafe > 0; violations: %v", result.Violations)
	}
}

// ---------------------------------------------------------------------------
// MaxQuantumVulnerable edge cases
// ---------------------------------------------------------------------------

// TestEvaluate_MaxQuantumVulnerable_ExactlyAtLimit_Passes tests the boundary
// where count equals max (should pass — limit is inclusive).
func TestEvaluate_MaxQuantumVulnerable_AtLimit_Passes(t *testing.T) {
	ff := make([]findings.UnifiedFinding, 3)
	for i := range ff {
		ff[i] = algFinding("RSA-2048", findings.SevHigh, findings.QRVulnerable)
	}
	p := Policy{MaxQuantumVulnerable: intPtr(3)}
	result := Evaluate(p, ff, nil, summaryFrom(ff))
	if !result.Pass {
		t.Errorf("count==max should pass (limit is inclusive); violations: %v", result.Violations)
	}
}

// TestEvaluate_MaxQuantumVulnerable_OneOverLimit_Fails tests the boundary
// where count exceeds max by exactly one.
func TestEvaluate_MaxQuantumVulnerable_OneOver_Fails(t *testing.T) {
	ff := make([]findings.UnifiedFinding, 4)
	for i := range ff {
		ff[i] = algFinding("RSA-2048", findings.SevHigh, findings.QRVulnerable)
	}
	p := Policy{MaxQuantumVulnerable: intPtr(3)}
	result := Evaluate(p, ff, nil, summaryFrom(ff))
	if result.Pass {
		t.Error("count > max should fail")
	}
}

// TestEvaluate_WhitespaceOnlyAllowedEntry verifies that " " (space) entries in
// AllowedAlgorithms are silently dropped and don't create false matches.
func TestEvaluate_AllowedAlgorithms_WhitespaceEntryDropped(t *testing.T) {
	ff := []findings.UnifiedFinding{
		algFinding("RSA-2048", findings.SevHigh, findings.QRVulnerable),
	}
	// AllowedAlgorithms with only whitespace should be treated as nil (no-op)
	p := Policy{AllowedAlgorithms: []string{"  ", "\t"}}
	result := Evaluate(p, ff, nil, summaryFrom(ff))
	// All whitespace entries → nil set → no allowed-algorithms rule fires
	for _, v := range result.Violations {
		if v.Rule == "allowed-algorithms" {
			t.Errorf("whitespace-only AllowedAlgorithms should not trigger allowed-algorithms rule; violations: %v", result.Violations)
		}
	}
}

// TestEvaluate_MultipleRulesAccumulate verifies that when multiple rules
// independently fire on the same finding, all violations are collected (not
// short-circuited after the first).
func TestEvaluate_MultipleViolationsPerFinding_AllCollected(t *testing.T) {
	ff := []findings.UnifiedFinding{
		algFinding("DES", findings.SevCritical, findings.QRVulnerable),
	}
	p := Policy{
		FailOn:            "high",     // triggers: critical >= high
		BlockedAlgorithms: []string{"DES"}, // triggers: DES blocked
		AllowedAlgorithms: []string{"AES-256"}, // triggers: DES not allowed
	}
	result := Evaluate(p, ff, nil, summaryFrom(ff))
	if result.Pass {
		t.Error("expected failure with three rules firing")
	}
	// Must have at least 3 violations: fail-on, blocked-algorithm, allowed-algorithms
	if len(result.Violations) < 3 {
		t.Errorf("expected at least 3 violations, got %d: %v", len(result.Violations), result.Violations)
	}
}
