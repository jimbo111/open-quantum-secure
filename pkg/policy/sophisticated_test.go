// Package policy — sophisticated tests covering fail-on, case-insensitivity,
// min QRS threshold, and glob-aware allow/block rules.
package policy

import (
	"testing"

	"github.com/jimbo111/open-quantum-secure/pkg/findings"
	"github.com/jimbo111/open-quantum-secure/pkg/quantum"
)

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func sophAlgFinding(name, sev string, qr findings.QuantumRisk) findings.UnifiedFinding {
	return findings.UnifiedFinding{
		Algorithm:   &findings.Algorithm{Name: name},
		Severity:    findings.Severity(sev),
		QuantumRisk: qr,
	}
}

func intp(n int) *int { return &n }

func sophQRS(score int) *quantum.QRS { return &quantum.QRS{Score: score, Grade: "F"} }

// ---------------------------------------------------------------------------
// 1. FailOn: critical threshold — high finding must NOT trigger
// ---------------------------------------------------------------------------

func TestPolicy_FailOn_CriticalOnly_HighDoesNotFail(t *testing.T) {
	p := Policy{FailOn: "critical"}
	ff := []findings.UnifiedFinding{
		sophAlgFinding("RSA", "high", findings.QRVulnerable),
	}
	result := Evaluate(p, ff, nil, ScanSummary{QuantumVulnerable: 1})
	if !result.Pass {
		t.Errorf("policy should PASS for 'high' finding when failOn=critical; violations: %+v", result.Violations)
	}
}

func TestPolicy_FailOn_CriticalOnly_CriticalFails(t *testing.T) {
	p := Policy{FailOn: "critical"}
	ff := []findings.UnifiedFinding{
		sophAlgFinding("RSA", "critical", findings.QRVulnerable),
	}
	result := Evaluate(p, ff, nil, ScanSummary{QuantumVulnerable: 1})
	if result.Pass {
		t.Error("policy should FAIL for 'critical' finding when failOn=critical")
	}
	if len(result.Violations) == 0 {
		t.Error("expected at least one violation")
	}
	if result.Violations[0].Rule != "fail-on" {
		t.Errorf("violation rule = %q; want fail-on", result.Violations[0].Rule)
	}
}

// ---------------------------------------------------------------------------
// 2. FailOn case-insensitivity (fix b7ddf11)
// ---------------------------------------------------------------------------

func TestPolicy_FailOn_CaseInsensitive(t *testing.T) {
	cases := []string{"Critical", "CRITICAL", "cRiTiCaL"}
	for _, failOn := range cases {
		p := Policy{FailOn: failOn}
		ff := []findings.UnifiedFinding{
			sophAlgFinding("RSA", "critical", findings.QRVulnerable),
		}
		result := Evaluate(p, ff, nil, ScanSummary{QuantumVulnerable: 1})
		if result.Pass {
			t.Errorf("failOn=%q should fail for critical finding; got pass", failOn)
		}
	}
}

// ---------------------------------------------------------------------------
// 3. FailOn: medium threshold — info and low pass, medium fails
// ---------------------------------------------------------------------------

func TestPolicy_FailOn_Medium_LowPasses(t *testing.T) {
	p := Policy{FailOn: "medium"}
	ff := []findings.UnifiedFinding{
		sophAlgFinding("AES-128", "low", findings.QRWeakened),
	}
	result := Evaluate(p, ff, nil, ScanSummary{})
	if !result.Pass {
		t.Errorf("low finding should not fail at failOn=medium; violations: %v", result.Violations)
	}
}

func TestPolicy_FailOn_Medium_MediumFails(t *testing.T) {
	p := Policy{FailOn: "medium"}
	ff := []findings.UnifiedFinding{
		sophAlgFinding("AES-128", "medium", findings.QRWeakened),
	}
	result := Evaluate(p, ff, nil, ScanSummary{})
	if result.Pass {
		t.Error("medium finding should fail at failOn=medium")
	}
}

// ---------------------------------------------------------------------------
// 4. MinQRS: score below threshold triggers violation
// ---------------------------------------------------------------------------

func TestPolicy_MinQRS_BelowThreshold_Fails(t *testing.T) {
	p := Policy{MinQRS: 70}
	result := Evaluate(p, nil, sophQRS(45), ScanSummary{})
	if result.Pass {
		t.Error("policy should FAIL when QRS 45 < minQRS 70")
	}
	found := false
	for _, v := range result.Violations {
		if v.Rule == "min-qrs" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected min-qrs violation; got: %+v", result.Violations)
	}
}

func TestPolicy_MinQRS_ExactThreshold_Passes(t *testing.T) {
	p := Policy{MinQRS: 70}
	result := Evaluate(p, nil, sophQRS(70), ScanSummary{})
	if !result.Pass {
		t.Errorf("policy should PASS when QRS equals minQRS; violations: %v", result.Violations)
	}
}

func TestPolicy_MinQRS_NilQRS_Fails(t *testing.T) {
	p := Policy{MinQRS: 50}
	result := Evaluate(p, nil, nil, ScanSummary{})
	if result.Pass {
		t.Error("policy should FAIL when QRS is nil and minQRS is set")
	}
}

// ---------------------------------------------------------------------------
// 5. Glob-aware blockedAlgorithms: "RSA*" blocks all RSA variants (fix a1cbd66)
// ---------------------------------------------------------------------------

func TestPolicy_BlockedAlgorithms_GlobMatchesVariants(t *testing.T) {
	p := Policy{BlockedAlgorithms: []string{"RSA*"}}
	variants := []string{"RSA", "RSA-2048", "RSA-4096", "RSA-OAEP", "RSA-PSS"}
	for _, variant := range variants {
		ff := []findings.UnifiedFinding{sophAlgFinding(variant, "high", findings.QRVulnerable)}
		result := Evaluate(p, ff, nil, ScanSummary{QuantumVulnerable: 1})
		if result.Pass {
			t.Errorf("RSA* glob should block %q but policy passed", variant)
		}
	}
}

// ---------------------------------------------------------------------------
// 6. Glob-aware allowedAlgorithms: non-matching algorithm gets violation
// ---------------------------------------------------------------------------

func TestPolicy_AllowedAlgorithms_NonMatchingTriggersViolation(t *testing.T) {
	p := Policy{AllowedAlgorithms: []string{"AES-256", "ML-KEM-1024"}}
	ff := []findings.UnifiedFinding{
		sophAlgFinding("RSA", "critical", findings.QRVulnerable),
	}
	result := Evaluate(p, ff, nil, ScanSummary{QuantumVulnerable: 1})
	if result.Pass {
		t.Error("RSA should fail the allowed-algorithms policy")
	}
	found := false
	for _, v := range result.Violations {
		if v.Rule == "allowed-algorithms" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected allowed-algorithms violation; got: %+v", result.Violations)
	}
}

// ---------------------------------------------------------------------------
// 7. AllowedAlgorithms: dependency findings are exempt (no Algorithm field)
// ---------------------------------------------------------------------------

func TestPolicy_AllowedAlgorithms_DependenciesExempt(t *testing.T) {
	p := Policy{AllowedAlgorithms: []string{"AES-256"}}
	dep := findings.UnifiedFinding{
		Dependency:  &findings.Dependency{Library: "openssl"},
		QuantumRisk: findings.QRVulnerable,
		Severity:    findings.SevHigh,
	}
	result := Evaluate(p, []findings.UnifiedFinding{dep}, nil, ScanSummary{QuantumVulnerable: 1})
	// The dependency finding has no Algorithm — allowed-algorithms rule must not fire.
	for _, v := range result.Violations {
		if v.Rule == "allowed-algorithms" {
			t.Errorf("allowed-algorithms rule should not apply to dependency findings (no Algorithm); violation: %+v", v)
		}
	}
}

// ---------------------------------------------------------------------------
// 8. RequirePQC: no safe/resistant findings triggers violation
// ---------------------------------------------------------------------------

func TestPolicy_RequirePQC_NoSafeFindings_Fails(t *testing.T) {
	p := Policy{RequirePQC: true}
	ff := []findings.UnifiedFinding{
		sophAlgFinding("RSA", "critical", findings.QRVulnerable),
	}
	result := Evaluate(p, ff, nil, ScanSummary{QuantumVulnerable: 1})
	if result.Pass {
		t.Error("requirePQC should fail when no PQC findings are present")
	}
	found := false
	for _, v := range result.Violations {
		if v.Rule == "require-pqc" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected require-pqc violation; got: %+v", result.Violations)
	}
}

func TestPolicy_RequirePQC_HasSafeFindings_Passes(t *testing.T) {
	p := Policy{RequirePQC: true}
	result := Evaluate(p, nil, nil, ScanSummary{QuantumSafe: 1})
	// Must pass when QuantumSafe > 0.
	foundRequirePQC := false
	for _, v := range result.Violations {
		if v.Rule == "require-pqc" {
			foundRequirePQC = true
		}
	}
	if foundRequirePQC {
		t.Error("requirePQC should not fire when QuantumSafe > 0")
	}
}

// ---------------------------------------------------------------------------
// 9. MaxQuantumVulnerable: nil disables, non-nil enforces cap
// ---------------------------------------------------------------------------

func TestPolicy_MaxQuantumVulnerable_NilDisables(t *testing.T) {
	p := Policy{MaxQuantumVulnerable: nil} // disabled
	result := Evaluate(p, nil, nil, ScanSummary{QuantumVulnerable: 9999})
	for _, v := range result.Violations {
		if v.Rule == "max-quantum-vulnerable" {
			t.Error("max-quantum-vulnerable should be disabled when field is nil")
		}
	}
}

func TestPolicy_MaxQuantumVulnerable_ZeroEnforcesHardCap(t *testing.T) {
	p := Policy{MaxQuantumVulnerable: intp(0)}
	result := Evaluate(p, nil, nil, ScanSummary{QuantumVulnerable: 1})
	if result.Pass {
		t.Error("max-quantum-vulnerable=0 should fail when there is 1 vulnerable finding")
	}
}

func TestPolicy_MaxQuantumVulnerable_AtCapPasses(t *testing.T) {
	p := Policy{MaxQuantumVulnerable: intp(5)}
	result := Evaluate(p, nil, nil, ScanSummary{QuantumVulnerable: 5})
	for _, v := range result.Violations {
		if v.Rule == "max-quantum-vulnerable" {
			t.Error("max-quantum-vulnerable=5 should pass when count=5 (boundary)")
		}
	}
}

// ---------------------------------------------------------------------------
// 10. Multiple simultaneous rules: multiple violations all reported
// ---------------------------------------------------------------------------

func TestPolicy_MultipleRulesFire_AllViolationsReported(t *testing.T) {
	p := Policy{
		FailOn:               "high",
		BlockedAlgorithms:    []string{"RSA*"},
		MaxQuantumVulnerable: intp(0),
	}
	ff := []findings.UnifiedFinding{
		sophAlgFinding("RSA-2048", "critical", findings.QRVulnerable),
	}
	result := Evaluate(p, ff, nil, ScanSummary{QuantumVulnerable: 1})

	rulesSeen := make(map[string]bool)
	for _, v := range result.Violations {
		rulesSeen[v.Rule] = true
	}

	expectedRules := []string{"fail-on", "blocked-algorithm", "max-quantum-vulnerable"}
	for _, r := range expectedRules {
		if !rulesSeen[r] {
			t.Errorf("expected violation for rule %q but it wasn't reported; violations: %+v", r, result.Violations)
		}
	}
}

// ---------------------------------------------------------------------------
// 11. Empty policy: zero value policy always passes
// ---------------------------------------------------------------------------

func TestPolicy_ZeroValue_AlwaysPasses(t *testing.T) {
	p := Policy{}
	ff := []findings.UnifiedFinding{
		sophAlgFinding("RSA", "critical", findings.QRVulnerable),
		sophAlgFinding("AES-128", "medium", findings.QRWeakened),
	}
	result := Evaluate(p, ff, nil, ScanSummary{QuantumVulnerable: 2})
	if !result.Pass {
		t.Errorf("zero-value policy should always pass; violations: %+v", result.Violations)
	}
}
