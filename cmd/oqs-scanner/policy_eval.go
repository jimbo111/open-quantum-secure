// policy_eval.go evaluates policy and compliance rules against scan findings.

package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/jimbo111/open-quantum-secure/pkg/compliance"
	"github.com/jimbo111/open-quantum-secure/pkg/config"
	"github.com/jimbo111/open-quantum-secure/pkg/findings"
	"github.com/jimbo111/open-quantum-secure/pkg/output"
	"github.com/jimbo111/open-quantum-secure/pkg/policy"
)

// validateFailOn validates the --fail-on flag value.
func validateFailOn(failOn string) error {
	if failOn == "" {
		return nil
	}
	valid := map[string]bool{"critical": true, "high": true, "medium": true, "low": true}
	if !valid[failOn] {
		return fmt.Errorf("--fail-on must be one of: critical, high, medium, low")
	}
	return nil
}

// evaluatePolicy runs policy evaluation and returns errFailOn if violations are found.
func evaluatePolicy(cfg config.Config, failOn string, results []findings.UnifiedFinding, scanResult output.ScanResult) error {
	pol := policy.Policy{
		FailOn:               failOn,
		AllowedAlgorithms:    cfg.Policy.AllowedAlgorithms,
		BlockedAlgorithms:    cfg.Policy.BlockedAlgorithms,
		RequirePQC:           cfg.Policy.RequirePQC,
		MaxQuantumVulnerable: cfg.Policy.MaxQuantumVulnerable,
		MinQRS:               cfg.Policy.MinQRS,
	}
	// Reject MinQRS out of [0,100] and negative MaxQuantumVulnerable BEFORE
	// running Evaluate — otherwise a typo'd `policy.minQRS: 200` silently
	// fails every scan, and `policy.maxQuantumVulnerable: -1` makes clean
	// scans fail with `0 > -1`.
	if err := pol.Validate(); err != nil {
		return err
	}
	summary := policy.ScanSummary{
		QuantumVulnerable: scanResult.Summary.QuantumVulnerable,
		QuantumSafe:       scanResult.Summary.QuantumSafe,
		QuantumResistant:  scanResult.Summary.QuantumResistant,
	}
	policyResult := policy.Evaluate(pol, results, scanResult.QRS, summary)
	if !policyResult.Pass {
		for _, v := range policyResult.Violations {
			fmt.Fprintf(os.Stderr, "Policy violation [%s]: %s\n", v.Rule, v.Message)
		}
		return errFailOn
	}
	return nil
}

// evaluateCompliance runs compliance evaluation for each requested framework
// against scan findings. It prints a per-framework summary to stderr and returns
// errFailOn if any framework has violations. It is a no-op when standards is empty.
func evaluateCompliance(standards []string, results []findings.UnifiedFinding) error {
	if len(standards) == 0 {
		return nil
	}
	hasViolations := false
	for _, id := range standards {
		fw, ok := compliance.Get(id)
		if !ok {
			return fmt.Errorf("--compliance: unsupported standard %q (supported: %s)",
				id, strings.Join(compliance.SupportedIDs(), ", "))
		}
		violations := fw.Evaluate(results)
		if len(violations) == 0 {
			fmt.Fprintf(os.Stderr, "%s Compliance: PASS\n", fw.Name())
			continue
		}
		fmt.Fprintf(os.Stderr, "%s Compliance: FAIL (%d violation(s))\n", fw.Name(), len(violations))
		for _, v := range violations {
			fmt.Fprintf(os.Stderr, "  [%s] %s\n", v.Rule, v.Message)
		}
		hasViolations = true
	}
	if hasViolations {
		return errFailOn
	}
	return nil
}

// expandComplianceAll expands the "all" sentinel value to the full list of
// registered framework IDs. If ids contains "all" anywhere, it is replaced in
// place by compliance.SupportedIDs() (deduplicated with any other IDs the user
// may have listed alongside). Called BEFORE validateComplianceFlags so downstream
// evaluation sees concrete IDs. Fix for ultrareview bug_007 — without expansion,
// "all" passed validation but failed inside evaluateCompliance after a multi-
// minute scan.
func expandComplianceAll(ids []string) []string {
	expanded := make([]string, 0, len(ids))
	seen := make(map[string]bool, len(ids))
	for _, id := range ids {
		if id == "all" {
			for _, fid := range compliance.SupportedIDs() {
				if !seen[fid] {
					seen[fid] = true
					expanded = append(expanded, fid)
				}
			}
			continue
		}
		if !seen[id] {
			seen[id] = true
			expanded = append(expanded, id)
		}
	}
	return expanded
}

// validateComplianceFlags validates all --compliance framework IDs before the scan
// runs. All unknown IDs are reported together in a single error message so the user
// can fix them all at once rather than discovering them one by one. Call
// expandComplianceAll FIRST to resolve the "all" sentinel.
func validateComplianceFlags(ids []string) error {
	if len(ids) == 0 {
		return nil
	}
	var unknown []string
	for _, id := range ids {
		if _, ok := compliance.Get(id); !ok {
			unknown = append(unknown, id)
		}
	}
	if len(unknown) > 0 {
		return fmt.Errorf("--compliance: unknown framework ID(s): %s (supported: %s, or \"all\")",
			strings.Join(unknown, ", "), strings.Join(compliance.SupportedIDs(), ", "))
	}
	return nil
}

// validateCIMode validates the --ci-mode flag value.
func validateCIMode(mode string) error {
	switch mode {
	case "blocking", "advisory", "silent":
		return nil
	default:
		return fmt.Errorf("--ci-mode must be one of: blocking, advisory, silent")
	}
}

// evaluatePolicyAdvisory runs policy evaluation in advisory mode: violations are
// printed to stderr with an [ADVISORY] prefix but always return nil (exit 0).
func evaluatePolicyAdvisory(cfg config.Config, failOn string, results []findings.UnifiedFinding, scanResult output.ScanResult) {
	pol := policy.Policy{
		FailOn:               failOn,
		AllowedAlgorithms:    cfg.Policy.AllowedAlgorithms,
		BlockedAlgorithms:    cfg.Policy.BlockedAlgorithms,
		RequirePQC:           cfg.Policy.RequirePQC,
		MaxQuantumVulnerable: cfg.Policy.MaxQuantumVulnerable,
		MinQRS:               cfg.Policy.MinQRS,
	}
	// Advisory mode never exits non-zero — surface validation errors as
	// warnings instead of blocking the scan.
	if err := pol.Validate(); err != nil {
		fmt.Fprintf(os.Stderr, "WARNING: [ADVISORY] policy validation: %s\n", err)
	}
	summary := policy.ScanSummary{
		QuantumVulnerable: scanResult.Summary.QuantumVulnerable,
		QuantumSafe:       scanResult.Summary.QuantumSafe,
		QuantumResistant:  scanResult.Summary.QuantumResistant,
	}
	policyResult := policy.Evaluate(pol, results, scanResult.QRS, summary)
	if !policyResult.Pass {
		for _, v := range policyResult.Violations {
			fmt.Fprintf(os.Stderr, "[ADVISORY] Policy violation [%s]: %s\n", v.Rule, v.Message)
		}
	}
}

// evaluateComplianceAdvisory runs compliance evaluation in advisory mode: violations
// are printed to stderr with an [ADVISORY] prefix but always exit 0.
func evaluateComplianceAdvisory(standards []string, results []findings.UnifiedFinding) {
	for _, id := range standards {
		fw, ok := compliance.Get(id)
		if !ok {
			fmt.Fprintf(os.Stderr, "[ADVISORY] --compliance: unsupported standard %q (supported: %s)\n",
				id, strings.Join(compliance.SupportedIDs(), ", "))
			continue
		}
		violations := fw.Evaluate(results)
		if len(violations) == 0 {
			fmt.Fprintf(os.Stderr, "[ADVISORY] %s Compliance: PASS\n", fw.Name())
			continue
		}
		fmt.Fprintf(os.Stderr, "[ADVISORY] %s Compliance: FAIL (%d violation(s))\n", fw.Name(), len(violations))
		for _, v := range violations {
			fmt.Fprintf(os.Stderr, "[ADVISORY]   [%s] %s\n", v.Rule, v.Message)
		}
	}
}
