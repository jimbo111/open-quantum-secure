package policy

import (
	"fmt"
	"path"
	"strings"

	"github.com/jimbo111/open-quantum-secure/pkg/findings"
	"github.com/jimbo111/open-quantum-secure/pkg/quantum"
)

// PolicyResult holds the outcome of a policy evaluation.
type PolicyResult struct {
	Pass       bool
	Violations []Violation
}

// Violation describes a single policy rule breach.
type Violation struct {
	// Rule is the machine-readable rule identifier.
	Rule string // e.g. "blocked-algorithm", "min-qrs", "max-vulnerable"

	// Severity is the violation severity classification.
	Severity string // "critical", "high", "medium", "low"

	// Message is the human-readable description of the violation.
	Message string

	// Finding is the individual finding that caused the violation, or nil for
	// aggregate violations (e.g. minQRS, requirePQC, maxQuantumVulnerable).
	Finding *findings.UnifiedFinding
}

// ScanSummary holds the aggregate counts needed for policy evaluation.
// This allows the policy package to stay decoupled from the output package.
type ScanSummary struct {
	QuantumVulnerable int
	QuantumSafe       int
	QuantumResistant  int
}

// severityRank maps severity strings to numeric levels for comparison.
// Higher value = more severe.
var severityRank = map[findings.Severity]int{
	findings.SevInfo:     0,
	findings.SevLow:      1,
	findings.SevMedium:   2,
	findings.SevHigh:     3,
	findings.SevCritical: 4,
}

// Evaluate checks all findings against the policy rules and returns a
// PolicyResult. It never returns an error; invalid policy fields (e.g. unknown
// FailOn value) silently skip that rule — callers should validate the policy
// before calling Evaluate.
//
// Parameters:
//   - p: the policy to evaluate against
//   - ff: the full list of unified findings from the scan
//   - qrs: the calculated Quantum Readiness Score (may be nil)
//   - summary: pre-computed aggregate counts
func Evaluate(p Policy, ff []findings.UnifiedFinding, qrs *quantum.QRS, summary ScanSummary) PolicyResult {
	var violations []Violation

	// Build pattern lists for algorithm allow/block rules. Patterns support
	// shell-style globs (*, ?, character classes) so policies like
	// BlockedAlgorithms: ["RSA*"] block every RSA-* variant.
	allowedPatterns := buildPatternList(p.AllowedAlgorithms)
	blockedPatterns := buildPatternList(p.BlockedAlgorithms)

	// failOn threshold (0 if FailOn is empty or unknown). Normalise to
	// lowercase so users can write `failOn: HIGH` or `failOn: Critical` in
	// YAML/config without the rule being silently skipped.
	failOnLevel, hasFailOn := severityRank[findings.Severity(strings.ToLower(p.FailOn))]

	for i := range ff {
		f := &ff[i]

		// --- Rule: failOn ---
		if hasFailOn {
			if level, ok := severityRank[f.Severity]; ok && level >= failOnLevel {
				violations = append(violations, Violation{
					Rule:     "fail-on",
					Severity: string(f.Severity),
					Message:  fmt.Sprintf("finding severity %q meets or exceeds fail-on threshold %q", f.Severity, p.FailOn),
					Finding:  f,
				})
			}
		}

		// Algorithm-specific rules only apply to findings that have an algorithm.
		if f.Algorithm == nil {
			continue
		}
		algName := f.Algorithm.Name
		algNameLower := strings.ToLower(algName)

		// --- Rule: blockedAlgorithms ---
		if len(blockedPatterns) > 0 {
			if matchesAnyPattern(algNameLower, blockedPatterns) {
				violations = append(violations, Violation{
					Rule:     "blocked-algorithm",
					Severity: "high",
					Message:  fmt.Sprintf("algorithm %q is on the blocked list", algName),
					Finding:  f,
				})
			}
		}

		// --- Rule: allowedAlgorithms ---
		if len(allowedPatterns) > 0 {
			if !matchesAnyPattern(algNameLower, allowedPatterns) {
				violations = append(violations, Violation{
					Rule:     "allowed-algorithms",
					Severity: "high",
					Message:  fmt.Sprintf("algorithm %q is not in the allowed list", algName),
					Finding:  f,
				})
			}
		}
	}

	// --- Rule: requirePQC ---
	if p.RequirePQC {
		hasPQC := summary.QuantumSafe > 0 || summary.QuantumResistant > 0
		if !hasPQC {
			violations = append(violations, Violation{
				Rule:     "require-pqc",
				Severity: "high",
				Message:  "no quantum-safe or quantum-resistant findings detected; requirePQC policy requires at least one",
				Finding:  nil,
			})
		}
	}

	// --- Rule: maxQuantumVulnerable ---
	// nil = disabled (YAML omitted). Non-nil enforces upper limit (including 0).
	if p.MaxQuantumVulnerable != nil && summary.QuantumVulnerable > *p.MaxQuantumVulnerable {
		violations = append(violations, Violation{
			Rule:     "max-quantum-vulnerable",
			Severity: "high",
			Message: fmt.Sprintf(
				"found %d quantum-vulnerable findings, exceeds maximum of %d",
				summary.QuantumVulnerable, *p.MaxQuantumVulnerable,
			),
			Finding: nil,
		})
	}

	// --- Rule: minQRS ---
	if p.MinQRS > 0 {
		if qrs == nil {
			violations = append(violations, Violation{
				Rule:     "min-qrs",
				Severity: "high",
				Message:  fmt.Sprintf("Quantum Readiness Score not available but minimum %d required", p.MinQRS),
				Finding:  nil,
			})
		} else if qrs.Score < p.MinQRS {
			violations = append(violations, Violation{
				Rule:     "min-qrs",
				Severity: "high",
				Message: fmt.Sprintf(
					"Quantum Readiness Score %d is below minimum required %d (grade: %s)",
					qrs.Score, p.MinQRS, qrs.Grade,
				),
				Finding: nil,
			})
		}
	}

	return PolicyResult{
		Pass:       len(violations) == 0,
		Violations: violations,
	}
}

// buildPatternList converts a string slice into a deduplicated, lowercase,
// whitespace-trimmed list of patterns. Each pattern may be a literal
// algorithm name (exact match) or a shell-style glob (*, ?, character
// classes) per Go's path.Match semantics.
func buildPatternList(items []string) []string {
	if len(items) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(items))
	out := make([]string, 0, len(items))
	for _, item := range items {
		trimmed := strings.ToLower(strings.TrimSpace(item))
		if trimmed == "" {
			continue
		}
		if _, dup := seen[trimmed]; dup {
			continue
		}
		seen[trimmed] = struct{}{}
		out = append(out, trimmed)
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// matchesAnyPattern reports whether algNameLower matches any of the
// lowercased patterns. Patterns containing `*`, `?`, or `[` are treated as
// shell globs via path.Match; all other patterns are exact-match.
func matchesAnyPattern(algNameLower string, patterns []string) bool {
	for _, p := range patterns {
		if strings.ContainsAny(p, "*?[") {
			ok, err := path.Match(p, algNameLower)
			if err == nil && ok {
				return true
			}
			continue
		}
		if p == algNameLower {
			return true
		}
	}
	return false
}

// buildLookupSet is retained for backward compatibility with callers that
// want a simple set membership check. Prefer buildPatternList +
// matchesAnyPattern for new uses that should support globs.
func buildLookupSet(items []string) map[string]struct{} {
	if len(items) == 0 {
		return nil
	}
	set := make(map[string]struct{}, len(items))
	for _, item := range items {
		trimmed := strings.TrimSpace(item)
		if trimmed == "" {
			continue
		}
		set[strings.ToLower(trimmed)] = struct{}{}
	}
	if len(set) == 0 {
		return nil
	}
	return set
}
