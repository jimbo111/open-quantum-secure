package policy

import "fmt"

// Policy defines the rules for evaluating scan findings.
// All fields are optional; a zero-value Policy allows everything.
type Policy struct {
	// FailOn is a severity threshold: fail if any finding is at or above this level.
	// Valid values: "critical", "high", "medium", "low". Empty string disables.
	FailOn string `yaml:"failOn"`

	// AllowedAlgorithms is a whitelist of algorithm names. When non-empty, any
	// finding whose algorithm name is NOT in this list produces a violation.
	// Dependency findings are not subject to this rule.
	AllowedAlgorithms []string `yaml:"allowedAlgorithms"`

	// BlockedAlgorithms is a blacklist of algorithm names. Any finding whose
	// algorithm name appears in this list produces a violation.
	BlockedAlgorithms []string `yaml:"blockedAlgorithms"`

	// RequirePQC requires at least one quantum-safe or quantum-resistant finding
	// in the scan results. Useful to enforce that a codebase has started PQC adoption.
	RequirePQC bool `yaml:"requirePQC"`

	// MaxQuantumVulnerable caps the number of quantum-vulnerable findings.
	// nil (YAML omitted) = disabled (unlimited).
	// 0 = zero quantum-vulnerable findings allowed.
	// Positive values (1, 2, …) are enforced as an upper limit.
	MaxQuantumVulnerable *int `yaml:"maxQuantumVulnerable"`

	// MinQRS sets the minimum required Quantum Readiness Score (0-100).
	// 0 (zero value) disables this check. Any positive value enforces a floor.
	MinQRS int `yaml:"minQRS"`
}

// Validate returns an error when the policy contains values that cannot be
// satisfied (MinQRS > 100, MinQRS < 0) or that are silently footguns
// (MaxQuantumVulnerable negative, which `Evaluate` interprets as "0 > -1"
// — making every clean scan fail on `cnsa2-max-vulnerable` instead of
// passing).
//
// Callers should run Validate() at config-load time so a typo'd policy
// surfaces before the scan begins, rather than after a multi-minute
// scan completes and Evaluate produces nonsensical violations.
func (p Policy) Validate() error {
	if p.MinQRS < 0 || p.MinQRS > 100 {
		return fmt.Errorf("policy.minQRS must be in [0, 100] (got %d); 0 disables the check, 100 requires a perfect score", p.MinQRS)
	}
	if p.MaxQuantumVulnerable != nil && *p.MaxQuantumVulnerable < 0 {
		return fmt.Errorf("policy.maxQuantumVulnerable must be >= 0 (got %d); negative values make 0-finding scans fail (0 > -1 is true). Omit the field to disable the check, or set 0 to require zero quantum-vulnerable findings", *p.MaxQuantumVulnerable)
	}
	return nil
}
