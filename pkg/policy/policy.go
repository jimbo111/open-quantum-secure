package policy

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
