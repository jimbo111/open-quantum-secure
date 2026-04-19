package compliance

import (
	"strings"

	"github.com/jimbo111/open-quantum-secure/pkg/findings"
)

// isHybridKEM returns true when the finding represents a hybrid PQC+classical
// key exchange (e.g. X25519MLKEM768, SecP256r1MLKEM768). It checks
// NegotiatedGroupName first (set by the TLS probe), then falls back to
// Algorithm.Name for code-scan findings.
func isHybridKEM(f *findings.UnifiedFinding) bool {
	name := f.NegotiatedGroupName
	if name == "" && f.Algorithm != nil {
		name = f.Algorithm.Name
	}
	return hybridKEMName(name)
}

// hybridKEMName returns true when name represents a hybrid classical+PQC KEM.
// Hybrid names combine a classical group with an ML-KEM variant, e.g.
// "X25519MLKEM768", "SecP256r1MLKEM768", "SecP384r1MLKEM1024".
// Underscores are NOT stripped (they indicate variable names per CLAUDE.md).
func hybridKEMName(name string) bool {
	// Normalise: uppercase, strip hyphens only (not underscores).
	upper := strings.ToUpper(strings.ReplaceAll(name, "-", ""))
	for _, prefix := range []string{
		"X25519MLKEM",
		"SECP256R1MLKEM",
		"SECP384R1MLKEM",
		"CURVESM2MLKEM",
	} {
		if strings.HasPrefix(upper, prefix) {
			return true
		}
	}
	return false
}

// isPureMLKEM returns true when the finding's algorithm name indicates a pure
// (non-hybrid) ML-KEM usage, e.g. "MLKEM768" or "ML-KEM-1024".
func isPureMLKEM(f *findings.UnifiedFinding) bool {
	name := f.NegotiatedGroupName
	if name == "" && f.Algorithm != nil {
		name = f.Algorithm.Name
	}
	upper := strings.ToUpper(strings.ReplaceAll(name, "-", ""))
	return strings.HasPrefix(upper, "MLKEM") && !hybridKEMName(name)
}

// isMLKEMKEX returns true when the finding is a key-exchange (KEM) finding
// involving ML-KEM — whether pure or hybrid.
func isMLKEMKEX(f *findings.UnifiedFinding) bool {
	return isHybridKEM(f) || isPureMLKEM(f)
}

// quantumVulnerableOrDeprecated returns true when the finding carries a
// quantum-vulnerable or deprecated risk classification.
func quantumVulnerableOrDeprecated(f *findings.UnifiedFinding) bool {
	return f.QuantumRisk == findings.QRVulnerable || f.QuantumRisk == findings.QRDeprecated
}

// algNameUpper returns the uppercased algorithm name from a finding, or "".
func algNameUpper(f *findings.UnifiedFinding) string {
	if f.Algorithm != nil {
		return strings.ToUpper(f.Algorithm.Name)
	}
	return ""
}

// mlKEMVariant extracts the numeric variant from an ML-KEM name, e.g.
// "ML-KEM-768" → 768, "MLKEM1024" → 1024. Returns 0 for bare "ML-KEM".
func mlKEMVariant(name string) int {
	return mlVariantLevel(name) // reuse cnsa2.go helper
}

// mlDSAVariant extracts the numeric variant from an ML-DSA name, e.g.
// "ML-DSA-87" → 87, "MLDSA44" → 44. Returns 0 for bare "ML-DSA".
func mlDSAVariant(name string) int {
	return mlVariantLevel(name) // reuse cnsa2.go helper
}
