package compliance

import (
	"regexp"
	"strconv"
	"strings"

	"github.com/jimbo111/open-quantum-secure/pkg/findings"
)

// variantSuffixRe matches the trailing digit sequence of a parameter-set name,
// e.g. "768" in "MLKEM768" or "ML-KEM-768" (after hyphens are stripped).
var variantSuffixRe = regexp.MustCompile(`(\d+)$`)

// mlVariantLevel extracts the numeric parameter level from an ML-KEM or ML-DSA name.
// It strips hyphens before searching for the trailing digits, so both hyphenated
// ("ML-KEM-768") and hyphen-less ("MLKEM768") forms return the correct value.
// Returns 0 when no numeric suffix is present (e.g. bare "ML-KEM" or "MLKEM").
func mlVariantLevel(name string) int {
	stripped := strings.ReplaceAll(strings.ToUpper(name), "-", "")
	m := variantSuffixRe.FindString(stripped)
	if m == "" {
		return 0
	}
	n, _ := strconv.Atoi(m)
	return n
}

// isMLKEMName returns true when name denotes an ML-KEM algorithm, whether in
// hyphenated ("ML-KEM-768") or hyphen-less ("MLKEM768") form.
func isMLKEMName(name string) bool {
	upper := strings.ToUpper(name)
	return strings.HasPrefix(upper, "ML-KEM") || strings.HasPrefix(upper, "MLKEM")
}

// isMLDSAName returns true when name denotes an ML-DSA algorithm, whether in
// hyphenated ("ML-DSA-87") or hyphen-less ("MLDSA44") form.
func isMLDSAName(name string) bool {
	upper := strings.ToUpper(name)
	return strings.HasPrefix(upper, "ML-DSA") || strings.HasPrefix(upper, "MLDSA")
}

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
	return isMLKEMName(name) && !hybridKEMName(name)
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

// isKEMPrimitive returns true when the finding's primitive suggests key exchange.
// This includes TLS probe findings (NegotiatedGroupName set) and code findings
// with a KEM or key-exchange primitive.
func isKEMPrimitive(f *findings.UnifiedFinding) bool {
	if f.NegotiatedGroupName != "" {
		return true
	}
	if f.Algorithm == nil {
		return false
	}
	prim := strings.ToLower(f.Algorithm.Primitive)
	return prim == "kem" || prim == "key-exchange" || prim == "kex" || prim == "key_exchange"
}

// depViolation returns a Violation for a quantum-vulnerable dependency finding
// (Algorithm == nil && QuantumRisk == QRVulnerable), or nil otherwise.
// This eliminates the repeated nil-Algorithm block across framework Evaluate methods.
func depViolation(f *findings.UnifiedFinding, rule, message, deadline, remediation string) *Violation {
	if f.Algorithm != nil || f.QuantumRisk != findings.QRVulnerable {
		return nil
	}
	v := Violation{
		Algorithm:   f.RawIdentifier,
		Rule:        rule,
		Message:     message,
		Deadline:    deadline,
		Remediation: remediation,
	}
	return &v
}
