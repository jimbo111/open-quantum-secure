package compliance

// bsiTR02102Framework implements Framework for BSI TR-02102-1 (Germany).
//
// Source: BSI TR-02102-1 "Cryptographic Mechanisms: Recommendations and Key Lengths"
// Version 2024-01 (January 2024), with PQC additions for NIST FIPS 203/204/205.
// https://www.bsi.bund.de/SharedDocs/Downloads/EN/BSI/Publications/TechGuidelines/TG02102/BSI-TR-02102-1.pdf
//
// Key divergences from CNSA 2.0:
//   - SLH-DSA (FIPS 205) IS approved by BSI.
//   - HQC, FrodoKEM, and Classic McEliece ARE approved.
//   - Hybrid PQC+classical key exchange is REQUIRED during the transition period
//     (pure standalone ML-KEM is not sufficient for new deployments).
//   - ML-KEM-512/768/1024 are all acceptable (no grade minimum beyond hybrid requirement).
//   - ML-DSA-44/65/87 are all acceptable.
//   - AES-128 is permitted (128-bit minimum symmetric security).
//   - SHA-256 is permitted for most uses; SHA-384/512 recommended for long-term.

import (
	"strings"

	"github.com/jimbo111/open-quantum-secure/pkg/findings"
)

const (
	bsiDeadlineKEX  = "2030-01-01" // hybrid key exchange transition deadline
	bsiDeadlineFull = "2035-12-31" // full quantum transition deadline
)

type bsiTR02102Framework struct{}

func (bsiTR02102Framework) ID() string          { return "bsi-tr-02102" }
func (bsiTR02102Framework) Name() string        { return "BSI TR-02102" }
func (bsiTR02102Framework) Description() string { return "BSI TR-02102-1 (Jan 2024), Germany" }

func (bsiTR02102Framework) ApprovedAlgos() []ApprovedAlgoRef {
	return []ApprovedAlgoRef{
		{"Key Exchange (hybrid)", "X25519MLKEM768, SecP256r1MLKEM768, SecP384r1MLKEM1024", "FIPS 203 + RFC 8446"},
		{"Key Exchange (standalone, future)", "ML-KEM-512/768/1024, FrodoKEM, HQC, Classic McEliece", "FIPS 203"},
		{"Digital Signatures", "ML-DSA-44/65/87, SLH-DSA (all), ML-DSA + ECDSA hybrid", "FIPS 204, FIPS 205"},
		{"Symmetric Encryption", "AES-128/192/256", "FIPS 197"},
		{"Hashing", "SHA-256/384/512, SHA-3 family", "FIPS 180-4, FIPS 202"},
	}
}

func (bsiTR02102Framework) Deadlines() []DeadlineRef {
	return []DeadlineRef{
		{"2030-01-01", "Hybrid PQC+classical key exchange required for new systems"},
		{"2035-12-31", "Full migration to PQC algorithms complete"},
	}
}

// Evaluate checks each finding in ff against BSI TR-02102-1 rules.
func (bsiTR02102Framework) Evaluate(ff []findings.UnifiedFinding) []Violation {
	var violations []Violation

	for i := range ff {
		f := &ff[i]

		if f.Algorithm == nil {
			if f.QuantumRisk == findings.QRVulnerable {
				violations = append(violations, Violation{
					Algorithm:   f.RawIdentifier,
					Rule:        "bsi-quantum-vulnerable",
					Message:     "quantum-vulnerable dependency must be replaced; BSI TR-02102 requires PQC or hybrid migration",
					Deadline:    bsiDeadlineKEX,
					Remediation: "Migrate dependency to a PQC or hybrid-PQC library per BSI TR-02102-1",
				})
			}
			continue
		}

		name := f.Algorithm.Name
		upper := strings.ToUpper(name)

		// --- Rule: quantum-vulnerable or deprecated ---
		if quantumVulnerableOrDeprecated(f) {
			violations = append(violations, Violation{
				Algorithm:   name,
				Rule:        "bsi-quantum-vulnerable",
				Message:     name + " is quantum-vulnerable; BSI TR-02102 requires PQC or hybrid key exchange for new systems",
				Deadline:    bsiDeadlineKEX,
				Remediation: "Replace with a hybrid KEM (e.g. X25519MLKEM768) or migrate to ML-KEM + classical combination per BSI TR-02102",
			})
			continue
		}

		// --- Rule: hybrid KEM required for key exchange during transition ---
		// BSI TR-02102-1 requires hybrid PQC+classical for new key exchange deployments.
		// Pure standalone ML-KEM (without a classical component) does not meet this
		// requirement during the transition period ending 2030.
		if isPureMLKEM(f) && isKEMPrimitive(f) {
			violations = append(violations, Violation{
				Algorithm:   name,
				Rule:        "bsi-hybrid-kem-required",
				Message:     name + " is a pure PQC KEM; BSI TR-02102 requires a hybrid PQC+classical combination for key exchange during the transition period",
				Deadline:    bsiDeadlineKEX,
				Remediation: "Use a hybrid KEM such as X25519MLKEM768 or SecP256r1MLKEM768 to satisfy BSI TR-02102 transition requirements",
			})
			continue
		}

		// SLH-DSA, ML-DSA (all levels), HQC, FrodoKEM, Classic McEliece, hybrid KEMs are approved.
		// AES-128+ is permitted. SHA-256+ is permitted.
		// No additional checks needed beyond quantum-vulnerability above.
		_ = upper
	}

	if len(violations) == 0 {
		return nil
	}
	return violations
}

func init() {
	Register(bsiTR02102Framework{})
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
