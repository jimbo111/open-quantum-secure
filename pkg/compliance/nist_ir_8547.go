package compliance

// nistIR8547Framework implements Framework for NIST IR 8547.
//
// Source: NIST Internal Report 8547 "Transition to Post-Quantum Cryptography Standards"
// (Initial Public Draft, November 2024). Applies to US federal civilian information
// systems (non-NSS) under FISMA.
// https://nvlpubs.nist.gov/nistpubs/ir/2024/NIST.IR.8547.ipd.pdf
//
// Key divergences from CNSA 2.0 (which covers NSS only):
//   - SLH-DSA IS approved (NIST IR 8547 covers civilian systems; CNSA 2.0 excludes it for NSS).
//   - ML-KEM-512/768/1024 and ML-DSA-44/65/87 are all acceptable.
//   - Explicit calendar: RSA/ECDSA/DH deprecated 2030, disallowed 2035.
//   - AES-128 is permissible for existing deployments.
//   - SHA-256 is permissible for most civilian uses.
//   - HQC is expected to be added upon NIST standardisation.

import (
	"strings"

	"github.com/jimbo111/open-quantum-secure/pkg/findings"
)

const (
	nist8547DeprecateDate = "2030-12-31" // RSA/ECDSA/DH deprecated for new systems
	nist8547DisallowDate  = "2035-12-31" // RSA/ECDSA/DH disallowed for all systems
)

type nistIR8547Framework struct{}

func (nistIR8547Framework) ID() string          { return "nist-ir-8547" }
func (nistIR8547Framework) Name() string        { return "NIST IR 8547" }
func (nistIR8547Framework) Description() string { return "NIST IR 8547 (Draft, Nov 2024) — Federal Civilian PQC Transition" }

func (nistIR8547Framework) ApprovedAlgos() []ApprovedAlgoRef {
	return []ApprovedAlgoRef{
		{"Key Exchange", "ML-KEM-512/768/1024", "FIPS 203"},
		{"Digital Signatures", "ML-DSA-44/65/87", "FIPS 204"},
		{"Digital Signatures (stateful hash)", "LMS/HSS, XMSS/XMSS^MT", "SP 800-208"},
		{"Digital Signatures (stateless hash)", "SLH-DSA (all)", "FIPS 205"},
		{"Symmetric Encryption", "AES-128/192/256", "FIPS 197"},
		{"Hashing", "SHA-256/384/512, SHA-3 family", "FIPS 180-4, FIPS 202"},
	}
}

func (nistIR8547Framework) Deadlines() []DeadlineRef {
	return []DeadlineRef{
		{"2030-12-31", "RSA, ECDSA, ECDH, DH deprecated for new federal civilian systems"},
		{"2035-12-31", "RSA, ECDSA, ECDH, DH disallowed across all federal civilian systems"},
	}
}

// Evaluate checks each finding in ff against NIST IR 8547 transition requirements.
func (nistIR8547Framework) Evaluate(ff []findings.UnifiedFinding) []Violation {
	var violations []Violation

	for i := range ff {
		f := &ff[i]

		if f.Algorithm == nil {
			if f.QuantumRisk == findings.QRVulnerable {
				violations = append(violations, Violation{
					Algorithm:   f.RawIdentifier,
					Rule:        "nist8547-quantum-vulnerable",
					Message:     "quantum-vulnerable dependency must be replaced per NIST IR 8547 federal civilian PQC transition schedule",
					Deadline:    nist8547DisallowDate,
					Remediation: "Migrate to NIST FIPS 203 (ML-KEM) or FIPS 204 (ML-DSA) per NIST IR 8547",
				})
			}
			continue
		}

		name := f.Algorithm.Name
		upper := strings.ToUpper(name)

		// --- Rule: quantum-vulnerable or deprecated ---
		// NIST IR 8547 §3.1: RSA, ECDSA, ECDH, DSA, DH are deprecated by 2030 and
		// disallowed by 2035 for all federal civilian information systems.
		if quantumVulnerableOrDeprecated(f) {
			deadline := nist8547DisallowDate
			if isKeyExchangeAlgorithm(upper) {
				deadline = nist8547DeprecateDate // deprecated 2030 (key exchange is the more urgent use case)
			}
			violations = append(violations, Violation{
				Algorithm: name,
				Rule:      "nist8547-quantum-vulnerable",
				Message: name + " is deprecated per NIST IR 8547 — federal civilian systems must migrate to " +
					"NIST PQC standards (FIPS 203/204/205) by 2030 (deprecated) and 2035 (disallowed)",
				Deadline:    deadline,
				Remediation: nist8547Remediation(upper),
			})
			continue
		}

		// All NIST PQC standards (ML-KEM, ML-DSA, SLH-DSA) at all parameter sets
		// are approved. LMS/HSS/XMSS are also approved. No further restrictions.
		_ = upper
	}

	if len(violations) == 0 {
		return nil
	}
	return violations
}

func init() {
	Register(nistIR8547Framework{})
}

// isKeyExchangeAlgorithm returns true for algorithms primarily used in key exchange.
func isKeyExchangeAlgorithm(upper string) bool {
	return strings.HasPrefix(upper, "RSA") ||
		strings.Contains(upper, "ECDH") ||
		strings.HasPrefix(upper, "DH-") ||
		upper == "DH" ||
		strings.Contains(upper, "DIFFIE")
}

func nist8547Remediation(upper string) string {
	switch {
	case strings.HasPrefix(upper, "RSA"), strings.Contains(upper, "ECDH"),
		strings.Contains(upper, "DH"), strings.Contains(upper, "DIFFIE"):
		return "Migrate to ML-KEM (FIPS 203) for key exchange per NIST IR 8547 §3.1"
	case strings.Contains(upper, "ECDSA"), strings.HasPrefix(upper, "DSA"):
		return "Migrate to ML-DSA (FIPS 204) or SLH-DSA (FIPS 205) for digital signatures per NIST IR 8547 §3.1"
	default:
		return "Replace with a NIST-standardised PQC algorithm per NIST IR 8547 transition schedule"
	}
}
