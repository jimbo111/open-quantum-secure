package compliance

// anssiFramework implements Framework for ANSSI (France) PQC guidance.
//
// Source: ANSSI "Guide de sélection d'algorithmes cryptographiques" v2 (2021)
// and ANSSI Position Paper on Post-Quantum Cryptography (2024).
// https://www.ssi.gouv.fr/guide/selection-dalgorithmes-cryptographiques/
//
// Key divergences from CNSA 2.0:
//   - SLH-DSA IS approved.
//   - Hybrid PQC+classical key exchange is REQUIRED during the transition period
//     (ANSSI aligns with BSI on the hybrid mandate for key exchange).
//   - ML-DSA-44/65/87 and SLH-DSA are all acceptable for signatures.
//   - ML-KEM-512/768/1024 are acceptable when combined with a classical KEM.
//   - AES-128 is permitted for most uses; AES-256 recommended for long-term.
//   - SHA-256 is permitted; SHA-384/512 recommended.

import (
	"github.com/jimbo111/open-quantum-secure/pkg/findings"
)

const (
	anssiDeadlineKEX  = "2030-01-01"
	anssiDeadlineFull = "2035-12-31"
)

type anssiFramework struct{}

func (anssiFramework) ID() string          { return "anssi-guide-pqc" }
func (anssiFramework) Name() string        { return "ANSSI Guide PQC" }
func (anssiFramework) Description() string { return "ANSSI Position Paper on PQC (2024), France" }

func (anssiFramework) ApprovedAlgos() []ApprovedAlgoRef {
	return []ApprovedAlgoRef{
		{"Key Exchange (hybrid)", "X25519MLKEM768, SecP256r1MLKEM768, SecP384r1MLKEM1024", "FIPS 203 + ANSSI guidance"},
		{"Key Exchange (standalone, future)", "ML-KEM-512/768/1024", "FIPS 203"},
		{"Digital Signatures", "ML-DSA-44/65/87, SLH-DSA (all)", "FIPS 204, FIPS 205"},
		{"Symmetric Encryption", "AES-128/192/256 (AES-256 recommended)", "FIPS 197"},
		{"Hashing", "SHA-256/384/512", "FIPS 180-4"},
	}
}

func (anssiFramework) Deadlines() []DeadlineRef {
	return []DeadlineRef{
		{"2030-01-01", "Hybrid PQC+classical key exchange required for new systems"},
		{"2035-12-31", "Full PQC migration complete"},
	}
}

// Evaluate checks each finding in ff against ANSSI PQC guidance rules.
func (anssiFramework) Evaluate(ff []findings.UnifiedFinding) []Violation {
	var violations []Violation

	for i := range ff {
		f := &ff[i]

		if f.Algorithm == nil {
			if v := depViolation(f, "anssi-quantum-vulnerable",
				"quantum-vulnerable dependency must be replaced; ANSSI requires PQC or hybrid migration",
				anssiDeadlineKEX,
				"Migrate to a hybrid PQC+classical library per ANSSI guidance"); v != nil {
				violations = append(violations, *v)
			}
			continue
		}

		name := f.Algorithm.Name

		// --- Rule: quantum-vulnerable or deprecated ---
		if quantumVulnerableOrDeprecated(f) {
			violations = append(violations, Violation{
				Algorithm:   name,
				Rule:        "anssi-quantum-vulnerable",
				Message:     name + " is quantum-vulnerable; ANSSI requires hybrid PQC+classical key exchange for new systems",
				Deadline:    anssiDeadlineKEX,
				Remediation: "Replace with a hybrid KEM (e.g. X25519MLKEM768) per ANSSI guidance",
			})
			continue
		}

		// --- Advisory: hybrid KEM strongly recommended for key exchange ---
		// ANSSI "Views on PQC transition (2023 follow-up)" §1.1-§1.2 strongly
		// emphasises hybrid PQC+classical as recommended practice, but does not
		// use normative "shall/must" language. Severity is "warn", not "error".
		if isPureMLKEM(f) && isKEMPrimitive(f) {
			violations = append(violations, Violation{
				Algorithm:   name,
				Rule:        "anssi-hybrid-kem-required",
				Severity:    "warn",
				Message:     name + " is a standalone PQC KEM; ANSSI strongly recommends hybrid PQC+classical combination for key exchange during the transition period",
				Deadline:    anssiDeadlineKEX,
				Remediation: "Use a hybrid KEM such as X25519MLKEM768 or SecP256r1MLKEM768 per ANSSI transition guidance (strongly recommended, not mandatory)",
			})
			continue
		}

		// SLH-DSA, ML-DSA (all levels), hybrid KEMs, and standard symmetric/hash
		// algorithms are approved by ANSSI. No additional checks needed.
	}

	if len(violations) == 0 {
		return nil
	}
	return violations
}

func init() {
	Register(anssiFramework{})
}
