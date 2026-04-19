package compliance

// ncscUKFramework implements Framework for NCSC UK post-quantum guidance.
//
// Source: NCSC UK "Post-Quantum Cryptography: Prepare your systems for the future"
// (2023, updated 2024) and NCSC Cryptography White Paper.
// https://www.ncsc.gov.uk/whitepaper/next-steps-preparing-for-post-quantum-cryptography
//
// Key properties vs. CNSA 2.0:
//   - SLH-DSA IS approved (NCSC does not exclude it like NSA does).
//   - All NIST PQC parameter sets are acceptable (ML-KEM-512/768/1024, ML-DSA-44/65/87).
//   - Hybrid PQC+classical is RECOMMENDED but not mandated (differs from BSI/ANSSI).
//   - Deprecation timeline aligns with NIST: key exchange 2030, full transition 2035.
//   - No restrictions beyond quantum vulnerability and deprecated algorithms.

import (
	"strings"

	"github.com/jimbo111/open-quantum-secure/pkg/findings"
)

const (
	ncscDeadlineKEX  = "2030-01-01"
	ncscDeadlineFull = "2035-12-31"
)

type ncscUKFramework struct{}

func (ncscUKFramework) ID() string          { return "ncsc-uk" }
func (ncscUKFramework) Name() string        { return "NCSC UK" }
func (ncscUKFramework) Description() string { return "NCSC UK Post-Quantum Cryptography Guidance (2024)" }

func (ncscUKFramework) ApprovedAlgos() []ApprovedAlgoRef {
	return []ApprovedAlgoRef{
		{"Key Exchange", "ML-KEM-512/768/1024 (hybrid recommended)", "FIPS 203"},
		{"Digital Signatures", "ML-DSA-44/65/87, SLH-DSA (all)", "FIPS 204, FIPS 205"},
		{"Symmetric Encryption", "AES-128/192/256", "FIPS 197"},
		{"Hashing", "SHA-256/384/512, SHA-3 family", "FIPS 180-4, FIPS 202"},
	}
}

func (ncscUKFramework) Deadlines() []DeadlineRef {
	return []DeadlineRef{
		{"2030-01-01", "Migrate key exchange to post-quantum algorithms"},
		{"2035-12-31", "Complete full migration to post-quantum cryptography"},
	}
}

// Evaluate checks each finding in ff against NCSC UK post-quantum guidance.
func (ncscUKFramework) Evaluate(ff []findings.UnifiedFinding) []Violation {
	var violations []Violation

	for i := range ff {
		f := &ff[i]

		if f.Algorithm == nil {
			if v := depViolation(f, "ncsc-quantum-vulnerable",
				"quantum-vulnerable dependency must be replaced; NCSC UK guidance requires PQC migration",
				ncscDeadlineKEX,
				"Migrate to an NCSC-recommended PQC algorithm per the NCSC post-quantum cryptography whitepaper"); v != nil {
				violations = append(violations, *v)
			}
			continue
		}

		name := f.Algorithm.Name
		upper := strings.ToUpper(name)

		// --- Rule: quantum-vulnerable or deprecated ---
		if quantumVulnerableOrDeprecated(f) {
			violations = append(violations, Violation{
				Algorithm:   name,
				Rule:        "ncsc-quantum-vulnerable",
				Message:     name + " is quantum-vulnerable; NCSC UK guidance requires migration to a NIST-standardised PQC algorithm",
				Deadline:    deadlineForAlgorithmType(upper),
				Remediation: ncscRemediation(upper),
			})
			continue
		}

		// All NIST PQC standards (ML-KEM, ML-DSA, SLH-DSA) at all parameter sets
		// are acceptable per NCSC UK guidance. No further checks needed.
	}

	if len(violations) == 0 {
		return nil
	}
	return violations
}

func init() {
	Register(ncscUKFramework{})
}

// deadlineForAlgorithmType returns a NIST-aligned deadline for the given algorithm.
// Key-exchange algorithms face the earlier 2030 deadline; others get 2035.
func deadlineForAlgorithmType(upper string) string {
	if isECDHFamily(upper) || isDHFamily(upper) || isRSAFamily(upper) {
		return ncscDeadlineKEX
	}
	return ncscDeadlineFull
}

func ncscRemediation(upper string) string {
	switch {
	case isRSAFamily(upper), isECDHFamily(upper), isDHFamily(upper):
		return "Migrate to ML-KEM (consider hybrid X25519MLKEM768) per NCSC UK post-quantum guidance"
	case isECDSAFamily(upper), isDSAFamily(upper):
		return "Migrate to ML-DSA or SLH-DSA per NCSC UK post-quantum guidance"
	default:
		return "Replace with a NIST-standardised PQC algorithm per NCSC UK post-quantum guidance"
	}
}
