package compliance

// asdISMFramework implements Framework for the Australian Signals Directorate
// Information Security Manual (ASD ISM).
//
// Source: ASD Information Security Manual (ISM) — Cryptography section, 2024 edition.
// https://www.cyber.gov.au/resources-business-and-government/essential-cyber-security/ism
//
// Key properties:
//   - SLH-DSA IS approved (unlike CNSA 2.0).
//   - Strict minimum grades: ML-KEM-1024 only (512/768 fail), ML-DSA-87 only (44/65 fail).
//   - AES-256 required (AES-128/192 insufficient for Australian government systems).
//   - SHA-384/512 required (SHA-256 insufficient).
//   - No hybrid requirement (unlike BSI/ANSSI), but hybrid is permitted.
//   - Quantum-vulnerable algorithms trigger violations with ASD deadlines.

import (
	"strings"

	"github.com/jimbo111/open-quantum-secure/pkg/findings"
)

const (
	asdDeadlineKEX  = "2030-01-01"
	asdDeadlineFull = "2035-12-31"
)

type asdISMFramework struct{}

func (asdISMFramework) ID() string          { return "asd-ism" }
func (asdISMFramework) Name() string        { return "ASD ISM" }
func (asdISMFramework) Description() string { return "ASD Information Security Manual (2024), Australia" }

func (asdISMFramework) ApprovedAlgos() []ApprovedAlgoRef {
	return []ApprovedAlgoRef{
		{"Key Exchange", "ML-KEM-1024", "FIPS 203"},
		{"Digital Signatures", "ML-DSA-87, SLH-DSA (all)", "FIPS 204, FIPS 205"},
		{"Symmetric Encryption", "AES-256", "FIPS 197"},
		{"Hashing", "SHA-384, SHA-512", "FIPS 180-4"},
	}
}

func (asdISMFramework) Deadlines() []DeadlineRef {
	return []DeadlineRef{
		{"2030-01-01", "Quantum-safe key exchange required for all Australian government systems"},
		{"2035-12-31", "Full migration to post-quantum cryptography complete"},
	}
}

// Evaluate checks each finding in ff against ASD ISM cryptography requirements.
func (asdISMFramework) Evaluate(ff []findings.UnifiedFinding) []Violation {
	var violations []Violation

	for i := range ff {
		f := &ff[i]

		if f.Algorithm == nil {
			if f.QuantumRisk == findings.QRVulnerable {
				violations = append(violations, Violation{
					Algorithm:   f.RawIdentifier,
					Rule:        "asd-quantum-vulnerable",
					Message:     "quantum-vulnerable dependency must be replaced; ASD ISM requires PQC migration for Australian government systems",
					Deadline:    asdDeadlineKEX,
					Remediation: "Migrate to an ASD ISM approved PQC library (ML-KEM-1024 for key exchange, ML-DSA-87 for signatures)",
				})
			}
			continue
		}

		name := f.Algorithm.Name
		upper := strings.ToUpper(name)
		keySize := f.Algorithm.KeySize

		// --- Rule: quantum-vulnerable or deprecated ---
		if quantumVulnerableOrDeprecated(f) {
			violations = append(violations, Violation{
				Algorithm:   name,
				Rule:        "asd-quantum-vulnerable",
				Message:     name + " is quantum-vulnerable; ASD ISM requires migration to ML-KEM-1024 or ML-DSA-87",
				Deadline:    asdDeadlineKEX,
				Remediation: "Replace with ML-KEM-1024 (key exchange) or ML-DSA-87 (signatures) per ASD ISM",
			})
			continue
		}

		// --- Rule: ML-KEM minimum grade: 1024 ---
		// ASD ISM mandates ML-KEM-1024; lower parameter sets are insufficient.
		// Matches both hyphenated ("ML-KEM-768") and hyphen-less ("MLKEM768") forms.
		if isMLKEMName(name) {
			variant := mlVariantLevel(name)
			if variant > 0 && variant < 1024 {
				violations = append(violations, Violation{
					Algorithm:   name,
					Rule:        "asd-ml-kem-grade",
					Message:     "ASD ISM requires ML-KEM-1024; " + name + " does not meet the minimum grade",
					Deadline:    asdDeadlineKEX,
					Remediation: "Upgrade to ML-KEM-1024; ASD ISM does not accept ML-KEM-512 or ML-KEM-768",
				})
			}
			continue
		}

		// --- Rule: ML-DSA minimum grade: 87 ---
		// ASD ISM mandates ML-DSA-87; lower parameter sets are insufficient.
		// Matches both hyphenated ("ML-DSA-44") and hyphen-less ("MLDSA44") forms.
		if isMLDSAName(name) {
			variant := mlVariantLevel(name)
			if variant > 0 && variant < 87 {
				violations = append(violations, Violation{
					Algorithm:   name,
					Rule:        "asd-ml-dsa-grade",
					Message:     "ASD ISM requires ML-DSA-87; " + name + " does not meet the minimum grade",
					Deadline:    asdDeadlineFull,
					Remediation: "Upgrade to ML-DSA-87; ASD ISM does not accept ML-DSA-44 or ML-DSA-65",
				})
			}
			continue
		}

		// SLH-DSA is approved (all parameter sets).
		if strings.HasPrefix(upper, "SLH-DSA") {
			continue
		}

		// --- Rule: AES-256 required ---
		if strings.HasPrefix(upper, "AES") {
			effective := resolveSymmetricKeySize(upper, keySize)
			if effective > 0 && effective < 256 {
				violations = append(violations, Violation{
					Algorithm:   name,
					Rule:        "asd-aes-key-size",
					Message:     "ASD ISM requires AES-256 for Australian government systems; " + name + " has insufficient key size",
					Deadline:    asdDeadlineFull,
					Remediation: "Upgrade to AES-256; ASD ISM does not permit AES-128 or AES-192",
				})
			}
			continue
		}

		// --- Rule: SHA-384/512 required ---
		if isHashFamily(upper) {
			size := resolveHashOutputSize(upper, keySize)
			if size > 0 && size < 384 {
				violations = append(violations, Violation{
					Algorithm:   name,
					Rule:        "asd-hash-output-size",
					Message:     "ASD ISM requires SHA-384 or SHA-512; " + name + " has insufficient output size",
					Deadline:    asdDeadlineFull,
					Remediation: "Upgrade to SHA-384 or SHA-512 per ASD ISM requirements",
				})
			}
			continue
		}
	}

	if len(violations) == 0 {
		return nil
	}
	return violations
}

func init() {
	Register(asdISMFramework{})
}
