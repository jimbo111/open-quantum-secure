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
//   - Default-deny: any KEM/signature primitive not explicitly approved above
//     (FrodoKEM, HQC, Classic McEliece, Falcon/FN-DSA, etc.) is a violation.
//
// NOTE: ISM-1917 Rev.3 transitional allowance for ML-KEM-768/ML-DSA-65 (until
// 2030) unconfirmed against primary PDF — revisit before hardening/softening.
// The grade checks below (asd-hybrid-sub-1024, asd-ml-kem-grade,
// asd-ml-dsa-grade) currently reject sub-1024/sub-87 unconditionally; if the
// transitional allowance is confirmed against the primary ISM text, those
// checks would need a date-gated carve-out.

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
			if v := depViolation(f, "asd-quantum-vulnerable",
				"quantum-vulnerable dependency must be replaced; ASD ISM requires PQC migration for Australian government systems",
				asdDeadlineKEX,
				"Migrate to an ASD ISM approved PQC library (ML-KEM-1024 for key exchange, ML-DSA-87 for signatures)"); v != nil {
				violations = append(violations, *v)
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
				Message:     name + " is " + riskDescriptor(f) + "; ASD ISM requires migration to ML-KEM-1024 or ML-DSA-87",
				Deadline:    asdDeadlineKEX,
				Remediation: "Replace with ML-KEM-1024 (key exchange) or ML-DSA-87 (signatures) per ASD ISM",
			})
			continue
		}

		// --- Rule: hybrid KEM with sub-1024 ML-KEM grade ---
		// ASD ISM mandates ML-KEM-1024 even within hybrid combinations. A hybrid
		// like X25519MLKEM768 uses ML-KEM-768 (insufficient grade) and must fail.
		// This branch runs BEFORE isMLKEMName so hybrids are caught first.
		// Mirrors CNSA 2.0's cnsa2-hybrid-sub-1024 pattern (cnsa2.go:136).
		if isHybridKEM(f) {
			variant := mlVariantLevel(name)
			if variant > 0 && variant < 1024 {
				violations = append(violations, Violation{
					Algorithm:   name,
					Rule:        "asd-hybrid-sub-1024",
					Message:     "ASD ISM requires ML-KEM-1024; " + name + " is a hybrid KEM using a sub-1024 ML-KEM variant",
					Deadline:    asdDeadlineKEX,
					Remediation: "Use a hybrid with ML-KEM-1024 (e.g. X25519MLKEM1024, SecP384r1MLKEM1024) or pure ML-KEM-1024",
				})
			}
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

		// SLH-DSA is approved (all parameter sets). Match hyphen-insensitively:
		// the TLS probe emits OID-derived hyphen-less names ("slhdsa-sha2-128s"
		// via LookupPQCSigAlgName) that a bare "SLH-DSA" prefix misses —
		// flagging them contradicted this framework's own approved list
		// (wave-2 review V16/V17).
		if strings.HasPrefix(upper, "SLH-DSA") ||
			strings.HasPrefix(strings.ReplaceAll(upper, "-", ""), "SLHDSA") {
			continue
		}

		// --- Rule: KEM default-deny (non-ML-KEM quantum-safe KEMs) ---
		// ASD ISM's ApprovedAlgos() restricts Key Exchange to ML-KEM-1024 only.
		// Any other quantum-safe KEM — FrodoKEM, Classic McEliece, HQC, BIKE,
		// future NIST Round 4 alternates — is NOT on the approved list. Pure/
		// hybrid ML-KEM is already handled by the isHybridKEM/isMLKEMName
		// branches above (which `continue` unconditionally), so only
		// non-ML-KEM KEMs reach here. Mirrors CNSA 2.0's cnsa2-kem-not-approved
		// default-deny (cnsa2.go:208-224). Matched by primitive
		// (isKEMPrimitive) rather than name prefix so new algorithms are
		// rejected without code updates.
		if isKEMPrimitive(f) {
			violations = append(violations, Violation{
				Algorithm:   name,
				Rule:        "asd-kem-not-approved",
				Message:     name + " is not an ASD ISM approved KEM; ASD ISM approves only ML-KEM-1024 for key exchange",
				Deadline:    asdDeadlineKEX,
				Remediation: "Replace with ML-KEM-1024; ASD ISM does not approve FrodoKEM, Classic McEliece, HQC, or other non-ML-KEM quantum-safe KEMs",
			})
			continue
		}

		// --- Rule: signature default-deny (non-ML-DSA/non-SLH-DSA quantum-safe signatures) ---
		// ASD ISM's ApprovedAlgos() restricts Digital Signatures to ML-DSA-87
		// and SLH-DSA (all parameter sets). Falcon/FN-DSA — classified
		// RiskSafe by pkg/quantum as a NIST-selected, standard-pending scheme
		// — is NOT on ASD ISM's approved list; the classifier's view (safe,
		// standard-pending) is independent of this framework's approved-list
		// enforcement. ML-DSA and SLH-DSA are handled by earlier branches
		// that `continue` before reaching here. Mirrors CNSA 2.0's
		// cnsa2-signature-not-approved default-deny (cnsa2.go:226-244).
		// SP 800-208 stateful hash signatures (LMS/HSS/XMSS/XMSS^MT) are
		// exempt, mirroring the CNSA 2.0 rule this default-deny is modeled
		// on — omitting the exemption flagged approved firmware-signing
		// schemes (wave-2 review V18).
		if isSignaturePrimitive(f) && !isStatefulHashSignatureName(upper) {
			violations = append(violations, Violation{
				Algorithm:   name,
				Rule:        "asd-signature-not-approved",
				Message:     name + " is not an ASD ISM approved signature; ASD ISM approves only ML-DSA-87 and SLH-DSA (all parameter sets)",
				Deadline:    asdDeadlineFull,
				Remediation: "Replace with ML-DSA-87 or SLH-DSA; ASD ISM does not approve Falcon/FN-DSA or other non-approved signature schemes",
			})
			continue
		}

		// --- Rule: non-AES symmetric ciphers NOT approved ---
		// ASD ISM requires AES-256 for symmetric encryption. Non-AES ciphers
		// (ChaCha20-Poly1305, Camellia, ARIA, SEED, Serpent, Twofish, 3DES, RC4)
		// are NOT approved regardless of key size. Catches ciphers that would
		// otherwise fall through to the end without a violation.
		if strings.HasPrefix(upper, "CHACHA") || strings.HasPrefix(upper, "CAMELLIA") ||
			strings.HasPrefix(upper, "ARIA") || strings.HasPrefix(upper, "SEED") ||
			strings.HasPrefix(upper, "SERPENT") || strings.HasPrefix(upper, "TWOFISH") ||
			strings.HasPrefix(upper, "3DES") || upper == "RC4" {
			violations = append(violations, Violation{
				Algorithm:   name,
				Rule:        "asd-symmetric-unapproved",
				Message:     name + " is not an ASD ISM approved symmetric cipher; only AES-256 is approved",
				Deadline:    asdDeadlineFull,
				Remediation: "Replace with AES-256",
			})
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

		// --- Rule: SHA-384/512 (SHA-2 family) required ---
		if isHashFamily(upper) {
			// Distinguish SHA-2 from SHA-3 and BLAKE. ASD ISM approves only SHA-2.
			// SHA-3 variants use prefix "SHA-3-" or "SHA3-" or are bare "SHA-3"/"SHA3".
			// "SHA-384" starts with "SHA-3" letter-wise, so the SHA-3 check needs the trailing dash.
			isSHA3 := strings.HasPrefix(upper, "SHA3-") || strings.HasPrefix(upper, "SHA-3-") ||
				upper == "SHA3" || upper == "SHA-3"
			isSHA2 := (strings.HasPrefix(upper, "SHA-") || strings.HasPrefix(upper, "SHA2") ||
				upper == "SHA256" || upper == "SHA384" || upper == "SHA512") && !isSHA3
			isHMACSHA2 := strings.HasPrefix(upper, "HMAC-SHA") && !strings.Contains(upper, "SHA3")
			if !isSHA2 && !isHMACSHA2 {
				violations = append(violations, Violation{
					Algorithm:   name,
					Rule:        "asd-hash-unapproved",
					Message:     name + " is not an ASD ISM approved hash; only SHA-384 and SHA-512 (SHA-2 family) are approved",
					Deadline:    asdDeadlineFull,
					Remediation: "Replace with SHA-384 or SHA-512 (SHA-2 family); SHA-3 and BLAKE are not approved",
				})
				continue
			}
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
