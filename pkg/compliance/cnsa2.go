// Package compliance implements compliance framework evaluation for scan findings.
// Supported frameworks are registered via framework.go's registry; each framework
// file calls Register() from its init().
package compliance

import (
	"strings"

	"github.com/jimbo111/open-quantum-secure/pkg/findings"
)

// Standard is a compliance standard identifier (used by the CLI --compliance flag
// and main.go for backward-compatible handling).
type Standard string

const (
	// StandardCNSA20 is the NSA CNSA 2.0 suite (May 2025 update).
	StandardCNSA20 Standard = "cnsa-2.0"
)

// CNSA 2.0 deadlines (NSA guidance, May 2025 update).
const (
	deadlineKeyExchange = "2030-01-01" // all NSS must use PQC for key exchange by this date
	deadlineFull        = "2035-12-31" // full transition complete
)

// cnsa20Framework implements Framework for NSA CNSA 2.0 (May 2025 update).
// Source: NSA CNSA 2.0 Algorithm Suite, Sep 2022 + May 2025 clarification memo.
// https://media.defense.gov/2022/Sep/07/2003071834/-1/-1/0/CSA_CNSA_2.0_ALGORITHMS_.PDF
type cnsa20Framework struct{}

func (cnsa20Framework) ID() string          { return "cnsa-2.0" }
func (cnsa20Framework) Name() string        { return "CNSA 2.0" }
func (cnsa20Framework) Description() string { return "NSA CNSA 2.0 (May 2025)" }

func (cnsa20Framework) ApprovedAlgos() []ApprovedAlgoRef {
	return []ApprovedAlgoRef{
		{"Key Exchange", "ML-KEM-1024", "FIPS 203"},
		{"Digital Signatures", "ML-DSA-87", "FIPS 204"},
		{"Firmware/Software Signing", "LMS/HSS, XMSS/XMSS^MT", "SP 800-208"},
		{"Symmetric Encryption", "AES-256", "FIPS 197"},
		{"Hashing", "SHA-384, SHA-512", "FIPS 180-4"},
	}
}

func (cnsa20Framework) Deadlines() []DeadlineRef {
	return []DeadlineRef{
		{"2030-01-01", "All key exchange must use ML-KEM-1024"},
		{"2035-12-31", "Full CNSA 2.0 transition complete"},
	}
}

// Evaluate checks each finding in ff against CNSA 2.0 rules and returns all
// violations found. The returned slice is nil when there are no violations.
//
// CNSA 2.0 rules applied:
//   - SLH-DSA: excluded despite NIST FIPS 205 approval
//   - HashML-DSA: not approved
//   - ML-KEM: only ML-KEM-1024 is approved (ML-KEM-512 and ML-KEM-768 are insufficient)
//   - ML-DSA: only ML-DSA-87 is approved (ML-DSA-44 and ML-DSA-65 are insufficient)
//   - Symmetric: AES-256 required (AES-128/192 insufficient)
//   - Hash: SHA-384 or SHA-512 required (SHA-256 insufficient)
//   - Quantum-vulnerable algorithms: violation with appropriate deadline
func (cnsa20Framework) Evaluate(ff []findings.UnifiedFinding) []Violation {
	var violations []Violation

	for i := range ff {
		f := &ff[i]
		if f.Algorithm == nil {
			// Dependency finding with no algorithm — only flag if quantum-vulnerable.
			if f.QuantumRisk == findings.QRVulnerable {
				violations = append(violations, newCNSA2Violation(
					f.RawIdentifier,
					"cnsa2-quantum-vulnerable",
					"quantum-vulnerable dependency must be replaced with CNSA 2.0 approved algorithms",
					deadlineForHNDL(f.HNDLRisk),
				))
			}
			continue
		}

		name := f.Algorithm.Name
		upper := strings.ToUpper(name)
		keySize := f.Algorithm.KeySize

		// --- Rule: quantum-vulnerable algorithms ---
		if f.QuantumRisk == findings.QRVulnerable || f.QuantumRisk == findings.QRDeprecated {
			violations = append(violations, newCNSA2Violation(
				name,
				"cnsa2-quantum-vulnerable",
				name+" is quantum-vulnerable and not approved for CNSA 2.0; migrate to an approved PQC algorithm",
				deadlineForHNDL(f.HNDLRisk),
			))
			continue
		}

		// --- Rule: SLH-DSA excluded ---
		// SLH-DSA (FIPS 205) is not approved by NSA CNSA 2.0 despite NIST standardisation.
		if strings.HasPrefix(upper, "SLH-DSA") {
			violations = append(violations, newCNSA2Violation(
				name,
				"cnsa2-slh-dsa-excluded",
				"SLH-DSA is excluded from CNSA 2.0 despite NIST FIPS 205 approval; use ML-DSA-87 instead",
				deadlineFull,
			))
			continue
		}

		// --- Rule: HashML-DSA excluded ---
		if strings.HasPrefix(upper, "HASHML-DSA") || upper == "HASH-ML-DSA" {
			violations = append(violations, newCNSA2Violation(
				name,
				"cnsa2-hashml-dsa-excluded",
				"HashML-DSA is not approved for CNSA 2.0; use ML-DSA-87 instead",
				deadlineFull,
			))
			continue
		}

		// --- Rule: HQC not yet CNSA 2.0 approved ---
		// HQC was selected by NIST as the 5th PQC standard (March 2025) but is not
		// yet included in NSA CNSA 2.0. Use ML-KEM-1024 for CNSA 2.0 compliance.
		if strings.HasPrefix(upper, "HQC") {
			violations = append(violations, newCNSA2Violation(
				name,
				"cnsa2-hqc-not-approved",
				"HQC is not yet approved for CNSA 2.0; use ML-KEM-1024 instead",
				deadlineKeyExchange,
			))
			continue
		}

		// --- Rule: hybrid KEM below ML-KEM-1024 grade ---
		// CNSA 2.0 requires ML-KEM-1024 for key exchange. Hybrid KEMs that use a
		// sub-1024 ML-KEM variant (e.g. X25519MLKEM768) do not meet the grade requirement.
		if isHybridKEM(f) {
			variant := mlVariantLevel(name)
			if variant > 0 && variant < 1024 {
				violations = append(violations, newCNSA2Violation(
					name,
					"cnsa2-hybrid-sub-1024",
					"CNSA 2.0 requires ML-KEM-1024; "+name+" is a hybrid KEM using a sub-1024 ML-KEM variant — upgrade to use ML-KEM-1024",
					deadlineKeyExchange,
				))
			}
			continue
		}

		// --- Rule: ML-KEM key size minimum ---
		// CNSA 2.0 requires ML-KEM-1024. ML-KEM-512 and ML-KEM-768 are insufficient.
		// Matches both hyphenated ("ML-KEM-768") and hyphen-less ("MLKEM768") forms.
		if isMLKEMName(name) {
			variant := mlVariantLevel(name)
			if variant > 0 && variant < 1024 {
				violations = append(violations, newCNSA2Violation(
					name,
					"cnsa2-ml-kem-key-size",
					"CNSA 2.0 requires ML-KEM-1024; "+name+" is insufficient — upgrade to ML-KEM-1024",
					deadlineKeyExchange,
				))
			}
			continue
		}

		// --- Rule: ML-DSA parameter set minimum ---
		// CNSA 2.0 requires ML-DSA-87. ML-DSA-44 and ML-DSA-65 are insufficient.
		// Matches both hyphenated ("ML-DSA-44") and hyphen-less ("MLDSA44") forms.
		if isMLDSAName(name) {
			variant := mlVariantLevel(name)
			if variant > 0 && variant < 87 {
				violations = append(violations, newCNSA2Violation(
					name,
					"cnsa2-ml-dsa-param-set",
					"CNSA 2.0 requires ML-DSA-87; "+name+" is insufficient — upgrade to ML-DSA-87",
					deadlineFull,
				))
			}
			continue
		}

		// Note: LMS/HSS and XMSS/XMSS^MT are ALL approved per NIST SP 800-208.
		// HSS is the multi-tree generalization of LMS; XMSS^MT is the multi-tree
		// generalization of XMSS. Both are approved for firmware/software signing.

		// --- Rule: AES-256 required (ARIA and other non-AES ciphers are NOT approved) ---
		if strings.HasPrefix(upper, "ARIA") || strings.HasPrefix(upper, "CAMELLIA") ||
			strings.HasPrefix(upper, "CHACHA") || strings.HasPrefix(upper, "SEED") ||
			strings.HasPrefix(upper, "TWOFISH") || strings.HasPrefix(upper, "SERPENT") {
			violations = append(violations, newCNSA2Violation(
				name,
				"cnsa2-symmetric-unapproved",
				name+" is not a CNSA 2.0 approved symmetric cipher; only AES-256 is approved",
				deadlineFull,
			))
			continue
		}
		if strings.HasPrefix(upper, "AES") {
			effective := resolveSymmetricKeySize(upper, keySize)
			if effective > 0 && effective < 256 {
				violations = append(violations, newCNSA2Violation(
					name,
					"cnsa2-symmetric-key-size",
					"CNSA 2.0 requires AES-256 (or equivalent 256-bit symmetric); "+name+" has insufficient key size — upgrade to AES-256",
					deadlineFull,
				))
			}
			continue
		}

		// --- Rule: SHA-384 or SHA-512 required (SHA-2 family ONLY) ---
		// CNSA 2.0 approves only SHA-384 and SHA-512 from the SHA-2 family.
		// SHA-3, BLAKE, and other hash families are NOT approved.
		if isHashFamily(upper) {
			// Check if it's SHA-2 family (not SHA-3 or other).
			// Note: "SHA-384" starts with "SHA-3" so we must check for "SHA-3-" (with trailing dash)
			// or "SHA3-" to distinguish SHA-2's SHA-384 from SHA-3 variants like SHA-3-256.
			isSHA3 := strings.HasPrefix(upper, "SHA3-") || strings.HasPrefix(upper, "SHA-3-") || upper == "SHA3" || upper == "SHA-3"
			isSHA2 := (strings.HasPrefix(upper, "SHA-") || strings.HasPrefix(upper, "SHA2") ||
				upper == "SHA256" || upper == "SHA384" || upper == "SHA512") && !isSHA3
			isHMACSHA2 := strings.HasPrefix(upper, "HMAC-SHA") && !strings.Contains(upper, "SHA3")
			if !isSHA2 && !isHMACSHA2 {
				violations = append(violations, newCNSA2Violation(
					name,
					"cnsa2-hash-unapproved",
					name+" is not a CNSA 2.0 approved hash; only SHA-384 and SHA-512 (SHA-2 family) are approved",
					deadlineFull,
				))
				continue
			}
			size := resolveHashOutputSize(upper, keySize)
			if size > 0 && size < 384 {
				violations = append(violations, newCNSA2Violation(
					name,
					"cnsa2-hash-output-size",
					"CNSA 2.0 requires SHA-384 or SHA-512; "+name+" has insufficient output size — upgrade to SHA-384 or SHA-512",
					deadlineFull,
				))
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
	Register(cnsa20Framework{})
}

// Evaluate is a package-level shim for backward compatibility with callers
// that do not need to select the framework (e.g. existing main.go paths).
func Evaluate(ff []findings.UnifiedFinding) []Violation {
	return cnsa20Framework{}.Evaluate(ff)
}

// newCNSA2Violation constructs a Violation with Remediation populated via
// remediationForRule so that the generic report generator can render it.
func newCNSA2Violation(algorithm, rule, message, deadline string) Violation {
	return Violation{
		Algorithm:   algorithm,
		Rule:        rule,
		Message:     message,
		Deadline:    deadline,
		Remediation: remediationForRule(rule, algorithm),
	}
}

// deadlineForHNDL returns the appropriate CNSA 2.0 deadline based on HNDL risk.
// Key exchange has an earlier (2030) deadline than other algorithms (2035).
func deadlineForHNDL(hndlRisk string) string {
	if hndlRisk == "immediate" {
		return deadlineKeyExchange
	}
	return deadlineFull
}

// resolveSymmetricKeySize returns the effective key size for a symmetric algorithm.
// It tries the provided keySize first, then infers from the name.
func resolveSymmetricKeySize(upperName string, keySize int) int {
	if keySize > 0 {
		return keySize
	}
	switch {
	case strings.Contains(upperName, "256"):
		return 256
	case strings.Contains(upperName, "192"):
		return 192
	case strings.Contains(upperName, "128"):
		return 128
	}
	return 0
}

// resolveHashOutputSize returns the hash output size in bits.
// It tries the provided keySize first, then infers from the name.
func resolveHashOutputSize(upperName string, keySize int) int {
	if keySize > 0 {
		return keySize
	}
	switch {
	case strings.Contains(upperName, "512"):
		return 512
	case strings.Contains(upperName, "384"):
		return 384
	case strings.Contains(upperName, "256"):
		return 256
	case strings.Contains(upperName, "224"):
		return 224
	case strings.Contains(upperName, "160"):
		return 160
	case strings.Contains(upperName, "128"):
		return 128
	}
	return 0
}

// isHashFamily returns true when the algorithm name looks like a hash or MAC family
// that is subject to the CNSA 2.0 output-size rule.
func isHashFamily(upper string) bool {
	hashPrefixes := []string{"SHA", "SHA-", "SHA2", "SHA3", "BLAKE", "HMAC-SHA", "HMAC"}
	for _, p := range hashPrefixes {
		if strings.HasPrefix(upper, p) {
			return true
		}
	}
	return false
}

// remediationForRule returns actionable remediation text for a known CNSA 2.0 rule ID.
func remediationForRule(rule, algorithm string) string {
	switch rule {
	case "cnsa2-quantum-vulnerable":
		upper := strings.ToUpper(algorithm)
		switch {
		case strings.HasPrefix(upper, "RSA"), strings.HasPrefix(upper, "DH"),
			strings.Contains(upper, "DIFFIE"):
			return "Migrate to ML-KEM-1024 for key exchange or ML-DSA-87 for digital signatures"
		case strings.HasPrefix(upper, "EC"), strings.HasPrefix(upper, "ECDH"),
			strings.HasPrefix(upper, "ECDSA"):
			return "Migrate to ML-KEM-1024 for key exchange or ML-DSA-87 for digital signatures"
		case strings.HasPrefix(upper, "DSA"):
			return "Migrate to ML-DSA-87 for digital signatures"
		default:
			return "Replace with an approved CNSA 2.0 algorithm (ML-KEM-1024, ML-DSA-87, AES-256, SHA-384/SHA-512)"
		}
	case "cnsa2-hybrid-sub-1024":
		return "Upgrade the ML-KEM component to ML-KEM-1024; CNSA 2.0 requires the 1024 parameter set regardless of hybrid configuration"
	case "cnsa2-ml-kem-key-size":
		return "Upgrade to ML-KEM-1024; ML-KEM-512 and ML-KEM-768 do not meet CNSA 2.0 minimum"
	case "cnsa2-ml-dsa-param-set":
		return "Upgrade to ML-DSA-87; ML-DSA-44 and ML-DSA-65 do not meet CNSA 2.0 minimum"
	case "cnsa2-slh-dsa-excluded":
		return "Replace with ML-DSA-87; SLH-DSA (FIPS 205) is excluded from CNSA 2.0 despite NIST approval"
	case "cnsa2-hashml-dsa-excluded":
		return "Replace with ML-DSA-87; HashML-DSA is not approved for CNSA 2.0"
	case "cnsa2-symmetric-key-size":
		return "Upgrade to AES-256; smaller AES key sizes do not meet CNSA 2.0 requirements"
	case "cnsa2-symmetric-unapproved":
		return "Replace with AES-256; only AES is approved for symmetric encryption under CNSA 2.0"
	case "cnsa2-hash-output-size":
		return "Upgrade to SHA-384 or SHA-512; shorter hash outputs do not meet CNSA 2.0 requirements"
	case "cnsa2-hash-unapproved":
		return "Replace with SHA-384 or SHA-512 (SHA-2 family only); SHA-3 and other hash families are not approved"
	default:
		return "Review and remediate per the applicable compliance framework guidance"
	}
}
