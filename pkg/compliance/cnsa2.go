// Package compliance implements compliance framework evaluation for scan findings.
// Currently supports CNSA 2.0 (NSA Commercial National Security Algorithm Suite 2.0,
// May 2025 update).
package compliance

import (
	"strings"

	"github.com/jimbo111/open-quantum-secure/pkg/findings"
)

// Standard is a compliance standard identifier.
type Standard string

const (
	// StandardCNSA20 is the NSA CNSA 2.0 suite (May 2025 update).
	StandardCNSA20 Standard = "cnsa-2.0"
)

// Violation is a single CNSA 2.0 rule breach for a finding.
type Violation struct {
	// Algorithm is the algorithm name that triggered the violation (may be empty
	// for quantum-vulnerable dependency findings).
	Algorithm string

	// Rule is the machine-readable rule identifier (e.g. "cnsa2-slh-dsa-excluded").
	Rule string

	// Message is the human-readable description.
	Message string

	// Deadline is the ISO 8601 date by which the issue must be resolved.
	// "2027-01-01" for key exchange, "2035-12-31" for all others.
	Deadline string
}

// CNSA 2.0 deadlines (NSA guidance, May 2025 update).
const (
	deadlineKeyExchange = "2030-01-01" // all NSS must use PQC for key exchange by this date
	deadlineFull        = "2035-12-31" // full transition complete
)

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
func Evaluate(ff []findings.UnifiedFinding) []Violation {
	var violations []Violation

	for i := range ff {
		f := &ff[i]
		if f.Algorithm == nil {
			// Dependency finding with no algorithm — only flag if quantum-vulnerable.
			if f.QuantumRisk == findings.QRVulnerable {
				violations = append(violations, Violation{
					Algorithm: f.RawIdentifier,
					Rule:      "cnsa2-quantum-vulnerable",
					Message:   "quantum-vulnerable dependency must be replaced with CNSA 2.0 approved algorithms",
					Deadline:  deadlineForHNDL(f.HNDLRisk),
				})
			}
			continue
		}

		name := f.Algorithm.Name
		upper := strings.ToUpper(name)
		keySize := f.Algorithm.KeySize

		// --- Rule: quantum-vulnerable algorithms ---
		if f.QuantumRisk == findings.QRVulnerable || f.QuantumRisk == findings.QRDeprecated {
			violations = append(violations, Violation{
				Algorithm: name,
				Rule:      "cnsa2-quantum-vulnerable",
				Message:   name + " is quantum-vulnerable and not approved for CNSA 2.0; migrate to an approved PQC algorithm",
				Deadline:  deadlineForHNDL(f.HNDLRisk),
			})
			continue
		}

		// --- Rule: SLH-DSA excluded ---
		// SLH-DSA (FIPS 205) is not approved by NSA CNSA 2.0 despite NIST standardisation.
		if strings.HasPrefix(upper, "SLH-DSA") {
			violations = append(violations, Violation{
				Algorithm: name,
				Rule:      "cnsa2-slh-dsa-excluded",
				Message:   "SLH-DSA is excluded from CNSA 2.0 despite NIST FIPS 205 approval; use ML-DSA-87 instead",
				Deadline:  deadlineFull,
			})
			continue
		}

		// --- Rule: HashML-DSA excluded ---
		if strings.HasPrefix(upper, "HASHML-DSA") || upper == "HASH-ML-DSA" {
			violations = append(violations, Violation{
				Algorithm: name,
				Rule:      "cnsa2-hashml-dsa-excluded",
				Message:   "HashML-DSA is not approved for CNSA 2.0; use ML-DSA-87 instead",
				Deadline:  deadlineFull,
			})
			continue
		}

		// --- Rule: HQC not yet CNSA 2.0 approved ---
		// HQC was selected by NIST as the 5th PQC standard (March 2025) but is not
		// yet included in NSA CNSA 2.0. Use ML-KEM-1024 for CNSA 2.0 compliance.
		if strings.HasPrefix(upper, "HQC") {
			violations = append(violations, Violation{
				Algorithm: name,
				Rule:      "cnsa2-hqc-not-approved",
				Message:   "HQC is not yet approved for CNSA 2.0; use ML-KEM-1024 instead",
				Deadline:  deadlineKeyExchange,
			})
			continue
		}

		// --- Rule: ML-KEM key size minimum ---
		// CNSA 2.0 requires ML-KEM-1024. ML-KEM-512 and ML-KEM-768 are insufficient.
		if strings.HasPrefix(upper, "ML-KEM") {
			variant := mlVariantLevel(name)
			if variant > 0 && variant < 1024 {
				violations = append(violations, Violation{
					Algorithm: name,
					Rule:      "cnsa2-ml-kem-key-size",
					Message:   "CNSA 2.0 requires ML-KEM-1024; " + name + " is insufficient — upgrade to ML-KEM-1024",
					Deadline:  deadlineKeyExchange,
				})
			}
			continue
		}

		// --- Rule: ML-DSA parameter set minimum ---
		// CNSA 2.0 requires ML-DSA-87. ML-DSA-44 and ML-DSA-65 are insufficient.
		if strings.HasPrefix(upper, "ML-DSA") {
			variant := mlVariantLevel(name)
			if variant > 0 && variant < 87 {
				violations = append(violations, Violation{
					Algorithm: name,
					Rule:      "cnsa2-ml-dsa-param-set",
					Message:   "CNSA 2.0 requires ML-DSA-87; " + name + " is insufficient — upgrade to ML-DSA-87",
					Deadline:  deadlineFull,
				})
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
			violations = append(violations, Violation{
				Algorithm: name,
				Rule:      "cnsa2-symmetric-unapproved",
				Message:   name + " is not a CNSA 2.0 approved symmetric cipher; only AES-256 is approved",
				Deadline:  deadlineFull,
			})
			continue
		}
		if strings.HasPrefix(upper, "AES") {
			effective := resolveSymmetricKeySize(upper, keySize)
			if effective > 0 && effective < 256 {
				violations = append(violations, Violation{
					Algorithm: name,
					Rule:      "cnsa2-symmetric-key-size",
					Message:   "CNSA 2.0 requires AES-256 (or equivalent 256-bit symmetric); " + name + " has insufficient key size — upgrade to AES-256",
					Deadline:  deadlineFull,
				})
			}
			continue
		}

		// --- Rule: SHA-384 or SHA-512 required (SHA-2 family ONLY) ---
		// CNSA 2.0 approves only SHA-384 and SHA-512 from the SHA-2 family.
		// SHA-3, BLAKE, and other hash families are NOT approved.
		if isHashFamily(upper) {
			// Check if it's SHA-2 family (not SHA-3 or other).
			// Note: "SHA-384" starts with "SHA-3" so we must check for "SHA-3-" or "SHA3-"
			// to distinguish SHA-2's SHA-384 from SHA-3 variants like SHA-3-256.
			isSHA3 := strings.HasPrefix(upper, "SHA3-") || strings.HasPrefix(upper, "SHA-3-") || upper == "SHA3" || upper == "SHA-3"
			isSHA2 := (strings.HasPrefix(upper, "SHA-") || strings.HasPrefix(upper, "SHA2") ||
				upper == "SHA256" || upper == "SHA384" || upper == "SHA512") && !isSHA3
			isHMACSHA2 := strings.HasPrefix(upper, "HMAC-SHA") && !strings.Contains(upper, "SHA3")
			if !isSHA2 && !isHMACSHA2 {
				violations = append(violations, Violation{
					Algorithm: name,
					Rule:      "cnsa2-hash-unapproved",
					Message:   name + " is not a CNSA 2.0 approved hash; only SHA-384 and SHA-512 (SHA-2 family) are approved",
					Deadline:  deadlineFull,
				})
				continue
			}
			size := resolveHashOutputSize(upper, keySize)
			if size > 0 && size < 384 {
				violations = append(violations, Violation{
					Algorithm: name,
					Rule:      "cnsa2-hash-output-size",
					Message:   "CNSA 2.0 requires SHA-384 or SHA-512; " + name + " has insufficient output size — upgrade to SHA-384 or SHA-512",
					Deadline:  deadlineFull,
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

// deadlineForHNDL returns the appropriate CNSA 2.0 deadline based on HNDL risk.
// Key exchange has an earlier (2027) deadline than other algorithms (2035).
func deadlineForHNDL(hndlRisk string) string {
	if hndlRisk == "immediate" {
		return deadlineKeyExchange
	}
	return deadlineFull
}

// mlVariantLevel extracts the numeric parameter level from an ML-KEM or ML-DSA
// name. For example: "ML-KEM-768" → 768, "ML-DSA-44" → 44, "ML-KEM" → 0.
// Returns 0 when no numeric suffix is present.
func mlVariantLevel(name string) int {
	// Find the last '-' and parse the suffix as an integer.
	idx := strings.LastIndex(name, "-")
	if idx < 0 || idx == len(name)-1 {
		return 0
	}
	suffix := name[idx+1:]
	n := 0
	for _, ch := range suffix {
		if ch < '0' || ch > '9' {
			return 0
		}
		n = n*10 + int(ch-'0')
	}
	return n
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
