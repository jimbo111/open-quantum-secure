package suricatalog

import (
	"fmt"
	"strings"

	"github.com/jimbo111/open-quantum-secure/pkg/findings"
	"github.com/jimbo111/open-quantum-secure/pkg/quantum"
)

const engineName = "suricata-log"

// tlsRecordToFindings converts a TLSRecord into zero or more UnifiedFindings.
// Emits one finding per distinct algorithm observed in the record.
func tlsRecordToFindings(rec TLSRecord) []findings.UnifiedFinding {
	var out []findings.UnifiedFinding

	// Sanitize attacker-controlled fields before they reach UnifiedFinding.
	target := sanitizeTarget(fmt.Sprintf("%s:%s", rec.DestIP, rec.DestPort))
	if rec.SNI != "" {
		target = sanitizeTarget(rec.SNI)
	}

	cipher := sanitizeField(rec.CipherSuite)
	// cipher_suite → algorithm finding
	if cipher != "" {
		prim := cipherPrimitive(cipher)
		c := quantum.ClassifyAlgorithm(cipher, prim, 0)
		f := buildFinding(cipher, prim, 0, c, target, rec.DestIP, rec.DestPort, "eve.json/cipher_suite")
		out = append(out, f)
	}

	// JA3S-based PQC annotation: check if server fingerprint matches a known
	// PQC-enabled server stack. Corroborating signal — does not override cipher.
	if rec.JA3SHash != "" {
		if hint, ok := lookupJA3S(rec.JA3SHash); ok && hint.PQCPresent {
			// Annotate an additional finding via the "suricata-ja3s" source signal.
			algName := "PQC-Server-Stack"
			c := quantum.ClassifyAlgorithm("MLKEM768", "key-agree", 0)
			f := buildFinding(algName, "key-agree", 0, c, target, rec.DestIP, rec.DestPort, "eve.json/ja3s")
			f.PQCPresent = true
			f.PQCMaturity = "draft"
			f.RawIdentifier = "suricata-ja3s:" + rec.JA3SHash
			out = append(out, f)
		}
	}

	// Custom Suricata config: sigalgs field (comma-separated, e.g. "rsa_pkcs1_sha256,ecdsa_secp256r1_sha256")
	// Only present when contrib/suricata/oqs-tls.yaml is loaded.
	for _, sa := range splitCSV(sanitizeField(rec.SigAlgs)) {
		if sa == "" {
			continue
		}
		c := quantum.ClassifyAlgorithm(sa, "signature", 0)
		f := buildFinding(sa, "signature", 0, c, target, rec.DestIP, rec.DestPort, "eve.json/sigalgs")
		out = append(out, f)
	}

	// Custom Suricata config: groups field (comma-separated group names/codepoints)
	// Only present when contrib/suricata/oqs-tls.yaml is loaded.
	for _, grp := range splitCSV(sanitizeField(rec.Groups)) {
		if grp == "" {
			continue
		}
		c := quantum.ClassifyAlgorithm(grp, "key-agree", 0)
		f := buildFinding(grp, "key-agree", 0, c, target, rec.DestIP, rec.DestPort, "eve.json/groups")
		out = append(out, f)
	}

	return out
}

// buildFinding constructs a UnifiedFinding from a classification result.
func buildFinding(algName, primitive string, keySize int, c quantum.Classification,
	target, host, port, source string) findings.UnifiedFinding {
	// File field encodes the logical source location so DedupeKey produces
	// unique keys per (host, algorithm). Format: (suricata-log)/<target>#<alg>
	filePath := fmt.Sprintf("(suricata-log)/%s#%s", sanitizeTarget(target), sanitizeField(algName))

	return findings.UnifiedFinding{
		Location: findings.Location{
			File: filePath,
			Line: 0,
		},
		Algorithm: &findings.Algorithm{
			Name:      algName,
			Primitive: primitive,
			KeySize:   keySize,
		},
		SourceEngine:    engineName,
		RawIdentifier:   algName,
		Confidence:      findings.ConfidenceMedium,
		Reachable:       findings.ReachableUnknown,
		QuantumRisk:     findings.QuantumRisk(c.Risk),
		Severity:        findings.Severity(c.Severity),
		Recommendation:  c.Recommendation,
		HNDLRisk:        c.HNDLRisk,
		MigrationEffort: c.MigrationEffort,
		TargetAlgorithm: c.TargetAlgorithm,
		TargetStandard:  c.TargetStandard,
	}
}

// cipherPrimitive maps a TLS cipher suite name to its quantum primitive.
// TLS 1.3 suites use AEAD-only names (no KEX component); classified as symmetric.
// TLS 1.2 suites embed key exchange, e.g. ECDHE_RSA → key-agree for the group part.
func cipherPrimitive(cipher string) string {
	u := strings.ToUpper(cipher)
	switch {
	case strings.Contains(u, "ECDHE") || strings.Contains(u, "DHE") || strings.Contains(u, "DH_"):
		return "key-agree"
	case strings.Contains(u, "RSA"):
		return "asymmetric"
	case strings.Contains(u, "ECDSA"):
		return "signature"
	default:
		// TLS 1.3 suites (AES_128_GCM_SHA256, etc.) are symmetric.
		return "symmetric"
	}
}

// splitCSV splits a comma-separated value string and trims whitespace.
func splitCSV(s string) []string {
	if s == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}
