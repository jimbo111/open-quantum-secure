package zeeklog

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/jimbo111/open-quantum-secure/pkg/findings"
	"github.com/jimbo111/open-quantum-secure/pkg/quantum"
)

const engineName = "zeek-log"

// sslRecordToFindings converts an SSLRecord into zero or more UnifiedFindings.
// Emits one finding per distinct algorithm observed in the record.
func sslRecordToFindings(rec SSLRecord) []findings.UnifiedFinding {
	var out []findings.UnifiedFinding
	target := fmt.Sprintf("%s:%s", rec.RespHost, rec.RespPort)
	if rec.ServerName != "" {
		target = rec.ServerName
	}

	// cipher → algorithm (informative for TLS 1.2 KEM identity)
	if rec.Cipher != "" {
		prim := cipherPrimitive(rec.Cipher)
		c := quantum.ClassifyAlgorithm(rec.Cipher, prim, 0)
		f := buildFinding(rec.Cipher, prim, 0, c, target, rec.RespHost, rec.RespPort, "ssl.log/cipher")
		out = append(out, f)
	}

	// curve / key-share group
	if rec.Curve != "" {
		c := quantum.ClassifyAlgorithm(rec.Curve, "key-agree", 0)
		f := buildFinding(rec.Curve, "key-agree", 0, c, target, rec.RespHost, rec.RespPort, "ssl.log/curve")
		// Annotate PQC-presence for hybrid/pure-ML-KEM groups.
		if gi, ok := quantum.ClassifyTLSGroup(tlsGroupCodepointByName(rec.Curve)); ok {
			f.PQCPresent = gi.PQCPresent
			f.PQCMaturity = gi.Maturity
			f.NegotiatedGroupName = gi.Name
		}
		out = append(out, f)
	}

	// Companion script key_share codepoints (comma-separated hex).
	// TODO(S5): wire companion script codepoint extraction from ssl.log pqc_key_share column
	// once Zeek 5+ supports the hook; for now, surface them as additional findings.
	for _, hexCP := range strings.Split(rec.PQCKeyShare, ",") {
		hexCP = strings.TrimSpace(hexCP)
		if hexCP == "" {
			continue
		}
		// Strip "0x" prefix if present.
		hexCP = strings.TrimPrefix(hexCP, "0x")
		cp64, err := strconv.ParseUint(hexCP, 16, 16)
		if err != nil {
			continue
		}
		cp := uint16(cp64)
		gi, ok := quantum.ClassifyTLSGroup(cp)
		if !ok {
			continue
		}
		c := quantum.ClassifyAlgorithm(gi.Name, "key-agree", 0)
		f := buildFinding(gi.Name, "key-agree", 0, c, target, rec.RespHost, rec.RespPort, "ssl.log/pqc_key_share")
		f.NegotiatedGroup = cp
		f.NegotiatedGroupName = gi.Name
		f.PQCPresent = gi.PQCPresent
		f.PQCMaturity = gi.Maturity
		out = append(out, f)
	}

	return out
}

// x509RecordToFindings converts an X509Record into UnifiedFindings.
func x509RecordToFindings(rec X509Record) []findings.UnifiedFinding {
	var out []findings.UnifiedFinding
	// Use first SAN DNS entry as target, fallback to cert fuid.
	target := rec.ID
	if rec.SANDNS != "" {
		// san.dns may be comma-separated in TSV (set_separator ,)
		parts := strings.SplitN(rec.SANDNS, ",", 2)
		if parts[0] != "" {
			target = parts[0]
		}
	}

	// Resolve sig_alg (may be raw OID from Zeek).
	sigAlg := rec.SigAlg
	if resolved, ok := resolveOIDAlgorithm(sigAlg); ok {
		sigAlg = resolved
	}
	if sigAlg != "" {
		c := quantum.ClassifyAlgorithm(sigAlg, "signature", 0)
		f := buildFinding(sigAlg, "signature", 0, c, target, "", "", "x509.log/sig_alg")
		out = append(out, f)
	}

	// Key algorithm + size from key_alg + key_type + key_length.
	keyAlg := rec.KeyAlg
	if resolved, ok := resolveOIDAlgorithm(keyAlg); ok {
		keyAlg = resolved
	}
	prim := keyTypeToPrimitive(rec.KeyType)
	if keyAlg != "" {
		c := quantum.ClassifyAlgorithm(keyAlg, prim, rec.KeyLen)
		f := buildFinding(keyAlg, prim, rec.KeyLen, c, target, "", "", "x509.log/key_alg")
		out = append(out, f)
	}

	return out
}

// buildFinding constructs a UnifiedFinding from a classification result.
func buildFinding(algName, primitive string, keySize int, c quantum.Classification,
	target, host, port, source string) findings.UnifiedFinding {
	// File field encodes the logical source location so DedupeKey produces
	// unique keys per (host, algorithm). Format: (zeek-log)/<target>#<alg>
	filePath := fmt.Sprintf("(zeek-log)/%s#%s", target, algName)

	f := findings.UnifiedFinding{
		Location: findings.Location{
			File: filePath,
			Line: 0,
		},
		Algorithm: &findings.Algorithm{
			Name:      algName,
			Primitive: primitive,
			KeySize:   keySize,
		},
		SourceEngine:   engineName,
		RawIdentifier:  algName,
		Confidence:     findings.ConfidenceMedium,
		Reachable:      findings.ReachableUnknown,
		QuantumRisk:    findings.QuantumRisk(c.Risk),
		Severity:       findings.Severity(c.Severity),
		Recommendation: c.Recommendation,
		HNDLRisk:       c.HNDLRisk,
		MigrationEffort: c.MigrationEffort,
		TargetAlgorithm: c.TargetAlgorithm,
		TargetStandard:  c.TargetStandard,
	}
	return f
}

// keyTypeToPrimitive maps Zeek x509 key_type to a quantum primitive string.
func keyTypeToPrimitive(kt string) string {
	switch strings.ToLower(kt) {
	case "rsa":
		return "asymmetric"
	case "ec", "ecdsa":
		return "signature"
	case "dh":
		return "key-agree"
	}
	return ""
}

// tlsGroupCodepointByName does a reverse lookup from group name to codepoint.
// Returns 0 when no entry is found — callers should check ClassifyTLSGroup(0)
// returns (GroupInfo{}, false) so they can skip the PQC annotation.
//
// TODO(S5): expose a reverse map from pkg/quantum/tls_groups.go to avoid
// the O(n) scan here.
var reverseGroupMap = func() map[string]uint16 {
	m := map[string]uint16{}
	knownNames := map[string]uint16{
		"X25519MLKEM768":     0x11EC,
		"SecP256r1MLKEM768":  0x11EB,
		"SecP384r1MLKEM1024": 0x11ED,
		"curveSM2MLKEM768":   0x11EE,
		"MLKEM512":           0x0200,
		"MLKEM768":           0x0201,
		"MLKEM1024":          0x0202,
		"secp256r1":          0x0017,
		"secp384r1":          0x0018,
		"secp521r1":          0x0019,
		"X25519":             0x001d,
		"X448":               0x001e,
		"ffdhe2048":          0x0100,
		"ffdhe3072":          0x0101,
		"ffdhe4096":          0x0102,
		"ffdhe6144":          0x0103,
		"ffdhe8192":          0x0104,
	}
	for k, v := range knownNames {
		m[k] = v
	}
	return m
}()

func tlsGroupCodepointByName(name string) uint16 {
	return reverseGroupMap[name]
}
