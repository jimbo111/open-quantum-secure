package zeeklog

import "strings"

// normalizeTLSVersion maps Zeek TLS version strings to canonical form.
// Zeek emits "TLSv12", "TLSv13", "SSLv3" etc.
func normalizeTLSVersion(v string) string {
	switch strings.ToLower(strings.ReplaceAll(v, " ", "")) {
	case "tlsv13", "tls1.3", "tls13":
		return "1.3"
	case "tlsv12", "tls1.2", "tls12":
		return "1.2"
	case "tlsv11", "tls1.1", "tls11":
		return "1.1"
	case "tlsv10", "tls1.0", "tls10":
		return "1.0"
	case "sslv3", "ssl3", "sslv2", "ssl2":
		return v
	}
	return v
}

// oidToAlgorithm maps PQC OIDs (as strings) to canonical algorithm names.
// Zeek may emit raw OID strings when it cannot decode a certificate field.
// Sources: NIST SP 800-208; ML-KEM IANA registry.
var oidToAlgorithm = map[string]string{
	// ML-DSA (FIPS 204)
	"2.16.840.1.101.3.4.3.17": "ML-DSA-44",
	"2.16.840.1.101.3.4.3.18": "ML-DSA-65",
	"2.16.840.1.101.3.4.3.19": "ML-DSA-87",
	// SLH-DSA (FIPS 205) — SHA2 variants
	"2.16.840.1.101.3.4.3.20": "SLH-DSA-SHA2-128s",
	"2.16.840.1.101.3.4.3.21": "SLH-DSA-SHA2-128f",
	"2.16.840.1.101.3.4.3.22": "SLH-DSA-SHA2-192s",
	"2.16.840.1.101.3.4.3.23": "SLH-DSA-SHA2-192f",
	"2.16.840.1.101.3.4.3.24": "SLH-DSA-SHA2-256s",
	"2.16.840.1.101.3.4.3.25": "SLH-DSA-SHA2-256f",
	// SLH-DSA (FIPS 205) — SHAKE variants
	"2.16.840.1.101.3.4.3.26": "SLH-DSA-SHAKE-128s",
	"2.16.840.1.101.3.4.3.27": "SLH-DSA-SHAKE-128f",
	"2.16.840.1.101.3.4.3.28": "SLH-DSA-SHAKE-192s",
	"2.16.840.1.101.3.4.3.29": "SLH-DSA-SHAKE-192f",
	"2.16.840.1.101.3.4.3.30": "SLH-DSA-SHAKE-256s",
	"2.16.840.1.101.3.4.3.31": "SLH-DSA-SHAKE-256f",
	// ML-KEM (FIPS 203)
	"2.16.840.1.101.3.4.4.1": "ML-KEM-512",
	"2.16.840.1.101.3.4.4.2": "ML-KEM-768",
	"2.16.840.1.101.3.4.4.3": "ML-KEM-1024",
}

// resolveOIDAlgorithm looks up a raw OID or algorithm name.
// If the input looks like "unknown <OID>" (Zeek's fallback format), extracts the OID.
// Returns the canonical name and true if resolved, otherwise ("", false).
func resolveOIDAlgorithm(raw string) (string, bool) {
	raw = strings.TrimSpace(raw)
	if name, ok := oidToAlgorithm[raw]; ok {
		return name, true
	}
	// Zeek unknown OID format: "unknown <dotted-oid>"
	if after, found := strings.CutPrefix(raw, "unknown "); found {
		oid := strings.TrimSpace(after)
		if name, ok := oidToAlgorithm[oid]; ok {
			return name, true
		}
	}
	return "", false
}

// curveNameToGroup maps Zeek ssl.log curve field values to TLS group names
// recognizable by ClassifyAlgorithm. Zeek uses lowercase with underscores.
func curveNameToGroup(curve string) string {
	switch strings.ToLower(curve) {
	case "secp256r1", "prime256v1":
		return "secp256r1"
	case "secp384r1":
		return "secp384r1"
	case "secp521r1":
		return "secp521r1"
	case "x25519":
		return "X25519"
	case "x448":
		return "X448"
	// Companion script emits hybrid KEX names directly.
	case "x25519mlkem768":
		return "X25519MLKEM768"
	case "secp256r1mlkem768":
		return "SecP256r1MLKEM768"
	case "secp384r1mlkem1024":
		return "SecP384r1MLKEM1024"
	case "curvesm2mlkem768":
		return "curveSM2MLKEM768"
	// Pure ML-KEM
	case "mlkem512":
		return "MLKEM512"
	case "mlkem768":
		return "MLKEM768"
	case "mlkem1024":
		return "MLKEM1024"
	}
	if curve == "" || curve == "-" {
		return ""
	}
	return curve
}

// cipherPrimitive returns the crypto primitive for a TLS cipher suite name.
// For TLS 1.3 AEAD-only suites the KEX is not encoded in the cipher name.
func cipherPrimitive(cipher string) string {
	u := strings.ToUpper(cipher)
	switch {
	case strings.Contains(u, "ECDH") || strings.Contains(u, "DHE"):
		return "key-agree"
	case strings.Contains(u, "RSA"):
		return "asymmetric"
	}
	// TLS_AES_* and TLS_CHACHA20_* are TLS 1.3 AEAD-only — symmetric.
	if strings.HasPrefix(u, "TLS_AES_") || strings.HasPrefix(u, "TLS_CHACHA20_") {
		return "ae"
	}
	return ""
}
