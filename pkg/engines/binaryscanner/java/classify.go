package java

import "strings"

// ClassifiedAlgorithm holds the parsed fields from a JCA algorithm string.
type ClassifiedAlgorithm struct {
	Name      string
	Mode      string
	Primitive string
	KeySize   int
}

// knownCryptoClasses is the set of JCA class simple names that represent
// cryptographic operations. Used when scanning constant-pool class references.
var knownCryptoClasses = map[string]bool{
	"Cipher":                      true,
	"KeyGenerator":                true,
	"Mac":                         true,
	"KeyAgreement":                true,
	"MessageDigest":               true,
	"Signature":                   true,
	"KeyPairGenerator":            true,
	"KeyFactory":                  true,
	"SecretKeyFactory":            true,
	"SSLContext":                  true,
	"SecureRandom":                true,
	"AlgorithmParameters":         true,
	"AlgorithmParameterGenerator": true,
	"CertificateFactory":          true,
	"CertPathValidator":           true,
	"TrustManagerFactory":         true,
	"KeyManagerFactory":           true,
	"KeyStore":                    true,
}

// classifyAlgorithmString attempts to recognise s as a JCA/JCE algorithm
// transform string (e.g. "AES/GCM/NoPadding") and returns a structured
// description. Returns nil when s is not a crypto identifier.
func classifyAlgorithmString(s string) *ClassifiedAlgorithm {
	if s == "" {
		return nil
	}

	// Reject strings that look like package paths, generic words, or encodings.
	if isNonCryptoString(s) {
		return nil
	}

	up := strings.ToUpper(s)

	// --- TLS / SSL protocol identifiers ---
	if strings.HasPrefix(up, "TLSV") || strings.HasPrefix(up, "SSLV") ||
		strings.EqualFold(s, "TLS") || strings.EqualFold(s, "SSL") ||
		strings.EqualFold(s, "TLSv1") || strings.EqualFold(s, "TLSv1.1") ||
		strings.EqualFold(s, "TLSv1.2") || strings.EqualFold(s, "TLSv1.3") ||
		strings.EqualFold(s, "SSLv2") || strings.EqualFold(s, "SSLv3") {
		mode := extractVersionSuffix(s)
		return &ClassifiedAlgorithm{Name: "TLS", Mode: mode, Primitive: "protocol"}
	}

	// --- PBKDF2 / KDF ---
	if strings.HasPrefix(up, "PBKDF2") {
		return &ClassifiedAlgorithm{Name: s, Primitive: "kdf"}
	}
	if up == "HKDF" || up == "SCRYPT" || up == "BCRYPT" || up == "ARGON2" {
		return &ClassifiedAlgorithm{Name: s, Primitive: "kdf"}
	}

	// --- HMAC ---
	if strings.HasPrefix(up, "HMAC") || strings.HasPrefix(up, "HMACSHA") {
		mode := ""
		if strings.Contains(up, "SHA") {
			// e.g. HmacSHA256 → mode=SHA-256
			mode = hmacMode(s)
		}
		return &ClassifiedAlgorithm{Name: "HMAC", Mode: mode, Primitive: "mac"}
	}

	// --- ChaCha20-Poly1305 (AEAD) ---
	if strings.HasPrefix(up, "CHACHA20") {
		return &ClassifiedAlgorithm{Name: s, Primitive: "ae"}
	}

	// --- JCA transform format: ALG/MODE/PADDING ---
	if strings.Contains(s, "/") {
		return classifyTransform(s)
	}

	// --- Signature / EC (check before hash — SHA256withECDSA is a signature) ---
	if sigPrim := signaturePrimitive(up); sigPrim != "" {
		return &ClassifiedAlgorithm{Name: s, Primitive: sigPrim}
	}

	// --- Hash algorithms ---
	if prim := hashPrimitive(up); prim != "" {
		return &ClassifiedAlgorithm{Name: s, Primitive: prim}
	}

	// --- Key-exchange ---
	if up == "DH" || up == "ECDH" || up == "X25519" || up == "X448" || up == "XDH" {
		return &ClassifiedAlgorithm{Name: s, Primitive: "key-exchange"}
	}

	// --- Symmetric ciphers (no mode suffix) ---
	if symPrim := symmetricPrimitive(up); symPrim != "" {
		return &ClassifiedAlgorithm{Name: s, Primitive: symPrim}
	}

	// --- AES alone ---
	if up == "AES" {
		return &ClassifiedAlgorithm{Name: "AES", Primitive: "symmetric"}
	}

	// --- RSA alone ---
	if up == "RSA" {
		return &ClassifiedAlgorithm{Name: "RSA", Primitive: "pke"}
	}

	return nil
}

// classifyTransform handles "ALG/MODE/PADDING" style strings.
func classifyTransform(s string) *ClassifiedAlgorithm {
	parts := strings.SplitN(s, "/", 3)
	alg := parts[0]
	mode := ""
	if len(parts) >= 2 {
		mode = parts[1]
	}
	up := strings.ToUpper(alg)

	// Determine primitive from the base algorithm name.
	var primitive string
	switch {
	case up == "AES":
		if isAEADMode(strings.ToUpper(mode)) {
			primitive = "ae"
		} else {
			primitive = "symmetric"
		}
	case up == "RSA":
		primitive = "pke"
	case up == "EC" || up == "ECDSA":
		primitive = "signature"
	case up == "DESEDE" || up == "DES" || up == "3DES":
		primitive = "symmetric"
	case up == "BLOWFISH" || up == "RC2" || up == "RC4":
		primitive = "symmetric"
	case up == "CHACHA20":
		primitive = "ae"
	default:
		// Unknown base algorithm — skip.
		return nil
	}

	return &ClassifiedAlgorithm{Name: alg, Mode: mode, Primitive: primitive}
}

func isAEADMode(mode string) bool {
	return mode == "GCM" || mode == "CCM" || mode == "EAX" || mode == "OCB"
}

// hashPrimitive returns "hash" if up is a recognised hash algorithm, else "".
func hashPrimitive(up string) string {
	switch {
	case up == "MD5" || up == "MD2":
		return "hash"
	case up == "SHA1" || up == "SHA-1":
		return "hash"
	case strings.HasPrefix(up, "SHA-") || strings.HasPrefix(up, "SHA2") ||
		strings.HasPrefix(up, "SHA3") || up == "SHA224" || up == "SHA256" ||
		up == "SHA384" || up == "SHA512":
		return "hash"
	case strings.HasPrefix(up, "SHA3-"):
		return "hash"
	case up == "RIPEMD160" || up == "WHIRLPOOL":
		return "hash"
	}
	return ""
}

// signaturePrimitive returns "signature" for known signature/EC schemes.
func signaturePrimitive(up string) string {
	switch up {
	case "EC", "ECDSA", "ECDSAWITHSHA256", "ECDSAWITHSHA384", "ECDSAWITHSHA512":
		return "signature"
	case "EDDSA", "ED25519", "ED448":
		return "signature"
	case "DSA":
		return "signature"
	}
	// Compound signature identifiers: SHAxxx withECDSA / withDSA / withRSA / withEdDSA.
	if strings.Contains(up, "WITHECDSA") || strings.Contains(up, "WITHEDDSA") ||
		strings.Contains(up, "WITHDSA") || strings.Contains(up, "WITHRSA") {
		return "signature"
	}
	return ""
}

// symmetricPrimitive returns the primitive for known symmetric ciphers.
func symmetricPrimitive(up string) string {
	switch up {
	case "DES", "DESEDE", "3DES", "TRIPLEDES":
		return "symmetric"
	case "BLOWFISH", "RC2", "RC4", "RC5", "CAST5", "CAST6", "CAMELLIA",
		"IDEA", "TWOFISH", "SERPENT", "SKIPJACK", "SEED", "ARIA", "LEA":
		return "symmetric"
	}
	return ""
}

// hmacMode extracts the hash name from an HmacSHAxxx identifier.
// e.g. "HmacSHA256" → "SHA-256", "HmacSHA512" → "SHA-512".
func hmacMode(s string) string {
	up := strings.ToUpper(s)
	// Strip leading "HMAC" and optional "WITH"
	rest := strings.TrimPrefix(up, "HMAC")
	rest = strings.TrimPrefix(rest, "WITH")
	switch rest {
	case "SHA1", "SHA-1":
		return "SHA-1"
	case "SHA224", "SHA-224":
		return "SHA-224"
	case "SHA256", "SHA-256":
		return "SHA-256"
	case "SHA384", "SHA-384":
		return "SHA-384"
	case "SHA512", "SHA-512":
		return "SHA-512"
	case "SHA512/224", "SHA-512/224":
		return "SHA-512/224"
	case "SHA512/256", "SHA-512/256":
		return "SHA-512/256"
	case "SHA3-224":
		return "SHA3-224"
	case "SHA3-256":
		return "SHA3-256"
	case "SHA3-384":
		return "SHA3-384"
	case "SHA3-512":
		return "SHA3-512"
	case "MD5":
		return "MD5"
	}
	if rest != "" {
		return rest
	}
	return ""
}

// extractVersionSuffix pulls the version from TLSvX.Y / SSLvX.Y style strings.
// e.g. "TLSv1.3" → "1.3", "TLS" → "".
func extractVersionSuffix(s string) string {
	up := strings.ToUpper(s)
	for _, prefix := range []string{"TLSV", "SSLV"} {
		if strings.HasPrefix(up, prefix) {
			return s[len(prefix):]
		}
	}
	return ""
}

// isNonCryptoString returns true for strings that look like they are NOT
// cryptographic identifiers (file encodings, package names, common words, etc.).
func isNonCryptoString(s string) bool {
	// Reject strings with spaces (not JCA identifiers).
	if strings.Contains(s, " ") {
		return true
	}

	// Reject single-char strings — no crypto algorithm has a 1-char name.
	if len(s) <= 1 {
		return true
	}

	up := strings.ToUpper(s)

	// Reject dots that indicate a class/package name, but allow TLSv1.x / SSLv3
	// version identifiers which legitimately contain dots.
	if strings.Contains(s, ".") {
		isTLSVersion := strings.HasPrefix(up, "TLSV") || strings.HasPrefix(up, "SSLV")
		if !isTLSVersion {
			return true
		}
	}

	// JCA transform strings use "/" as a segment separator (e.g. "AES/GCM/NoPadding").
	// JVM internal class names use "/" as a package separator (e.g. "java/lang/Object").
	// Distinguish them: JVM class names always start with a lowercase package segment.
	if strings.Contains(s, "/") {
		firstSegment := s[:strings.Index(s, "/")]
		if len(firstSegment) > 0 && firstSegment[0] >= 'a' && firstSegment[0] <= 'z' {
			// Lowercase first segment → JVM package path, not a JCA transform.
			return true
		}
	}

	// Common non-crypto identifiers frequently found in constant pools.
	nonCrypto := []string{
		"UTF-8", "UTF-16", "UTF-32", "ISO-8859", "ASCII", "LATIN1",
		"MAIN", "INIT", "<INIT>", "<CLINIT>", "CODE", "LINE", "STACK",
		"VOID", "BOOLEAN", "BYTE", "CHAR", "SHORT", "INT", "LONG",
		"FLOAT", "DOUBLE", "OBJECT", "STRING", "CLASS",
	}
	for _, nc := range nonCrypto {
		if up == nc || strings.HasPrefix(up, nc) {
			return true
		}
	}

	return false
}
