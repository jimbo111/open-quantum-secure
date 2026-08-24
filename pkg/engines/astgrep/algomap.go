package astgrep

import (
	"strconv"
	"strings"
)

// ruleMeta holds the algorithm/primitive metadata attached to a rule, sourced
// from the rule YAML's `metadata:` block (loaded at rule-flatten time) or the
// builtin table below. ast-grep's `scan --json` output does NOT echo rule
// metadata back per match, so the wrapper records it while flattening the rule
// files and consults it by ruleId when normalizing matches.
type ruleMeta struct {
	Algorithm string
	Primitive string
}

// builtinRuleMeta is the curated ruleID -> {algorithm, primitive} table for the
// embedded rule set. It mirrors the `metadata:` blocks in rules/*.yml and acts
// as a safety net when normalize runs without a loaded metadata map (unit
// tests, or a future caller that skips rule loading). An empty Algorithm means
// the rule is value-generic: the algorithm comes from a captured metavariable
// and no static name must ever be invented for it.
var builtinRuleMeta = map[string]ruleMeta{
	// Go
	"crypto-go-aes-new-cipher":     {"AES", "symmetric"},
	"crypto-go-rsa-generate-key":   {"RSA", "pke"},
	"crypto-go-rsa-encrypt-oaep":   {"RSA", "pke"},
	"crypto-go-rsa-sign-pkcs1v15":  {"RSA", "signature"},
	"crypto-go-ecdsa-generate-key": {"ECDSA", "signature"},
	"crypto-go-ecdsa-sign":         {"ECDSA", "signature"},
	"crypto-go-sha256-new":         {"SHA-256", "hash"},
	"crypto-go-sha512-new":         {"SHA-512", "hash"},
	"crypto-go-md5-new":            {"MD5", "hash"},
	"crypto-go-hmac-new":           {"HMAC", "mac"},
	"crypto-go-tls-config":         {"TLS", "protocol"},
	"crypto-go-ecdh-generate-key":  {"ECDH", "key-agree"},
	// Java (all value-generic: $ALGO carries the algorithm string)
	"crypto-java-cipher":             {"", "symmetric"},
	"crypto-java-message-digest":     {"", "hash"},
	"crypto-java-key-pair-generator": {"", "pke"},
	"crypto-java-key-generator":      {"", "symmetric"},
	"crypto-java-secret-key-factory": {"", "symmetric"},
	"crypto-java-mac":                {"", "mac"},
	"crypto-java-signature":          {"", "signature"},
	"crypto-java-key-agreement":      {"", "key-agree"},
	// Python
	"crypto-python-hashlib-new":               {"", "hash"},
	"crypto-python-hashlib-sha256":            {"SHA-256", "hash"},
	"crypto-python-hashlib-sha1":              {"SHA-1", "hash"},
	"crypto-python-hashlib-md5":               {"MD5", "hash"},
	"crypto-python-pycryptodome-aes":          {"AES", "symmetric"},
	"crypto-python-pycryptodome-rsa-generate": {"RSA", "pke"},
	"crypto-python-cryptography-hazmat-aes":   {"AES", "symmetric"},
	"crypto-python-cryptography-hazmat-rsa":   {"RSA", "pke"},
	"crypto-python-cryptography-hazmat-ec":    {"ECDSA", "signature"},
	"crypto-python-ssl-wrap-socket":           {"TLS", "protocol"},
	// OpenSSL (cipher/digest selectors are parsed from captures)
	"crypto-openssl-evp-encrypt-init":    {"", "symmetric"},
	"crypto-openssl-evp-encrypt-init-ex": {"", "symmetric"},
	"crypto-openssl-evp-decrypt-init":    {"", "symmetric"},
	"crypto-openssl-evp-decrypt-init-ex": {"", "symmetric"},
	"crypto-openssl-evp-digest-init":     {"", "hash"},
	"crypto-openssl-evp-digest-init-ex":  {"", "hash"},
	"crypto-openssl-ssl-ctx-new":         {"TLS", "protocol"},
	"crypto-openssl-rsa-generate-key-ex": {"RSA", "pke"},
	"crypto-openssl-evp-pkey-keygen":     {"", "pke"},
	"crypto-openssl-evp-cipher-fetch":    {"", "symmetric"},
	"crypto-openssl-evp-md-fetch":        {"", "hash"},
	"crypto-openssl-hmac-init-ex":        {"HMAC", "mac"},
	// Node.js / TypeScript ("-ts" id variants resolve via lookupBuiltinRuleMeta)
	"crypto-node-create-hash":                    {"", "hash"},
	"crypto-node-generate-key-pair":              {"", "pke"},
	"crypto-node-generate-key-pair-sync":         {"", "pke"},
	"crypto-node-generate-key-pair-modulus":      {"", "pke"},
	"crypto-node-generate-key-pair-sync-modulus": {"", "pke"},
	"crypto-node-create-diffie-hellman":          {"DH", "key-agree"},
	"crypto-node-create-ecdh":                    {"ECDH", "key-agree"},
	"crypto-node-create-sign":                    {"", "signature"},
	"crypto-node-create-verify":                  {"", "signature"},
	"crypto-node-jwt-sign":                       {"", "signature"},
	"crypto-node-webcrypto-generate-key":         {"", "pke"},
}

// lookupBuiltinRuleMeta resolves a ruleID in the builtin table, treating a
// trailing "-ts" as the TypeScript variant of the same rule.
func lookupBuiltinRuleMeta(ruleID string) (ruleMeta, bool) {
	if rm, ok := builtinRuleMeta[ruleID]; ok {
		return rm, true
	}
	if trimmed := strings.TrimSuffix(ruleID, "-ts"); trimmed != ruleID {
		if rm, ok := builtinRuleMeta[trimmed]; ok {
			return rm, true
		}
	}
	return ruleMeta{}, false
}

// algoTokenNames maps captured algorithm tokens (Node type strings, hashlib
// names, JWA signing tokens, ...) and ruleID tokens to canonical names the
// quantum classifier recognizes. Keys are lowercase.
var algoTokenNames = map[string]string{
	"rsa": "RSA", "dsa": "DSA",
	"ec": "ECDSA", "ecdsa": "ECDSA", "ecdh": "ECDH",
	"dh": "DH", "diffie-hellman": "DH", "diffiehellman": "DH",
	"ed25519": "Ed25519", "ed448": "Ed448",
	"x25519": "X25519", "x448": "X448",
	"md2": "MD2", "md4": "MD4", "md5": "MD5",
	"sha1": "SHA-1", "sha-1": "SHA-1",
	"sha224": "SHA-224", "sha-224": "SHA-224",
	"sha256": "SHA-256", "sha-256": "SHA-256",
	"sha384": "SHA-384", "sha-384": "SHA-384",
	"sha512": "SHA-512", "sha-512": "SHA-512",
	"sha3-224": "SHA3-224", "sha3-256": "SHA3-256",
	"sha3-384": "SHA3-384", "sha3-512": "SHA3-512",
	"aes": "AES", "des": "DES", "3des": "3DES",
	"des-ede3": "3DES", "desede": "3DES", "tripledes": "3DES",
	"rc2": "RC2", "rc4": "RC4", "blowfish": "Blowfish",
	"chacha20": "ChaCha20",
	"hmac":     "HMAC",
	"tls":      "TLS",
	// JWA signing tokens (RFC 7518) as used by jsonwebtoken / jose.
	"rs256": "RSA", "rs384": "RSA", "rs512": "RSA",
	"ps256": "RSA", "ps384": "RSA", "ps512": "RSA",
	"es256": "ECDSA", "es384": "ECDSA", "es512": "ECDSA", "es256k": "ECDSA",
	"hs256": "HMAC-SHA256", "hs384": "HMAC-SHA384", "hs512": "HMAC-SHA512",
	"eddsa": "Ed25519",
	// PQC tokens, mainly for ruleID inference over external rule packs.
	"mlkem": "ML-KEM", "ml-kem": "ML-KEM",
	"mlkem512": "MLKEM512", "mlkem768": "MLKEM768", "mlkem1024": "MLKEM1024",
	"mldsa": "ML-DSA", "ml-dsa": "ML-DSA",
	"kyber": "Kyber", "kyber512": "Kyber512", "kyber768": "Kyber768", "kyber1024": "Kyber1024",
	"dilithium": "Dilithium",
}

// canonicalAlgoName maps a captured token to a canonical algorithm name, or ""
// when the token is not recognized. Case-insensitive.
func canonicalAlgoName(s string) string {
	t := strings.TrimSpace(s)
	if t == "" {
		return ""
	}
	lower := strings.ToLower(t)
	if name, ok := algoTokenNames[lower]; ok {
		return name
	}
	// Java JCA signature transforms: "SHA256withRSA", "SHA1withDSA", ...
	upper := strings.ToUpper(t)
	switch {
	case strings.Contains(upper, "WITHRSA"):
		return "RSA"
	case strings.Contains(upper, "WITHECDSA"):
		return "ECDSA"
	case strings.Contains(upper, "WITHDSA"):
		return "DSA"
	}
	// Java JCA MAC names: "HmacSHA256" -> "HMAC-SHA256".
	if rest, ok := strings.CutPrefix(lower, "hmac"); ok {
		if rest == "" {
			return "HMAC"
		}
		return "HMAC-" + strings.ToUpper(rest)
	}
	return ""
}

// evpFamilyNames maps the first identifier segment of OpenSSL EVP selector
// functions (EVP_aes_128_cbc, EVP_sha256, ...) to canonical algorithm names.
var evpFamilyNames = map[string]string{
	"aes": "AES", "aria": "ARIA", "camellia": "Camellia",
	"chacha20": "ChaCha20", "sm4": "SM4",
	"des": "DES", "des3": "3DES", "bf": "Blowfish",
	"rc2": "RC2", "rc4": "RC4", "rc5": "RC5",
	"cast5": "CAST5", "seed": "SEED", "idea": "IDEA",
	"md4": "MD4", "md5": "MD5",
	"sha1": "SHA-1", "sha224": "SHA-224", "sha256": "SHA-256",
	"sha384": "SHA-384", "sha512": "SHA-512",
	"sha3": "SHA3", "shake128": "SHAKE128", "shake256": "SHAKE256",
	"sm3": "SM3", "ripemd160": "RIPEMD-160",
	"blake2b512": "BLAKE2b", "blake2s256": "BLAKE2s",
}

// cipherModes are block/stream cipher modes recognized in identifiers.
var cipherModes = map[string]bool{
	"cbc": true, "ecb": true, "gcm": true, "ctr": true,
	"cfb": true, "cfb1": true, "cfb8": true, "ofb": true,
	"ccm": true, "xts": true, "ocb": true, "siv": true, "wrap": true,
}

// parseCryptoIdentifier parses OpenSSL-style selector identifiers into
// (algorithm, keySize, mode):
//
//	EVP_aes_128_cbc()  -> ("AES", 128, "CBC")
//	EVP_sha256()       -> ("SHA-256", 0, "")
//	sha256.New         -> ("SHA-256", 0, "")   (Go hash constructor value)
//	"AES-128-CBC"      -> ("AES", 128, "CBC")  (EVP_CIPHER_fetch name)
//	TLS_client_method()-> ("TLS", 0, "")
//
// Returns ("", 0, "") for anything unrecognized (e.g. a variable name).
func parseCryptoIdentifier(s string) (string, int, string) {
	id := strings.ToLower(strings.TrimSpace(s))
	id = strings.TrimSuffix(id, "()")
	if id == "" || strings.ContainsAny(id, " \t\n(){},") {
		return "", 0, ""
	}
	if strings.HasSuffix(id, "_method") {
		return parseTLSMethod(id), 0, ""
	}
	id = strings.TrimPrefix(id, "evp_")
	parts := strings.FieldsFunc(id, func(r rune) bool {
		return r == '_' || r == '-' || r == '.'
	})
	if len(parts) == 0 {
		return "", 0, ""
	}
	family, ok := evpFamilyNames[parts[0]]
	if !ok {
		return "", 0, ""
	}
	// EVP_des_ede3_cbc -> Triple DES.
	if parts[0] == "des" && len(parts) > 1 && strings.HasPrefix(parts[1], "ede") {
		family = "3DES"
	}
	// EVP_sha3_256 -> SHA3-256 (the digit segment is a variant, not a key size).
	if parts[0] == "sha3" && len(parts) > 1 {
		if _, err := strconv.Atoi(parts[1]); err == nil {
			return "SHA3-" + parts[1], 0, ""
		}
		return "SHA3", 0, ""
	}
	bits := 0
	mode := ""
	for _, p := range parts[1:] {
		if n, err := strconv.Atoi(p); err == nil {
			if bits == 0 && (n == 128 || n == 192 || n == 256) {
				bits = n
			}
			continue
		}
		if mode == "" && cipherModes[p] {
			mode = strings.ToUpper(p)
		}
	}
	return family, bits, mode
}

// parseTLSMethod maps OpenSSL *_method selector names to protocol names.
// SSLv23_method is the version-flexible selector, so it maps to plain "TLS"
// (checked before the sslv2/sslv3 prefixes it shares).
func parseTLSMethod(id string) string {
	base := strings.TrimSuffix(id, "_method")
	base = strings.TrimSuffix(base, "_client")
	base = strings.TrimSuffix(base, "_server")
	switch {
	case strings.HasPrefix(base, "sslv23"):
		return "TLS"
	case strings.HasPrefix(base, "sslv3"):
		return "SSLv3"
	case strings.HasPrefix(base, "sslv2"):
		return "SSLv2"
	case strings.HasPrefix(base, "tlsv1_3"):
		return "TLSv1.3"
	case strings.HasPrefix(base, "tlsv1_2"):
		return "TLSv1.2"
	case strings.HasPrefix(base, "tlsv1_1"):
		return "TLSv1.1"
	case strings.HasPrefix(base, "tlsv1"):
		return "TLSv1.0"
	}
	return "TLS"
}

// inferAlgorithmFromRuleID is the generic fallback for unknown external rules:
// it scans the ruleID tokens for a recognizable algorithm token. Unlike the old
// last-segment fallback, it never invents names like "NEW" or "CONFIG" — if no
// token maps, the finding carries no algorithm rather than a poisoned one.
// External rule authors should prefer an explicit `metadata: {algorithm: ...}`.
func inferAlgorithmFromRuleID(ruleID string) string {
	if ruleID == "" {
		return ""
	}
	// Hybrid KEM ids must not resolve to their classical component token.
	compact := strings.ToLower(strings.Map(func(r rune) rune {
		if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' {
			return r
		}
		return -1
	}, ruleID))
	if strings.Contains(compact, "x25519mlkem768") {
		return "X25519MLKEM768"
	}
	tokens := strings.FieldsFunc(strings.ToLower(ruleID), func(r rune) bool {
		return r == '-' || r == '_' || r == '.' || r == '/' || r == ':'
	})
	for _, tok := range tokens {
		if name, ok := algoTokenNames[tok]; ok {
			return name
		}
	}
	return ""
}

// isQuotedLiteral reports whether the raw capture text is a string literal
// (matching leading/trailing quote character).
func isQuotedLiteral(s string) bool {
	if len(s) < 2 {
		return false
	}
	q := s[0]
	return (q == '"' || q == '\'' || q == '`') && s[len(s)-1] == q
}

// isHashName reports whether the parsed algorithm names a hash function.
func isHashName(n string) bool {
	u := strings.ToUpper(n)
	return strings.HasPrefix(u, "SHA") || strings.HasPrefix(u, "MD") ||
		strings.HasPrefix(u, "SM3") || strings.HasPrefix(u, "RIPEMD") ||
		strings.HasPrefix(u, "BLAKE2")
}

// resolveCapture canonicalizes a captured metavariable value into an algorithm
// name plus optional key size and mode. Priority: known token > parseable
// crypto identifier > verbatim string literal. Unquoted unrecognized captures
// (usually variable names) resolve to "" so metadata fallbacks apply.
func resolveCapture(raw string) (string, int, string) {
	rawTrim := strings.TrimSpace(raw)
	lit := strings.Trim(rawTrim, "\"'`")
	if lit == "" {
		return "", 0, ""
	}
	if name := canonicalAlgoName(lit); name != "" {
		return name, 0, ""
	}
	if name, bits, mode := parseCryptoIdentifier(lit); name != "" {
		return name, bits, mode
	}
	if isQuotedLiteral(rawTrim) {
		// The code's own algorithm spelling, e.g. "AES/CBC/PKCS5Padding" —
		// keep it verbatim; the quantum classifier resolves family prefixes.
		return lit, 0, ""
	}
	return "", 0, ""
}

// capturedKeySize reads a numeric key-size metavariable ($BITS in the RSA
// keygen rules, $KS in hazmat rsa.generate_private_key, modulusLength in the
// Node keygen rules).
func capturedKeySize(m rawMatch) int {
	for _, key := range []string{"BITS", "KS", "MODULUSLENGTH", "KEYSIZE"} {
		mv, ok := m.MetaVars[key]
		if !ok {
			continue
		}
		if n, err := strconv.Atoi(strings.TrimSpace(mv.Text)); err == nil && n > 0 && n <= 1<<20 {
			return n
		}
	}
	return 0
}

// capturedMode reads a cipher-mode metavariable (e.g. PyCryptodome's
// AES.MODE_CBC in $MODE).
func capturedMode(m rawMatch) string {
	mv, ok := m.MetaVars["MODE"]
	if !ok {
		return ""
	}
	t := strings.ToLower(strings.Trim(strings.TrimSpace(mv.Text), "\"'`"))
	if i := strings.LastIndex(t, "mode_"); i >= 0 {
		t = t[i+len("mode_"):]
	}
	if cipherModes[t] {
		return strings.ToUpper(t)
	}
	return ""
}

// extractCurve reads an elliptic-curve metavariable ($CURVE) and maps common
// spellings (elliptic.P256(), ec.SECP256R1(), 'secp256k1') to curve names.
func extractCurve(m rawMatch) string {
	mv, ok := m.MetaVars["CURVE"]
	if !ok {
		return ""
	}
	t := strings.ToLower(mv.Text)
	switch {
	// secp256k1 contains the substring "p256" — check it first.
	case strings.Contains(t, "secp256k1"):
		return "secp256k1"
	case strings.Contains(t, "p224"), strings.Contains(t, "secp224r1"):
		return "P-224"
	case strings.Contains(t, "p256"), strings.Contains(t, "prime256v1"):
		return "P-256"
	case strings.Contains(t, "p384"):
		return "P-384"
	case strings.Contains(t, "p521"):
		return "P-521"
	case strings.Contains(t, "curve25519"), strings.Contains(t, "x25519"):
		return "Curve25519"
	case strings.Contains(t, "ed25519"):
		return "Ed25519"
	}
	return ""
}

// extractAlgorithmDetails derives (algorithm, keySize, mode) for a match.
// Priority:
//  1. captured metavariables ($ALGO / $TYPE / $CIPHER / $METHOD)
//  2. rule metadata from the rule file's `metadata:` block
//  3. curated builtin table for the embedded rule set
//  4. token-based ruleID inference (unknown external rules only)
//
// The old message-suffix fallback is gone: it poisoned names with message
// fragments like "2048-bit" or "elliptic.P256()", and the old last-ruleID-
// segment fallback minted garbage like "NEW"/"CONFIG" — both broke
// classification and cross-engine dedup (DedupeKey includes Algorithm.Name).
func extractAlgorithmDetails(m rawMatch, meta map[string]ruleMeta) (string, int, string) {
	keySize := capturedKeySize(m)
	mode := capturedMode(m)

	// 1. Captured metavariables, most-specific key first. ALGO/TYPE carry
	// quoted algorithm strings or digest selectors; CIPHER/METHOD carry
	// OpenSSL selector calls.
	for _, key := range []string{"ALGO", "CIPHER", "TYPE", "METHOD"} {
		mv, ok := m.MetaVars[key]
		if !ok {
			continue
		}
		if name, bits, md := resolveCapture(mv.Text); name != "" {
			if keySize == 0 {
				keySize = bits
			}
			if mode == "" {
				mode = md
			}
			return name, keySize, mode
		}
	}

	// 2-4. Static resolution by ruleID.
	name := ""
	if rm, ok := meta[m.RuleID]; ok && rm.Algorithm != "" {
		name = rm.Algorithm
	} else if rm, ok := lookupBuiltinRuleMeta(m.RuleID); ok {
		name = rm.Algorithm // may be "" for value-generic rules
	} else {
		name = inferAlgorithmFromRuleID(m.RuleID)
	}

	// Refine bare HMAC with the captured underlying hash ($HASH in Go's
	// hmac.New, $MD in OpenSSL's HMAC_Init_ex): HMAC + SHA-256 -> HMAC-SHA256.
	if name == "HMAC" {
		for _, key := range []string{"MD", "HASH"} {
			mv, ok := m.MetaVars[key]
			if !ok {
				continue
			}
			if h, _, _ := parseCryptoIdentifier(strings.Trim(strings.TrimSpace(mv.Text), "\"'`")); h != "" && isHashName(h) {
				return "HMAC-" + strings.ReplaceAll(h, "-", ""), keySize, mode
			}
		}
	}

	return name, keySize, mode
}

// extractPrimitive resolves the primitive class for a finding: rule metadata >
// builtin table > ruleID heuristics.
func extractPrimitive(ruleID string, meta map[string]ruleMeta) string {
	if rm, ok := meta[ruleID]; ok && rm.Primitive != "" {
		return rm.Primitive
	}
	if rm, ok := lookupBuiltinRuleMeta(ruleID); ok && rm.Primitive != "" {
		return rm.Primitive
	}
	return primitiveFromRuleID(ruleID)
}
