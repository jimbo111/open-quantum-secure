package configscanner

import (
	"strconv"
	"strings"

	"github.com/jimbo111/open-quantum-secure/pkg/findings"
)

// CryptoParam defines a detectable crypto configuration parameter.
type CryptoParam struct {
	// KeyPattern is a substring that must appear in the lowercased config key.
	KeyPattern string
	// ValueHints, if non-empty, require the lowercased value to contain at
	// least one entry. When empty, the key alone is sufficient (e.g. key-size).
	ValueHints []string
	// Algorithm name to emit in the finding (e.g. "AES").
	Algorithm string
	// Primitive type (e.g. "symmetric", "hash").
	Primitive string
	// KeySize is a static hint. 0 means try to parse from value.
	KeySize int
	// Mode hint (e.g. "GCM").
	Mode string
}

// cryptoParams is the vocabulary of detectable crypto configuration entries.
// Entries are evaluated in order; the first matching entry for a key-value
// pair wins.
var cryptoParams = []CryptoParam{
	// --- algorithm name keys ---
	{KeyPattern: "algorithm", ValueHints: []string{"aes-256-gcm", "aes256gcm"}, Algorithm: "AES", Primitive: "symmetric", KeySize: 256, Mode: "GCM"},
	{KeyPattern: "algorithm", ValueHints: []string{"aes-128-gcm", "aes128gcm"}, Algorithm: "AES", Primitive: "symmetric", KeySize: 128, Mode: "GCM"},
	{KeyPattern: "algorithm", ValueHints: []string{"aes-256-cbc", "aes256cbc"}, Algorithm: "AES", Primitive: "symmetric", KeySize: 256, Mode: "CBC"},
	{KeyPattern: "algorithm", ValueHints: []string{"aes-128-cbc", "aes128cbc"}, Algorithm: "AES", Primitive: "symmetric", KeySize: 128, Mode: "CBC"},
	{KeyPattern: "algorithm", ValueHints: []string{"chacha20-poly1305"}, Algorithm: "ChaCha20-Poly1305", Primitive: "ae"},
	{KeyPattern: "algorithm", ValueHints: []string{"chacha20"}, Algorithm: "ChaCha20", Primitive: "symmetric"},
	{KeyPattern: "algorithm", ValueHints: []string{"3des", "desede", "tripledes"}, Algorithm: "3DES", Primitive: "symmetric"},
	{KeyPattern: "algorithm", ValueHints: []string{"aes"}, Algorithm: "AES", Primitive: "symmetric"},
	{KeyPattern: "algorithm", ValueHints: []string{"rsa"}, Algorithm: "RSA", Primitive: "asymmetric"},
	{KeyPattern: "algorithm", ValueHints: []string{"des"}, Algorithm: "DES", Primitive: "symmetric"},
	{KeyPattern: "algorithm", ValueHints: []string{"blowfish"}, Algorithm: "Blowfish", Primitive: "symmetric"},
	{KeyPattern: "algorithm", ValueHints: []string{"sha-256", "sha256"}, Algorithm: "SHA-256", Primitive: "hash"},
	{KeyPattern: "algorithm", ValueHints: []string{"sha-512", "sha512"}, Algorithm: "SHA-512", Primitive: "hash"},
	{KeyPattern: "algorithm", ValueHints: []string{"sha-1", "sha1"}, Algorithm: "SHA-1", Primitive: "hash"},
	{KeyPattern: "algorithm", ValueHints: []string{"md5"}, Algorithm: "MD5", Primitive: "hash"},
	{KeyPattern: "algorithm", ValueHints: []string{"hmac"}, Algorithm: "HMAC", Primitive: "mac"},
	{KeyPattern: "algorithm", ValueHints: []string{"ecdsa"}, Algorithm: "ECDSA", Primitive: "signature"},
	{KeyPattern: "algorithm", ValueHints: []string{"ecdh"}, Algorithm: "ECDH", Primitive: "key-exchange"},
	{KeyPattern: "algorithm", ValueHints: []string{"ed25519"}, Algorithm: "Ed25519", Primitive: "signature"},
	{KeyPattern: "algorithm", ValueHints: []string{"x25519"}, Algorithm: "X25519", Primitive: "key-exchange"},
	// --- PQC under 'algorithm' (NIST FIPS 203/204/205 + IETF hybrid KEMs) ---
	// More-specific hints first so first-match-wins picks the canonical name.
	{KeyPattern: "algorithm", ValueHints: []string{"x25519mlkem768", "x25519-mlkem-768"}, Algorithm: "X25519MLKEM768", Primitive: "kem"},
	{KeyPattern: "algorithm", ValueHints: []string{"secp256r1mlkem768", "secp256r1-mlkem-768"}, Algorithm: "SecP256r1MLKEM768", Primitive: "kem"},
	{KeyPattern: "algorithm", ValueHints: []string{"secp384r1mlkem1024", "secp384r1-mlkem-1024"}, Algorithm: "SecP384r1MLKEM1024", Primitive: "kem"},
	{KeyPattern: "algorithm", ValueHints: []string{"ml-kem-512", "mlkem512"}, Algorithm: "ML-KEM-512", Primitive: "kem"},
	{KeyPattern: "algorithm", ValueHints: []string{"ml-kem-768", "mlkem768"}, Algorithm: "ML-KEM-768", Primitive: "kem"},
	{KeyPattern: "algorithm", ValueHints: []string{"ml-kem-1024", "mlkem1024"}, Algorithm: "ML-KEM-1024", Primitive: "kem"},
	{KeyPattern: "algorithm", ValueHints: []string{"ml-kem"}, Algorithm: "ML-KEM", Primitive: "kem"},
	{KeyPattern: "algorithm", ValueHints: []string{"ml-dsa-44", "mldsa44"}, Algorithm: "ML-DSA-44", Primitive: "signature"},
	{KeyPattern: "algorithm", ValueHints: []string{"ml-dsa-65", "mldsa65"}, Algorithm: "ML-DSA-65", Primitive: "signature"},
	{KeyPattern: "algorithm", ValueHints: []string{"ml-dsa-87", "mldsa87"}, Algorithm: "ML-DSA-87", Primitive: "signature"},
	{KeyPattern: "algorithm", ValueHints: []string{"ml-dsa"}, Algorithm: "ML-DSA", Primitive: "signature"},
	{KeyPattern: "algorithm", ValueHints: []string{"slh-dsa-sha2-128s"}, Algorithm: "SLH-DSA-SHA2-128s", Primitive: "signature"},
	{KeyPattern: "algorithm", ValueHints: []string{"slh-dsa-sha2-128f"}, Algorithm: "SLH-DSA-SHA2-128f", Primitive: "signature"},
	{KeyPattern: "algorithm", ValueHints: []string{"slh-dsa-sha2-192s"}, Algorithm: "SLH-DSA-SHA2-192s", Primitive: "signature"},
	{KeyPattern: "algorithm", ValueHints: []string{"slh-dsa-sha2-256s"}, Algorithm: "SLH-DSA-SHA2-256s", Primitive: "signature"},
	{KeyPattern: "algorithm", ValueHints: []string{"slh-dsa"}, Algorithm: "SLH-DSA", Primitive: "signature"},
	{KeyPattern: "algorithm", ValueHints: []string{"fn-dsa-512", "falcon-512"}, Algorithm: "Falcon-512", Primitive: "signature"},
	{KeyPattern: "algorithm", ValueHints: []string{"fn-dsa-1024", "falcon-1024"}, Algorithm: "Falcon-1024", Primitive: "signature"},
	{KeyPattern: "algorithm", ValueHints: []string{"falcon", "fn-dsa"}, Algorithm: "Falcon", Primitive: "signature"},
	{KeyPattern: "algorithm", ValueHints: []string{"hqc-128"}, Algorithm: "HQC-128", Primitive: "kem"},
	{KeyPattern: "algorithm", ValueHints: []string{"hqc-192"}, Algorithm: "HQC-192", Primitive: "kem"},
	{KeyPattern: "algorithm", ValueHints: []string{"hqc-256"}, Algorithm: "HQC-256", Primitive: "kem"},
	{KeyPattern: "algorithm", ValueHints: []string{"hqc"}, Algorithm: "HQC", Primitive: "kem"},
	// Legacy / draft Kyber names still appear in older configs.
	{KeyPattern: "algorithm", ValueHints: []string{"kyber"}, Algorithm: "Kyber", Primitive: "kem"},
	{KeyPattern: "algorithm", ValueHints: []string{"dilithium"}, Algorithm: "Dilithium", Primitive: "signature"},

	// --- Korean KCMVP algorithms ---
	{KeyPattern: "algorithm", ValueHints: []string{"aria-256-gcm", "aria256gcm"}, Algorithm: "ARIA", Primitive: "symmetric", KeySize: 256, Mode: "GCM"},
	{KeyPattern: "algorithm", ValueHints: []string{"aria-128-gcm", "aria128gcm"}, Algorithm: "ARIA", Primitive: "symmetric", KeySize: 128, Mode: "GCM"},
	{KeyPattern: "algorithm", ValueHints: []string{"aria-256-cbc", "aria256cbc"}, Algorithm: "ARIA", Primitive: "symmetric", KeySize: 256, Mode: "CBC"},
	{KeyPattern: "algorithm", ValueHints: []string{"aria-128-cbc", "aria128cbc"}, Algorithm: "ARIA", Primitive: "symmetric", KeySize: 128, Mode: "CBC"},
	{KeyPattern: "algorithm", ValueHints: []string{"aria-192"}, Algorithm: "ARIA", Primitive: "symmetric", KeySize: 192},
	{KeyPattern: "algorithm", ValueHints: []string{"aria-256"}, Algorithm: "ARIA", Primitive: "symmetric", KeySize: 256},
	{KeyPattern: "algorithm", ValueHints: []string{"aria-128"}, Algorithm: "ARIA", Primitive: "symmetric", KeySize: 128},
	{KeyPattern: "algorithm", ValueHints: []string{"aria"}, Algorithm: "ARIA", Primitive: "symmetric"},
	{KeyPattern: "algorithm", ValueHints: []string{"seed-cbc"}, Algorithm: "SEED", Primitive: "symmetric", KeySize: 128, Mode: "CBC"},
	{KeyPattern: "algorithm", ValueHints: []string{"seed-ecb"}, Algorithm: "SEED", Primitive: "symmetric", KeySize: 128, Mode: "ECB"},
	{KeyPattern: "algorithm", ValueHints: []string{"seed"}, Algorithm: "SEED", Primitive: "symmetric", KeySize: 128},
	{KeyPattern: "algorithm", ValueHints: []string{"lea-256-gcm", "lea256gcm"}, Algorithm: "LEA", Primitive: "symmetric", KeySize: 256, Mode: "GCM"},
	{KeyPattern: "algorithm", ValueHints: []string{"lea-128-gcm", "lea128gcm"}, Algorithm: "LEA", Primitive: "symmetric", KeySize: 128, Mode: "GCM"},
	{KeyPattern: "algorithm", ValueHints: []string{"lea-256"}, Algorithm: "LEA", Primitive: "symmetric", KeySize: 256},
	{KeyPattern: "algorithm", ValueHints: []string{"lea-192"}, Algorithm: "LEA", Primitive: "symmetric", KeySize: 192},
	{KeyPattern: "algorithm", ValueHints: []string{"lea-128"}, Algorithm: "LEA", Primitive: "symmetric", KeySize: 128},
	{KeyPattern: "algorithm", ValueHints: []string{"lea"}, Algorithm: "LEA", Primitive: "symmetric"},
	{KeyPattern: "algorithm", ValueHints: []string{"eckcdsa", "ec-kcdsa"}, Algorithm: "EC-KCDSA", Primitive: "signature"},
	{KeyPattern: "algorithm", ValueHints: []string{"kcdsa"}, Algorithm: "KCDSA", Primitive: "signature"},
	{KeyPattern: "algorithm", ValueHints: []string{"has-160", "has160"}, Algorithm: "HAS-160", Primitive: "hash"},
	{KeyPattern: "algorithm", ValueHints: []string{"lsh-512", "lsh512"}, Algorithm: "LSH-512", Primitive: "hash"},
	{KeyPattern: "algorithm", ValueHints: []string{"lsh-256", "lsh256"}, Algorithm: "LSH-256", Primitive: "hash"},
	{KeyPattern: "algorithm", ValueHints: []string{"lsh"}, Algorithm: "LSH", Primitive: "hash"},
	// K-PQC Round 4 finalists
	{KeyPattern: "algorithm", ValueHints: []string{"smaug-t", "smaug"}, Algorithm: "SMAUG-T", Primitive: "kem"},
	{KeyPattern: "algorithm", ValueHints: []string{"haetae"}, Algorithm: "HAETAE", Primitive: "signature"},
	{KeyPattern: "algorithm", ValueHints: []string{"aimer"}, Algorithm: "AIMer", Primitive: "signature"},
	{KeyPattern: "algorithm", ValueHints: []string{"ntru+", "ntruplus"}, Algorithm: "NTRU+", Primitive: "kem"},

	// Korean algorithms in cipher/encryption keys
	{KeyPattern: "cipher", ValueHints: []string{"aria-256-gcm"}, Algorithm: "ARIA", Primitive: "symmetric", KeySize: 256, Mode: "GCM"},
	{KeyPattern: "cipher", ValueHints: []string{"aria-128-gcm"}, Algorithm: "ARIA", Primitive: "symmetric", KeySize: 128, Mode: "GCM"},
	{KeyPattern: "cipher", ValueHints: []string{"aria"}, Algorithm: "ARIA", Primitive: "symmetric"},
	{KeyPattern: "cipher", ValueHints: []string{"seed"}, Algorithm: "SEED", Primitive: "symmetric", KeySize: 128},
	{KeyPattern: "cipher", ValueHints: []string{"lea"}, Algorithm: "LEA", Primitive: "symmetric"},
	{KeyPattern: "encryption", ValueHints: []string{"aria"}, Algorithm: "ARIA", Primitive: "symmetric"},
	{KeyPattern: "encryption", ValueHints: []string{"seed"}, Algorithm: "SEED", Primitive: "symmetric", KeySize: 128},
	{KeyPattern: "encryption", ValueHints: []string{"lea"}, Algorithm: "LEA", Primitive: "symmetric"},
	{KeyPattern: "hash", ValueHints: []string{"has-160", "has160"}, Algorithm: "HAS-160", Primitive: "hash"},
	{KeyPattern: "hash", ValueHints: []string{"lsh-512", "lsh512"}, Algorithm: "LSH-512", Primitive: "hash"},
	{KeyPattern: "hash", ValueHints: []string{"lsh-256", "lsh256"}, Algorithm: "LSH-256", Primitive: "hash"},
	{KeyPattern: "signature", ValueHints: []string{"eckcdsa", "ec-kcdsa"}, Algorithm: "EC-KCDSA", Primitive: "signature"},
	{KeyPattern: "signature", ValueHints: []string{"kcdsa"}, Algorithm: "KCDSA", Primitive: "signature"},
	{KeyPattern: "signature", ValueHints: []string{"haetae"}, Algorithm: "HAETAE", Primitive: "signature"},
	{KeyPattern: "signature", ValueHints: []string{"aimer"}, Algorithm: "AIMer", Primitive: "signature"},

	// --- cipher suite keys (must appear before bare "cipher" entries) ---
	// These use longer KeyPattern substrings (ciphersuite/cipher-suite/cipher_suite)
	// and will only match keys that contain those exact substrings.
	// PQC hybrid + pure KEMs come first so first-match-wins picks the canonical name.
	{KeyPattern: "ciphersuite", ValueHints: []string{"x25519mlkem768", "x25519-mlkem-768"}, Algorithm: "X25519MLKEM768", Primitive: "kem"},
	{KeyPattern: "cipher-suite", ValueHints: []string{"x25519mlkem768", "x25519-mlkem-768"}, Algorithm: "X25519MLKEM768", Primitive: "kem"},
	{KeyPattern: "cipher_suite", ValueHints: []string{"x25519mlkem768", "x25519-mlkem-768"}, Algorithm: "X25519MLKEM768", Primitive: "kem"},
	{KeyPattern: "ciphersuite", ValueHints: []string{"mlkem"}, Algorithm: "ML-KEM", Primitive: "kem"},
	{KeyPattern: "cipher-suite", ValueHints: []string{"mlkem"}, Algorithm: "ML-KEM", Primitive: "kem"},
	{KeyPattern: "cipher_suite", ValueHints: []string{"mlkem"}, Algorithm: "ML-KEM", Primitive: "kem"},
	{KeyPattern: "ciphersuite", ValueHints: []string{"ecdhe"}, Algorithm: "ECDHE", Primitive: "key-exchange"},
	{KeyPattern: "cipher-suite", ValueHints: []string{"ecdhe"}, Algorithm: "ECDHE", Primitive: "key-exchange"},
	{KeyPattern: "cipher_suite", ValueHints: []string{"ecdhe"}, Algorithm: "ECDHE", Primitive: "key-exchange"},
	{KeyPattern: "ciphersuite", ValueHints: []string{"rsa"}, Algorithm: "RSA", Primitive: "asymmetric"},
	{KeyPattern: "cipher-suite", ValueHints: []string{"rsa"}, Algorithm: "RSA", Primitive: "asymmetric"},
	{KeyPattern: "cipher_suite", ValueHints: []string{"rsa"}, Algorithm: "RSA", Primitive: "asymmetric"},

	// --- TLS SupportedGroups / named-group / key-exchange keys (PQC-aware) ---
	// Modern TLS 1.3 configs name groups directly (e.g. groups=X25519MLKEM768).
	// Longer hints first; pure ML-KEM and hybrids classify as RiskSafe via pqcSafeFamilies.
	{KeyPattern: "groups", ValueHints: []string{"x25519mlkem768", "x25519-mlkem-768"}, Algorithm: "X25519MLKEM768", Primitive: "kem"},
	{KeyPattern: "groups", ValueHints: []string{"secp256r1mlkem768", "secp256r1-mlkem-768"}, Algorithm: "SecP256r1MLKEM768", Primitive: "kem"},
	{KeyPattern: "groups", ValueHints: []string{"secp384r1mlkem1024", "secp384r1-mlkem-1024"}, Algorithm: "SecP384r1MLKEM1024", Primitive: "kem"},
	{KeyPattern: "groups", ValueHints: []string{"mlkem768", "ml-kem-768"}, Algorithm: "ML-KEM-768", Primitive: "kem"},
	{KeyPattern: "groups", ValueHints: []string{"mlkem1024", "ml-kem-1024"}, Algorithm: "ML-KEM-1024", Primitive: "kem"},
	{KeyPattern: "groups", ValueHints: []string{"mlkem512", "ml-kem-512"}, Algorithm: "ML-KEM-512", Primitive: "kem"},
	{KeyPattern: "groups", ValueHints: []string{"kyber"}, Algorithm: "Kyber", Primitive: "kem"},
	{KeyPattern: "groups", ValueHints: []string{"x25519"}, Algorithm: "X25519", Primitive: "key-exchange"},
	{KeyPattern: "groups", ValueHints: []string{"secp256r1", "p-256"}, Algorithm: "ECDH", Primitive: "key-exchange"},
	{KeyPattern: "groups", ValueHints: []string{"secp384r1", "p-384"}, Algorithm: "ECDH", Primitive: "key-exchange"},
	{KeyPattern: "kex", ValueHints: []string{"x25519mlkem768", "x25519-mlkem-768"}, Algorithm: "X25519MLKEM768", Primitive: "kem"},
	{KeyPattern: "kex", ValueHints: []string{"mlkem"}, Algorithm: "ML-KEM", Primitive: "kem"},
	{KeyPattern: "kex", ValueHints: []string{"ecdhe"}, Algorithm: "ECDHE", Primitive: "key-exchange"},
	{KeyPattern: "key_exchange", ValueHints: []string{"x25519mlkem768", "x25519-mlkem-768"}, Algorithm: "X25519MLKEM768", Primitive: "kem"},
	{KeyPattern: "key_exchange", ValueHints: []string{"mlkem"}, Algorithm: "ML-KEM", Primitive: "kem"},
	{KeyPattern: "key_exchange", ValueHints: []string{"ecdhe"}, Algorithm: "ECDHE", Primitive: "key-exchange"},

	// --- cipher mode keys ---
	// PQC hints under bare 'cipher' come before classical so first-match-wins picks PQC.
	{KeyPattern: "cipher", ValueHints: []string{"x25519mlkem768", "x25519-mlkem-768"}, Algorithm: "X25519MLKEM768", Primitive: "kem"},
	{KeyPattern: "cipher", ValueHints: []string{"mlkem", "ml-kem"}, Algorithm: "ML-KEM", Primitive: "kem"},
	{KeyPattern: "cipher", ValueHints: []string{"mldsa", "ml-dsa"}, Algorithm: "ML-DSA", Primitive: "signature"},
	{KeyPattern: "cipher", ValueHints: []string{"slh-dsa", "slhdsa"}, Algorithm: "SLH-DSA", Primitive: "signature"},
	{KeyPattern: "cipher", ValueHints: []string{"falcon", "fn-dsa"}, Algorithm: "Falcon", Primitive: "signature"},
	{KeyPattern: "cipher", ValueHints: []string{"hqc"}, Algorithm: "HQC", Primitive: "kem"},
	{KeyPattern: "cipher", ValueHints: []string{"aes-256-gcm", "aes256gcm"}, Algorithm: "AES", Primitive: "symmetric", KeySize: 256, Mode: "GCM"},
	{KeyPattern: "cipher", ValueHints: []string{"aes-128-gcm", "aes128gcm"}, Algorithm: "AES", Primitive: "symmetric", KeySize: 128, Mode: "GCM"},
	{KeyPattern: "cipher", ValueHints: []string{"aes-256-cbc", "aes256cbc"}, Algorithm: "AES", Primitive: "symmetric", KeySize: 256, Mode: "CBC"},
	{KeyPattern: "cipher", ValueHints: []string{"aes-128-cbc", "aes128cbc"}, Algorithm: "AES", Primitive: "symmetric", KeySize: 128, Mode: "CBC"},
	{KeyPattern: "cipher", ValueHints: []string{"chacha20-poly1305"}, Algorithm: "ChaCha20-Poly1305", Primitive: "ae"},
	{KeyPattern: "cipher", ValueHints: []string{"rc4"}, Algorithm: "RC4", Primitive: "stream-cipher"},
	{KeyPattern: "cipher", ValueHints: []string{"des"}, Algorithm: "DES", Primitive: "symmetric"},
	{KeyPattern: "cipher", ValueHints: []string{"aes"}, Algorithm: "AES", Primitive: "symmetric"},

	// --- SSL/TLS protocol version keys ---
	// PQC hybrid names occasionally appear in 'protocol' / 'named_groups' style configs.
	{KeyPattern: "protocol", ValueHints: []string{"x25519mlkem768", "x25519-mlkem-768"}, Algorithm: "X25519MLKEM768", Primitive: "kem"},
	{KeyPattern: "protocol", ValueHints: []string{"mlkem", "ml-kem"}, Algorithm: "ML-KEM", Primitive: "kem"},
	{KeyPattern: "protocol", ValueHints: []string{"sslv3", "ssl3", "ssl 3"}, Algorithm: "SSLv3", Primitive: "protocol"},
	// TLS entries carry the version in Algorithm.Name itself (not just a Mode
	// hint) because pkg/quantum.ClassifyAlgorithm classifies on (name,
	// primitive, keySize) and has no Mode parameter — Mode is populated
	// elsewhere (cipherscope's AES-GCM/CBC) but is never read by the
	// classifier, so a Mode-only encoding would leave the version unusable
	// downstream. Distinct names let ClassifyAlgorithm tell TLSv1.0/1.1
	// (classically deprecated), TLSv1.2 (classically fine but no PQC
	// key-exchange option), and TLSv1.3 (current baseline) apart. See review
	// finding B6 (previously all four emitted the same Algorithm:"TLS").
	{KeyPattern: "protocol", ValueHints: []string{"tlsv1.0", "tls1.0", "tls 1.0"}, Algorithm: "TLSv1.0", Primitive: "protocol"},
	{KeyPattern: "protocol", ValueHints: []string{"tlsv1.1", "tls1.1", "tls 1.1"}, Algorithm: "TLSv1.1", Primitive: "protocol"},
	{KeyPattern: "protocol", ValueHints: []string{"tlsv1.2", "tls1.2", "tls 1.2"}, Algorithm: "TLSv1.2", Primitive: "protocol"},
	{KeyPattern: "protocol", ValueHints: []string{"tlsv1.3", "tls1.3", "tls 1.3"}, Algorithm: "TLSv1.3", Primitive: "protocol"},

	// --- key size keys (value parsed as integer) ---
	{KeyPattern: "key.size", Algorithm: "AES", Primitive: "symmetric"},
	{KeyPattern: "keysize", Algorithm: "AES", Primitive: "symmetric"},
	{KeyPattern: "key-size", Algorithm: "AES", Primitive: "symmetric"},
	{KeyPattern: "key_size", Algorithm: "AES", Primitive: "symmetric"},
	{KeyPattern: "keylength", Algorithm: "AES", Primitive: "symmetric"},
	{KeyPattern: "key-length", Algorithm: "AES", Primitive: "symmetric"},
	{KeyPattern: "key_length", Algorithm: "AES", Primitive: "symmetric"},

	// --- encryption keys ---
	{KeyPattern: "encryption", ValueHints: []string{"aes"}, Algorithm: "AES", Primitive: "symmetric"},
	{KeyPattern: "encryption", ValueHints: []string{"rsa"}, Algorithm: "RSA", Primitive: "asymmetric"},
	{KeyPattern: "encryption", ValueHints: []string{"des"}, Algorithm: "DES", Primitive: "symmetric"},
	{KeyPattern: "encryption", ValueHints: []string{"chacha20"}, Algorithm: "ChaCha20", Primitive: "symmetric"},

	// --- hash/digest keys ---
	{KeyPattern: "hash", ValueHints: []string{"sha-256", "sha256"}, Algorithm: "SHA-256", Primitive: "hash"},
	{KeyPattern: "hash", ValueHints: []string{"sha-512", "sha512"}, Algorithm: "SHA-512", Primitive: "hash"},
	{KeyPattern: "hash", ValueHints: []string{"sha-1", "sha1"}, Algorithm: "SHA-1", Primitive: "hash"},
	{KeyPattern: "hash", ValueHints: []string{"md5"}, Algorithm: "MD5", Primitive: "hash"},
	{KeyPattern: "digest", ValueHints: []string{"sha-256", "sha256"}, Algorithm: "SHA-256", Primitive: "hash"},
	{KeyPattern: "digest", ValueHints: []string{"sha-512", "sha512"}, Algorithm: "SHA-512", Primitive: "hash"},
	{KeyPattern: "digest", ValueHints: []string{"sha-1", "sha1"}, Algorithm: "SHA-1", Primitive: "hash"},
	{KeyPattern: "digest", ValueHints: []string{"md5"}, Algorithm: "MD5", Primitive: "hash"},

	// --- signature keys ---
	{KeyPattern: "signature", ValueHints: []string{"rsa"}, Algorithm: "RSA", Primitive: "signature"},
	{KeyPattern: "signature", ValueHints: []string{"ecdsa"}, Algorithm: "ECDSA", Primitive: "signature"},
	{KeyPattern: "signature", ValueHints: []string{"ed25519"}, Algorithm: "Ed25519", Primitive: "signature"},

	// --- JWT/JWS 'alg' claim (RFC 7518 §3.1) ---
	// The registered claim name is the 3-character key "alg" (e.g. {"alg":
	// "RS256"}), which is shorter than the 9-character substring "algorithm"
	// that every entry above requires — strings.Contains("alg", "algorithm")
	// can never be true, so this extremely common, security-relevant key was
	// previously unreachable by any vocabulary entry (review finding B7/audit
	// §2). Adding a standalone "alg" KeyPattern is only safe now that key
	// matching is segment-boundary-aware (keyMatchesPattern): "alg" matches
	// the whole segment "alg" in "jwt.alg" but does NOT match as a substring
	// of "algorithm" (no boundary after "alg" inside "algorithm").
	{KeyPattern: "alg", ValueHints: []string{"rs256", "rs384", "rs512"}, Algorithm: "RSA", Primitive: "signature"},
	{KeyPattern: "alg", ValueHints: []string{"ps256", "ps384", "ps512"}, Algorithm: "RSASSA-PSS", Primitive: "signature"},
	{KeyPattern: "alg", ValueHints: []string{"es256", "es384", "es512"}, Algorithm: "ECDSA", Primitive: "signature"},
	{KeyPattern: "alg", ValueHints: []string{"hs256", "hs384", "hs512"}, Algorithm: "HMAC", Primitive: "mac"},
}

// keySizePatterns lists KeyPattern values for which the value is parsed as an
// integer key size rather than being matched against ValueHints.
var keySizePatterns = map[string]bool{
	"key.size":   true,
	"keysize":    true,
	"key-size":   true,
	"key_size":   true,
	"keylength":  true,
	"key-length": true,
	"key_length": true,
}

// isKeySizePattern reports whether the given key pattern expects the value to
// be parsed as a key size integer.
func isKeySizePattern(pattern string) bool {
	return keySizePatterns[pattern]
}

// parseIntValue parses an integer from a string value, stripping common
// suffixes like "bits" or "b". Returns 0 when the value cannot be parsed.
func parseIntValue(s string) int {
	s = strings.TrimSpace(s)
	s = strings.ToLower(s)
	// Strip common suffixes.
	for _, suffix := range []string{"bits", "bit", "b"} {
		if strings.HasSuffix(s, suffix) {
			s = strings.TrimSuffix(s, suffix)
			s = strings.TrimSpace(s)
			break
		}
	}
	n, err := strconv.Atoi(s)
	if err != nil || n <= 0 || n > 65536 {
		return 0
	}
	return n
}

// containsWordBoundary checks whether hint appears in s bounded by non-alphanumeric
// characters, start/end of string, or common separators (prevents "des" matching "description").
func containsWordBoundary(s, hint string) bool {
	idx := strings.Index(s, hint)
	for idx >= 0 {
		end := idx + len(hint)
		leftOK := idx == 0 || !isAlphaNumeric(s[idx-1])
		rightOK := end >= len(s) || !isAlphaNumeric(s[end])
		if leftOK && rightOK {
			return true
		}
		// Search for next occurrence.
		if end >= len(s) {
			break
		}
		next := strings.Index(s[end:], hint)
		if next < 0 {
			break
		}
		idx = end + next
	}
	return false
}

func isAlphaNumeric(c byte) bool {
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')
}

// insertCamelCaseBoundaries inserts a '.' separator before each ASCII
// lower-or-digit-to-upper transition in s (e.g. "sslProtocol" ->
// "ssl.Protocol", "expectedAlgorithms" -> "expected.Algorithms"). This must
// run on the ORIGINAL-case string — the case transition that marks a
// camelCase boundary is destroyed by strings.ToLower, so this has to happen
// before lowering, not after. Non-ASCII runes are left untouched (never
// treated as upper/lower for this purpose), which is conservative: it never
// invents a boundary that could turn a false positive into a false negative
// for non-Latin keys.
func insertCamelCaseBoundaries(s string) string {
	runes := []rune(s)
	if len(runes) < 2 {
		return s
	}
	var b strings.Builder
	b.Grow(len(s) + 4)
	b.WriteRune(runes[0])
	for i := 1; i < len(runes); i++ {
		prev, cur := runes[i-1], runes[i]
		if isASCIIUpper(cur) && (isASCIILower(prev) || isASCIIDigit(prev)) {
			b.WriteByte('.')
		}
		b.WriteRune(cur)
	}
	return b.String()
}

func isASCIIUpper(r rune) bool { return r >= 'A' && r <= 'Z' }
func isASCIILower(r rune) bool { return r >= 'a' && r <= 'z' }
func isASCIIDigit(r rune) bool { return r >= '0' && r <= '9' }

// keyMatchesPattern reports whether pattern matches a whole segment of key,
// where segments are separated by ./[/]/_/- or a camelCase transition. This
// replaces a bare strings.Contains(lowerKey, pattern) check, which
// false-positived on any key that merely contained pattern as a substring
// regardless of word boundaries — e.g. the flattened JSON key
// "expectedAlgorithms[0]" (from a ground-truth manifest's OWN
// {"expectedAlgorithms": [...]} schema) matched the "algorithm" vocabulary
// entry purely because "expectedAlgorithms" contains "algorithm" as a
// substring (review finding B7). Segment-bounding preserves the intended
// matches — "encryption_algorithm", "spring.ssl.algorithm", camelCase
// "sslProtocol" — while rejecting unrelated glued compounds.
//
// Multi-token patterns that embed their own separator (e.g. "cipher-suite",
// "key_size") are handled the same way: containsWordBoundary requires the
// pattern's own separator characters to appear literally in key too, so
// these still only match when the full compound substring is present and
// bounded on both ends.
//
// Compound patterns additionally tolerate a single trailing plural "s" (e.g.
// "cipher-suite" matches the real-world key "cipher-suites"), since strict
// boundary matching would otherwise regress that common plural form relative
// to the old bare-substring behavior. This tolerance is deliberately NOT
// extended to single-word patterns like "algorithm"/"cipher"/"protocol" --
// doing so would resurrect exactly the bug this function fixes: "algorithm"
// is a substring of "algorithms", and "expectedAlgorithms" (camelCase-split
// to segment "algorithms") must NOT match. Gating the plural tolerance on
// "pattern contains its own separator" cleanly distinguishes the two cases.
func keyMatchesPattern(key, pattern string) bool {
	segmented := strings.ToLower(insertCamelCaseBoundaries(key))
	if containsWordBoundary(segmented, pattern) {
		return true
	}
	if strings.ContainsAny(pattern, "-_.") {
		return containsWordBoundary(segmented, pattern+"s")
	}
	return false
}

// KeyValue represents a parsed config key-value pair with its source location.
type KeyValue struct {
	Key   string
	Value string
	Line  int
}

// matchCryptoParams scans a slice of key-value pairs against the crypto
// vocabulary and returns a finding for each match. The first matching
// CryptoParam entry wins for a given key-value pair.
func matchCryptoParams(filePath string, kvPairs []KeyValue) []findings.UnifiedFinding {
	var result []findings.UnifiedFinding
	for _, kv := range kvPairs {
		lowerVal := strings.ToLower(kv.Value)

		for _, param := range cryptoParams {
			if !keyMatchesPattern(kv.Key, param.KeyPattern) {
				continue
			}

			// If value hints are specified the value must contain one of them.
			if len(param.ValueHints) > 0 {
				matched := false
				for _, hint := range param.ValueHints {
					if containsWordBoundary(lowerVal, hint) {
						matched = true
						break
					}
				}
				if !matched {
					continue
				}
			}

			keySize := param.KeySize
			if keySize == 0 && isKeySizePattern(param.KeyPattern) {
				keySize = parseIntValue(kv.Value)
			}

			f := findings.UnifiedFinding{
				Location: findings.Location{
					File: filePath,
					Line: kv.Line,
				},
				Algorithm: &findings.Algorithm{
					Name:      param.Algorithm,
					Primitive: param.Primitive,
					KeySize:   keySize,
					Mode:      param.Mode,
				},
				Confidence:    findings.ConfidenceMedium,
				SourceEngine:  "config-scanner",
				Reachable:     findings.ReachableUnknown,
				RawIdentifier: kv.Key + "=" + kv.Value,
			}
			result = append(result, f)
			break // first match wins per KV pair
		}
	}
	return result
}
