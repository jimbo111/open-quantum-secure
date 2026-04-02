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
	{KeyPattern: "ciphersuite", ValueHints: []string{"ecdhe"}, Algorithm: "ECDHE", Primitive: "key-exchange"},
	{KeyPattern: "cipher-suite", ValueHints: []string{"ecdhe"}, Algorithm: "ECDHE", Primitive: "key-exchange"},
	{KeyPattern: "cipher_suite", ValueHints: []string{"ecdhe"}, Algorithm: "ECDHE", Primitive: "key-exchange"},
	{KeyPattern: "ciphersuite", ValueHints: []string{"rsa"}, Algorithm: "RSA", Primitive: "asymmetric"},
	{KeyPattern: "cipher-suite", ValueHints: []string{"rsa"}, Algorithm: "RSA", Primitive: "asymmetric"},
	{KeyPattern: "cipher_suite", ValueHints: []string{"rsa"}, Algorithm: "RSA", Primitive: "asymmetric"},

	// --- cipher mode keys ---
	{KeyPattern: "cipher", ValueHints: []string{"aes-256-gcm", "aes256gcm"}, Algorithm: "AES", Primitive: "symmetric", KeySize: 256, Mode: "GCM"},
	{KeyPattern: "cipher", ValueHints: []string{"aes-128-gcm", "aes128gcm"}, Algorithm: "AES", Primitive: "symmetric", KeySize: 128, Mode: "GCM"},
	{KeyPattern: "cipher", ValueHints: []string{"aes-256-cbc", "aes256cbc"}, Algorithm: "AES", Primitive: "symmetric", KeySize: 256, Mode: "CBC"},
	{KeyPattern: "cipher", ValueHints: []string{"aes-128-cbc", "aes128cbc"}, Algorithm: "AES", Primitive: "symmetric", KeySize: 128, Mode: "CBC"},
	{KeyPattern: "cipher", ValueHints: []string{"chacha20-poly1305"}, Algorithm: "ChaCha20-Poly1305", Primitive: "ae"},
	{KeyPattern: "cipher", ValueHints: []string{"rc4"}, Algorithm: "RC4", Primitive: "stream-cipher"},
	{KeyPattern: "cipher", ValueHints: []string{"des"}, Algorithm: "DES", Primitive: "symmetric"},
	{KeyPattern: "cipher", ValueHints: []string{"aes"}, Algorithm: "AES", Primitive: "symmetric"},

	// --- SSL/TLS protocol version keys ---
	{KeyPattern: "protocol", ValueHints: []string{"sslv3", "ssl3", "ssl 3"}, Algorithm: "SSLv3", Primitive: "protocol"},
	{KeyPattern: "protocol", ValueHints: []string{"tlsv1.0", "tls1.0", "tls 1.0"}, Algorithm: "TLS", Primitive: "protocol"},
	{KeyPattern: "protocol", ValueHints: []string{"tlsv1.1", "tls1.1", "tls 1.1"}, Algorithm: "TLS", Primitive: "protocol"},
	{KeyPattern: "protocol", ValueHints: []string{"tlsv1.2", "tls1.2", "tls 1.2"}, Algorithm: "TLS", Primitive: "protocol"},
	{KeyPattern: "protocol", ValueHints: []string{"tlsv1.3", "tls1.3", "tls 1.3"}, Algorithm: "TLS", Primitive: "protocol"},

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
		lowerKey := strings.ToLower(kv.Key)
		lowerVal := strings.ToLower(kv.Value)

		for _, param := range cryptoParams {
			if !strings.Contains(lowerKey, param.KeyPattern) {
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
