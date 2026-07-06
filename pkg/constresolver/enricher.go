package constresolver

import (
	"path/filepath"
	"sort"
	"strings"

	"github.com/jimbo111/open-quantum-secure/pkg/findings"
)

// EnrichFindings fills in missing Algorithm.KeySize values by matching
// constant field names in ConstMap against each finding's RawIdentifier.
// Only enriches findings where Algorithm != nil and KeySize == 0.
// When multiple constants match, the longest field name wins (most specific).
//
// In practice this rarely fires: every current engine populates
// RawIdentifier with an algorithm name (cipherscope: "AES") or a rule ID
// (astgrep: "crypto-go-aes-new-cipher"), never with source text containing a
// const's name. It is kept for callers with a flat ConstMap and a
// RawIdentifier that does happen to carry a matching name. The production
// orchestrator wiring uses EnrichFindingsByFile instead, which is
// Location-keyed and doesn't depend on RawIdentifier at all.
func EnrichFindings(ff []findings.UnifiedFinding, cm ConstMap) {
	if len(cm) == 0 {
		return
	}

	// Pre-compute sorted keys and extracted field names for deterministic matching.
	type entry struct {
		field string
		value int
	}
	entries := make([]entry, 0, len(cm))
	for key, value := range cm {
		if value <= 0 {
			continue // skip zero/negative values
		}
		field := fieldName(key)
		if field == "" {
			continue
		}
		entries = append(entries, entry{field: field, value: value})
	}
	// Sort longest field first for most-specific match; break ties alphabetically.
	sort.Slice(entries, func(i, j int) bool {
		if len(entries[i].field) != len(entries[j].field) {
			return len(entries[i].field) > len(entries[j].field)
		}
		return entries[i].field < entries[j].field
	})

	for i := range ff {
		f := &ff[i]
		if f.Algorithm == nil || f.Algorithm.KeySize > 0 || f.RawIdentifier == "" {
			continue
		}
		// Find the longest matching field name in the RawIdentifier.
		for _, e := range entries {
			if containsWord(f.RawIdentifier, e.field) {
				f.Algorithm.KeySize = e.value
				break
			}
		}
	}
}

// containsWord checks whether field appears in s as a whole "word",
// bounded by start/end of string, underscores, dots, or other non-alphanumeric chars.
// Loops through all occurrences to find a valid word-bounded match.
func containsWord(s, field string) bool {
	idx := strings.Index(s, field)
	for idx >= 0 {
		end := idx + len(field)
		leftOK := idx == 0 || !isAlphaNum(s[idx-1])
		rightOK := end >= len(s) || !isAlphaNum(s[end])
		if leftOK && rightOK {
			return true
		}
		// Search for next occurrence after current match.
		if end >= len(s) {
			break
		}
		next := strings.Index(s[end:], field)
		if next < 0 {
			break
		}
		idx = end + next
	}
	return false
}

func isAlphaNum(c byte) bool {
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')
}

// fieldName strips the qualifier prefix (package/class/module) from a
// ConstMap key, returning just the constant's own name (e.g.
// "CryptoService.AES_KEY_SIZE" -> "AES_KEY_SIZE"). Bare keys with no "."
// (e.g. the C++ parser's un-namespaced keys) are returned unchanged.
func fieldName(key string) string {
	parts := strings.SplitN(key, ".", 2)
	if len(parts) == 2 {
		return parts[1]
	}
	return key
}

// minPlausibleKeySize is the smallest value EnrichFindingsByFile will treat
// as a candidate key size. It exists to keep unrelated small integer
// constants in a file (retry counts, pool sizes, etc.) from being mistaken
// for a crypto key size when they happen to be the file's only constant.
// 8 is a floor, not a real minimum classical key size -- it only filters out
// obviously-not-bit-length values.
const minPlausibleKeySize = 8

// EnrichFindingsByFile fills in missing Algorithm.KeySize values using
// integer constants declared in the SAME FILE as the finding, keyed by
// Location.File rather than RawIdentifier (see EnrichFindings doc for why
// RawIdentifier-based matching doesn't fire against real engine output).
//
// For each finding with Algorithm != nil and KeySize == 0, it looks at the
// plausible-key-size constants (>= minPlausibleKeySize) declared in that
// finding's own file:
//
//   - Zero candidates: no-op.
//   - One candidate: assign it. A lone crypto-relevant integer constant in a
//     file is almost always the key size for that file's one crypto call --
//     this is the shape of the go-crypto ground-truth sample (a single
//     `const KeySize = 256` next to a single aes.NewCipher call).
//   - Multiple candidates: only assign when exactly one candidate's field
//     name contains the finding's algorithm token as a whole word (e.g.
//     field "RSA_KEY_LENGTH" for an "RSA" finding, "AES_KEY_SIZE" for an
//     "AES" finding in the same file) -- a bare substring check would let
//     "PARSABLE_LIMIT" false-match "RSA". This is what keeps two co-located
//     constants (RSA modulus bits + AES key size) from cross-contaminating
//     each other's findings. If the name match is itself ambiguous (zero or
//     2+ matches), the finding is left unenriched rather than guessed at --
//     a wrong KeySize actively misclassifies quantum risk, whereas KeySize
//     staying 0 only falls back to the existing "unknown" classification.
func EnrichFindingsByFile(ff []findings.UnifiedFinding, fc FileConstants) {
	if len(fc) == 0 {
		return
	}

	for i := range ff {
		f := &ff[i]
		if f.Algorithm == nil || f.Algorithm.KeySize > 0 || f.Location.File == "" {
			continue
		}
		fileCM, ok := fc[filepath.Clean(f.Location.File)]
		if !ok || len(fileCM) == 0 {
			continue
		}

		type candidate struct {
			field string
			value int
		}
		var candidates []candidate
		for key, value := range fileCM {
			if value < minPlausibleKeySize {
				continue
			}
			candidates = append(candidates, candidate{field: fieldName(key), value: value})
		}

		// Key-evidence gate (wave-2 review V4/V5): a constant may only
		// become a KeySize when BOTH hold:
		//   (a) its name carries key evidence — a KEY/MODULUS/BITS/
		//       STRENGTH name segment, or the finding's algorithm token
		//       word-bounded in the name. Names like defaultBufSize or
		//       PARSABLE_LIMIT do not qualify.
		//   (b) its value is plausible for the algorithm family (4096 is
		//       a fine RSA modulus but never an AES key).
		// Without this, a file's lone unrelated int const (buffer size,
		// iteration count, retry limit) silently became the key size and
		// flipped the quantum-risk verdict in either direction.
		algoToken := primaryAlgorithmToken(f.Algorithm.Name)
		var eligible []candidate
		for _, c := range candidates {
			if !keyEvidenceName(c.field, algoToken) {
				continue
			}
			if !plausibleKeySize(algoToken, c.value) {
				continue
			}
			eligible = append(eligible, c)
		}

		switch len(eligible) {
		case 0:
			continue
		case 1:
			f.Algorithm.KeySize = eligible[0].value
		default:
			if algoToken == "" {
				continue
			}
			var matchValue int
			matches := 0
			for _, c := range eligible {
				// Word-bounded, not a bare substring check: "PARSABLE_LIMIT"
				// contains "RSA" as raw bytes (P-A-R-S-A-...) but isn't an
				// RSA-related constant. containsWord requires the token to
				// sit on an alphanumeric boundary in the field name.
				if containsWord(strings.ToUpper(c.field), algoToken) {
					matchValue = c.value
					matches++
				}
			}
			if matches == 1 {
				f.Algorithm.KeySize = matchValue
			}
		}
	}
}

// keyEvidenceName reports whether a constant's field name provides
// evidence of being a key-size constant: a KEY/MODULUS/BITS/STRENGTH
// segment (split on non-alphanumerics and camelCase boundaries), or the
// finding's algorithm token appearing word-bounded in the name. A bare
// SIZE/LENGTH/LEN segment is deliberately NOT sufficient — defaultBufSize
// and MAX_LENGTH are the exact false-positive shapes being excluded.
func keyEvidenceName(field, algoToken string) bool {
	if algoToken != "" && containsWord(strings.ToUpper(field), algoToken) {
		return true
	}
	for _, seg := range nameSegments(field) {
		switch seg {
		case "KEY", "MODULUS", "BITS", "STRENGTH":
			return true
		}
	}
	return false
}

// nameSegments splits an identifier on non-alphanumerics and lower→upper
// camelCase boundaries, returning uppercased segments ("rsaKeyBits" →
// [RSA KEY BITS], "PARSABLE_LIMIT" → [PARSABLE LIMIT]).
func nameSegments(s string) []string {
	var segs []string
	var cur []byte
	flush := func() {
		if len(cur) > 0 {
			segs = append(segs, strings.ToUpper(string(cur)))
			cur = cur[:0]
		}
	}
	prevLower := false
	for i := 0; i < len(s); i++ {
		c := s[i]
		isAlnum := (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')
		if !isAlnum {
			flush()
			prevLower = false
			continue
		}
		if c >= 'A' && c <= 'Z' && prevLower {
			flush()
		}
		cur = append(cur, c)
		prevLower = c >= 'a' && c <= 'z'
	}
	flush()
	return segs
}

// plausibleKeySize reports whether value is a credible key size for the
// algorithm family named by token. Unknown families accept the union of
// all known sets (conservative), never arbitrary integers.
func plausibleKeySize(token string, value int) bool {
	symmetric := map[int]bool{128: true, 192: true, 256: true, 512: true}
	rsaClass := map[int]bool{1024: true, 2048: true, 3072: true, 4096: true, 7680: true, 8192: true, 15360: true}
	ecClass := map[int]bool{224: true, 233: true, 255: true, 256: true, 283: true, 384: true, 409: true, 448: true, 521: true, 571: true}
	switch token {
	case "AES", "SM4", "CHACHA", "CHACHA20", "CAMELLIA", "ARIA", "SEED", "LEA", "TWOFISH", "SERPENT":
		return symmetric[value]
	case "RSA", "RSAES", "RSASSA", "DSA", "DH", "FFDH", "ELGAMAL", "DIFFIE":
		return rsaClass[value]
	case "ECDSA", "ECDH", "ECDHE", "EC", "ED25519", "ED448", "X25519", "X448", "SM2", "ECIES":
		return ecClass[value]
	}
	return symmetric[value] || rsaClass[value] || ecClass[value]
}

// primaryAlgorithmToken extracts the leading alphanumeric token from an
// algorithm name for name-based disambiguation ("AES-GCM" -> "AES",
// "RSA-OAEP" -> "RSA", "AES" -> "AES"). Returns "" for an empty name.
func primaryAlgorithmToken(name string) string {
	upper := strings.ToUpper(name)
	end := strings.IndexFunc(upper, func(r rune) bool {
		return !((r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9'))
	})
	if end == -1 {
		return upper
	}
	return upper[:end]
}
