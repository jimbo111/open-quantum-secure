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

		switch len(candidates) {
		case 0:
			continue
		case 1:
			f.Algorithm.KeySize = candidates[0].value
		default:
			algoToken := primaryAlgorithmToken(f.Algorithm.Name)
			if algoToken == "" {
				continue
			}
			var matchValue int
			matches := 0
			for _, c := range candidates {
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
