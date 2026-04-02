package constresolver

import (
	"sort"
	"strings"

	"github.com/jimbo111/open-quantum-secure/pkg/findings"
)

// EnrichFindings fills in missing Algorithm.KeySize values by matching
// constant field names in ConstMap against each finding's RawIdentifier.
// Only enriches findings where Algorithm != nil and KeySize == 0.
// When multiple constants match, the longest field name wins (most specific).
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
		parts := strings.SplitN(key, ".", 2)
		field := key
		if len(parts) == 2 {
			field = parts[1]
		}
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
