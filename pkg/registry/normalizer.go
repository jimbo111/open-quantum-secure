package registry

import "strings"

// MatchType describes how confident the normalization result is.
type MatchType string

const (
	MatchExact  MatchType = "exact"
	MatchPrefix MatchType = "prefix"
	MatchFuzzy  MatchType = "fuzzy"
	MatchNone   MatchType = "none"
)

// NormalizedResult holds the result of normalizing a raw algorithm name.
type NormalizedResult struct {
	CanonicalName string
	Family        string
	Primitive     string
	Parameters    map[string]string
	Confidence    string // "high", "medium", "low"
	MatchType     MatchType
}

// Normalize converts a raw algorithm name into a canonical NormalizedResult.
// keySize and mode are optional hints (pass 0 / "" to omit).
func (r *Registry) Normalize(raw string, keySize int, mode string) NormalizedResult {
	cleaned := cleanInput(raw)

	// Step 1: Try exact pattern match against both the cleaned and original input.
	// cleanInput replaces underscores with hyphens, which breaks names like
	// "RSASSA-PKCS1-v1_5" where the underscore is significant.
	candidates := []string{cleaned}
	trimmed := strings.TrimSpace(raw)
	if trimmed != cleaned {
		candidates = append(candidates, trimmed)
	}

	for _, candidate := range candidates {
		for _, cp := range r.patternIndex {
			if params, ok := cp.match(candidate); ok {
				return NormalizedResult{
					CanonicalName: cp.canonical,
					Family:        cp.family,
					Primitive:     cp.primitive,
					Parameters:    params,
					Confidence:    "high",
					MatchType:     MatchExact,
				}
			}
		}
	}

	// Step 2: Try family prefix match (longest prefix wins — sorted by length desc)
	upper := strings.ToUpper(cleaned)
	for _, familyName := range r.familyPrefixes {
		if strings.HasPrefix(upper, familyName) {
			fam := r.familyIndex[familyName]
			canonical := buildCanonical(fam.Family, keySize, mode)
			primitive := ""
			if len(fam.Variant) > 0 {
				primitive = fam.Variant[0].Primitive
			}
			return NormalizedResult{
				CanonicalName: canonical,
				Family:        fam.Family,
				Primitive:     primitive,
				Confidence:    "medium",
				MatchType:     MatchPrefix,
			}
		}
	}

	// Step 3: Fallback with low confidence
	return NormalizedResult{
		CanonicalName: raw,
		Family:        extractFamily(raw),
		Confidence:    "low",
		MatchType:     MatchNone,
	}
}

func cleanInput(s string) string {
	s = strings.TrimSpace(s)
	s = strings.ReplaceAll(s, "_", "-")
	return s
}

func buildCanonical(family string, keySize int, mode string) string {
	name := family
	if keySize > 0 {
		name += "-" + itoa(keySize)
	}
	if mode != "" {
		name += "-" + strings.ToUpper(mode)
	}
	return name
}

func extractFamily(raw string) string {
	parts := strings.FieldsFunc(raw, func(r rune) bool {
		return r == '-' || r == '_'
	})
	if len(parts) > 0 {
		return parts[0]
	}
	return raw
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	if n < 0 {
		return "-" + utoa(uint(-int64(n)))
	}
	return utoa(uint(n))
}

func utoa(n uint) string {
	if n == 0 {
		return "0"
	}
	digits := make([]byte, 0, 20)
	for n > 0 {
		digits = append(digits, byte('0'+n%10))
		n /= 10
	}
	for i, j := 0, len(digits)-1; i < j; i, j = i+1, j-1 {
		digits[i], digits[j] = digits[j], digits[i]
	}
	return string(digits)
}
