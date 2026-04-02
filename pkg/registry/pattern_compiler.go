package registry

import (
	"regexp"
	"strings"
)

type compiledPattern struct {
	regex     *regexp.Regexp
	family    string
	canonical string
	primitive string
}

func compilePattern(pattern, family string) (compiledPattern, error) {
	canonical := pattern // The pattern IS the canonical name for exact matches

	// Convert CycloneDX pattern syntax to regex
	regexStr := convertPatternToRegex(pattern)

	re, err := regexp.Compile("(?i)^" + regexStr + "$")
	if err != nil {
		return compiledPattern{}, err
	}

	return compiledPattern{
		regex:     re,
		family:    family,
		canonical: canonical,
	}, nil
}

func convertPatternToRegex(pattern string) string {
	// Step 1: Extract {placeholder} tokens before escaping metacharacters.
	// This prevents dot/plus escaping from corrupting placeholder names.
	type placeholder struct {
		token string // e.g. "{keySize}"
		name  string // e.g. "keySize"
	}
	var placeholders []placeholder
	tmp := pattern
	idx := 0
	for {
		start := strings.Index(tmp, "{")
		if start == -1 {
			break
		}
		end := strings.Index(tmp[start:], "}")
		if end == -1 {
			break
		}
		name := tmp[start+1 : start+end]
		token := tmp[start : start+end+1]
		sentinel := "\x00PH" + itoa(idx) + "\x00"
		tmp = tmp[:start] + sentinel + tmp[start+end+1:]
		placeholders = append(placeholders, placeholder{token: token, name: name})
		idx++
	}

	// Step 2: Escape regex metacharacters on the placeholder-free string
	tmp = strings.ReplaceAll(tmp, ".", "\\.")
	tmp = strings.ReplaceAll(tmp, "+", "\\+")

	// Step 3: Convert optional groups [...] to (?:...)?
	tmp = strings.ReplaceAll(tmp, "[", "(?:")
	tmp = strings.ReplaceAll(tmp, "]", ")?")

	// Step 4: Replace sentinels with named capture groups
	for i, ph := range placeholders {
		sentinel := "\x00PH" + itoa(i) + "\x00"
		tmp = strings.ReplaceAll(tmp, sentinel, "(?P<"+ph.name+">\\w+)")
	}

	return tmp
}

func (cp *compiledPattern) match(input string) (map[string]string, bool) {
	matches := cp.regex.FindStringSubmatch(input)
	if matches == nil {
		return nil, false
	}

	params := make(map[string]string)
	for i, name := range cp.regex.SubexpNames() {
		if i != 0 && name != "" && i < len(matches) && matches[i] != "" {
			params[name] = matches[i]
		}
	}
	return params, true
}
