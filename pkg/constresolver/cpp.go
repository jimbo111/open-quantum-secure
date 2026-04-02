package constresolver

import (
	"bufio"
	"bytes"
	"regexp"
	"strconv"
	"strings"
)

// cppDefineRe matches simple #define macros with literal integer values.
// Groups: (1) name, (2) value
// Excludes: function-like macros (FOO(x)), multiline (ends with \), expressions (contains operators or parens).
var cppDefineRe = regexp.MustCompile(`(?m)^[ \t]*#define[ \t]+([A-Za-z_]\w*)[ \t]+((?:0[bB][01']+|0[xX][0-9a-fA-F']+|0[0-7']+|\d[\d']*))(?:[uUlL]{1,3})?[ \t]*$`)

// cppConstRe matches const variable declarations (C and C++).
// Matches: [static] const [type] NAME = value;
// Types: int, unsigned, unsigned int, long, size_t, etc.
var cppConstRe = regexp.MustCompile(`(?m)(?:static\s+)?const\s+(?:unsigned\s+)?(?:int|long(?:\s+long)?|short|char|size_t|uint\d*_t|int\d*_t|ptrdiff_t|unsigned)?\s*([A-Za-z_]\w*)\s*=\s*(0[bB][01']+|0[xX][0-9a-fA-F']+|0[0-7']+|\d[\d']*)(?:[uUlL]{1,3})?\s*;`)

// cppConstexprRe matches constexpr declarations (C++11+).
// Matches: [static] constexpr [type] NAME = value;
var cppConstexprRe = regexp.MustCompile(`(?m)(?:static\s+)?constexpr\s+(?:unsigned\s+)?(?:int|long(?:\s+long)?|short|char|size_t|uint\d*_t|int\d*_t|ptrdiff_t|unsigned)?\s*([A-Za-z_]\w*)\s*=\s*(0[bB][01']+|0[xX][0-9a-fA-F']+|0[0-7']+|\d[\d']*)(?:[uUlL]{1,3})?\s*;`)

// cppEnumValueRe matches enum values with explicit integer assignments.
// Used to find NAME = value pairs inside enum bodies.
var cppEnumValueRe = regexp.MustCompile(`\b([A-Za-z_]\w*)\s*=\s*(0[bB][01']+|0[xX][0-9a-fA-F']+|0[0-7']+|\d[\d']*)`)

// cppEnumBodyRe matches enum declarations and captures their body.
// Matches: enum [class|struct] [Name] [: base_type] { ... }
var cppEnumBodyRe = regexp.MustCompile(`(?s)\benum\s+(?:(?:class|struct)\s+)?(?:\w+\s*)?(?::\s*\w+\s*)?\{([^}]*)\}`)

// cppMultilineDefineRe detects multiline #define (ends with backslash).
var cppMultilineDefineRe = regexp.MustCompile(`(?m)^[ \t]*#define\b.*\\[ \t]*$`)

// CppParser parses C/C++ source files for integer constant definitions.
type CppParser struct{}

// Extensions returns C/C++ file extensions handled by this parser.
func (p *CppParser) Extensions() []string {
	return []string{".c", ".cpp", ".cc", ".cxx", ".h", ".hpp", ".hxx"}
}

// ParseFile extracts integer constants from a C/C++ source file.
// Key format: "CONST_NAME" (unqualified — namespace/class qualifiers are not extracted).
func (p *CppParser) ParseFile(path string, content []byte) (ConstMap, error) {
	result := make(ConstMap)

	// Build set of names defined on multiline #define lines so we can skip them.
	multilineNames := extractMultilineDefineNames(content)

	// 1. Extract #define macros with simple literal integer values.
	parseDefines(content, multilineNames, result)

	// 2. Extract const variable declarations.
	parseConstDecls(cppConstRe, content, result)

	// 3. Extract constexpr declarations.
	parseConstDecls(cppConstexprRe, content, result)

	// 4. Extract enum values with explicit integer assignments.
	parseEnumValues(content, result)

	return result, nil
}

// extractMultilineDefineNames returns the set of macro names that appear on
// multiline #define lines (lines ending with \). These must be skipped because
// the body spans multiple lines and cannot be safely evaluated.
func extractMultilineDefineNames(content []byte) map[string]bool {
	names := make(map[string]bool)
	scanner := bufio.NewScanner(bytes.NewReader(content))
	for scanner.Scan() {
		line := scanner.Text()
		trimmed := strings.TrimLeft(line, " \t")
		if !strings.HasPrefix(trimmed, "#define") {
			continue
		}
		// Check if it ends with backslash (after optional whitespace).
		stripped := strings.TrimRight(line, " \t")
		if strings.HasSuffix(stripped, `\`) {
			// Extract macro name: third token after splitting on whitespace.
			parts := strings.Fields(trimmed)
			if len(parts) >= 2 {
				// Remove function-like macro parameters: FOO(x) → FOO
				name := parts[1]
				if idx := strings.IndexByte(name, '('); idx >= 0 {
					name = name[:idx]
				}
				names[name] = true
			}
		}
	}
	return names
}

// parseDefines extracts #define NAME value entries from content.
// Skips function-like macros (name contains '(' before the value group) and
// multiline defines (tracked in multilineNames).
func parseDefines(content []byte, multilineNames map[string]bool, result ConstMap) {
	matches := cppDefineRe.FindAllSubmatch(content, -1)
	for _, m := range matches {
		name := string(m[1])

		// Skip if this name is part of a multiline define.
		if multilineNames[name] {
			continue
		}

		raw := stripDigitSeparators(string(m[2]))
		val64, err := parseCppInt(raw)
		if err != nil {
			continue
		}
		result[name] = int(val64)
	}
}

// parseConstDecls extracts constant declarations using the given regex.
// The regex must have groups: (1) name, (2) value literal.
func parseConstDecls(re *regexp.Regexp, content []byte, result ConstMap) {
	matches := re.FindAllSubmatch(content, -1)
	for _, m := range matches {
		name := string(m[1])
		raw := stripDigitSeparators(string(m[2]))
		val64, err := parseCppInt(raw)
		if err != nil {
			continue
		}
		// Do not overwrite an already-seen name (first occurrence wins).
		if _, exists := result[name]; !exists {
			result[name] = int(val64)
		}
	}
}

// parseEnumValues extracts NAME = literal_int pairs from enum bodies.
func parseEnumValues(content []byte, result ConstMap) {
	enumBodies := cppEnumBodyRe.FindAllSubmatch(content, -1)
	for _, body := range enumBodies {
		pairs := cppEnumValueRe.FindAllSubmatch(body[1], -1)
		for _, m := range pairs {
			name := string(m[1])
			raw := stripDigitSeparators(string(m[2]))
			val64, err := parseCppInt(raw)
			if err != nil {
				continue
			}
			if _, exists := result[name]; !exists {
				result[name] = int(val64)
			}
		}
	}
}

// stripDigitSeparators removes C++ digit separator apostrophes (e.g. 2'048 → 2048).
func stripDigitSeparators(s string) string {
	return strings.ReplaceAll(s, "'", "")
}

// parseCppInt parses a C/C++ integer literal (decimal, hex 0x, octal 0, binary 0b/0B).
// strconv.ParseInt with base 0 handles decimal, hex (0x), and octal (0) automatically.
// Binary (0b/0B) is handled separately since Go's strconv supports it from Go 1.13+.
func parseCppInt(s string) (int64, error) {
	// strconv.ParseInt with base=0 detects 0x (hex), 0 (octal), and decimal.
	// It also handles 0b (binary) starting from Go 1.13.
	return strconv.ParseInt(s, 0, 64)
}
