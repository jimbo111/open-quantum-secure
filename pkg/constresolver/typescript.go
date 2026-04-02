package constresolver

import (
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

// tsConstRe matches TypeScript UPPER_SNAKE_CASE const declarations.
// Matches: [export] const KEY_SIZE [: number] = 256;
// Also matches hex literals (0x100).
var tsConstRe = regexp.MustCompile(`(?m)(?:export\s+)?const\s+([A-Z][A-Z0-9_]+)\s*(?::\s*number\s*)?=\s*(0[xX][0-9a-fA-F_]+|\d[\d_]*)`)

// TypeScriptParser parses TypeScript source files for UPPER_SNAKE_CASE constants.
type TypeScriptParser struct{}

// Extensions returns TypeScript file extensions.
func (p *TypeScriptParser) Extensions() []string {
	return []string{".ts", ".tsx"}
}

// ParseFile extracts UPPER_SNAKE_CASE integer constants from a TypeScript file.
// Key format: "modulename.CONST_NAME"
func (p *TypeScriptParser) ParseFile(path string, content []byte) (ConstMap, error) {
	result := make(ConstMap)
	moduleName := tsModuleNameFromFile(path)

	matches := tsConstRe.FindAllSubmatch(content, -1)
	for _, m := range matches {
		field := string(m[1])
		raw := strings.ReplaceAll(string(m[2]), "_", "")
		val64, err := strconv.ParseInt(raw, 0, 64)
		if err != nil {
			continue
		}
		key := moduleName + "." + field
		result[key] = int(val64)
	}

	return result, nil
}

// tsModuleNameFromFile extracts the base filename without .ts or .tsx extension.
func tsModuleNameFromFile(path string) string {
	base := filepath.Base(path)
	// Strip .tsx first, then .ts
	name := strings.TrimSuffix(base, filepath.Ext(base))
	return name
}
