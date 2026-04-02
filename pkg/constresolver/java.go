package constresolver

import (
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

// javaClassRe matches class declarations to extract the class name.
var javaClassRe = regexp.MustCompile(`(?m)(?:public\s+)?(?:abstract\s+)?(?:final\s+)?class\s+(\w+)`)

// javaConstRe matches static final int constant declarations.
// Matches: [public|private|protected] static final int FIELD_NAME = 123;
// Also matches hex (0x100), octal (0777), and underscore-separated (2_048) literals.
var javaConstRe = regexp.MustCompile(`(?m)(?:public\s+|private\s+|protected\s+)?static\s+final\s+int\s+(\w+)\s*=\s*(0[xX][0-9a-fA-F_]+|0[0-7_]+|\d[\d_]*)`)

// JavaParser parses Java source files for static final int constants.
type JavaParser struct{}

// Extensions returns Java file extensions.
func (p *JavaParser) Extensions() []string {
	return []string{".java"}
}

// ParseFile extracts static final int constants from a Java source file.
// Key format: "ClassName.FIELD_NAME"
func (p *JavaParser) ParseFile(path string, content []byte) (ConstMap, error) {
	result := make(ConstMap)

	// Determine class name: first try class declaration, fall back to filename.
	className := classNameFromFile(path)
	if m := javaClassRe.FindSubmatch(content); m != nil {
		className = string(m[1])
	}

	matches := javaConstRe.FindAllSubmatch(content, -1)
	for _, m := range matches {
		field := string(m[1])
		// Strip Java underscore separators (e.g., 2_048 → 2048) before parsing.
		raw := strings.ReplaceAll(string(m[2]), "_", "")
		val64, err := strconv.ParseInt(raw, 0, 64)
		if err != nil {
			continue
		}
		key := className + "." + field
		result[key] = int(val64)
	}

	return result, nil
}

// classNameFromFile extracts the base filename without extension.
func classNameFromFile(path string) string {
	base := filepath.Base(path)
	name := strings.TrimSuffix(base, filepath.Ext(base))
	return name
}
