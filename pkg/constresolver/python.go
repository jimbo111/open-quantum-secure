package constresolver

import (
	"bufio"
	"bytes"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

// pythonConstRe matches module-level UPPER_SNAKE_CASE constants.
// Only matches lines starting at the beginning (no leading whitespace).
// Supports decimal and hex (0x...) integer literals.
var pythonConstRe = regexp.MustCompile(`^([A-Z][A-Z0-9_]+)\s*=\s*(0[xX][0-9a-fA-F_]+|\d[\d_]*)`)

// PythonParser parses Python source files for module-level uppercase constants.
type PythonParser struct{}

// Extensions returns Python file extensions.
func (p *PythonParser) Extensions() []string {
	return []string{".py"}
}

// ParseFile extracts module-level UPPER_SNAKE_CASE = integer constants from a Python file.
// Key format: "modulename.CONST_NAME"
// Lines with leading whitespace (inside functions/classes) are skipped.
func (p *PythonParser) ParseFile(path string, content []byte) (ConstMap, error) {
	result := make(ConstMap)
	moduleName := moduleNameFromFile(path)

	scanner := bufio.NewScanner(bytes.NewReader(content))
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024) // up to 1MB per line
	for scanner.Scan() {
		line := scanner.Text()

		// Skip lines with leading whitespace (inside functions/classes).
		if len(line) > 0 && (line[0] == ' ' || line[0] == '\t') {
			continue
		}

		m := pythonConstRe.FindStringSubmatch(line)
		if m == nil {
			continue
		}

		field := m[1]
		raw := strings.ReplaceAll(m[2], "_", "")
		val64, err := strconv.ParseInt(raw, 0, 64)
		if err != nil {
			continue
		}
		val := int(val64)

		key := moduleName + "." + field
		result[key] = val
	}

	return result, scanner.Err()
}

// moduleNameFromFile extracts the base filename without extension.
func moduleNameFromFile(path string) string {
	base := filepath.Base(path)
	name := strings.TrimSuffix(base, filepath.Ext(base))
	return name
}
