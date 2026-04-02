package constresolver

import (
	"context"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
)

// ConstMap maps qualified constant names (e.g., "ClassName.FIELD", "pkg.name") to integer values.
type ConstMap map[string]int

// LanguageParser extracts constant definitions from source files.
type LanguageParser interface {
	// Extensions returns file extensions this parser handles (e.g., ".java", ".go").
	Extensions() []string
	// ParseFile extracts constants from a single file. Returns partial map on error.
	ParseFile(path string, content []byte) (ConstMap, error)
}

// Collector walks a directory tree and extracts constants using registered parsers.
type Collector struct {
	parsers []LanguageParser
}

// maxFileSize is the maximum file size to parse (1MB). Constants should not be in huge files.
const maxFileSize = 1 << 20 // 1MB

// excludedDirs are directory names that should be skipped during walk.
var excludedDirs = map[string]bool{
	"vendor":       true,
	"node_modules": true,
	".git":         true,
}

// New creates a Collector with all built-in language parsers.
func New() *Collector {
	return &Collector{
		parsers: []LanguageParser{
			&JavaParser{},
			&GoParser{},
			&PythonParser{},
			&TypeScriptParser{},
			&CppParser{},
		},
	}
}

// Collect walks targetPath, extracts constants from supported files, and returns
// the merged ConstMap. Non-fatal errors are logged to stderr. Returns empty map (not nil)
// on complete failure.
func (c *Collector) Collect(ctx context.Context, targetPath string) ConstMap {
	result := make(ConstMap)

	// Build extension-to-parser index.
	extToParser := make(map[string]LanguageParser)
	for _, p := range c.parsers {
		for _, ext := range p.Extensions() {
			extToParser[ext] = p
		}
	}

	err := filepath.WalkDir(targetPath, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil // skip unreadable entries, non-fatal
		}

		// Check for context cancellation between files.
		if ctx.Err() != nil {
			return ctx.Err()
		}

		// Skip excluded directories.
		if d.IsDir() {
			if excludedDirs[d.Name()] {
				return filepath.SkipDir
			}
			return nil
		}

		ext := filepath.Ext(path)
		parser, ok := extToParser[ext]
		if !ok {
			return nil
		}

		info, err := d.Info()
		if err != nil {
			return nil
		}
		if info.Size() > maxFileSize {
			return nil
		}

		content, err := os.ReadFile(path)
		if err != nil {
			fmt.Fprintf(os.Stderr, "constresolver: read %s: %v\n", path, err)
			return nil
		}

		cm, err := parser.ParseFile(path, content)
		if err != nil {
			fmt.Fprintf(os.Stderr, "constresolver: parse %s: %v\n", path, err)
			// Continue with partial results if any.
		}

		for k, v := range cm {
			result[k] = v
		}
		return nil
	})

	if err != nil && ctx.Err() == nil {
		fmt.Fprintf(os.Stderr, "constresolver: walk %s: %v\n", targetPath, err)
	}

	return result
}
