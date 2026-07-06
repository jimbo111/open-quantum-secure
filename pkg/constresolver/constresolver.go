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

// FileConstants maps a cleaned file path to the integer constants declared
// in that single file. Unlike the flat ConstMap returned by Collect (which
// merges every file in the tree into one qualified-name space, discarding
// which file each constant came from), FileConstants keeps per-file
// provenance so EnrichFindingsByFile can match a finding against only the
// constants declared in its own file -- see enricher.go.
type FileConstants map[string]ConstMap

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
	c.walk(ctx, targetPath, func(_ string, cm ConstMap) {
		for k, v := range cm {
			result[k] = v
		}
	})
	return result
}

// CollectByFile walks targetPath like Collect, but groups constants by the
// file they were declared in instead of merging everything into one flat
// qualified-name space. Used by EnrichFindingsByFile for same-file proximity
// matching, which needs to know which constants live in a given finding's
// file without relying on RawIdentifier (which engines never populate with
// source text -- see enricher.go).
func (c *Collector) CollectByFile(ctx context.Context, targetPath string) FileConstants {
	result := make(FileConstants)
	c.walk(ctx, targetPath, func(path string, cm ConstMap) {
		clean := filepath.Clean(path)
		fileCM, ok := result[clean]
		if !ok {
			fileCM = make(ConstMap, len(cm))
			result[clean] = fileCM
		}
		for k, v := range cm {
			fileCM[k] = v
		}
	})
	return result
}

// walk performs the directory traversal shared by Collect and CollectByFile,
// invoking visit(path, cm) once per successfully-read file that has a
// registered parser, regardless of whether parsing found any constants
// (empty maps are passed through; callers decide whether to keep them).
func (c *Collector) walk(ctx context.Context, targetPath string, visit func(path string, cm ConstMap)) {
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

		visit(path, cm)
		return nil
	})

	if err != nil && ctx.Err() == nil {
		fmt.Fprintf(os.Stderr, "constresolver: walk %s: %v\n", targetPath, err)
	}
}
