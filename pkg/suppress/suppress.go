// Package suppress implements inline suppression directives (// oqs:ignore) and
// .oqs-ignore file-based exclusion for the OQS Scanner.
package suppress

import (
	"bufio"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
)

// Suppression represents a single suppression directive found in source code.
type Suppression struct {
	FilePath   string   // file where directive was found
	Line       int      // line number of the directive
	Algorithms []string // empty = suppress all; ["RSA"] = only RSA
	Reason     string   // optional reason text
}

// Stats tracks suppression statistics for reporting.
type Stats struct {
	SuppressedByInline int
	SuppressedByIgnore int
	TotalDirectives    int
}

// Scanner scans source files for suppression directives and manages .oqs-ignore patterns.
type Scanner struct {
	ignorePatterns []string // glob patterns from .oqs-ignore
	rootPath       string

	mu          sync.Mutex
	suppressMap map[string][]Suppression // file → suppressions
	stats       Stats
}

// directivePattern matches oqs:ignore with optional algorithm list and reason.
// Matches:
//
//	// oqs:ignore
//	// oqs:ignore[RSA,DES]
//	// oqs:ignore — reason text
//	// oqs:ignore[RSA] — reason text
//	# oqs:ignore
//	/* oqs:ignore */
//	<!-- oqs:ignore -->
var directivePattern = regexp.MustCompile(
	`(?://|#|/\*|<!--)\s*oqs:ignore` +
		`(?:\[([^\]]*)\])?` + // optional algorithm list
		`(?:\s*(?:[—:—]\s*|\s*-+\s*)(.+?))?` + // optional reason
		`(?:\s*\*/|\s*-->)?` + // optional closing
		`\s*$`,
)

// NewScanner creates a suppression scanner. It loads .oqs-ignore from rootPath
// if the file exists.
func NewScanner(rootPath string) (*Scanner, error) {
	s := &Scanner{
		rootPath:    rootPath,
		suppressMap: make(map[string][]Suppression),
	}

	// Load .oqs-ignore if present.
	ignorePath := filepath.Join(rootPath, ".oqs-ignore")
	if data, err := os.ReadFile(ignorePath); err == nil {
		s.ignorePatterns = parseIgnoreFile(string(data))
	}

	return s, nil
}

// parseIgnoreFile parses a .oqs-ignore file into glob patterns.
func parseIgnoreFile(content string) []string {
	var patterns []string
	scanner := bufio.NewScanner(strings.NewReader(content))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		patterns = append(patterns, line)
	}
	return patterns
}

// ScanFile reads a source file and extracts suppression directives.
func (s *Scanner) ScanFile(filePath string) ([]Suppression, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, err
	}
	return s.scanContent(filePath, string(data)), nil
}

// scanContent extracts suppression directives from file content.
func (s *Scanner) scanContent(filePath, content string) []Suppression {
	var suppressions []Suppression
	lines := strings.Split(content, "\n")
	for i, line := range lines {
		lineNum := i + 1
		trimmed := strings.TrimSpace(line)
		// Strip string-literal contents before matching so that a directive
		// appearing INSIDE "..." / `...` / '...' is not mistaken for a real
		// comment directive (F1).
		scannable := stripStringLiterals(trimmed)
		matches := directivePattern.FindStringSubmatch(scannable)
		if matches == nil {
			continue
		}

		sup := Suppression{
			FilePath: filePath,
			Line:     lineNum,
		}

		// Parse algorithm list
		if matches[1] != "" {
			algos := strings.Split(matches[1], ",")
			for _, a := range algos {
				a = strings.TrimSpace(a)
				if a != "" {
					sup.Algorithms = append(sup.Algorithms, a)
				}
			}
		}

		// Parse reason
		if len(matches) > 2 && matches[2] != "" {
			sup.Reason = strings.TrimSpace(matches[2])
		}

		suppressions = append(suppressions, sup)
	}
	return suppressions
}

// IsSuppressed checks if a finding at (filePath, line, algorithm) is suppressed.
// It checks both .oqs-ignore patterns and inline directives.
// The directive suppresses the same line AND the next line (like // nolint in Go).
func (s *Scanner) IsSuppressed(filePath string, line int, algorithm string) bool {
	// Check .oqs-ignore patterns first
	if s.MatchesIgnorePattern(filePath) {
		s.mu.Lock()
		s.stats.SuppressedByIgnore++
		s.mu.Unlock()
		return true
	}

	// Check inline directives with double-check pattern to prevent TOCTOU race.
	s.mu.Lock()
	suppressions, loaded := s.suppressMap[filePath]
	s.mu.Unlock()

	if !loaded {
		// Lazy-load suppressions for this file (outside lock for I/O).
		sups, err := s.ScanFile(filePath)
		if err != nil {
			return false
		}
		// Double-check: another goroutine may have loaded this file while we
		// were reading it. Only store if still absent.
		s.mu.Lock()
		if existing, alreadyLoaded := s.suppressMap[filePath]; alreadyLoaded {
			suppressions = existing
		} else {
			s.suppressMap[filePath] = sups
			s.stats.TotalDirectives += len(sups)
			suppressions = sups
		}
		s.mu.Unlock()
	}

	for _, sup := range suppressions {
		// Directive applies to same line or next line
		if sup.Line != line && sup.Line != line-1 {
			continue
		}

		// Empty algorithm list = suppress all
		if len(sup.Algorithms) == 0 {
			s.mu.Lock()
			s.stats.SuppressedByInline++
			s.mu.Unlock()
			return true
		}

		// Check if the specific algorithm is in the suppression list
		for _, a := range sup.Algorithms {
			if strings.EqualFold(a, algorithm) {
				s.mu.Lock()
				s.stats.SuppressedByInline++
				s.mu.Unlock()
				return true
			}
		}
	}

	return false
}

// MatchesIgnorePattern checks if filePath matches any .oqs-ignore pattern.
//
// Patterns are evaluated top-to-bottom gitignore-style: each pattern either
// sets or clears the "ignored" flag. A leading `!` negates — it re-includes
// files that an earlier pattern matched. The final flag wins, so ordering
// matters (just like .gitignore).
func (s *Scanner) MatchesIgnorePattern(filePath string) bool {
	if len(s.ignorePatterns) == 0 {
		return false
	}

	// Normalize path for matching
	relPath := filePath
	if s.rootPath != "" {
		if rel, err := filepath.Rel(s.rootPath, filePath); err == nil {
			relPath = rel
		}
	}
	relPath = filepath.ToSlash(relPath)

	ignored := false
	for _, pattern := range s.ignorePatterns {
		negate := strings.HasPrefix(pattern, "!")
		if negate {
			pattern = pattern[1:]
			// Only negations can CLEAR an ignore; skip if not currently ignored.
			if !ignored {
				continue
			}
		} else {
			// Positive pattern only matters if not already ignored (short-circuit).
			if ignored {
				continue
			}
		}
		if patternMatchesPath(pattern, relPath) {
			ignored = !negate
		}
	}
	return ignored
}

// patternMatchesPath reports whether pattern matches relPath using the same
// matching rules as MatchesIgnorePattern's inner loop (handles `**`, whole
// path, basename, and path suffix forms).
func patternMatchesPath(pattern, relPath string) bool {
	pattern = filepath.ToSlash(pattern)

	if strings.Contains(pattern, "**") {
		return matchDoubleStar(pattern, relPath)
	}

	if matched, err := filepath.Match(pattern, relPath); err == nil && matched {
		return true
	}
	if matched, err := filepath.Match(pattern, filepath.Base(relPath)); err == nil && matched {
		return true
	}

	parts := strings.Split(relPath, "/")
	for i := range parts {
		suffix := strings.Join(parts[i:], "/")
		if matched, err := filepath.Match(pattern, suffix); err == nil && matched {
			return true
		}
	}
	return false
}

// matchDoubleStar reports whether path matches a glob pattern that may contain
// "**" segments. "**" matches zero or more path segments; other segments are
// matched with filepath.Match (so "*" matches any single-segment substring).
// Both pattern and path use forward slashes.
func matchDoubleStar(pattern, path string) bool {
	return matchSegments(strings.Split(pattern, "/"), strings.Split(path, "/"))
}

func matchSegments(pat, path []string) bool {
	for len(pat) > 0 {
		if pat[0] == "**" {
			// Collapse consecutive ** to one.
			for len(pat) > 1 && pat[1] == "**" {
				pat = pat[1:]
			}
			// ** at end matches any remaining path (including empty).
			if len(pat) == 1 {
				return true
			}
			// Try matching the rest of pattern against every suffix of path.
			rest := pat[1:]
			for i := 0; i <= len(path); i++ {
				if matchSegments(rest, path[i:]) {
					return true
				}
			}
			return false
		}
		if len(path) == 0 {
			return false
		}
		matched, err := filepath.Match(pat[0], path[0])
		if err != nil || !matched {
			return false
		}
		pat = pat[1:]
		path = path[1:]
	}
	return len(path) == 0
}

// stripStringLiterals removes content between matched quote pairs so a
// subsequent regex scan doesn't treat text inside string data as a comment
// directive. Handles Go/Python/Ruby/C quote styles: "...", '...', and Go raw
// backtick strings. A backslash escapes the next character inside "..." and
// '...' but not inside `...` (raw strings). Unmatched openings consume the
// rest of the line, which is the safe choice — better to miss a possible
// trailing directive than to match one embedded in unterminated string data.
func stripStringLiterals(line string) string {
	var out strings.Builder
	out.Grow(len(line))
	i := 0
	for i < len(line) {
		c := line[i]
		if c == '"' || c == '\'' || c == '`' {
			quote := c
			i++
			for i < len(line) {
				if quote != '`' && line[i] == '\\' && i+1 < len(line) {
					i += 2
					continue
				}
				if line[i] == quote {
					i++
					break
				}
				i++
			}
			continue
		}
		out.WriteByte(c)
		i++
	}
	return out.String()
}

// Stats returns suppression statistics.
func (s *Scanner) Stats() Stats {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.stats
}

// PreloadFile caches suppression directives for a file.
// Safe to call multiple times — only the first call for a given file takes effect.
func (s *Scanner) PreloadFile(filePath string) {
	s.mu.Lock()
	if _, loaded := s.suppressMap[filePath]; loaded {
		s.mu.Unlock()
		return
	}
	s.mu.Unlock()

	sups, err := s.ScanFile(filePath)
	if err != nil {
		return
	}

	s.mu.Lock()
	if _, loaded := s.suppressMap[filePath]; !loaded {
		s.suppressMap[filePath] = sups
		s.stats.TotalDirectives += len(sups)
	}
	s.mu.Unlock()
}
