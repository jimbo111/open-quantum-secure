package findings

import (
	"path/filepath"
	"sort"
	"strings"
)

// CalculatePriority computes a priority level (P1–P4) for a finding based on
// severity, reachability, blast radius, confidence, and source-file type.
//
// Priority matrix:
//
//	P1 (Critical): severity=critical AND (reachable=yes OR blastRadius≥70 OR confidence≥medium-high)
//	P2 (High):     severity=critical AND reachable=unknown; OR severity=high AND (reachable=yes OR blastRadius≥40)
//	P3 (Medium):   severity=high AND reachable=unknown; OR severity=medium AND reachable=yes
//	P4 (Low):      severity=low/info; OR severity=medium AND reachable≠yes; OR test/generated file
//
// Test-file and generated-file findings are always P4 regardless of other signals.
func CalculatePriority(f *UnifiedFinding) string {
	// Test and generated files are always low priority.
	if f.TestFile || f.GeneratedFile {
		return "P4"
	}

	switch f.Severity {
	case SevCritical:
		if f.Reachable == ReachableYes || f.BlastRadius >= 70 || confidenceRank(f.Confidence) >= 4 {
			return "P1"
		}
		return "P2"

	case SevHigh:
		if f.Reachable == ReachableYes || f.BlastRadius >= 40 {
			return "P2"
		}
		return "P3"

	case SevMedium:
		if f.Reachable == ReachableYes {
			return "P3"
		}
		return "P4"

	default: // SevLow, SevInfo, ""
		return "P4"
	}
}

// confidenceRank returns a numeric rank for confidence level comparison.
func confidenceRank(c Confidence) int {
	switch c {
	case ConfidenceHigh:
		return 5
	case ConfidenceMediumHigh:
		return 4
	case ConfidenceMedium:
		return 3
	case ConfidenceMediumLow:
		return 2
	case ConfidenceLow:
		return 1
	default:
		return 0
	}
}

// priorityRank returns a numeric rank for sort ordering (lower = higher priority).
func priorityRank(p string) int {
	switch p {
	case "P1":
		return 1
	case "P2":
		return 2
	case "P3":
		return 3
	case "P4":
		return 4
	default:
		return 5
	}
}

// severityRank returns a numeric rank for sort ordering (lower = higher severity).
func severityRank(s Severity) int {
	switch s {
	case SevCritical:
		return 1
	case SevHigh:
		return 2
	case SevMedium:
		return 3
	case SevLow:
		return 4
	case SevInfo:
		return 5
	default:
		return 6
	}
}

// SortByPriority sorts findings by priority (P1 first), then severity, then file path.
func SortByPriority(ff []UnifiedFinding) {
	sort.SliceStable(ff, func(i, j int) bool {
		pi, pj := priorityRank(ff[i].Priority), priorityRank(ff[j].Priority)
		if pi != pj {
			return pi < pj
		}
		si, sj := severityRank(ff[i].Severity), severityRank(ff[j].Severity)
		if si != sj {
			return si < sj
		}
		return ff[i].Location.File < ff[j].Location.File
	})
}

// IsTestFile returns true if the file path matches common test file patterns.
func IsTestFile(path string) bool {
	base := filepath.Base(path)
	lower := strings.ToLower(base)
	normalized := strings.ToLower(filepath.ToSlash(path))

	// Suffix patterns
	if strings.HasSuffix(lower, "_test.go") ||
		strings.HasSuffix(lower, "_test.py") ||
		strings.HasSuffix(lower, ".test.js") ||
		strings.HasSuffix(lower, ".test.ts") ||
		strings.HasSuffix(lower, ".test.tsx") ||
		strings.HasSuffix(lower, ".test.jsx") ||
		strings.HasSuffix(lower, ".spec.js") ||
		strings.HasSuffix(lower, ".spec.ts") ||
		strings.HasSuffix(lower, ".spec.tsx") {
		return true
	}

	// Directory patterns
	testDirs := []string{"/test/", "/tests/", "/__tests__/", "/testdata/", "/test_fixtures/", "/testutil/"}
	for _, d := range testDirs {
		if strings.Contains(normalized, d) {
			return true
		}
	}

	// Check if path starts with test directory
	for _, d := range testDirs {
		if strings.HasPrefix(normalized, strings.TrimPrefix(d, "/")) {
			return true
		}
	}

	return false
}

// IsGeneratedFile returns true if the file path matches common generated file patterns.
func IsGeneratedFile(path string) bool {
	base := filepath.Base(path)
	lower := strings.ToLower(base)
	normalized := strings.ToLower(filepath.ToSlash(path))

	// Suffix patterns
	if strings.HasSuffix(lower, ".pb.go") ||
		strings.HasSuffix(lower, ".pb.cc") ||
		strings.HasSuffix(lower, ".pb.h") ||
		strings.HasSuffix(lower, "_generated.go") ||
		strings.HasSuffix(lower, ".generated.go") ||
		strings.HasSuffix(lower, ".generated.ts") ||
		strings.HasSuffix(lower, "_generated.ts") {
		return true
	}

	// Prefix patterns
	if strings.HasPrefix(lower, "mock_") ||
		strings.HasPrefix(lower, "zz_generated") {
		return true
	}

	// Directory patterns
	genDirs := []string{"/generated/", "/gen/", "/__generated__/", "/autogen/"}
	for _, d := range genDirs {
		if strings.Contains(normalized, d) {
			return true
		}
	}

	return false
}

// MarkTestAndGenerated marks findings from test/generated files with the
// appropriate flags. Findings are marked but not dropped — consumers can
// filter based on these flags.
func MarkTestAndGenerated(ff []UnifiedFinding) {
	for i := range ff {
		path := ff[i].Location.File
		if IsTestFile(path) {
			ff[i].TestFile = true
		}
		if IsGeneratedFile(path) {
			ff[i].GeneratedFile = true
		}
	}
}
