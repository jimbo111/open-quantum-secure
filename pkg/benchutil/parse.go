// Package benchutil provides utilities for parsing Go benchmark output and
// comparing results against a baseline to detect performance regressions.
package benchutil

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// BenchResult holds the parsed result for a single benchmark.
type BenchResult struct {
	Name     string  `json:"name"`
	N        int     `json:"n"`
	NsPerOp  float64 `json:"nsPerOp"`
	BPerOp   int64   `json:"bPerOp"`
	AllocsOp int64   `json:"allocsPerOp"`
}

// BenchReport is the full report saved to / loaded from a JSON baseline file.
type BenchReport struct {
	GoVersion string        `json:"goVersion"`
	Commit    string        `json:"commit"`
	Timestamp time.Time     `json:"timestamp"`
	Results   []BenchResult `json:"results"`
}

// benchLineRe matches a standard go test -bench output line, e.g.:
//
//	BenchmarkNormalize-8    50000    23456 ns/op    4096 B/op    128 allocs/op
//
// Groups: 1=name (with GOMAXPROCS suffix stripped), 2=N, 3=ns/op,
// optionally 4=B/op, optionally 5=allocs/op.
var benchLineRe = regexp.MustCompile(
	`^(Benchmark\S+?)-\d+\s+(\d+)\s+([\d.]+)\s+ns/op` +
		`(?:\s+([\d.]+)\s+B/op` +
		`(?:\s+([\d.]+)\s+allocs/op)?)?`,
)

// goVersionRe matches the "go: ..." or "goos:" preamble lines that contain
// the Go version, e.g. "go test -v ... GOARCH=..." but we look for the
// explicit version line emitted by -v or just pick it up if present.
var goVersionRe = regexp.MustCompile(`^go\s+version\s+(\S+)`)

// ParseBenchOutput reads go test -bench stdout from r and returns all parsed
// BenchResult entries. Lines that do not match the benchmark output format are
// silently skipped (preamble, PASS, log lines, etc.).
func ParseBenchOutput(r io.Reader) ([]BenchResult, error) {
	var results []BenchResult
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		line := scanner.Text()
		m := benchLineRe.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		// m[1]=name, m[2]=N, m[3]=ns/op, m[4]=B/op, m[5]=allocs/op
		n, err := strconv.Atoi(m[2])
		if err != nil {
			continue
		}
		nsPerOp, err := strconv.ParseFloat(m[3], 64)
		if err != nil {
			continue
		}
		var bPerOp int64
		if m[4] != "" {
			f, err := strconv.ParseFloat(m[4], 64)
			if err == nil {
				bPerOp = int64(f)
			}
		}
		var allocsOp int64
		if m[5] != "" {
			f, err := strconv.ParseFloat(m[5], 64)
			if err == nil {
				allocsOp = int64(f)
			}
		}
		results = append(results, BenchResult{
			Name:     m[1],
			N:        n,
			NsPerOp:  nsPerOp,
			BPerOp:   bPerOp,
			AllocsOp: allocsOp,
		})
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("benchutil: scanning bench output: %w", err)
	}
	return results, nil
}

// goVersionFromOutput attempts to extract the Go version string from bench
// output text (when -v is passed). Returns empty string if not found.
func goVersionFromOutput(lines []string) string {
	for _, l := range lines {
		if m := goVersionRe.FindStringSubmatch(strings.TrimSpace(l)); m != nil {
			return m[1]
		}
	}
	return ""
}

// LoadReport reads and unmarshals a BenchReport from a JSON file at path.
func LoadReport(path string) (*BenchReport, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("benchutil: loading report %q: %w", path, err)
	}
	var report BenchReport
	if err := json.Unmarshal(data, &report); err != nil {
		return nil, fmt.Errorf("benchutil: parsing report %q: %w", path, err)
	}
	return &report, nil
}

// SaveReport writes report to path as JSON using an atomic temp-rename pattern
// to prevent partial writes.
func SaveReport(path string, report *BenchReport) error {
	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return fmt.Errorf("benchutil: marshalling report: %w", err)
	}

	// Determine the directory for the temp file (same filesystem as target).
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, "benchreport-*.json.tmp")
	if err != nil {
		return fmt.Errorf("benchutil: creating temp file: %w", err)
	}
	tmpName := tmp.Name()

	if err := tmp.Chmod(0o644); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmpName)
		return fmt.Errorf("benchutil: chmod temp file: %w", err)
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmpName)
		return fmt.Errorf("benchutil: writing temp file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpName)
		return fmt.Errorf("benchutil: closing temp file: %w", err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		_ = os.Remove(tmpName)
		return fmt.Errorf("benchutil: renaming temp file to %q: %w", path, err)
	}
	return nil
}

