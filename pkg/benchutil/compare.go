package benchutil

import (
	"fmt"
	"strings"
)

// Comparison is the result of comparing one benchmark between baseline and current.
type Comparison struct {
	Name          string  `json:"name"`
	BaselineNsOp  float64 `json:"baselineNsPerOp"`
	CurrentNsOp   float64 `json:"currentNsPerOp"`
	ChangePercent float64 `json:"changePercent"` // positive = regression, negative = improvement
	Passed        bool    `json:"passed"`
}

// CompareResult is the overall comparison report.
type CompareResult struct {
	Comparisons     []Comparison `json:"comparisons"`
	AllPassed       bool         `json:"allPassed"`
	NewBenchmarks   []string     `json:"newBenchmarks,omitempty"`
	RemovedBenchmarks []string   `json:"removedBenchmarks,omitempty"`
}

// Compare compares current benchmark results against baseline using threshold as
// the maximum allowed percentage increase in ns/op (e.g., 20 means 20%).
// A positive ChangePercent represents a regression; negative is an improvement.
// Benchmarks present only in current are listed in NewBenchmarks (not a failure).
// Benchmarks absent from current are listed in RemovedBenchmarks (not a failure).
// threshold is exclusive: change must be strictly greater than threshold to fail.
func Compare(baseline, current []BenchResult, threshold float64) *CompareResult {
	baseMap := make(map[string]float64, len(baseline))
	for _, b := range baseline {
		baseMap[b.Name] = b.NsPerOp
	}
	currMap := make(map[string]float64, len(current))
	for _, c := range current {
		currMap[c.Name] = c.NsPerOp
	}

	result := &CompareResult{
		AllPassed: true,
	}

	// Process current results against baseline.
	for _, c := range current {
		baseNs, found := baseMap[c.Name]
		if !found {
			result.NewBenchmarks = append(result.NewBenchmarks, c.Name)
			continue
		}
		var changePct float64
		if baseNs > 0 {
			changePct = (c.NsPerOp - baseNs) / baseNs * 100
		}
		passed := changePct <= threshold
		if !passed {
			result.AllPassed = false
		}
		result.Comparisons = append(result.Comparisons, Comparison{
			Name:          c.Name,
			BaselineNsOp:  baseNs,
			CurrentNsOp:   c.NsPerOp,
			ChangePercent: changePct,
			Passed:        passed,
		})
	}

	// Find removed benchmarks (in baseline but not in current).
	for _, b := range baseline {
		if _, found := currMap[b.Name]; !found {
			result.RemovedBenchmarks = append(result.RemovedBenchmarks, b.Name)
		}
	}

	return result
}

// FormatTable returns a human-readable table of the CompareResult.
func FormatTable(result *CompareResult) string {
	var sb strings.Builder

	sb.WriteString("Performance Regression Report\n")
	sb.WriteString(strings.Repeat("=", 80) + "\n\n")

	if len(result.Comparisons) > 0 {
		sb.WriteString(fmt.Sprintf("%-40s %12s %12s %10s %6s\n",
			"Benchmark", "Baseline(ns)", "Current(ns)", "Change%", "Pass"))
		sb.WriteString(strings.Repeat("-", 80) + "\n")
		for _, c := range result.Comparisons {
			status := "PASS"
			if !c.Passed {
				status = "FAIL"
			}
			sign := ""
			if c.ChangePercent > 0 {
				sign = "+"
			}
			sb.WriteString(fmt.Sprintf("%-40s %12.1f %12.1f %9s%% %6s\n",
				c.Name,
				c.BaselineNsOp,
				c.CurrentNsOp,
				fmt.Sprintf("%s%.2f", sign, c.ChangePercent),
				status,
			))
		}
		sb.WriteString("\n")
	}

	if len(result.NewBenchmarks) > 0 {
		sb.WriteString("New benchmarks (no baseline):\n")
		for _, name := range result.NewBenchmarks {
			sb.WriteString(fmt.Sprintf("  + %s\n", name))
		}
		sb.WriteString("\n")
	}

	if len(result.RemovedBenchmarks) > 0 {
		sb.WriteString("Removed benchmarks (no current):\n")
		for _, name := range result.RemovedBenchmarks {
			sb.WriteString(fmt.Sprintf("  - %s\n", name))
		}
		sb.WriteString("\n")
	}

	if result.AllPassed {
		sb.WriteString("Result: PASSED — no performance regressions detected\n")
	} else {
		sb.WriteString("Result: FAILED — performance regressions detected\n")
	}

	return sb.String()
}
