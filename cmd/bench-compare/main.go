// bench-compare parses go test -bench output from stdin and either saves a
// baseline report or compares against an existing baseline.
//
// Usage:
//
//	go run ./cmd/bench-compare -baseline benchmarks/baseline.json -threshold 20
//	go run ./cmd/bench-compare -save -output benchmarks/baseline.json
package main

import (
	"flag"
	"fmt"
	"os"
	"runtime"
	"time"

	"github.com/jimbo111/open-quantum-secure/pkg/benchutil"
)

func main() {
	os.Exit(run())
}

func run() int {
	var (
		baselinePath string
		outputPath   string
		threshold    float64
		save         bool
		commit       string
	)

	flag.StringVar(&baselinePath, "baseline", "", "path to baseline JSON report (compare mode)")
	flag.StringVar(&outputPath, "output", "", "path to write the new report (save mode)")
	flag.Float64Var(&threshold, "threshold", 20, "regression threshold in percent (default 20)")
	flag.BoolVar(&save, "save", false, "save current results as baseline instead of comparing")
	flag.StringVar(&commit, "commit", "", "git commit SHA to embed in saved report")
	flag.Parse()

	// Parse bench output from stdin.
	results, err := benchutil.ParseBenchOutput(os.Stdin)
	if err != nil {
		fmt.Fprintf(os.Stderr, "bench-compare: parsing bench output: %v\n", err)
		return 1
	}

	if save {
		return saveMode(results, outputPath, commit)
	}
	return compareMode(results, baselinePath, threshold)
}

func saveMode(results []benchutil.BenchResult, outputPath, commit string) int {
	if outputPath == "" {
		fmt.Fprintln(os.Stderr, "bench-compare: -output is required when using -save")
		return 1
	}
	report := &benchutil.BenchReport{
		GoVersion: runtime.Version(),
		Commit:    commit,
		Timestamp: time.Now().UTC(),
		Results:   results,
	}
	if err := benchutil.SaveReport(outputPath, report); err != nil {
		fmt.Fprintf(os.Stderr, "bench-compare: %v\n", err)
		return 1
	}
	fmt.Fprintf(os.Stdout, "Saved %d benchmark results to %s\n", len(results), outputPath)
	return 0
}

func compareMode(results []benchutil.BenchResult, baselinePath string, threshold float64) int {
	if baselinePath == "" {
		fmt.Fprintln(os.Stderr, "bench-compare: -baseline is required in compare mode (or use -save)")
		return 1
	}

	baseline, err := benchutil.LoadReport(baselinePath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "bench-compare: loading baseline: %v\n", err)
		return 1
	}

	cmp := benchutil.Compare(baseline.Results, results, threshold)
	fmt.Print(benchutil.FormatTable(cmp))

	if !cmp.AllPassed {
		return 1
	}
	return 0
}
