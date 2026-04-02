package benchutil

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// ParseBenchOutput tests
// ---------------------------------------------------------------------------

func TestParseBenchOutput_Standard(t *testing.T) {
	input := `goos: darwin
goarch: arm64
pkg: github.com/jimbo111/open-quantum-secure/pkg/orchestrator
BenchmarkNormalize-8       50000       23456 ns/op    4096 B/op    128 allocs/op
BenchmarkDedupe-8          30000       45678 ns/op    8192 B/op    256 allocs/op
BenchmarkClassify-8        60000       12345 ns/op    2048 B/op     64 allocs/op
PASS
ok  	github.com/jimbo111/open-quantum-secure/pkg/orchestrator	12.345s
`
	results, err := ParseBenchOutput(strings.NewReader(input))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(results) != 3 {
		t.Fatalf("expected 3 results, got %d", len(results))
	}

	cases := []struct {
		name     string
		n        int
		nsPerOp  float64
		bPerOp   int64
		allocsOp int64
	}{
		{"BenchmarkNormalize", 50000, 23456, 4096, 128},
		{"BenchmarkDedupe", 30000, 45678, 8192, 256},
		{"BenchmarkClassify", 60000, 12345, 2048, 64},
	}
	for i, tc := range cases {
		r := results[i]
		if r.Name != tc.name {
			t.Errorf("[%d] Name: want %q got %q", i, tc.name, r.Name)
		}
		if r.N != tc.n {
			t.Errorf("[%d] N: want %d got %d", i, tc.n, r.N)
		}
		if r.NsPerOp != tc.nsPerOp {
			t.Errorf("[%d] NsPerOp: want %v got %v", i, tc.nsPerOp, r.NsPerOp)
		}
		if r.BPerOp != tc.bPerOp {
			t.Errorf("[%d] BPerOp: want %d got %d", i, tc.bPerOp, r.BPerOp)
		}
		if r.AllocsOp != tc.allocsOp {
			t.Errorf("[%d] AllocsOp: want %d got %d", i, tc.allocsOp, r.AllocsOp)
		}
	}
}

func TestParseBenchOutput_SubBenchmarks(t *testing.T) {
	input := `BenchmarkScan/Small-8      10000      100000 ns/op    1024 B/op     32 allocs/op
BenchmarkScan/Medium-8      5000      500000 ns/op    4096 B/op    128 allocs/op
BenchmarkScan/Large-8       1000     5000000 ns/op   16384 B/op    512 allocs/op
`
	results, err := ParseBenchOutput(strings.NewReader(input))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(results) != 3 {
		t.Fatalf("expected 3 results, got %d", len(results))
	}
	wantNames := []string{"BenchmarkScan/Small", "BenchmarkScan/Medium", "BenchmarkScan/Large"}
	for i, want := range wantNames {
		if results[i].Name != want {
			t.Errorf("[%d] Name: want %q got %q", i, want, results[i].Name)
		}
	}
}

func TestParseBenchOutput_NsOpOnly(t *testing.T) {
	// Some benchmarks omit B/op and allocs/op when ReportAllocs is not called.
	input := `BenchmarkFoo-4    100000    9876 ns/op
`
	results, err := ParseBenchOutput(strings.NewReader(input))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	r := results[0]
	if r.Name != "BenchmarkFoo" {
		t.Errorf("Name: want BenchmarkFoo got %q", r.Name)
	}
	if r.NsPerOp != 9876 {
		t.Errorf("NsPerOp: want 9876 got %v", r.NsPerOp)
	}
	if r.BPerOp != 0 {
		t.Errorf("BPerOp: want 0 got %d", r.BPerOp)
	}
	if r.AllocsOp != 0 {
		t.Errorf("AllocsOp: want 0 got %d", r.AllocsOp)
	}
}

func TestParseBenchOutput_Empty(t *testing.T) {
	results, err := ParseBenchOutput(strings.NewReader(""))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(results) != 0 {
		t.Fatalf("expected 0 results, got %d", len(results))
	}
}

func TestParseBenchOutput_NoMatchingLines(t *testing.T) {
	input := `PASS
ok  github.com/foo/bar   0.001s
`
	results, err := ParseBenchOutput(strings.NewReader(input))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(results) != 0 {
		t.Fatalf("expected 0 results, got %d", len(results))
	}
}

// ---------------------------------------------------------------------------
// SaveReport / LoadReport tests
// ---------------------------------------------------------------------------

func TestSaveLoadReport(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "baseline.json")

	report := &BenchReport{
		GoVersion: "go1.25.0",
		Commit:    "abc1234",
		Timestamp: time.Date(2026, 3, 4, 12, 0, 0, 0, time.UTC),
		Results: []BenchResult{
			{Name: "BenchmarkFoo", N: 1000, NsPerOp: 500.0, BPerOp: 128, AllocsOp: 4},
		},
	}

	if err := SaveReport(path, report); err != nil {
		t.Fatalf("SaveReport: %v", err)
	}

	loaded, err := LoadReport(path)
	if err != nil {
		t.Fatalf("LoadReport: %v", err)
	}
	if loaded.GoVersion != report.GoVersion {
		t.Errorf("GoVersion: want %q got %q", report.GoVersion, loaded.GoVersion)
	}
	if loaded.Commit != report.Commit {
		t.Errorf("Commit: want %q got %q", report.Commit, loaded.Commit)
	}
	if len(loaded.Results) != 1 {
		t.Fatalf("Results: want 1 got %d", len(loaded.Results))
	}
	if loaded.Results[0].NsPerOp != 500.0 {
		t.Errorf("NsPerOp: want 500 got %v", loaded.Results[0].NsPerOp)
	}
}

func TestLoadReport_NotFound(t *testing.T) {
	_, err := LoadReport("/nonexistent/path/baseline.json")
	if err == nil {
		t.Fatal("expected error for missing file, got nil")
	}
}

func TestLoadReport_InvalidJSON(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.json")
	if err := os.WriteFile(path, []byte("{invalid}"), 0o644); err != nil {
		t.Fatal(err)
	}
	_, err := LoadReport(path)
	if err == nil {
		t.Fatal("expected error for invalid JSON, got nil")
	}
}

// ---------------------------------------------------------------------------
// Compare tests
// ---------------------------------------------------------------------------

func mkResults(pairs ...interface{}) []BenchResult {
	var out []BenchResult
	for i := 0; i < len(pairs); i += 2 {
		out = append(out, BenchResult{
			Name:    pairs[i].(string),
			NsPerOp: pairs[i+1].(float64),
		})
	}
	return out
}

func TestCompare_NoRegression(t *testing.T) {
	baseline := mkResults("BenchmarkFoo", 1000.0, "BenchmarkBar", 2000.0)
	current := mkResults("BenchmarkFoo", 1050.0, "BenchmarkBar", 2000.0) // +5%, within 20%
	result := Compare(baseline, current, 20)
	if !result.AllPassed {
		t.Errorf("expected AllPassed=true for 5%% change within 20%% threshold")
	}
	if len(result.Comparisons) != 2 {
		t.Fatalf("expected 2 comparisons, got %d", len(result.Comparisons))
	}
}

func TestCompare_RegressionAboveThreshold(t *testing.T) {
	baseline := mkResults("BenchmarkFoo", 1000.0)
	current := mkResults("BenchmarkFoo", 1300.0) // +30%, exceeds 20%
	result := Compare(baseline, current, 20)
	if result.AllPassed {
		t.Errorf("expected AllPassed=false for 30%% change above 20%% threshold")
	}
	if len(result.Comparisons) != 1 {
		t.Fatalf("expected 1 comparison, got %d", len(result.Comparisons))
	}
	c := result.Comparisons[0]
	if c.Passed {
		t.Errorf("expected Passed=false for regression")
	}
	if c.ChangePercent <= 0 {
		t.Errorf("expected positive ChangePercent for regression, got %v", c.ChangePercent)
	}
}

func TestCompare_Improvement(t *testing.T) {
	baseline := mkResults("BenchmarkFoo", 1000.0)
	current := mkResults("BenchmarkFoo", 800.0) // -20%, improvement
	result := Compare(baseline, current, 20)
	if !result.AllPassed {
		t.Errorf("expected AllPassed=true for improvement")
	}
	c := result.Comparisons[0]
	if c.ChangePercent >= 0 {
		t.Errorf("expected negative ChangePercent for improvement, got %v", c.ChangePercent)
	}
	if !c.Passed {
		t.Errorf("expected Passed=true for improvement")
	}
}

func TestCompare_NewBenchmark(t *testing.T) {
	baseline := mkResults("BenchmarkFoo", 1000.0)
	current := mkResults("BenchmarkFoo", 1000.0, "BenchmarkNew", 500.0)
	result := Compare(baseline, current, 20)
	if !result.AllPassed {
		t.Errorf("expected AllPassed=true when only new benchmarks added")
	}
	if len(result.NewBenchmarks) != 1 || result.NewBenchmarks[0] != "BenchmarkNew" {
		t.Errorf("expected NewBenchmarks=[BenchmarkNew], got %v", result.NewBenchmarks)
	}
}

func TestCompare_RemovedBenchmark(t *testing.T) {
	baseline := mkResults("BenchmarkFoo", 1000.0, "BenchmarkRemoved", 2000.0)
	current := mkResults("BenchmarkFoo", 1000.0)
	result := Compare(baseline, current, 20)
	if !result.AllPassed {
		t.Errorf("expected AllPassed=true when benchmark removed")
	}
	if len(result.RemovedBenchmarks) != 1 || result.RemovedBenchmarks[0] != "BenchmarkRemoved" {
		t.Errorf("expected RemovedBenchmarks=[BenchmarkRemoved], got %v", result.RemovedBenchmarks)
	}
}

func TestCompare_ExactlyAtThreshold(t *testing.T) {
	// Exactly at threshold (20%) should pass — threshold is exclusive.
	baseline := mkResults("BenchmarkFoo", 1000.0)
	current := mkResults("BenchmarkFoo", 1200.0) // exactly +20%
	result := Compare(baseline, current, 20)
	if !result.AllPassed {
		t.Errorf("expected AllPassed=true when change equals threshold (exclusive)")
	}
	if !result.Comparisons[0].Passed {
		t.Errorf("expected Passed=true when change equals threshold (exclusive)")
	}
}

func TestCompare_EmptyBaseline(t *testing.T) {
	current := mkResults("BenchmarkFoo", 1000.0, "BenchmarkBar", 2000.0)
	result := Compare([]BenchResult{}, current, 20)
	if !result.AllPassed {
		t.Errorf("expected AllPassed=true when baseline is empty")
	}
	if len(result.Comparisons) != 0 {
		t.Errorf("expected 0 comparisons with empty baseline, got %d", len(result.Comparisons))
	}
	if len(result.NewBenchmarks) != 2 {
		t.Errorf("expected 2 new benchmarks, got %d", len(result.NewBenchmarks))
	}
}

func TestCompare_EmptyCurrent(t *testing.T) {
	baseline := mkResults("BenchmarkFoo", 1000.0, "BenchmarkBar", 2000.0)
	result := Compare(baseline, []BenchResult{}, 20)
	if !result.AllPassed {
		t.Errorf("expected AllPassed=true when current is empty (removed, not regression)")
	}
	if len(result.Comparisons) != 0 {
		t.Errorf("expected 0 comparisons with empty current, got %d", len(result.Comparisons))
	}
	if len(result.RemovedBenchmarks) != 2 {
		t.Errorf("expected 2 removed benchmarks, got %d", len(result.RemovedBenchmarks))
	}
}

func TestCompare_ZeroThreshold(t *testing.T) {
	// threshold=0: any positive change fails.
	baseline := mkResults("BenchmarkFoo", 1000.0)
	current := mkResults("BenchmarkFoo", 1001.0) // tiny regression
	result := Compare(baseline, current, 0)
	if result.AllPassed {
		t.Errorf("expected AllPassed=false with threshold=0 and any regression")
	}
}

func TestCompare_ZeroThreshold_NoChange(t *testing.T) {
	// threshold=0: exact same value passes.
	baseline := mkResults("BenchmarkFoo", 1000.0)
	current := mkResults("BenchmarkFoo", 1000.0)
	result := Compare(baseline, current, 0)
	if !result.AllPassed {
		t.Errorf("expected AllPassed=true with threshold=0 and no change")
	}
}

// ---------------------------------------------------------------------------
// FormatTable tests
// ---------------------------------------------------------------------------

func TestFormatTable_PassedResult(t *testing.T) {
	result := &CompareResult{
		AllPassed: true,
		Comparisons: []Comparison{
			{
				Name:          "BenchmarkFoo",
				BaselineNsOp:  1000.0,
				CurrentNsOp:   1050.0,
				ChangePercent: 5.0,
				Passed:        true,
			},
		},
	}
	out := FormatTable(result)
	if !strings.Contains(out, "BenchmarkFoo") {
		t.Errorf("table missing benchmark name")
	}
	if !strings.Contains(out, "PASS") {
		t.Errorf("table missing PASS status")
	}
	if !strings.Contains(out, "PASSED") {
		t.Errorf("table missing overall PASSED result")
	}
}

func TestFormatTable_FailedResult(t *testing.T) {
	result := &CompareResult{
		AllPassed: false,
		Comparisons: []Comparison{
			{
				Name:          "BenchmarkBar",
				BaselineNsOp:  1000.0,
				CurrentNsOp:   1350.0,
				ChangePercent: 35.0,
				Passed:        false,
			},
		},
	}
	out := FormatTable(result)
	if !strings.Contains(out, "FAIL") {
		t.Errorf("table missing FAIL status")
	}
	if !strings.Contains(out, "FAILED") {
		t.Errorf("table missing overall FAILED result")
	}
}

func TestFormatTable_NewAndRemovedBenchmarks(t *testing.T) {
	result := &CompareResult{
		AllPassed:         true,
		NewBenchmarks:     []string{"BenchmarkNew"},
		RemovedBenchmarks: []string{"BenchmarkOld"},
	}
	out := FormatTable(result)
	if !strings.Contains(out, "BenchmarkNew") {
		t.Errorf("table missing new benchmark name")
	}
	if !strings.Contains(out, "BenchmarkOld") {
		t.Errorf("table missing removed benchmark name")
	}
}
