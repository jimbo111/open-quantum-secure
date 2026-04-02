package findings

import (
	"sync"
	"testing"
)

func TestCalculatePriority(t *testing.T) {
	tests := []struct {
		name     string
		finding  UnifiedFinding
		expected string
	}{
		// P1 cases
		{
			name:     "P1: critical + reachable",
			finding:  UnifiedFinding{Severity: SevCritical, Reachable: ReachableYes},
			expected: "P1",
		},
		{
			name:     "P1: critical + high blast radius",
			finding:  UnifiedFinding{Severity: SevCritical, BlastRadius: 70},
			expected: "P1",
		},
		{
			name:     "P1: critical + blast radius 100",
			finding:  UnifiedFinding{Severity: SevCritical, BlastRadius: 100},
			expected: "P1",
		},
		{
			name:     "P1: critical + medium-high confidence",
			finding:  UnifiedFinding{Severity: SevCritical, Confidence: ConfidenceMediumHigh},
			expected: "P1",
		},
		{
			name:     "P1: critical + high confidence",
			finding:  UnifiedFinding{Severity: SevCritical, Confidence: ConfidenceHigh},
			expected: "P1",
		},
		// P2 cases
		{
			name:     "P2: critical + unknown reachability",
			finding:  UnifiedFinding{Severity: SevCritical, Reachable: ReachableUnknown},
			expected: "P2",
		},
		{
			name:     "P2: critical + no reachability + low confidence",
			finding:  UnifiedFinding{Severity: SevCritical, Reachable: ReachableNo, Confidence: ConfidenceLow},
			expected: "P2",
		},
		{
			name:     "P2: high + reachable",
			finding:  UnifiedFinding{Severity: SevHigh, Reachable: ReachableYes},
			expected: "P2",
		},
		{
			name:     "P2: high + blast radius 40",
			finding:  UnifiedFinding{Severity: SevHigh, BlastRadius: 40},
			expected: "P2",
		},
		{
			name:     "P2: high + blast radius 55",
			finding:  UnifiedFinding{Severity: SevHigh, BlastRadius: 55},
			expected: "P2",
		},
		// P3 cases
		{
			name:     "P3: high + unknown reachability",
			finding:  UnifiedFinding{Severity: SevHigh, Reachable: ReachableUnknown},
			expected: "P3",
		},
		{
			name:     "P3: high + no reachability + low blast",
			finding:  UnifiedFinding{Severity: SevHigh, Reachable: ReachableNo, BlastRadius: 10},
			expected: "P3",
		},
		{
			name:     "P3: medium + reachable",
			finding:  UnifiedFinding{Severity: SevMedium, Reachable: ReachableYes},
			expected: "P3",
		},
		// P4 cases
		{
			name:     "P4: medium + unknown reachability",
			finding:  UnifiedFinding{Severity: SevMedium, Reachable: ReachableUnknown},
			expected: "P4",
		},
		{
			name:     "P4: medium + not reachable",
			finding:  UnifiedFinding{Severity: SevMedium, Reachable: ReachableNo},
			expected: "P4",
		},
		{
			name:     "P4: low severity always",
			finding:  UnifiedFinding{Severity: SevLow, Reachable: ReachableYes, BlastRadius: 90},
			expected: "P4",
		},
		{
			name:     "P4: info severity",
			finding:  UnifiedFinding{Severity: SevInfo},
			expected: "P4",
		},
		{
			name:     "P4: empty severity",
			finding:  UnifiedFinding{},
			expected: "P4",
		},
		// Test/generated file override
		{
			name:     "P4: test file overrides critical + reachable",
			finding:  UnifiedFinding{Severity: SevCritical, Reachable: ReachableYes, TestFile: true},
			expected: "P4",
		},
		{
			name:     "P4: generated file overrides critical + high blast",
			finding:  UnifiedFinding{Severity: SevCritical, BlastRadius: 90, GeneratedFile: true},
			expected: "P4",
		},
		// Edge cases
		{
			name:     "P2: critical + blast radius 69 (just below P1 threshold)",
			finding:  UnifiedFinding{Severity: SevCritical, BlastRadius: 69},
			expected: "P2",
		},
		{
			name:     "P3: high + blast radius 39 (just below P2 threshold)",
			finding:  UnifiedFinding{Severity: SevHigh, BlastRadius: 39},
			expected: "P3",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := CalculatePriority(&tt.finding)
			if got != tt.expected {
				t.Errorf("CalculatePriority() = %q, want %q", got, tt.expected)
			}
		})
	}
}

func TestSortByPriority(t *testing.T) {
	ff := []UnifiedFinding{
		{Location: Location{File: "d.go"}, Severity: SevLow, Priority: "P4"},
		{Location: Location{File: "a.go"}, Severity: SevCritical, Priority: "P1"},
		{Location: Location{File: "c.go"}, Severity: SevHigh, Priority: "P3"},
		{Location: Location{File: "b.go"}, Severity: SevCritical, Priority: "P2"},
		{Location: Location{File: "e.go"}, Severity: SevMedium, Priority: "P3"},
	}

	SortByPriority(ff)

	expected := []string{"P1", "P2", "P3", "P3", "P4"}
	for i, f := range ff {
		if f.Priority != expected[i] {
			t.Errorf("index %d: got priority %q, want %q", i, f.Priority, expected[i])
		}
	}

	// Within P3, severity should be ordered (high before medium)
	if ff[2].Severity != SevHigh || ff[3].Severity != SevMedium {
		t.Errorf("within P3, expected high before medium: got %s, %s", ff[2].Severity, ff[3].Severity)
	}
}

func TestSortByPriority_StableWithinSamePriorityAndSeverity(t *testing.T) {
	ff := []UnifiedFinding{
		{Location: Location{File: "z.go"}, Priority: "P2", Severity: SevHigh},
		{Location: Location{File: "a.go"}, Priority: "P2", Severity: SevHigh},
		{Location: Location{File: "m.go"}, Priority: "P2", Severity: SevHigh},
	}

	SortByPriority(ff)

	// Within same priority and severity, sort by file path
	if ff[0].Location.File != "a.go" || ff[1].Location.File != "m.go" || ff[2].Location.File != "z.go" {
		t.Errorf("expected alphabetical file order within same priority/severity, got %s, %s, %s",
			ff[0].Location.File, ff[1].Location.File, ff[2].Location.File)
	}
}

func TestIsTestFile(t *testing.T) {
	tests := []struct {
		path     string
		expected bool
	}{
		{"auth_test.go", true},
		{"src/auth_test.go", true},
		{"crypto.test.js", true},
		{"crypto.test.ts", true},
		{"crypto.spec.js", true},
		{"crypto.spec.ts", true},
		{"crypto.spec.tsx", true},
		{"test_utils.py", false}, // prefix "test_" is not a test file suffix
		{"auth_test.py", true},
		{"src/test/java/App.java", true},
		{"src/tests/crypto.go", true},
		{"src/__tests__/auth.js", true},
		{"testdata/samples.go", true},
		{"test_fixtures/data.json", true},
		// Not test files
		{"src/auth.go", false},
		{"pkg/crypto/aes.go", false},
		{"contest.go", false},
		{"latest.go", false},
		{"", false},
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			if got := IsTestFile(tt.path); got != tt.expected {
				t.Errorf("IsTestFile(%q) = %v, want %v", tt.path, got, tt.expected)
			}
		})
	}
}

func TestIsGeneratedFile(t *testing.T) {
	tests := []struct {
		path     string
		expected bool
	}{
		{"api.pb.go", true},
		{"service.pb.cc", true},
		{"schema_generated.go", true},
		{"types.generated.ts", true},
		{"mock_auth.go", true},
		{"zz_generated_deepcopy.go", true},
		{"src/generated/api.go", true},
		{"src/gen/models.go", true},
		{"src/__generated__/types.ts", true},
		{"src/autogen/config.go", true},
		// Not generated
		{"src/auth.go", false},
		{"pkg/generator.go", false},
		{"general.go", false},
		{"", false},
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			if got := IsGeneratedFile(tt.path); got != tt.expected {
				t.Errorf("IsGeneratedFile(%q) = %v, want %v", tt.path, got, tt.expected)
			}
		})
	}
}

func TestMarkTestAndGenerated(t *testing.T) {
	ff := []UnifiedFinding{
		{Location: Location{File: "src/auth.go"}},
		{Location: Location{File: "src/auth_test.go"}},
		{Location: Location{File: "src/gen/api.pb.go"}},
		{Location: Location{File: "testdata/crypto.go"}},
	}

	MarkTestAndGenerated(ff)

	if ff[0].TestFile || ff[0].GeneratedFile {
		t.Error("auth.go should not be marked")
	}
	if !ff[1].TestFile {
		t.Error("auth_test.go should be marked as test file")
	}
	if !ff[2].GeneratedFile {
		t.Error("api.pb.go should be marked as generated file")
	}
	if !ff[3].TestFile {
		t.Error("testdata/crypto.go should be marked as test file")
	}
}

func TestCalculatePriority_ZeroValueFinding(t *testing.T) {
	var f UnifiedFinding
	got := CalculatePriority(&f)
	if got != "P4" {
		t.Errorf("zero-value finding should be P4, got %q", got)
	}
}

func TestCalculatePriority_ConcurrentAccess(t *testing.T) {
	f := UnifiedFinding{Severity: SevCritical, Reachable: ReachableYes}
	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			p := CalculatePriority(&f)
			if p != "P1" {
				t.Errorf("concurrent: expected P1, got %q", p)
			}
		}()
	}
	wg.Wait()
}

func TestConfidenceRank(t *testing.T) {
	tests := []struct {
		conf Confidence
		rank int
	}{
		{ConfidenceHigh, 5},
		{ConfidenceMediumHigh, 4},
		{ConfidenceMedium, 3},
		{ConfidenceMediumLow, 2},
		{ConfidenceLow, 1},
		{"", 0},
		{"unknown", 0},
	}
	for _, tt := range tests {
		if got := confidenceRank(tt.conf); got != tt.rank {
			t.Errorf("confidenceRank(%q) = %d, want %d", tt.conf, got, tt.rank)
		}
	}
}
