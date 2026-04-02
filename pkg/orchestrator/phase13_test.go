package orchestrator

import (
	"testing"

	"github.com/jimbo111/open-quantum-secure/pkg/findings"
)

func TestMergeReachability(t *testing.T) {
	tests := []struct {
		name     string
		winner   findings.Reachability
		other    findings.Reachability
		expected findings.Reachability
	}{
		{"yes+unknown→yes", findings.ReachableYes, findings.ReachableUnknown, findings.ReachableYes},
		{"unknown+yes→yes", findings.ReachableUnknown, findings.ReachableYes, findings.ReachableYes},
		{"yes+no→yes", findings.ReachableYes, findings.ReachableNo, findings.ReachableYes},
		{"no+yes→yes", findings.ReachableNo, findings.ReachableYes, findings.ReachableYes},
		{"unknown+no→unknown", findings.ReachableUnknown, findings.ReachableNo, findings.ReachableUnknown},
		{"no+unknown→unknown", findings.ReachableNo, findings.ReachableUnknown, findings.ReachableUnknown},
		{"no+no→no", findings.ReachableNo, findings.ReachableNo, findings.ReachableNo},
		{"unknown+unknown→unknown", findings.ReachableUnknown, findings.ReachableUnknown, findings.ReachableUnknown},
		{"yes+yes→yes", findings.ReachableYes, findings.ReachableYes, findings.ReachableYes},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			winner := &findings.UnifiedFinding{Reachable: tt.winner}
			other := &findings.UnifiedFinding{Reachable: tt.other}
			mergeReachability(winner, other)
			if winner.Reachable != tt.expected {
				t.Errorf("mergeReachability(%s, %s) = %s, want %s",
					tt.winner, tt.other, winner.Reachable, tt.expected)
			}
		})
	}
}

func TestDedupe_PropagatesReachability(t *testing.T) {
	all := []findings.UnifiedFinding{
		{
			Location:     findings.Location{File: "auth.go", Line: 42},
			Algorithm:    &findings.Algorithm{Name: "RSA", KeySize: 2048},
			Confidence:   findings.ConfidenceMedium,
			SourceEngine: "cipherscope",
			Reachable:    findings.ReachableUnknown,
		},
		{
			Location:     findings.Location{File: "auth.go", Line: 42},
			Algorithm:    &findings.Algorithm{Name: "RSA", KeySize: 2048},
			Confidence:   findings.ConfidenceHigh,
			SourceEngine: "semgrep",
			Reachable:    findings.ReachableYes,
		},
	}

	deduped := dedupe(all)

	if len(deduped) != 1 {
		t.Fatalf("expected 1 finding after dedup, got %d", len(deduped))
	}

	if deduped[0].Reachable != findings.ReachableYes {
		t.Errorf("expected ReachableYes after merge, got %s", deduped[0].Reachable)
	}
}

func TestDedupe_EmptyFindings(t *testing.T) {
	deduped := dedupe(nil)
	if len(deduped) != 0 {
		t.Errorf("expected 0 findings from nil input, got %d", len(deduped))
	}

	deduped = dedupe([]findings.UnifiedFinding{})
	if len(deduped) != 0 {
		t.Errorf("expected 0 findings from empty input, got %d", len(deduped))
	}
}

func TestPriority_ZeroBlastRadius_FallsThrough(t *testing.T) {
	// When ImpactGraph=false, BlastRadius stays at 0.
	// Critical + unknown reachability + 0 blast radius → P2 (not P1)
	f := findings.UnifiedFinding{
		Severity:    findings.SevCritical,
		Reachable:   findings.ReachableUnknown,
		BlastRadius: 0,
	}
	p := findings.CalculatePriority(&f)
	if p != "P2" {
		t.Errorf("critical + unknown + 0 blast → expected P2, got %s", p)
	}
}

func TestPriority_AllSuppressedDoesNotCrash(t *testing.T) {
	// Empty slice after all suppressed — SortByPriority should not crash
	var empty []findings.UnifiedFinding
	findings.SortByPriority(empty)
	// No panic = pass
}
