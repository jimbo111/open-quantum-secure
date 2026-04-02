package orchestrator

import (
	"context"
	"fmt"
	"testing"

	"github.com/jimbo111/open-quantum-secure/pkg/engines"
	"github.com/jimbo111/open-quantum-secure/pkg/findings"
)

// TestScanWithMetrics_ReturnsMetrics verifies that ScanWithMetrics returns
// non-nil ScanMetrics with per-engine entries for each available engine.
func TestScanWithMetrics_ReturnsMetrics(t *testing.T) {
	ctx := context.Background()

	engA := &mockEngine{
		name:      "metrics-a",
		tier:      engines.Tier1Pattern,
		available: true,
		results: []findings.UnifiedFinding{
			{
				Location:     findings.Location{File: "/src/main.go", Line: 10},
				Algorithm:    &findings.Algorithm{Name: "RSA-2048", Primitive: "pke", KeySize: 2048},
				Confidence:   findings.ConfidenceMedium,
				SourceEngine: "metrics-a",
			},
		},
	}
	engB := &mockEngine{
		name:      "metrics-b",
		tier:      engines.Tier1Pattern,
		available: true,
		results: []findings.UnifiedFinding{
			{
				Location:     findings.Location{File: "/src/util.go", Line: 5},
				Algorithm:    &findings.Algorithm{Name: "AES-256-GCM", Primitive: "ae", KeySize: 256},
				Confidence:   findings.ConfidenceMedium,
				SourceEngine: "metrics-b",
			},
		},
	}

	orch := New(engA, engB)
	opts := engines.ScanOptions{Mode: engines.ModeFull}

	ff, _, m, err := orch.ScanWithMetrics(ctx, opts)
	if err != nil {
		t.Fatalf("ScanWithMetrics() error: %v", err)
	}
	if m == nil {
		t.Fatal("ScanWithMetrics() returned nil ScanMetrics")
	}
	if len(ff) == 0 {
		t.Fatal("ScanWithMetrics() returned no findings")
	}

	// Two engines registered.
	if len(m.Engines) != 2 {
		t.Errorf("Engines metric count = %d, want 2", len(m.Engines))
	}

	// Engine names must match registration order.
	if m.Engines[0].Name != "metrics-a" {
		t.Errorf("Engines[0].Name = %q, want metrics-a", m.Engines[0].Name)
	}
	if m.Engines[1].Name != "metrics-b" {
		t.Errorf("Engines[1].Name = %q, want metrics-b", m.Engines[1].Name)
	}

	// Each engine should report 1 finding.
	if m.Engines[0].Findings != 1 {
		t.Errorf("Engines[0].Findings = %d, want 1", m.Engines[0].Findings)
	}
	if m.Engines[1].Findings != 1 {
		t.Errorf("Engines[1].Findings = %d, want 1", m.Engines[1].Findings)
	}

	// No errors expected.
	if m.Engines[0].Error != "" {
		t.Errorf("Engines[0].Error = %q, want empty", m.Engines[0].Error)
	}
	if m.Engines[1].Error != "" {
		t.Errorf("Engines[1].Error = %q, want empty", m.Engines[1].Error)
	}

	// Total duration must be positive.
	if m.TotalDuration <= 0 {
		t.Error("TotalDuration must be > 0")
	}
	// Normalize duration must be recorded (even if near-zero).
	if m.NormalizeDur < 0 {
		t.Error("NormalizeDur must be >= 0")
	}
}

// TestScanWithMetrics_BackwardCompat verifies that ScanWithImpact still works
// correctly (backward compatibility) after the internal refactor.
func TestScanWithMetrics_BackwardCompat(t *testing.T) {
	ctx := context.Background()

	eng := &mockEngine{
		name:      "compat-eng",
		tier:      engines.Tier1Pattern,
		available: true,
		results: []findings.UnifiedFinding{
			{
				Location:     findings.Location{File: "/a.go", Line: 1},
				Algorithm:    &findings.Algorithm{Name: "ECDSA", Primitive: "signature"},
				Confidence:   findings.ConfidenceLow,
				SourceEngine: "compat-eng",
			},
		},
	}

	orch := New(eng)
	opts := engines.ScanOptions{Mode: engines.ModeFull}

	ff, impactResult, err := orch.ScanWithImpact(ctx, opts)
	if err != nil {
		t.Fatalf("ScanWithImpact() error: %v", err)
	}
	if len(ff) != 1 {
		t.Fatalf("ScanWithImpact() returned %d findings, want 1", len(ff))
	}
	// ImpactGraph disabled — impactResult must be nil.
	if impactResult != nil {
		t.Errorf("expected nil impact result, got non-nil")
	}
}

// TestScanWithMetrics_FailedEngine verifies that a failed engine records its
// error in EngineMetrics.Error.
func TestScanWithMetrics_FailedEngine(t *testing.T) {
	ctx := context.Background()

	bad := &mockEngine{
		name:      "bad-eng",
		tier:      engines.Tier1Pattern,
		available: true,
		scanErr:   fmt.Errorf("simulated engine failure"),
	}
	good := &mockEngine{
		name:      "good-eng",
		tier:      engines.Tier1Pattern,
		available: true,
		results: []findings.UnifiedFinding{
			{
				Location:     findings.Location{File: "/ok.go", Line: 1},
				Algorithm:    &findings.Algorithm{Name: "AES-256-GCM"},
				SourceEngine: "good-eng",
			},
		},
	}

	orch := New(bad, good)
	_, _, m, err := orch.ScanWithMetrics(ctx, engines.ScanOptions{Mode: engines.ModeFull})
	if err != nil {
		t.Fatalf("ScanWithMetrics() should not return error on partial failure, got: %v", err)
	}
	if m == nil {
		t.Fatal("ScanWithMetrics() returned nil metrics")
	}

	// Find the bad engine's metrics entry.
	var badMetrics *EngineMetrics
	for i := range m.Engines {
		if m.Engines[i].Name == "bad-eng" {
			badMetrics = &m.Engines[i]
			break
		}
	}
	if badMetrics == nil {
		t.Fatal("bad-eng not found in Engines metrics")
	}
	if badMetrics.Error == "" {
		t.Error("bad-eng metrics should record a non-empty Error")
	}
}
