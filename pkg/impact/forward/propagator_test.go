package forward

import (
	"context"
	"testing"

	"github.com/jimbo111/open-quantum-secure/pkg/findings"
	"github.com/jimbo111/open-quantum-secure/pkg/impact"
)

// helper to build a minimal finding with Algorithm and DataFlowPath
func rsaFinding(file string, line int, steps []findings.FlowStep) findings.UnifiedFinding {
	return findings.UnifiedFinding{
		Location:     findings.Location{File: file, Line: line},
		Algorithm:    &findings.Algorithm{Name: "RSA-2048", Primitive: "signature", KeySize: 2048},
		SourceEngine: "mock",
		DataFlowPath: steps,
	}
}

func TestNew_DefaultMaxHops(t *testing.T) {
	p := New(0)
	if p.maxHops != defaultMaxHops {
		t.Errorf("maxHops = %d, want %d", p.maxHops, defaultMaxHops)
	}
}

func TestNew_CustomMaxHops(t *testing.T) {
	p := New(5)
	if p.maxHops != 5 {
		t.Errorf("maxHops = %d, want 5", p.maxHops)
	}
}

func TestAnalyze_NoopForFindingsWithoutDataFlowPath(t *testing.T) {
	ctx := context.Background()
	ff := []findings.UnifiedFinding{
		{
			Location:  findings.Location{File: "main.go", Line: 1},
			Algorithm: &findings.Algorithm{Name: "RSA-2048"},
			// DataFlowPath is empty
		},
	}

	result, err := New(10).Analyze(ctx, ff, impact.ImpactOpts{})
	if err != nil {
		t.Fatalf("Analyze() error: %v", err)
	}
	if len(result.ForwardEdges) != 0 {
		t.Errorf("ForwardEdges = %d, want 0 for finding without DataFlowPath", len(result.ForwardEdges))
	}
	if len(result.ImpactZones) != 0 {
		t.Errorf("ImpactZones = %d, want 0 for finding without DataFlowPath", len(result.ImpactZones))
	}
}

func TestAnalyze_NoopForFindingsWithNilAlgorithm(t *testing.T) {
	ctx := context.Background()
	ff := []findings.UnifiedFinding{
		{
			Location:     findings.Location{File: "main.go", Line: 1},
			Algorithm:    nil,
			DataFlowPath: []findings.FlowStep{{File: "main.go", Line: 2}},
		},
	}

	result, err := New(10).Analyze(ctx, ff, impact.ImpactOpts{})
	if err != nil {
		t.Fatalf("Analyze() error: %v", err)
	}
	if len(result.ForwardEdges) != 0 {
		t.Errorf("ForwardEdges = %d, want 0 for finding with nil Algorithm", len(result.ForwardEdges))
	}
}

func TestAnalyze_BuildsForwardEdges(t *testing.T) {
	ctx := context.Background()

	steps := []findings.FlowStep{
		{File: "auth.go", Line: 10, Message: "source taint"},
		{File: "store.go", Line: 20, Message: "store call"},
		{File: "network.go", Line: 30, Message: "send over TLS"},
	}
	ff := []findings.UnifiedFinding{rsaFinding("crypto.go", 5, steps)}

	result, err := New(10).Analyze(ctx, ff, impact.ImpactOpts{})
	if err != nil {
		t.Fatalf("Analyze() error: %v", err)
	}

	if len(result.ForwardEdges) != 3 {
		t.Fatalf("ForwardEdges = %d, want 3", len(result.ForwardEdges))
	}

	// First edge: source is the finding location, target is step[0]
	e0 := result.ForwardEdges[0]
	if e0.Hop != 1 {
		t.Errorf("edge[0].Hop = %d, want 1", e0.Hop)
	}
	if e0.TargetFile != "auth.go" || e0.TargetLine != 10 {
		t.Errorf("edge[0] target = %s:%d, want auth.go:10", e0.TargetFile, e0.TargetLine)
	}

	// Subsequent edges: source is the previous step
	e1 := result.ForwardEdges[1]
	if e1.Hop != 2 {
		t.Errorf("edge[1].Hop = %d, want 2", e1.Hop)
	}
	if e1.SourceFile != "auth.go" || e1.SourceLine != 10 {
		t.Errorf("edge[1] source = %s:%d, want auth.go:10", e1.SourceFile, e1.SourceLine)
	}
	if e1.TargetFile != "store.go" || e1.TargetLine != 20 {
		t.Errorf("edge[1] target = %s:%d, want store.go:20", e1.TargetFile, e1.TargetLine)
	}
}

func TestAnalyze_MaxHopsCapEdges(t *testing.T) {
	ctx := context.Background()

	var steps []findings.FlowStep
	for i := range 20 {
		steps = append(steps, findings.FlowStep{File: "f.go", Line: i + 1})
	}
	ff := []findings.UnifiedFinding{rsaFinding("src.go", 1, steps)}

	result, err := New(5).Analyze(ctx, ff, impact.ImpactOpts{})
	if err != nil {
		t.Fatalf("Analyze() error: %v", err)
	}
	if len(result.ForwardEdges) != 5 {
		t.Errorf("ForwardEdges = %d, want 5 (capped at maxHops)", len(result.ForwardEdges))
	}
}

func TestAnalyze_BuilsImpactZonesForRSA(t *testing.T) {
	ctx := context.Background()

	steps := []findings.FlowStep{
		{File: "auth.go", Line: 10, Message: "buf := make([]byte, 256)"},
		{File: "net.go", Line: 20, Message: "jwt.Sign(claims, key)"},
	}
	ff := []findings.UnifiedFinding{rsaFinding("crypto.go", 5, steps)}

	result, err := New(10).Analyze(ctx, ff, impact.ImpactOpts{})
	if err != nil {
		t.Fatalf("Analyze() error: %v", err)
	}

	// RSA → ML-DSA-65, ML-DSA-87 (two migration targets)
	if len(result.ImpactZones) != 2 {
		t.Fatalf("ImpactZones = %d, want 2 (ML-DSA-65 and ML-DSA-87)", len(result.ImpactZones))
	}

	for _, zone := range result.ImpactZones {
		if zone.FromAlgorithm != "RSA-2048" {
			t.Errorf("zone.FromAlgorithm = %q, want RSA-2048", zone.FromAlgorithm)
		}
		if zone.BlastRadiusScore < 0 || zone.BlastRadiusScore > 100 {
			t.Errorf("BlastRadiusScore = %d, want [0,100]", zone.BlastRadiusScore)
		}
		if zone.BlastRadiusGrade == "" {
			t.Error("BlastRadiusGrade is empty")
		}
		if zone.FindingKey == "" {
			t.Error("FindingKey is empty")
		}
		// ML-DSA signatures are much larger than RSA-2048's 256-byte sig → ratio > 1
		if zone.SizeRatio <= 0 {
			t.Errorf("SizeRatio = %f, want > 0", zone.SizeRatio)
		}
	}
}

func TestAnalyze_ConstraintHitsRecorded(t *testing.T) {
	ctx := context.Background()

	// make([]byte, 256) will fire a buffer-alloc constraint
	steps := []findings.FlowStep{
		{File: "buf.go", Line: 5, Message: "buf := make([]byte, 256)"},
	}
	ff := []findings.UnifiedFinding{rsaFinding("src.go", 1, steps)}

	result, err := New(10).Analyze(ctx, ff, impact.ImpactOpts{})
	if err != nil {
		t.Fatalf("Analyze() error: %v", err)
	}

	if len(result.Constraints) == 0 {
		t.Error("expected at least one ConstraintHit for make([]byte, 256)")
	}
	if result.Constraints[0].Type != "buffer-alloc" {
		t.Errorf("Constraint.Type = %q, want buffer-alloc", result.Constraints[0].Type)
	}
	if result.Constraints[0].MaxBytes != 256 {
		t.Errorf("Constraint.MaxBytes = %d, want 256", result.Constraints[0].MaxBytes)
	}
}

func TestAnalyze_BoundaryHitsRecorded(t *testing.T) {
	ctx := context.Background()

	steps := []findings.FlowStep{
		{File: "auth.go", Line: 15, Message: "jwt.Sign(claims, key)"},
	}
	ff := []findings.UnifiedFinding{rsaFinding("src.go", 1, steps)}

	result, err := New(10).Analyze(ctx, ff, impact.ImpactOpts{})
	if err != nil {
		t.Fatalf("Analyze() error: %v", err)
	}

	found := false
	for _, b := range result.Boundaries {
		if b.Protocol == "JWT" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected JWT BoundaryHit, got: %+v", result.Boundaries)
	}
}

func TestAnalyze_ContextCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel immediately

	steps := []findings.FlowStep{{File: "a.go", Line: 1}}
	ff := []findings.UnifiedFinding{
		rsaFinding("src.go", 1, steps),
		rsaFinding("src2.go", 2, steps),
	}

	// Should return immediately without error — just partial or empty result.
	result, err := New(10).Analyze(ctx, ff, impact.ImpactOpts{})
	if err != nil {
		t.Fatalf("Analyze() returned error on cancelled context: %v", err)
	}
	// Result might be empty or partial — we just verify no panic and no error.
	_ = result
}

func TestAnalyze_EmptyInput(t *testing.T) {
	result, err := New(10).Analyze(context.Background(), nil, impact.ImpactOpts{})
	if err != nil {
		t.Fatalf("Analyze(nil) error: %v", err)
	}
	if len(result.ForwardEdges) != 0 || len(result.ImpactZones) != 0 {
		t.Errorf("expected empty result for nil input")
	}
}

func TestAnalyze_NoMigrationTargetsForUnknownAlgorithm(t *testing.T) {
	ctx := context.Background()

	steps := []findings.FlowStep{{File: "a.go", Line: 1}}
	ff := []findings.UnifiedFinding{{
		Location:     findings.Location{File: "a.go", Line: 1},
		Algorithm:    &findings.Algorithm{Name: "UNKNOWN-ALGO"},
		DataFlowPath: steps,
		SourceEngine: "mock",
	}}

	result, err := New(10).Analyze(ctx, ff, impact.ImpactOpts{})
	if err != nil {
		t.Fatalf("Analyze() error: %v", err)
	}
	// Edges are built but no ImpactZones (no migration targets)
	if len(result.ImpactZones) != 0 {
		t.Errorf("ImpactZones = %d, want 0 for unknown algorithm", len(result.ImpactZones))
	}
	if len(result.ForwardEdges) == 0 {
		t.Error("ForwardEdges should be non-empty even for unknown algorithm")
	}
}

func TestConsumerFromMessage(t *testing.T) {
	tests := []struct {
		msg  string
		want impact.ConsumerType
	}{
		{"serialize to JSON", impact.ConsumerSerialization},
		{"store in database", impact.ConsumerStorage},
		{"send over TLS", impact.ConsumerNetwork},
		{"return result", impact.ConsumerReturn},
		{"append to slice", impact.ConsumerAggregation},
		{"x := key", impact.ConsumerAssignment},
		// Case-insensitive matching (Bug 2 fix)
		{"json.Marshal(data)", impact.ConsumerSerialization},
		{"http.Post(url)", impact.ConsumerNetwork},
		{"tls.Config{}", impact.ConsumerNetwork},
		{"grpc.Invoke(ctx)", impact.ConsumerNetwork},
		{"db.insert(row)", impact.ConsumerStorage},
	}

	for _, tc := range tests {
		got := consumerFromMessage(tc.msg)
		if got != tc.want {
			t.Errorf("consumerFromMessage(%q) = %q, want %q", tc.msg, got, tc.want)
		}
	}
}

func TestImpactDataForFinding_MatchesCorrectZone(t *testing.T) {
	ctx := context.Background()

	steps := []findings.FlowStep{{File: "a.go", Line: 1}}
	f := rsaFinding("crypto.go", 5, steps)
	ff := []findings.UnifiedFinding{f}

	result, err := New(10).Analyze(ctx, ff, impact.ImpactOpts{})
	if err != nil {
		t.Fatalf("Analyze() error: %v", err)
	}
	if len(result.ImpactZones) == 0 {
		t.Fatal("expected ImpactZones to be populated")
	}

	key := f.DedupeKey()
	zone := result.ImpactDataForFinding(key)
	if zone == nil {
		t.Errorf("ImpactDataForFinding(%q) returned nil, want a zone", key)
	}
}

// TestAnalyze_ProtocolViolation_WithEncodingOverhead verifies that protocol
// violation checks apply encoding overhead. ML-DSA-65 signature is 3309 raw
// bytes (under JWT's 4096 limit) but 4412 bytes base64-encoded (over the limit).
func TestAnalyze_ProtocolViolation_WithEncodingOverhead(t *testing.T) {
	ctx := context.Background()

	// RSA-2048 → ML-DSA-65 migration. JWT boundary via jwt.Sign in FlowStep.
	steps := []findings.FlowStep{
		{File: "auth.go", Line: 10, Message: "jwt.Sign(token, key)"},
	}
	ff := []findings.UnifiedFinding{rsaFinding("crypto.go", 5, steps)}

	result, err := New(10).Analyze(ctx, ff, impact.ImpactOpts{})
	if err != nil {
		t.Fatalf("Analyze() error: %v", err)
	}

	// Find the ML-DSA-65 zone (first migration target for RSA).
	var mldsa65Zone *impact.ImpactZone
	for i := range result.ImpactZones {
		if result.ImpactZones[i].ToAlgorithm == "ML-DSA-65" {
			mldsa65Zone = &result.ImpactZones[i]
			break
		}
	}
	if mldsa65Zone == nil {
		t.Fatal("expected ImpactZone for ML-DSA-65")
	}

	// ML-DSA-65 sig = 3309 raw, base64 = ((3309+2)/3)*4 = 4416 > 4096.
	// Must have a JWT protocol violation.
	found := false
	for _, v := range mldsa65Zone.ViolatedProtocols {
		if v.Protocol == "JWT" {
			found = true
			if v.ProjectedBytes <= v.MaxBytes {
				t.Errorf("JWT projected=%d should exceed max=%d (encoding overhead not applied)", v.ProjectedBytes, v.MaxBytes)
			}
		}
	}
	if !found {
		t.Error("expected JWT protocol violation for ML-DSA-65 with base64 encoding overhead")
	}
}
