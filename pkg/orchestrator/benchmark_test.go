package orchestrator

import (
	"context"
	"fmt"
	"testing"

	"github.com/jimbo111/open-quantum-secure/pkg/engines"
	"github.com/jimbo111/open-quantum-secure/pkg/findings"
)

// benchEngine is a mock engine that returns a pre-built slice of findings.
type benchEngine struct {
	name     string
	tier     engines.Tier
	findings []findings.UnifiedFinding
}

func (e *benchEngine) Name() string                 { return e.name }
func (e *benchEngine) Tier() engines.Tier           { return e.tier }
func (e *benchEngine) Available() bool              { return true }
func (e *benchEngine) Version() string              { return "test" }
func (e *benchEngine) SupportedLanguages() []string { return []string{"go"} }
func (e *benchEngine) Scan(_ context.Context, _ engines.ScanOptions) ([]findings.UnifiedFinding, error) {
	// Return a copy to avoid mutations across iterations.
	out := make([]findings.UnifiedFinding, len(e.findings))
	copy(out, e.findings)
	return out, nil
}

func generateFindings(n int) []findings.UnifiedFinding {
	algs := []string{"AES", "RSA", "SHA-256", "ECDSA", "ChaCha20", "3DES", "MD5", "HMAC"}
	prims := []string{"symmetric", "asymmetric", "hash", "signature", "symmetric", "symmetric", "hash", "mac"}
	ff := make([]findings.UnifiedFinding, n)
	for i := range ff {
		a := i % len(algs)
		ff[i] = findings.UnifiedFinding{
			Location:     findings.Location{File: fmt.Sprintf("/src/file%d.go", i), Line: i + 1},
			Algorithm:    &findings.Algorithm{Name: algs[a], Primitive: prims[a], KeySize: 256},
			Confidence:   findings.ConfidenceMedium,
			SourceEngine: "bench-engine",
			Reachable:    findings.ReachableUnknown,
		}
	}
	return ff
}

func generateDupFindings(n int) []findings.UnifiedFinding {
	ff := make([]findings.UnifiedFinding, n)
	for i := range ff {
		eng := "engine-a"
		if i%2 == 1 {
			eng = "engine-b"
		}
		ff[i] = findings.UnifiedFinding{
			Location:     findings.Location{File: fmt.Sprintf("/src/file%d.go", i/2), Line: (i/2)*10 + 1},
			Algorithm:    &findings.Algorithm{Name: "AES", Primitive: "symmetric", KeySize: 256},
			Confidence:   findings.ConfidenceMedium,
			SourceEngine: eng,
			Reachable:    findings.ReachableUnknown,
		}
	}
	return ff
}

func BenchmarkNormalize(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		b.StopTimer()
		ff := generateFindings(100)
		b.StartTimer()
		normalizeFindings(ff)
	}
}

func BenchmarkDedupe(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		b.StopTimer()
		ff := generateDupFindings(200)
		b.StartTimer()
		dedupe(ff)
	}
}

func BenchmarkClassify(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		b.StopTimer()
		ff := generateFindings(100)
		b.StartTimer()
		classifyFindings(ff)
	}
}

func benchScan(b *testing.B, n int) {
	b.Helper()
	ff := generateFindings(n)
	eng := &benchEngine{name: "bench", tier: engines.Tier1Pattern, findings: ff}
	orch := New(eng)
	opts := engines.ScanOptions{TargetPath: b.TempDir()}
	ctx := context.Background()

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_, _ = orch.Scan(ctx, opts)
	}
}

func BenchmarkScan_Small(b *testing.B)  { benchScan(b, 10) }
func BenchmarkScan_Medium(b *testing.B) { benchScan(b, 100) }
func BenchmarkScan_Large(b *testing.B)  { benchScan(b, 1000) }
