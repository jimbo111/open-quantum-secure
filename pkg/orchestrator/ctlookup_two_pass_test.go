// ctlookup_two_pass_test.go — Orchestrator integration test for the two-pass
// ECH → CT-lookup enrichment loop (Sprint 3).
//
// Scenario: a tls-probe engine returns a finding with PartialInventory=true and
// PartialInventoryReason="ECH_ENABLED". When CTLookupFromECH=true the
// orchestrator must extract the hostname from that finding and pass it to the
// ct-lookup engine as an additional CTLookupTarget.
//
// NOTE: This test uses a spy ct-lookup engine rather than the real
// ctlookup.New() because the real engine's HTTP client base URL cannot be
// injected from outside the package without a source-side seam.
// Required source seam for a full integration test:
//   pkg/engines/ctlookup.NewWithBaseURL(baseURL string) *Engine
// This would allow passing an httptest.Server URL directly to ctlookup.New().
// Mark as a blocker for the fix-blockers round.
package orchestrator

import (
	"context"
	"sync"
	"testing"

	"github.com/jimbo111/open-quantum-secure/pkg/engines"
	"github.com/jimbo111/open-quantum-secure/pkg/findings"
)

// spyCTLookupEngine implements engines.Engine and records every ScanOptions
// it receives. It always reports itself as "ct-lookup" so the orchestrator
// routes it through the two-pass ECH-enrichment path.
type spyCTLookupEngine struct {
	mu       sync.Mutex
	callOpts []engines.ScanOptions
}

func (s *spyCTLookupEngine) Name() string                  { return "ct-lookup" }
func (s *spyCTLookupEngine) Tier() engines.Tier            { return engines.Tier5Network }
func (s *spyCTLookupEngine) SupportedLanguages() []string  { return nil }
func (s *spyCTLookupEngine) Available() bool               { return true }
func (s *spyCTLookupEngine) Version() string               { return "spy" }
func (s *spyCTLookupEngine) Scan(_ context.Context, opts engines.ScanOptions) ([]findings.UnifiedFinding, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.callOpts = append(s.callOpts, opts)
	return nil, nil
}

// spyTLSProbeEngine returns a single ECH-annotated finding from a predetermined
// host so the orchestrator can extract it for CT lookup enrichment.
type spyTLSProbeEngine struct {
	echHostname string
}

func (s *spyTLSProbeEngine) Name() string                  { return "tls-probe" }
func (s *spyTLSProbeEngine) Tier() engines.Tier            { return engines.Tier5Network }
func (s *spyTLSProbeEngine) SupportedLanguages() []string  { return nil }
func (s *spyTLSProbeEngine) Available() bool               { return true }
func (s *spyTLSProbeEngine) Version() string               { return "spy" }
func (s *spyTLSProbeEngine) Scan(_ context.Context, _ engines.ScanOptions) ([]findings.UnifiedFinding, error) {
	return []findings.UnifiedFinding{
		{
			Location: findings.Location{
				File: "(tls-probe)/" + s.echHostname + ":443#kex",
			},
			Algorithm:              &findings.Algorithm{Name: "ECDHE", Primitive: "key-exchange"},
			Confidence:             findings.ConfidenceMedium,
			SourceEngine:           "tls-probe",
			Reachable:              findings.ReachableYes,
			PartialInventory:       true,
			PartialInventoryReason: "ECH_ENABLED",
		},
	}, nil
}

// TestOrchestrator_CTLookupFromECH_AutoEnrichment verifies that when
// CTLookupFromECH=true:
//  1. The tls-probe engine runs in pass 1 and returns an ECH finding.
//  2. The orchestrator extracts the hostname from the ECH finding.
//  3. The ct-lookup engine is invoked in pass 2 with that hostname in its
//     CTLookupTargets (in addition to any explicitly provided targets).
func TestOrchestrator_CTLookupFromECH_AutoEnrichment(t *testing.T) {
	const echHost = "ech-secret.example.com"

	tlsProbe := &spyTLSProbeEngine{echHostname: echHost}
	ctLookup := &spyCTLookupEngine{}

	o := New(tlsProbe, ctLookup)

	_, err := o.Scan(context.Background(), engines.ScanOptions{
		CTLookupFromECH: true,
	})
	if err != nil {
		t.Fatalf("Scan error: %v", err)
	}

	ctLookup.mu.Lock()
	defer ctLookup.mu.Unlock()

	if len(ctLookup.callOpts) == 0 {
		t.Fatal("ct-lookup engine was never called")
	}

	// Verify the ECH hostname was injected into CTLookupTargets.
	var found bool
	for _, target := range ctLookup.callOpts[0].CTLookupTargets {
		if target == echHost {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("ct-lookup CTLookupTargets = %v, expected to contain %q (extracted from ECH finding)",
			ctLookup.callOpts[0].CTLookupTargets, echHost)
	}
}

// TestOrchestrator_CTLookupFromECH_NoDuplication verifies that when a hostname
// is present in both an explicit CTLookupTargets list AND extracted from ECH
// findings, it appears exactly once in the ct-lookup engine's opts.
func TestOrchestrator_CTLookupFromECH_NoDuplication(t *testing.T) {
	const echHost = "dedup.example.com"

	tlsProbe := &spyTLSProbeEngine{echHostname: echHost}
	ctLookup := &spyCTLookupEngine{}

	o := New(tlsProbe, ctLookup)

	_, err := o.Scan(context.Background(), engines.ScanOptions{
		CTLookupFromECH: true,
		// echHost explicitly listed as well — should not appear twice.
		CTLookupTargets: []string{echHost},
	})
	if err != nil {
		t.Fatalf("Scan error: %v", err)
	}

	ctLookup.mu.Lock()
	defer ctLookup.mu.Unlock()

	if len(ctLookup.callOpts) == 0 {
		t.Fatal("ct-lookup engine was never called")
	}

	targets := ctLookup.callOpts[0].CTLookupTargets
	var count int
	for _, h := range targets {
		if h == echHost {
			count++
		}
	}
	if count != 1 {
		t.Errorf("echHost appeared %d times in CTLookupTargets, want exactly 1 (dedup check)", count)
	}
}

// TestOrchestrator_CTLookupFromECH_Disabled verifies that when CTLookupFromECH=false,
// ECH-annotated findings do NOT auto-populate CTLookupTargets, so the ct-lookup
// engine is called with no auto-enriched targets. TLSTargets is provided so that
// Tier5Network engines are included in the scan; the tls-probe spy returns an
// ECH finding, but the orchestrator should ignore it when CTLookupFromECH=false.
func TestOrchestrator_CTLookupFromECH_Disabled(t *testing.T) {
	tlsProbe := &spyTLSProbeEngine{echHostname: "no-inject.example.com"}
	ctLookup := &spyCTLookupEngine{}

	o := New(tlsProbe, ctLookup)

	_, err := o.Scan(context.Background(), engines.ScanOptions{
		CTLookupFromECH: false,
		// TLSTargets causes Tier5Network engines to be included.
		TLSTargets: []string{"no-inject.example.com:443"},
	})
	if err != nil {
		t.Fatalf("Scan error: %v", err)
	}

	ctLookup.mu.Lock()
	defer ctLookup.mu.Unlock()

	// Either not called at all, or called with no CTLookupTargets.
	for _, opts := range ctLookup.callOpts {
		for _, h := range opts.CTLookupTargets {
			if h == "no-inject.example.com" {
				t.Errorf("CTLookupFromECH=false: hostname %q must not appear in CTLookupTargets", h)
			}
		}
	}
}

// TestOrchestrator_CTLookupFromECH_NoECHFindings verifies that when the
// tls-probe engine produces no ECH-annotated findings, the ct-lookup engine
// receives no auto-enriched targets.
func TestOrchestrator_CTLookupFromECH_NoECHFindings(t *testing.T) {
	// tls-probe returns an ordinary (non-ECH) finding.
	noECHProbe := &mockEngine{
		name:      "tls-probe",
		tier:      engines.Tier5Network,
		available: true,
		results: []findings.UnifiedFinding{
			{
				Location:     findings.Location{File: "(tls-probe)/plain.host:443#kex"},
				Algorithm:    &findings.Algorithm{Name: "ECDHE"},
				SourceEngine: "tls-probe",
				// PartialInventory is false (not ECH).
			},
		},
	}
	ctLookup := &spyCTLookupEngine{}

	o := New(noECHProbe, ctLookup)

	_, err := o.Scan(context.Background(), engines.ScanOptions{
		CTLookupFromECH: true,
	})
	if err != nil {
		t.Fatalf("Scan error: %v", err)
	}

	ctLookup.mu.Lock()
	defer ctLookup.mu.Unlock()

	for _, opts := range ctLookup.callOpts {
		if len(opts.CTLookupTargets) > 0 {
			t.Errorf("no ECH findings: expected empty CTLookupTargets, got %v", opts.CTLookupTargets)
		}
	}
}
