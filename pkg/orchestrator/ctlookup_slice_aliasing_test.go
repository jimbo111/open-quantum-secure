package orchestrator

import (
	"context"
	"testing"

	"github.com/jimbo111/open-quantum-secure/pkg/engines"
)

// TestOrchestrator_CTLookupEnrichment_NoSliceAliasing verifies A4: when
// CTLookupFromECH enriches CTLookupTargets, the caller's original slice must
// not be mutated, even when the slice has excess capacity (cap > len).
func TestOrchestrator_CTLookupEnrichment_NoSliceAliasing(t *testing.T) {
	const echHost = "alias-check.example.com"

	tlsProbe := &spyTLSProbeEngine{echHostname: echHost}
	ctSpy := &spyCTLookupEngine{}

	o := New(tlsProbe, ctSpy)

	// Pre-allocate with excess capacity so append would mutate the backing array
	// without a copy — this is the aliasing scenario we're guarding against.
	initialTargets := make([]string, 1, 10)
	initialTargets[0] = "preset.example.com"

	opts := engines.ScanOptions{
		CTLookupFromECH: true,
		CTLookupTargets: initialTargets,
	}

	_, err := o.Scan(context.Background(), opts)
	if err != nil {
		t.Fatalf("Scan error: %v", err)
	}

	// The caller's original slice must be unchanged in length.
	if len(opts.CTLookupTargets) != 1 {
		t.Errorf("caller's CTLookupTargets mutated: len=%d, want 1", len(opts.CTLookupTargets))
	}
	if opts.CTLookupTargets[0] != "preset.example.com" {
		t.Errorf("caller's CTLookupTargets[0] = %q, want preset.example.com", opts.CTLookupTargets[0])
	}
	// The ct-lookup engine must have seen both targets.
	ctSpy.mu.Lock()
	defer ctSpy.mu.Unlock()
	if len(ctSpy.callOpts) == 0 {
		t.Fatal("ct-lookup engine was never called")
	}
	targets := ctSpy.callOpts[0].CTLookupTargets
	hasPreset := false
	hasECH := false
	for _, h := range targets {
		if h == "preset.example.com" {
			hasPreset = true
		}
		if h == echHost {
			hasECH = true
		}
	}
	if !hasPreset {
		t.Errorf("ct-lookup targets missing preset.example.com: %v", targets)
	}
	if !hasECH {
		t.Errorf("ct-lookup targets missing ECH host %q: %v", echHost, targets)
	}
}
