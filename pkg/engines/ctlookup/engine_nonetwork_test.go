// engine_nonetwork_test.go — Offline-mode invariant test. When NoNetwork=true
// the engine must return (nil, nil) without issuing any HTTP request.
// The panicTransport proves this: if any HTTP call is made the test panics,
// giving an unambiguous signal that the gate was bypassed.
package ctlookup

import (
	"context"
	"net/http"
	"testing"

	"github.com/jimbo111/open-quantum-secure/pkg/engines"
)

// panicTransport is an http.RoundTripper that panics on any use. Injecting it
// into the engine's HTTP client guarantees that any network call is caught
// immediately rather than hitting an external service or timing out.
type panicTransport struct{}

func (panicTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	panic("ctlookup: NoNetwork=true but an HTTP request was attempted for " + r.URL.String())
}

// TestEngine_NoNetwork_NeverCallsHTTP verifies that Scan honours NoNetwork=true
// by returning (nil, nil) without making any HTTP call. If the gate is bypassed,
// the panicTransport causes the goroutine to panic and the test runtime reports
// the failure.
func TestEngine_NoNetwork_NeverCallsHTTP(t *testing.T) {
	e := New()
	e.client.httpClient = &http.Client{Transport: panicTransport{}}

	opts := engines.ScanOptions{
		CTLookupTargets: []string{"example.com", "test.org", "should-not-be-contacted.net"},
		NoNetwork:       true,
	}
	ff, err := e.Scan(context.Background(), opts)
	if err != nil {
		t.Fatalf("Scan(NoNetwork=true) returned unexpected error: %v", err)
	}
	if ff != nil {
		t.Errorf("Scan(NoNetwork=true) returned non-nil findings: %v", ff)
	}
}

// TestEngine_NoNetwork_EmptyTargets also uses NoNetwork=true to verify that
// the dual gate (NoNetwork OR empty targets) both short-circuit at the same
// point without attempting any HTTP call.
func TestEngine_NoNetwork_EmptyTargets(t *testing.T) {
	e := New()
	e.client.httpClient = &http.Client{Transport: panicTransport{}}

	// Both conditions apply: NoNetwork=true AND targets is empty.
	opts := engines.ScanOptions{
		CTLookupTargets: nil,
		NoNetwork:       true,
	}
	ff, err := e.Scan(context.Background(), opts)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ff != nil {
		t.Errorf("expected nil, got %v", ff)
	}
}
