package ctlookup

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/jimbo111/open-quantum-secure/pkg/engines"
)

// TestEngine_Scan_DERFetchFailure_NoSpuriousFinding verifies A3: when all DER
// fetches fail (e.g. 500 from crt.sh), Scan must return zero findings rather
// than emitting an "unknown"-algorithm record per failed cert.
func TestEngine_Scan_DERFetchFailure_NoSpuriousFinding(t *testing.T) {
	entries := []crtShEntry{{
		ID:           9001,
		IssuerName:   "CN=Test CA",
		CommonName:   "fail.example.com",
		NameValue:    "fail.example.com",
		SerialNumber: "DEADBEEF",
		NotBefore:    "2024-01-01T00:00:00",
		NotAfter:     "2025-01-01T00:00:00",
	}}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("output") == "json" {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(entries)
			return
		}
		// All DER fetches return 500 — simulates crt.sh internal error.
		http.Error(w, "internal server error", http.StatusInternalServerError)
	}))
	defer srv.Close()

	e := New()
	e.client.baseURL = srv.URL
	e.client.httpClient = srv.Client()
	e.rl = newRateLimiter(10000.0, 10000.0)

	ff, err := e.Scan(context.Background(), engines.ScanOptions{
		CTLookupTargets: []string{"fail.example.com"},
	})
	if err != nil {
		t.Fatalf("Scan returned unexpected error: %v", err)
	}
	for _, f := range ff {
		algo := ""
		if f.Algorithm != nil {
			algo = f.Algorithm.Name
		}
		if algo == "" || algo == "unknown" {
			t.Errorf("spurious finding emitted with empty/unknown algorithm: file=%s algo=%q",
				f.Location.File, algo)
		}
	}
}

// TestEngine_Scan_DERParseFailure_NoSpuriousFinding verifies A3: when the DER
// cannot be parsed (corrupt bytes), Scan must not emit an unknown-algorithm finding.
func TestEngine_Scan_DERParseFailure_NoSpuriousFinding(t *testing.T) {
	entries := []crtShEntry{{
		ID:           9002,
		IssuerName:   "CN=Test CA",
		CommonName:   "corrupt.example.com",
		NameValue:    "corrupt.example.com",
		SerialNumber: "CAFEBABE",
		NotBefore:    "2024-01-01T00:00:00",
		NotAfter:     "2025-01-01T00:00:00",
	}}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("output") == "json" {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(entries)
			return
		}
		// Return corrupt DER bytes.
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "this is not a valid DER certificate")
	}))
	defer srv.Close()

	e := New()
	e.client.baseURL = srv.URL
	e.client.httpClient = srv.Client()
	e.rl = newRateLimiter(10000.0, 10000.0)

	ff, err := e.Scan(context.Background(), engines.ScanOptions{
		CTLookupTargets: []string{"corrupt.example.com"},
	})
	if err != nil {
		t.Fatalf("Scan returned unexpected error: %v", err)
	}
	for _, f := range ff {
		algo := ""
		if f.Algorithm != nil {
			algo = f.Algorithm.Name
		}
		if algo == "" || algo == "unknown" {
			t.Errorf("spurious finding emitted with empty/unknown algorithm: file=%s algo=%q",
				f.Location.File, algo)
		}
	}
}
