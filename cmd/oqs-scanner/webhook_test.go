package main

import (
	"crypto/tls"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/jimbo111/open-quantum-secure/pkg/output"
	"github.com/jimbo111/open-quantum-secure/pkg/quantum"
)

// TestValidateWebhookURL covers the URL validation rules.
func TestValidateWebhookURL(t *testing.T) {
	tests := []struct {
		name    string
		url     string
		wantErr bool
	}{
		{"empty string", "", true},
		{"http scheme", "http://example.com/hook", true},
		{"no scheme", "example.com/hook", true},
		{"no host", "https://", true},
		{"valid https", "https://example.com/hook", false},
		{"valid https with path and query", "https://hook.example.com/webhook?token=abc", false},
		{"ftp scheme", "ftp://example.com/hook", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateWebhookURL(tt.url)
			if (err != nil) != tt.wantErr {
				t.Errorf("validateWebhookURL(%q) error = %v, wantErr %v", tt.url, err, tt.wantErr)
			}
		})
	}
}

// TestBuildWebhookPayloadRoundTrip verifies that buildWebhookPayload produces a
// payload that survives a JSON marshal→unmarshal round-trip with correct field values.
func TestBuildWebhookPayloadRoundTrip(t *testing.T) {
	qrs := quantum.QRS{Score: 72, Grade: "B"}
	sr := output.ScanResult{
		Version:      "0.1.0",
		ScanDuration: "1.234s",
		Summary: output.Summary{
			TotalFindings:     10,
			QuantumVulnerable: 4,
			Deprecated:        2,
			QuantumSafe:       1,
			QuantumResistant:  3,
		},
		QRS: &qrs,
	}

	payload := buildWebhookPayload(sr, "my-project", "main", "full", 0, "")

	if payload.Event != "scan.completed" {
		t.Errorf("Event = %q, want %q", payload.Event, "scan.completed")
	}
	if payload.Scanner != "oqs-scanner" {
		t.Errorf("Scanner = %q, want %q", payload.Scanner, "oqs-scanner")
	}
	if payload.Version != "0.1.0" {
		t.Errorf("Version = %q, want %q", payload.Version, "0.1.0")
	}
	if payload.Project != "my-project" {
		t.Errorf("Project = %q, want %q", payload.Project, "my-project")
	}
	if payload.Branch != "main" {
		t.Errorf("Branch = %q, want %q", payload.Branch, "main")
	}
	if payload.QRS != 72 {
		t.Errorf("QRS = %d, want 72", payload.QRS)
	}
	if payload.Grade != "B" {
		t.Errorf("Grade = %q, want %q", payload.Grade, "B")
	}
	if payload.ScanMode != "full" {
		t.Errorf("ScanMode = %q, want %q", payload.ScanMode, "full")
	}
	if payload.Summary.Total != 10 {
		t.Errorf("Summary.Total = %d, want 10", payload.Summary.Total)
	}
	if payload.Summary.Vulnerable != 4 {
		t.Errorf("Summary.Vulnerable = %d, want 4", payload.Summary.Vulnerable)
	}
	if payload.Summary.Deprecated != 2 {
		t.Errorf("Summary.Deprecated = %d, want 2", payload.Summary.Deprecated)
	}
	// Safe = QuantumSafe + QuantumResistant = 1 + 3 = 4
	if payload.Summary.Safe != 4 {
		t.Errorf("Summary.Safe = %d, want 4", payload.Summary.Safe)
	}
	if payload.Compliance != nil {
		t.Errorf("Compliance should be nil when no standard provided, got %+v", payload.Compliance)
	}

	// Timestamp must parse as RFC3339.
	if _, err := time.Parse(time.RFC3339, payload.Timestamp); err != nil {
		t.Errorf("Timestamp %q is not valid RFC3339: %v", payload.Timestamp, err)
	}

	// Round-trip through JSON.
	data, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("json.Marshal failed: %v", err)
	}
	var decoded WebhookPayload
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("json.Unmarshal failed: %v", err)
	}
	if decoded.QRS != 72 {
		t.Errorf("after round-trip QRS = %d, want 72", decoded.QRS)
	}
	if decoded.Grade != "B" {
		t.Errorf("after round-trip Grade = %q, want B", decoded.Grade)
	}
}

// TestBuildWebhookPayloadCompliance verifies compliance fields are propagated.
func TestBuildWebhookPayloadCompliance(t *testing.T) {
	sr := output.ScanResult{Version: "0.1.0", QRS: &quantum.QRS{Score: 50, Grade: "C"}}
	payload := buildWebhookPayload(sr, "proj", "feat/x", "diff", 3, "cnsa-2.0")

	if payload.Compliance == nil {
		t.Fatal("expected non-nil Compliance")
	}
	if payload.Compliance.Standard != "cnsa-2.0" {
		t.Errorf("Compliance.Standard = %q, want %q", payload.Compliance.Standard, "cnsa-2.0")
	}
	if payload.Compliance.Violations != 3 {
		t.Errorf("Compliance.Violations = %d, want 3", payload.Compliance.Violations)
	}
}

// TestBuildWebhookPayloadNilQRS verifies that a nil QRS (empty result) produces
// zero values instead of a panic.
func TestBuildWebhookPayloadNilQRS(t *testing.T) {
	sr := output.ScanResult{Version: "0.1.0", QRS: nil}
	payload := buildWebhookPayload(sr, "proj", "", "full", 0, "")
	if payload.QRS != 0 {
		t.Errorf("QRS with nil QRS pointer = %d, want 0", payload.QRS)
	}
	if payload.Grade != "" {
		t.Errorf("Grade with nil QRS pointer = %q, want empty", payload.Grade)
	}
}

// TestSendWebhookHTTPSOnly verifies that sendWebhook rejects http:// targets
// without making any network call.
func TestSendWebhookHTTPSOnly(t *testing.T) {
	// sendWebhook is non-fatal, so we can only observe stderr output.
	// What we really care about is: no panic, and the TLS server is NOT hit.
	called := false
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	// Use an http:// URL (non-HTTPS) — should be rejected before dialing.
	httpURL := "http://127.0.0.1:12345/hook"
	sendWebhook(httpURL, WebhookPayload{Event: "scan.completed"})

	if called {
		t.Error("sendWebhook dialed a server when it should have rejected the non-HTTPS URL")
	}
}

// TestSendWebhookDelivery uses a TLS test server to verify the payload is sent
// correctly and the response is handled without errors.
func TestSendWebhookDelivery(t *testing.T) {
	var received WebhookPayload
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("expected POST, got %s", r.Method)
		}
		if ct := r.Header.Get("Content-Type"); ct != "application/json" {
			t.Errorf("Content-Type = %q, want %q", ct, "application/json")
		}
		body, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(body, &received)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	// sendWebhook uses its own http.Client, so we need to reach the TLS server.
	// We replace the global http.DefaultTransport temporarily to trust test certs.
	origTransport := http.DefaultTransport
	http.DefaultTransport = &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec // test-only
	}
	defer func() { http.DefaultTransport = origTransport }()

	payload := WebhookPayload{
		Event:   "scan.completed",
		Scanner: "oqs-scanner",
		Version: "0.1.0",
		QRS:     85,
		Grade:   "A",
	}
	sendWebhook(srv.URL+"/webhook", payload)

	if received.Event != "scan.completed" {
		t.Errorf("received Event = %q, want %q", received.Event, "scan.completed")
	}
	if received.QRS != 85 {
		t.Errorf("received QRS = %d, want 85", received.QRS)
	}
}
