package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"time"

	"github.com/jimbo111/open-quantum-secure/pkg/output"
)

// WebhookPayload is the JSON body POSTed to --webhook-url on scan completion.
type WebhookPayload struct {
	Event     string `json:"event"`     // always "scan.completed"
	Timestamp string `json:"timestamp"` // RFC3339
	Project   string `json:"project"`
	Branch    string `json:"branch,omitempty"`
	Scanner   string `json:"scanner"` // "oqs-scanner"
	Version   string `json:"version"`

	QRS   int    `json:"quantumReadinessScore"`
	Grade string `json:"quantumReadinessGrade"`

	Summary struct {
		Total      int `json:"total"`
		Vulnerable int `json:"vulnerable"`
		Deprecated int `json:"deprecated"`
		Safe       int `json:"safe"`
	} `json:"summary"`

	ScanMode  string `json:"scanMode"`
	Duration  string `json:"duration"`

	Compliance *WebhookCompliance `json:"compliance,omitempty"`
}

// WebhookCompliance carries optional compliance metadata in the payload.
type WebhookCompliance struct {
	Standard   string `json:"standard,omitempty"`
	Violations int    `json:"violations,omitempty"`
}

// buildWebhookPayload constructs a WebhookPayload from a completed ScanResult.
// project, branch, scanMode, and complianceStandard are caller-supplied because
// they are not embedded in output.ScanResult.
func buildWebhookPayload(
	scanResult output.ScanResult,
	project, branch, scanMode string,
	complianceViolations int,
	complianceStandard string,
) WebhookPayload {
	p := WebhookPayload{
		Event:     "scan.completed",
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		Project:   project,
		Branch:    branch,
		Scanner:   "oqs-scanner",
		Version:   scanResult.Version,
		ScanMode:  scanMode,
		Duration:  scanResult.ScanDuration,
	}

	if scanResult.QRS != nil {
		p.QRS = scanResult.QRS.Score
		p.Grade = scanResult.QRS.Grade
	}

	p.Summary.Total = scanResult.Summary.TotalFindings
	p.Summary.Vulnerable = scanResult.Summary.QuantumVulnerable
	p.Summary.Deprecated = scanResult.Summary.Deprecated
	p.Summary.Safe = scanResult.Summary.QuantumSafe + scanResult.Summary.QuantumResistant

	if complianceStandard != "" {
		p.Compliance = &WebhookCompliance{
			Standard:   complianceStandard,
			Violations: complianceViolations,
		}
	}

	return p
}

// validateWebhookURL returns an error if the URL is empty, non-HTTPS, or
// otherwise malformed. http:// is rejected to prevent sending findings in
// cleartext.
func validateWebhookURL(rawURL string) error {
	if rawURL == "" {
		return fmt.Errorf("webhook URL is empty")
	}
	u, err := url.Parse(rawURL)
	if err != nil {
		return fmt.Errorf("webhook URL parse error: %w", err)
	}
	if u.Scheme != "https" {
		return fmt.Errorf("webhook URL must use HTTPS (got %q)", u.Scheme)
	}
	if u.Host == "" {
		return fmt.Errorf("webhook URL has no host")
	}
	return nil
}

// sendWebhook marshals payload to JSON and POSTs it to webhookURL.
// All failures are non-fatal: a warning is printed to stderr and the scan
// exit code is not affected.
func sendWebhook(webhookURL string, payload WebhookPayload) {
	if err := validateWebhookURL(webhookURL); err != nil {
		fmt.Fprintf(os.Stderr, "WARNING: webhook skipped: %s\n", err)
		return
	}

	body, err := json.Marshal(payload)
	if err != nil {
		fmt.Fprintf(os.Stderr, "WARNING: webhook marshal failed: %s\n", err)
		return
	}

	client := &http.Client{
		Timeout: 10 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			// Prevent HTTPS→HTTP redirect downgrade (same pattern as engine downloader).
			if req.URL.Scheme != "https" {
				return fmt.Errorf("refusing redirect from HTTPS to %s", req.URL.Scheme)
			}
			if len(via) >= 3 {
				return fmt.Errorf("too many redirects")
			}
			return nil
		},
	}
	req, err := http.NewRequest(http.MethodPost, webhookURL, bytes.NewReader(body))
	if err != nil {
		fmt.Fprintf(os.Stderr, "WARNING: webhook request build failed: %s\n", err)
		return
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "oqs-scanner/"+payload.Version)

	resp, err := client.Do(req)
	if err != nil {
		fmt.Fprintf(os.Stderr, "WARNING: webhook delivery failed: %s\n", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		fmt.Fprintf(os.Stderr, "WARNING: webhook returned non-2xx status: %d\n", resp.StatusCode)
		return
	}

	fmt.Fprintf(os.Stderr, "Webhook delivered to %s (HTTP %d)\n", webhookURL, resp.StatusCode)
}
