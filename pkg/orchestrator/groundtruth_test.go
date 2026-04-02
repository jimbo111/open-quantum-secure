package orchestrator_test

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jimbo111/open-quantum-secure/pkg/engines"
	"github.com/jimbo111/open-quantum-secure/pkg/engines/configscanner"
	"github.com/jimbo111/open-quantum-secure/pkg/findings"
	"github.com/jimbo111/open-quantum-secure/pkg/orchestrator"
)

// expectedFindings describes the expected scan output for a ground-truth fixture.
type expectedFindings struct {
	Description        string   `json:"description"`
	MinFindings        int      `json:"minFindings"`
	ExpectedAlgorithms []string `json:"expectedAlgorithms"`
}

// loadExpected reads and parses expected-findings.json from dir.
func loadExpected(t *testing.T, dir string) expectedFindings {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(dir, "expected-findings.json"))
	if err != nil {
		t.Fatalf("loadExpected: %v", err)
	}
	var ef expectedFindings
	if err := json.Unmarshal(data, &ef); err != nil {
		t.Fatalf("loadExpected: JSON unmarshal: %v", err)
	}
	return ef
}

// foundAlgorithmNames builds a set of algorithm base names from findings.
// It checks both exact match and prefix match so "AES" covers "AES-256-GCM".
func foundAlgorithmNames(ff []findings.UnifiedFinding) map[string]bool {
	names := make(map[string]bool, len(ff))
	for _, f := range ff {
		if f.Algorithm != nil && f.Algorithm.Name != "" {
			names[strings.ToUpper(f.Algorithm.Name)] = true
		}
	}
	return names
}

// checkExpectedAlgorithms asserts that every expected algorithm appears in the
// found set, using prefix matching (e.g. "AES" matches "AES-256-GCM").
func checkExpectedAlgorithms(t *testing.T, expected []string, ff []findings.UnifiedFinding) {
	t.Helper()
	foundNames := foundAlgorithmNames(ff)

	for _, want := range expected {
		upper := strings.ToUpper(want)
		found := foundNames[upper]
		if !found {
			for name := range foundNames {
				if strings.HasPrefix(name, upper) {
					found = true
					break
				}
			}
		}
		if !found {
			// Collect actual algorithm names for diagnostic message.
			var actual []string
			for name := range foundNames {
				actual = append(actual, name)
			}
			t.Errorf("expected algorithm %q not found; found: %v", want, actual)
		}
	}
}

// TestGroundTruth_ConfigCrypto scans the config-crypto ground-truth fixture
// with the embedded config-scanner engine and verifies expected coverage.
// This test always runs because config-scanner is pure Go (always available).
func TestGroundTruth_ConfigCrypto(t *testing.T) {
	dir := filepath.Join("testdata", "ground-truth", "config-crypto")
	expected := loadExpected(t, dir)

	eng := configscanner.New()
	orch := orchestrator.New(eng)
	opts := engines.ScanOptions{
		TargetPath: dir,
		Mode:       engines.ModeFull,
	}

	ff, err := orch.Scan(context.Background(), opts)
	if err != nil {
		t.Fatalf("Scan() error: %v", err)
	}

	if len(ff) < expected.MinFindings {
		t.Errorf("got %d findings, want >= %d (%s)", len(ff), expected.MinFindings, expected.Description)
	}

	checkExpectedAlgorithms(t, expected.ExpectedAlgorithms, ff)
}

// TestGroundTruth_ConfigCrypto_WithMetrics verifies ScanWithMetrics end-to-end
// using the always-available config-scanner engine.
func TestGroundTruth_ConfigCrypto_WithMetrics(t *testing.T) {
	dir := filepath.Join("testdata", "ground-truth", "config-crypto")

	eng := configscanner.New()
	orch := orchestrator.New(eng)
	opts := engines.ScanOptions{
		TargetPath: dir,
		Mode:       engines.ModeFull,
	}

	ff, _, m, err := orch.ScanWithMetrics(context.Background(), opts)
	if err != nil {
		t.Fatalf("ScanWithMetrics() error: %v", err)
	}
	if m == nil {
		t.Fatal("ScanWithMetrics() returned nil metrics")
	}
	if m.TotalDuration <= 0 {
		t.Error("TotalDuration must be > 0")
	}
	if len(m.Engines) != 1 {
		t.Errorf("Engines metric count = %d, want 1", len(m.Engines))
	}
	if m.Engines[0].Name != "config-scanner" {
		t.Errorf("Engines[0].Name = %q, want config-scanner", m.Engines[0].Name)
	}
	if m.Engines[0].Error != "" {
		t.Errorf("config-scanner error: %s", m.Engines[0].Error)
	}
	if len(ff) == 0 {
		t.Error("expected at least one finding from config-scanner")
	}
}
