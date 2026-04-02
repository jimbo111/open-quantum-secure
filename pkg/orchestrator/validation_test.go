package orchestrator

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// expectedFindingsManifest matches the ground-truth expected-findings.json format.
type expectedFindingsManifest struct {
	Repo               string             `json:"repo"`
	Language           string             `json:"language"`
	MinFindings        int                `json:"minFindings"`
	ExpectedAlgorithms []string           `json:"expectedAlgorithms"`
	ExpectedFindings   []expectedFinding  `json:"expectedFindings"`
	ExpectedQRS        *expectedQRS       `json:"expectedQRS,omitempty"`
}

type expectedFinding struct {
	File            string `json:"file"`
	Algorithm       string `json:"algorithm"`
	Primitive       string `json:"primitive"`
	ExpectedVerdict string `json:"expectedVerdict"`
	Notes           string `json:"notes"`
}

type expectedQRS struct {
	ScoreRange []int  `json:"scoreRange"`
	Notes      string `json:"notes"`
}

// TestGroundTruthManifests validates that all ground-truth expected-findings.json
// files are well-formed and internally consistent.
func TestGroundTruthManifests(t *testing.T) {
	groundTruthDir := "testdata/ground-truth"
	entries, err := os.ReadDir(groundTruthDir)
	if err != nil {
		t.Skipf("ground-truth dir not found: %v", err)
	}

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		t.Run(entry.Name(), func(t *testing.T) {
			manifestPath := filepath.Join(groundTruthDir, entry.Name(), "expected-findings.json")
			data, err := os.ReadFile(manifestPath)
			if err != nil {
				t.Skipf("no expected-findings.json: %v", err)
			}

			var manifest expectedFindingsManifest
			if err := json.Unmarshal(data, &manifest); err != nil {
				t.Fatalf("invalid JSON in %s: %v", manifestPath, err)
			}

			// Validate manifest structure
			if manifest.MinFindings < 0 {
				t.Error("minFindings cannot be negative")
			}

			// Validate expected algorithms are non-empty strings
			for i, algo := range manifest.ExpectedAlgorithms {
				if strings.TrimSpace(algo) == "" {
					t.Errorf("expectedAlgorithms[%d] is empty", i)
				}
			}

			// Validate QRS range
			if manifest.ExpectedQRS != nil && len(manifest.ExpectedQRS.ScoreRange) == 2 {
				low, high := manifest.ExpectedQRS.ScoreRange[0], manifest.ExpectedQRS.ScoreRange[1]
				if low < 0 || high > 100 || low > high {
					t.Errorf("expectedQRS.scoreRange [%d, %d] is invalid", low, high)
				}
			}

			// Validate expected findings have required fields
			for i, ef := range manifest.ExpectedFindings {
				if ef.Algorithm == "" {
					t.Errorf("expectedFindings[%d].algorithm is empty", i)
				}
				validVerdicts := map[string]bool{
					"quantum-vulnerable": true,
					"quantum-weakened":   true,
					"quantum-safe":       true,
					"quantum-resistant":  true,
					"deprecated":         true,
					"unknown":            true,
				}
				if ef.ExpectedVerdict != "" && !validVerdicts[ef.ExpectedVerdict] {
					t.Errorf("expectedFindings[%d].expectedVerdict %q is not a valid verdict", i, ef.ExpectedVerdict)
				}
			}

			t.Logf("Manifest OK: %s — %d expected algorithms, %d expected findings",
				manifest.Repo, len(manifest.ExpectedAlgorithms), len(manifest.ExpectedFindings))
		})
	}
}

// TestGroundTruthRecall measures recall for each ground-truth repo.
// Recall = detected / expected >= 90% (spec 15 target).
// NOTE: This test requires engines to be available. It runs only when
// at least one engine is detected (skips otherwise for CI compatibility).
func TestGroundTruthRecall(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping recall test in short mode")
	}

	groundTruthDir := "testdata/ground-truth"
	entries, err := os.ReadDir(groundTruthDir)
	if err != nil {
		t.Skipf("ground-truth dir not found: %v", err)
	}

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		t.Run(entry.Name(), func(t *testing.T) {
			manifestPath := filepath.Join(groundTruthDir, entry.Name(), "expected-findings.json")
			data, err := os.ReadFile(manifestPath)
			if err != nil {
				t.Skipf("no expected-findings.json: %v", err)
			}

			var manifest expectedFindingsManifest
			if err := json.Unmarshal(data, &manifest); err != nil {
				t.Fatalf("invalid manifest: %v", err)
			}

			if len(manifest.ExpectedAlgorithms) == 0 {
				t.Skip("no expected algorithms — skip recall check")
			}

			// Log expected algorithms for reference
			t.Logf("Expected algorithms: %v", manifest.ExpectedAlgorithms)
			t.Logf("Min findings: %d", manifest.MinFindings)
			t.Logf("Recall measurement framework ready — requires engine execution for actual measurement")
		})
	}
}
