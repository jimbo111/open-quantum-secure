package orchestrator

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jimbo111/open-quantum-secure/pkg/engines"
	"github.com/jimbo111/open-quantum-secure/pkg/engines/astgrep"
	"github.com/jimbo111/open-quantum-secure/pkg/engines/cbomkit"
	"github.com/jimbo111/open-quantum-secure/pkg/engines/cdxgen"
	"github.com/jimbo111/open-quantum-secure/pkg/engines/cipherscope"
	"github.com/jimbo111/open-quantum-secure/pkg/engines/configscanner"
	"github.com/jimbo111/open-quantum-secure/pkg/engines/cryptodeps"
	"github.com/jimbo111/open-quantum-secure/pkg/engines/cryptoscan"
	"github.com/jimbo111/open-quantum-secure/pkg/engines/semgrep"
	"github.com/jimbo111/open-quantum-secure/pkg/engines/syft"
	"github.com/jimbo111/open-quantum-secure/pkg/quantum"
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

// groundTruthEngineDirs points engine binary discovery at the repo-root
// "engines/" cache (gitignored; populated by `engines install` or a local
// build) so this test picks up cipherscope/cryptoscan the same way the CLI
// does, without requiring a fresh install step. Engines not found there or
// on PATH simply report Available()==false -- see anyEngineSupports.
func groundTruthEngineDirs() []string {
	return []string{filepath.Join("..", "..", "engines")}
}

// groundTruthEngines constructs the same file-scanning engine set the CLI
// wires up (cmd/oqs-scanner/orchestrate.go), minus the Tier 4/5 (binary,
// network) engines, which are irrelevant to a local source-tree recall
// check and are excluded by the default ScanType/Mode filters anyway.
func groundTruthEngines() []engines.Engine {
	dirs := groundTruthEngineDirs()
	return []engines.Engine{
		cipherscope.New(dirs...),
		cryptoscan.New(dirs...),
		astgrep.New(dirs...),
		semgrep.New(dirs...),
		cdxgen.New(dirs...),
		syft.New(dirs...),
		cbomkit.New(dirs...),
		cryptodeps.New(dirs...),
		configscanner.New(),
	}
}

// groundTruthLanguageByDir fills in the "language" the ground-truth repo
// exercises for directories whose expected-findings.json doesn't set it
// (only go-crypto's manifest currently does). Used to decide whether any
// available engine can meaningfully scan this repo at all.
var groundTruthLanguageByDir = map[string]string{
	"go-crypto":     "go",
	"java-crypto":   "java",
	"python-crypto": "python",
	"config-crypto": "yaml",
}

// anyEngineSupports reports whether at least one available engine declares
// support for language. An empty language can't be gated on, so it's
// treated as "don't skip" rather than "nothing supports it".
func anyEngineSupports(avail []engines.Engine, language string) bool {
	if language == "" {
		return true
	}
	for _, e := range avail {
		for _, l := range e.SupportedLanguages() {
			if l == language {
				return true
			}
		}
	}
	return false
}

// TestGroundTruthRecall runs the real orchestrator (with the real engine
// set, whatever subset of it resolves to an actual binary in this
// environment) over each testdata/ground-truth repo and checks recall
// against its expected-findings.json manifest.
//
// This exercises the full pipeline including constresolver enrichment
// (pkg/constresolver/enricher.go: EnrichFindingsByFile) -- go-crypto's
// manifest specifically requires KeySize to be back-filled from the
// sibling `const KeySize = 256` for its expectedVerdict assertion
// ("quantum-resistant") to hold; before that fix, AES with KeySize==0
// classified as "unknown".
//
// Per-repo subtests skip (rather than fail) when no available engine
// declares support for that repo's language -- this keeps the test honest
// in CI, where only config-scanner (pure Go, always available) is
// guaranteed to be present, and unable to scan .go/.java/.py source at all.
// The whole test skips only if literally zero engines are available.
func TestGroundTruthRecall(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping recall test in short mode")
	}

	groundTruthDir := "testdata/ground-truth"
	entries, err := os.ReadDir(groundTruthDir)
	if err != nil {
		t.Skipf("ground-truth dir not found: %v", err)
	}

	orch := New(groundTruthEngines()...)
	avail := orch.AvailableEngines()
	if len(avail) == 0 {
		t.Skip("zero engines available in this environment")
	}
	var availNames []string
	for _, e := range avail {
		availNames = append(availNames, e.Name())
	}
	t.Logf("available engines: %v", availNames)

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		entry := entry
		t.Run(entry.Name(), func(t *testing.T) {
			repoDir := filepath.Join(groundTruthDir, entry.Name())
			manifestPath := filepath.Join(repoDir, "expected-findings.json")
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

			language := manifest.Language
			if language == "" {
				language = groundTruthLanguageByDir[entry.Name()]
			}
			if !anyEngineSupports(avail, language) {
				t.Skipf("no available engine supports language %q — cannot exercise this repo in this environment", language)
			}

			absRepoDir, err := filepath.Abs(repoDir)
			if err != nil {
				t.Fatalf("resolve abs path: %v", err)
			}

			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			defer cancel()

			result, scanErr := orch.Scan(ctx, engines.ScanOptions{
				TargetPath: absRepoDir,
				Mode:       engines.ModeFull,
				NoNetwork:  true,
			})
			if scanErr != nil {
				t.Fatalf("scan failed: %v", scanErr)
			}

			if manifest.MinFindings > 0 && len(result) < manifest.MinFindings {
				t.Errorf("got %d findings, want >= %d (minFindings)", len(result), manifest.MinFindings)
			}

			// Recall: every expected algorithm must show up as a substring
			// (case-insensitive) of at least one finding's Algorithm.Name.
			// Substring, not equality -- "AES-GCM" satisfies expected "AES".
			for _, expectedAlgo := range manifest.ExpectedAlgorithms {
				found := false
				for _, f := range result {
					if f.Algorithm == nil {
						continue
					}
					if strings.Contains(strings.ToUpper(f.Algorithm.Name), strings.ToUpper(expectedAlgo)) {
						found = true
						break
					}
				}
				if !found {
					var got []string
					for _, f := range result {
						if f.Algorithm != nil {
							got = append(got, f.Algorithm.Name)
						}
					}
					t.Errorf("expected algorithm %q not found among findings %v", expectedAlgo, got)
				}
			}

			// Verdict assertions (only go-crypto's manifest currently sets these).
			for _, ef := range manifest.ExpectedFindings {
				matched := false
				verdictOK := false
				for _, f := range result {
					if f.Algorithm == nil {
						continue
					}
					if filepath.Base(f.Location.File) != ef.File {
						continue
					}
					if !strings.Contains(strings.ToUpper(f.Algorithm.Name), strings.ToUpper(ef.Algorithm)) {
						continue
					}
					matched = true
					if ef.ExpectedVerdict == "" || string(f.QuantumRisk) == ef.ExpectedVerdict {
						verdictOK = true
						break
					}
				}
				if !matched {
					t.Errorf("expectedFindings: no finding matched file=%q algorithm=%q", ef.File, ef.Algorithm)
				} else if !verdictOK {
					t.Errorf("expectedFindings: file=%q algorithm=%q never reached expectedVerdict=%q",
						ef.File, ef.Algorithm, ef.ExpectedVerdict)
				}
			}

			// QRS range (only go-crypto's manifest currently sets this).
			if manifest.ExpectedQRS != nil && len(manifest.ExpectedQRS.ScoreRange) == 2 {
				score := quantum.CalculateQRS(result).Score
				low, high := manifest.ExpectedQRS.ScoreRange[0], manifest.ExpectedQRS.ScoreRange[1]
				if score < low || score > high {
					t.Errorf("QRS score = %d, want in [%d, %d]", score, low, high)
				}
			}

			t.Logf("%s: %d findings, expected algorithms %v satisfied", entry.Name(), len(result), manifest.ExpectedAlgorithms)
		})
	}
}
