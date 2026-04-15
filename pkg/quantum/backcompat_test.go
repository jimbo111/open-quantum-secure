package quantum

// backcompat_test.go — backwards-compatibility golden snapshot tests.
//
// Classifies a fixed set of algorithm specimens and compares the result against a
// golden JSON file. The snapshot ensures that future refactors do not silently
// change the classification output.
//
// # Expected to CHANGE between model versions
//   - HNDLRisk values (if HNDL model is revised)
//   - Recommendation text (if wording is updated)
//   - TargetAlgorithm / TargetStandard (as NIST standards evolve)
//
// # Expected to STAY STABLE
//   - Risk field (quantum-vulnerable / quantum-safe / deprecated / etc.)
//   - Severity field (critical / high / medium / low / info)
//   - Algorithm names and which families they belong to
//
// To regenerate the golden file after an intentional change:
//
//	go test ./pkg/quantum/ -run TestBackcompat_ClassificationSnapshot -update
//
// Commit the updated golden file alongside the code change that caused it.

import (
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"testing"
)

var updateGolden = flag.Bool("update", false, "regenerate golden snapshot files")

// goldenSpecimen is a single test specimen for the golden snapshot.
type goldenSpecimen struct {
	Algorithm string `json:"algorithm"`
	Primitive string `json:"primitive"`
	KeySize   int    `json:"keySize,omitempty"`
}

// goldenRecord captures the Classification fields we snapshot.
// We snapshot only the fields expected to be stable; omit free-form text.
type goldenRecord struct {
	Specimen        goldenSpecimen `json:"specimen"`
	Risk            Risk           `json:"risk"`
	Severity        Severity       `json:"severity"`
	HNDLRisk        string         `json:"hndlRisk"`
	MigrationEffort string         `json:"migrationEffort,omitempty"` // effort set by ClassifyEffort
}

// goldenSnapshot is the top-level golden file structure.
type goldenSnapshot struct {
	// SchemaVersion lets us detect when the snapshot format itself changes.
	SchemaVersion string         `json:"schemaVersion"`
	Records       []goldenRecord `json:"records"`
}

// specimens is the fixed set of algorithm inputs. These cover:
//   - Classical KEM/exchange (RSA, ECDH, ECDSA, X25519)
//   - S0.F4 hybrid forms (canonical and hyphenated)
//   - Pure PQ (ML-KEM, ML-DSA, SLH-DSA)
//   - Korean K-PQC finalists (SMAUG-T, HAETAE)
//   - Deprecated (MD5, DES)
//   - Symmetric/hash (AES-256-GCM, SHA-256)
var specimens = []goldenSpecimen{
	{"RSA-2048", "signature", 2048},
	{"RSA-2048", "kem", 2048},
	{"ECDH", "key-exchange", 0},
	{"ECDSA", "signature", 0},
	{"X25519", "key-exchange", 0},
	{"X25519MLKEM768", "kem", 0},         // canonical hybrid — S0.F4 regression guard
	{"X25519-MLKEM-768", "kem", 0},       // hyphenated hybrid — S0.F4 regression guard
	{"SecP256r1MLKEM768", "kem", 0},
	{"ML-KEM-768", "kem", 0},
	{"ML-KEM-512", "kem", 0},
	{"ML-DSA-65", "signature", 0},
	{"SLH-DSA-128s", "signature", 0},
	{"SMAUG-T-128", "kem", 0},
	{"HAETAE-3", "signature", 0},
	{"AES-256-GCM", "symmetric", 256},
	{"AES-128-CBC", "symmetric", 128},
	{"SHA-256", "hash", 256},
	{"MD5", "hash", 0},
	{"DES", "symmetric", 56},
}

const (
	goldenDir  = "testdata/s0-backcompat"
	goldenFile = "testdata/s0-backcompat/golden.json"
	schemaVer  = "1"
)

// buildSnapshot classifies all specimens and returns the golden snapshot struct.
func buildSnapshot() goldenSnapshot {
	records := make([]goldenRecord, len(specimens))
	for i, s := range specimens {
		c := ClassifyAlgorithm(s.Algorithm, s.Primitive, s.KeySize)
		effort := ClassifyEffort(c, s.Primitive, false)
		records[i] = goldenRecord{
			Specimen:        s,
			Risk:            c.Risk,
			Severity:        c.Severity,
			HNDLRisk:        c.HNDLRisk,
			MigrationEffort: effort,
		}
	}
	return goldenSnapshot{SchemaVersion: schemaVer, Records: records}
}

// TestBackcompat_ClassificationSnapshot is the golden snapshot test.
// Pass -update to regenerate; otherwise it reads the existing golden file and
// compares field-by-field.
func TestBackcompat_ClassificationSnapshot(t *testing.T) {
	current := buildSnapshot()

	if *updateGolden {
		data, err := json.MarshalIndent(current, "", "  ")
		if err != nil {
			t.Fatalf("marshal snapshot: %v", err)
		}
		if err := os.MkdirAll(goldenDir, 0755); err != nil {
			t.Fatalf("mkdir %s: %v", goldenDir, err)
		}
		if err := os.WriteFile(goldenFile, append(data, '\n'), 0644); err != nil {
			t.Fatalf("write golden file: %v", err)
		}
		t.Logf("golden file updated: %s (%d records)", goldenFile, len(current.Records))
		return
	}

	data, err := os.ReadFile(filepath.Join(".", goldenFile))
	if err != nil {
		t.Fatalf("read golden file %q: %v\n\nRun with -update to generate it.", goldenFile, err)
	}

	var golden goldenSnapshot
	if err := json.Unmarshal(data, &golden); err != nil {
		t.Fatalf("unmarshal golden file: %v", err)
	}

	if len(golden.Records) != len(current.Records) {
		t.Fatalf("record count mismatch: golden=%d current=%d (was a specimen added/removed?)",
			len(golden.Records), len(current.Records))
	}

	for i, cur := range current.Records {
		gold := golden.Records[i]
		spec := cur.Specimen

		// STABLE fields: these must not change without an intentional update.
		if cur.Risk != gold.Risk {
			t.Errorf("[%d] %s(%s): Risk changed: %q → %q (STABLE field — update golden if intentional)",
				i, spec.Algorithm, spec.Primitive, gold.Risk, cur.Risk)
		}
		if cur.Severity != gold.Severity {
			t.Errorf("[%d] %s(%s): Severity changed: %q → %q (STABLE field)",
				i, spec.Algorithm, spec.Primitive, gold.Severity, cur.Severity)
		}
		if cur.MigrationEffort != gold.MigrationEffort {
			t.Errorf("[%d] %s(%s): MigrationEffort changed: %q → %q (STABLE field)",
				i, spec.Algorithm, spec.Primitive, gold.MigrationEffort, cur.MigrationEffort)
		}

		// HNDL risk: labelled separately because it is expected to evolve with the HNDL model.
		if cur.HNDLRisk != gold.HNDLRisk {
			t.Errorf("[%d] %s(%s): HNDLRisk changed: %q → %q (HNDL model field — update golden if HNDL model changed)",
				i, spec.Algorithm, spec.Primitive, gold.HNDLRisk, cur.HNDLRisk)
		}
	}
}

// TestBackcompat_StableFieldsInvariant verifies the invariants that must hold
// for stable fields regardless of what the golden file says — if these fail,
// the classifier has a bug, not just an evolution.
func TestBackcompat_StableFieldsInvariant(t *testing.T) {
	for _, s := range specimens {
		s := s
		name := s.Algorithm + "(" + s.Primitive + ")"
		t.Run(name, func(t *testing.T) {
			c := ClassifyAlgorithm(s.Algorithm, s.Primitive, s.KeySize)

			// RiskSafe algorithms must never have a non-empty HNDLRisk.
			if c.Risk == RiskSafe && c.HNDLRisk != "" {
				t.Errorf("%s: Risk=safe but HNDLRisk=%q (PQ-safe algorithms have no HNDL risk)", name, c.HNDLRisk)
			}

			// RiskDeprecated algorithms must never have an HNDLRisk (classically broken ≠ HNDL risk).
			if c.Risk == RiskDeprecated && c.HNDLRisk != "" {
				t.Errorf("%s: Risk=deprecated but HNDLRisk=%q (deprecated algos are classically broken, not HNDL)", name, c.HNDLRisk)
			}

			// Classical KEMs (immediate) must be RiskVulnerable.
			if c.HNDLRisk == HNDLImmediate && c.Risk != RiskVulnerable {
				t.Errorf("%s: HNDLRisk=immediate but Risk=%q (should be RiskVulnerable)", name, c.Risk)
			}

			// Deferred signatures must be RiskVulnerable.
			if c.HNDLRisk == HNDLDeferred && c.Risk != RiskVulnerable {
				t.Errorf("%s: HNDLRisk=deferred but Risk=%q (should be RiskVulnerable)", name, c.Risk)
			}
		})
	}
}
