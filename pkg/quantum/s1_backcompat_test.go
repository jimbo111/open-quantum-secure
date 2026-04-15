package quantum

// s1_backcompat_test.go — Sprint 1 backwards-compatibility golden snapshot for
// ClassifyTLSGroup.
//
// Snapshots (id, Name, PQCPresent, Maturity) tuples for all codepoint categories
// introduced in S1.3: classical ECDH/FFDH, hybrid PQC-final, pure ML-KEM, and
// deprecated-draft Kyber. Future refactors that silently alter these tuples will
// break the snapshot before they reach production.
//
// # Expected to CHANGE between registry versions
//   - New codepoints added to s1Specimens as IANA allocates them
//
// # Expected to STAY STABLE
//   - Name — canonical algorithm identifier used in findings, SARIF, and CBOM
//   - PQCPresent — drives risk classification downstream
//   - Maturity — distinguishes deprecated draft from FIPS-finalised standard
//
// To regenerate the golden file after an intentional change:
//
//	go test ./pkg/quantum/ -run TestS1Backcompat_TLSGroupSnapshot -update
//
// Commit the updated golden file alongside the code change that caused it.

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

// s1GroupRecord is what we snapshot per codepoint.
type s1GroupRecord struct {
	IDHex      string `json:"id"`
	Name       string `json:"name"`
	PQCPresent bool   `json:"pqcPresent"`
	Maturity   string `json:"maturity"`
	Known      bool   `json:"known"`
}

// s1GoldenSnapshot is the top-level S1 golden file structure.
type s1GoldenSnapshot struct {
	// SchemaVersion lets us detect when the snapshot format itself changes.
	SchemaVersion string          `json:"schemaVersion"`
	Records       []s1GroupRecord `json:"records"`
}

// s1Specimens is the fixed codepoint set covering all four categories:
// classical ECDH/FFDH, hybrid-final (S1.3 hybrid-KEMs), pure ML-KEM, and
// deprecated-draft Kyber (two codepoints for the same algorithm).
var s1Specimens = []uint16{
	// Classical ECDH
	0x0017, // secp256r1
	0x001d, // X25519
	0x001e, // X448
	// Classical FFDH
	0x0100, // ffdhe2048
	0x0104, // ffdhe8192
	// Hybrid KEMs: classical ECDH + ML-KEM (FIPS 203 + IETF hybrid-design)
	0x11EB, // SecP256r1MLKEM768
	0x11EC, // X25519MLKEM768
	0x11ED, // SecP384r1MLKEM1024
	0x11EE, // curveSM2MLKEM768
	// Pure ML-KEM (FIPS 203)
	0x0200, // MLKEM512
	0x0201, // MLKEM768
	0x0202, // MLKEM1024
	// Deprecated draft Kyber (pre-FIPS 203): two codepoints, same algorithm name
	0x6399, // X25519Kyber768Draft00 (primary codepoint)
	0x636D, // X25519Kyber768Draft00 (alternate codepoint)
}

const (
	s1GoldenDir  = "testdata/s1-pqc"
	s1GoldenFile = "testdata/s1-pqc/golden.json"
	s1SchemaVer  = "1"
)

// buildS1Snapshot classifies all s1Specimens and returns the snapshot struct.
func buildS1Snapshot() s1GoldenSnapshot {
	records := make([]s1GroupRecord, len(s1Specimens))
	for i, id := range s1Specimens {
		info, ok := ClassifyTLSGroup(id)
		records[i] = s1GroupRecord{
			IDHex:      fmt.Sprintf("0x%04x", id),
			Name:       info.Name,
			PQCPresent: info.PQCPresent,
			Maturity:   info.Maturity,
			Known:      ok,
		}
	}
	return s1GoldenSnapshot{SchemaVersion: s1SchemaVer, Records: records}
}

// TestS1Backcompat_TLSGroupSnapshot is the golden snapshot test for
// ClassifyTLSGroup. Pass -update to regenerate; otherwise it reads the existing
// golden file and compares field-by-field.
func TestS1Backcompat_TLSGroupSnapshot(t *testing.T) {
	current := buildS1Snapshot()

	if *updateGolden {
		data, err := json.MarshalIndent(current, "", "  ")
		if err != nil {
			t.Fatalf("marshal snapshot: %v", err)
		}
		if err := os.MkdirAll(s1GoldenDir, 0755); err != nil {
			t.Fatalf("mkdir %s: %v", s1GoldenDir, err)
		}
		if err := os.WriteFile(s1GoldenFile, append(data, '\n'), 0644); err != nil {
			t.Fatalf("write golden file: %v", err)
		}
		t.Logf("golden file updated: %s (%d records)", s1GoldenFile, len(current.Records))
		return
	}

	data, err := os.ReadFile(filepath.Join(".", s1GoldenFile))
	if err != nil {
		t.Fatalf("read golden file %q: %v\n\nRun with -update to generate it.", s1GoldenFile, err)
	}

	var golden s1GoldenSnapshot
	if err := json.Unmarshal(data, &golden); err != nil {
		t.Fatalf("unmarshal golden file: %v", err)
	}

	if golden.SchemaVersion != s1SchemaVer {
		t.Fatalf("schemaVersion mismatch: golden=%q current=%q (update the test or bump the constant)",
			golden.SchemaVersion, s1SchemaVer)
	}
	if len(golden.Records) != len(current.Records) {
		t.Fatalf("record count mismatch: golden=%d current=%d (was a specimen added/removed?)",
			len(golden.Records), len(current.Records))
	}

	for i, cur := range current.Records {
		gold := golden.Records[i]

		if cur.IDHex != gold.IDHex {
			t.Errorf("[%d]: IDHex changed: %q → %q (specimen order must be stable)", i, gold.IDHex, cur.IDHex)
		}
		// STABLE: Name is the canonical algorithm identifier in findings/SARIF/CBOM.
		if cur.Name != gold.Name {
			t.Errorf("[%d] %s: Name changed: %q → %q (STABLE — update golden if intentional)",
				i, gold.IDHex, gold.Name, cur.Name)
		}
		// STABLE: PQCPresent drives risk classification; a flip here masks quantum risk.
		if cur.PQCPresent != gold.PQCPresent {
			t.Errorf("[%d] %s (%s): PQCPresent changed: %v → %v (STABLE — would alter risk classification)",
				i, gold.IDHex, gold.Name, gold.PQCPresent, cur.PQCPresent)
		}
		// STABLE: Maturity distinguishes deprecated draft from FIPS-finalised standard.
		if cur.Maturity != gold.Maturity {
			t.Errorf("[%d] %s (%s): Maturity changed: %q → %q (STABLE — update golden if intentional)",
				i, gold.IDHex, gold.Name, gold.Maturity, cur.Maturity)
		}
		// STABLE: known/unknown status must not flip without intent.
		if cur.Known != gold.Known {
			t.Errorf("[%d] %s (%s): Known changed: %v → %v (codepoint added to or removed from registry)",
				i, gold.IDHex, gold.Name, gold.Known, cur.Known)
		}
	}
}

// TestS1Backcompat_CategoryInvariants asserts cross-cutting invariants that must
// hold for all S1 codepoints regardless of golden file content.
func TestS1Backcompat_CategoryInvariants(t *testing.T) {
	snap := buildS1Snapshot()
	for _, r := range snap.Records {
		r := r
		t.Run(r.IDHex+"/"+r.Name, func(t *testing.T) {
			// Every specimen must be a known codepoint.
			if !r.Known {
				t.Errorf("%s: specimen must be a known codepoint — was it removed from the registry?", r.IDHex)
			}
			// PQCPresent=true must carry a non-empty Name.
			if r.PQCPresent && r.Name == "" {
				t.Errorf("%s: PQCPresent=true but Name is empty", r.IDHex)
			}
			// Classical groups (PQCPresent=false) must have empty Maturity.
			if !r.PQCPresent && r.Maturity != "" {
				t.Errorf("%s (%s): classical codepoint has non-empty Maturity=%q — would imply PQC",
					r.IDHex, r.Name, r.Maturity)
			}
			// Maturity must be one of the three valid values.
			switch r.Maturity {
			case "", "final", "draft":
				// valid
			default:
				t.Errorf("%s (%s): invalid Maturity=%q (want \"\", \"final\", or \"draft\")",
					r.IDHex, r.Name, r.Maturity)
			}
		})
	}
}
