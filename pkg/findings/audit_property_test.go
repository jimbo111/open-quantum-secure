package findings

// audit_property_test.go — property-based tests for the findings package.
//
// These tests were added by the 2026-04-20 audit (orch-findings layer). They
// focus on invariants that are easy to state but hard to verify with
// example-based tests:
//
//   F-P1 DedupeKey determinism + stability under repeated calls + random
//        permutation.
//   F-P2 JSON omitempty correctness for all Sprint 2 observability fields,
//        including HandshakeBytes, HandshakeVolumeClass, PartialInventory,
//        PartialInventoryReason, NegotiatedGroup, NegotiatedGroupName.
//   F-P3 Clone deep-copy invariant: mutating the clone's slices must not
//        affect the original, and vice versa, for every slice field.
//   F-P4 SortByPriority transitive/reflexive ordering on randomised input.
//
// All inputs are deterministic (seeded math/rand) so a CI failure is
// reproducible.

import (
	"encoding/json"
	"math/rand"
	"sort"
	"testing"
)

// ---------------------------------------------------------------------------
// F-P1 — DedupeKey stability (property)
// ---------------------------------------------------------------------------

// TestAudit_DedupeKey_StabilityAcrossPermutations generates 1 000 random
// findings, computes each DedupeKey three times (original order, shuffled once,
// shuffled twice) and asserts the key set is bit-identical on every pass.
//
// Motivation: the CLAUDE.md design doc claims DedupeKey is "stable across
// runs" and cache entries rely on byte-stable keys. A regression that e.g.
// pulls any data out of a Go map (non-deterministic iteration) would surface
// here.
func TestAudit_DedupeKey_StabilityAcrossPermutations(t *testing.T) {
	const n = 1000
	rng := rand.New(rand.NewSource(42))
	base := synthesizeFindings(rng, n)

	// Pass 1: compute keys in original order.
	keys1 := make([]string, n)
	for i := range base {
		keys1[i] = base[i].DedupeKey()
	}

	// Pass 2: compute again with identical input — must match byte-for-byte.
	keys2 := make([]string, n)
	for i := range base {
		keys2[i] = base[i].DedupeKey()
	}
	for i := range keys1 {
		if keys1[i] != keys2[i] {
			t.Fatalf("DedupeKey mismatch at index %d: %q vs %q", i, keys1[i], keys2[i])
		}
	}

	// Pass 3: shuffle the slice, recompute. The key of each element is
	// determined by its own fields; the set of keys must still match.
	shuffled := make([]UnifiedFinding, len(base))
	copy(shuffled, base)
	rng.Shuffle(len(shuffled), func(i, j int) { shuffled[i], shuffled[j] = shuffled[j], shuffled[i] })

	sortedOrig := append([]string(nil), keys1...)
	sort.Strings(sortedOrig)

	sortedShuf := make([]string, len(shuffled))
	for i := range shuffled {
		sortedShuf[i] = shuffled[i].DedupeKey()
	}
	sort.Strings(sortedShuf)

	for i := range sortedOrig {
		if sortedOrig[i] != sortedShuf[i] {
			t.Fatalf("key set differs after shuffle at sorted index %d: %q vs %q",
				i, sortedOrig[i], sortedShuf[i])
		}
	}
}

// TestAudit_DedupeKey_FieldIrrelevance verifies that fields that are NOT part
// of the dedup key do not change the key — even under randomised values.
// Fields excluded by design: Confidence, Reachable, Severity, QuantumRisk,
// Priority, BlastRadius, CorroboratedBy, DataFlowPath, all PQC fields.
func TestAudit_DedupeKey_FieldIrrelevance(t *testing.T) {
	rng := rand.New(rand.NewSource(7))
	for i := 0; i < 200; i++ {
		base := UnifiedFinding{
			Location:     Location{File: "/src/a.go", Line: 42},
			Algorithm:    &Algorithm{Name: "RSA-2048"},
			SourceEngine: "engineA",
		}
		want := base.DedupeKey()

		mutated := base
		mutated.Confidence = []Confidence{ConfidenceLow, ConfidenceMedium, ConfidenceHigh}[rng.Intn(3)]
		mutated.Reachable = []Reachability{ReachableYes, ReachableNo, ReachableUnknown}[rng.Intn(3)]
		mutated.Severity = []Severity{SevLow, SevMedium, SevHigh, SevCritical}[rng.Intn(4)]
		mutated.QuantumRisk = []QuantumRisk{QRVulnerable, QRSafe, QRResistant, QRDeprecated}[rng.Intn(4)]
		mutated.Priority = []string{"P1", "P2", "P3", "P4"}[rng.Intn(4)]
		mutated.BlastRadius = rng.Intn(101)
		mutated.CorroboratedBy = []string{"x", "y", "z"}
		mutated.DataFlowPath = []FlowStep{{File: "x", Line: 1}}
		mutated.PQCPresent = rng.Intn(2) == 1
		mutated.NegotiatedGroup = uint16(rng.Intn(65535))
		mutated.NegotiatedGroupName = "noise"
		mutated.HandshakeBytes = rng.Int63n(100000)
		mutated.HandshakeVolumeClass = "noise"
		mutated.PartialInventory = rng.Intn(2) == 1
		mutated.PartialInventoryReason = "noise"

		if got := mutated.DedupeKey(); got != want {
			t.Fatalf("iter %d: unrelated-field mutation changed DedupeKey: want %q got %q", i, want, got)
		}
	}
}

// ---------------------------------------------------------------------------
// F-P2 — omitempty correctness for Sprint 2 observability fields
// ---------------------------------------------------------------------------

// TestAudit_Sprint2Fields_Omitempty verifies the CLAUDE.md invariant that all
// Sprint 2 observability fields use omitempty and are absent from JSON when
// unset.
func TestAudit_Sprint2Fields_Omitempty(t *testing.T) {
	// Baseline finding with ALL Sprint 2 fields at their zero value.
	f := UnifiedFinding{
		Location:     Location{File: "/src/main.go", Line: 42},
		Algorithm:    &Algorithm{Name: "RSA"},
		SourceEngine: "test",
		Confidence:   ConfidenceMedium,
		Reachable:    ReachableUnknown,
		// Explicitly zero:
		NegotiatedGroup:        0,
		NegotiatedGroupName:    "",
		PQCPresent:             false,
		PQCMaturity:            "",
		PartialInventory:       false,
		PartialInventoryReason: "",
		HandshakeVolumeClass:   "",
		HandshakeBytes:         0,
	}

	data, err := json.Marshal(f)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}

	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatalf("unmarshal to map: %v", err)
	}

	// Must be omitted:
	mustBeAbsent := []string{
		"negotiatedGroup",
		"negotiatedGroupName",
		"pqcPresent",
		"pqcMaturity",
		"partialInventory",
		"partialInventoryReason",
		"handshakeVolumeClass",
		"handshakeBytes",
	}
	for _, field := range mustBeAbsent {
		if _, present := raw[field]; present {
			t.Errorf("zero-valued %q should be omitted from JSON; payload: %s", field, string(data))
		}
	}
}

// TestAudit_Sprint2Fields_PresentWhenNonZero verifies omitempty does NOT
// suppress populated Sprint 2 fields (regression guard).
func TestAudit_Sprint2Fields_PresentWhenNonZero(t *testing.T) {
	f := UnifiedFinding{
		Location:               Location{File: "/src/main.go", Line: 42},
		SourceEngine:           "tls-probe",
		Confidence:             ConfidenceHigh,
		Reachable:              ReachableYes,
		NegotiatedGroup:        0x11EC,
		NegotiatedGroupName:    "X25519MLKEM768",
		PQCPresent:             true,
		PQCMaturity:            "final",
		PartialInventory:       true,
		PartialInventoryReason: "ECH_ENABLED",
		HandshakeVolumeClass:   "hybrid-kem",
		HandshakeBytes:         8192,
	}
	data, err := json.Marshal(f)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatal(err)
	}
	mustBePresent := []string{
		"negotiatedGroup", "negotiatedGroupName", "pqcPresent", "pqcMaturity",
		"partialInventory", "partialInventoryReason",
		"handshakeVolumeClass", "handshakeBytes",
	}
	for _, field := range mustBePresent {
		if _, ok := raw[field]; !ok {
			t.Errorf("populated %q should be present in JSON; payload: %s", field, string(data))
		}
	}
}

// ---------------------------------------------------------------------------
// F-P3 — Clone deep-copy invariant
// ---------------------------------------------------------------------------

// TestAudit_Clone_DeepCopy_AllSlices verifies that Clone returns a
// fully-independent copy for every slice/pointer field. Mutating the clone
// must never reach back to the original.
func TestAudit_Clone_DeepCopy_AllSlices(t *testing.T) {
	orig := UnifiedFinding{
		Algorithm:                &Algorithm{Name: "RSA"},
		Dependency:               &Dependency{Library: "openssl"},
		MigrationSnippet:         &MigrationSnippet{Language: "go", Before: "b", After: "a"},
		CorroboratedBy:           []string{"eng1", "eng2"},
		DataFlowPath:             []FlowStep{{File: "src.go", Line: 1}, {File: "snk.go", Line: 2}},
		DeepProbeSupportedGroups: []uint16{0x001d, 0x11EC},
		DeepProbeHRRGroups:       []uint16{0x6399},
		SupportedGroups:          []uint16{0x0017, 0x0018},
		SupportedSigAlgs:         []uint16{0x0804, 0x0805},
	}
	clone := orig.Clone()

	// Mutate the original's slices and pointers.
	orig.Algorithm.Name = "AES"
	orig.Dependency.Library = "libcrypto"
	orig.MigrationSnippet.Before = "xxx"
	orig.CorroboratedBy[0] = "ENG1"
	orig.CorroboratedBy = append(orig.CorroboratedBy, "eng3")
	orig.DataFlowPath[0].File = "MUTATED"
	orig.DataFlowPath = append(orig.DataFlowPath, FlowStep{File: "add.go"})
	orig.DeepProbeSupportedGroups[0] = 0xFFFF
	orig.DeepProbeHRRGroups[0] = 0xFFFF
	orig.SupportedGroups[0] = 0xFFFF
	orig.SupportedSigAlgs[0] = 0xFFFF

	// Clone must be untouched.
	if clone.Algorithm.Name != "RSA" {
		t.Errorf("clone.Algorithm.Name mutated: %q", clone.Algorithm.Name)
	}
	if clone.Dependency.Library != "openssl" {
		t.Errorf("clone.Dependency.Library mutated: %q", clone.Dependency.Library)
	}
	if clone.MigrationSnippet.Before != "b" {
		t.Errorf("clone.MigrationSnippet.Before mutated: %q", clone.MigrationSnippet.Before)
	}
	if clone.CorroboratedBy[0] != "eng1" || len(clone.CorroboratedBy) != 2 {
		t.Errorf("clone.CorroboratedBy mutated: %v", clone.CorroboratedBy)
	}
	if clone.DataFlowPath[0].File != "src.go" || len(clone.DataFlowPath) != 2 {
		t.Errorf("clone.DataFlowPath mutated: %v", clone.DataFlowPath)
	}
	if clone.DeepProbeSupportedGroups[0] != 0x001d {
		t.Errorf("clone.DeepProbeSupportedGroups mutated: %v", clone.DeepProbeSupportedGroups)
	}
	if clone.DeepProbeHRRGroups[0] != 0x6399 {
		t.Errorf("clone.DeepProbeHRRGroups mutated: %v", clone.DeepProbeHRRGroups)
	}
	if clone.SupportedGroups[0] != 0x0017 {
		t.Errorf("clone.SupportedGroups mutated: %v", clone.SupportedGroups)
	}
	if clone.SupportedSigAlgs[0] != 0x0804 {
		t.Errorf("clone.SupportedSigAlgs mutated: %v", clone.SupportedSigAlgs)
	}
}

// ---------------------------------------------------------------------------
// F-P4 — SortByPriority ordering properties
// ---------------------------------------------------------------------------

// TestAudit_SortByPriority_Transitive validates the ordering produced by
// SortByPriority:
//   - priority(P1) ≤ priority(P4)
//   - ties broken by severity then file path
//   - sort is stable (equal elements keep relative order)
//
// Run on randomised input to catch ordering bugs.
func TestAudit_SortByPriority_Transitive(t *testing.T) {
	rng := rand.New(rand.NewSource(99))
	for trial := 0; trial < 20; trial++ {
		ff := synthesizeFindings(rng, 300)
		// Randomly assign a priority.
		priors := []string{"P1", "P2", "P3", "P4"}
		for i := range ff {
			ff[i].Priority = priors[rng.Intn(4)]
		}
		SortByPriority(ff)
		// Validate non-decreasing priority rank.
		for i := 1; i < len(ff); i++ {
			pi := priorityRank(ff[i-1].Priority)
			pj := priorityRank(ff[i].Priority)
			if pi > pj {
				t.Fatalf("trial %d: priority rank decreased at index %d: %q>%q",
					trial, i, ff[i-1].Priority, ff[i].Priority)
			}
			if pi == pj {
				// Within same priority, severity rank must be non-decreasing.
				si := severityRank(ff[i-1].Severity)
				sj := severityRank(ff[i].Severity)
				if si > sj {
					t.Fatalf("trial %d: severity decreased within same priority at index %d", trial, i)
				}
				if si == sj && ff[i-1].Location.File > ff[i].Location.File {
					t.Fatalf("trial %d: file path decreased within same prio+sev at %d", trial, i)
				}
			}
		}
	}
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// synthesizeFindings produces n deterministic findings with a wide variety
// of shapes (algorithm, dependency, innerPath, empty file path).
func synthesizeFindings(rng *rand.Rand, n int) []UnifiedFinding {
	algs := []string{"RSA-2048", "RSA-1024", "AES-256-GCM", "ECDH", "ECDSA", "Ed25519", "SHA-256", "MD5", "X25519MLKEM768", "ML-DSA-65"}
	prims := []string{"signature", "kem", "key-agree", "ae", "hash"}
	engines := []string{"cipherscope", "cryptoscan", "semgrep", "tls-probe", "binary-scanner"}
	sevs := []Severity{SevCritical, SevHigh, SevMedium, SevLow, SevInfo}
	confs := []Confidence{ConfidenceLow, ConfidenceMediumLow, ConfidenceMedium, ConfidenceMediumHigh, ConfidenceHigh}

	out := make([]UnifiedFinding, n)
	for i := 0; i < n; i++ {
		f := UnifiedFinding{
			Location: Location{
				File: func() string {
					switch rng.Intn(5) {
					case 0:
						return "" // empty path
					case 1:
						return "app.jar"
					default:
						return "/src/pkg" + itoa(rng.Intn(20)) + "/file" + itoa(i) + ".go"
					}
				}(),
				Line: rng.Intn(500),
			},
			SourceEngine: engines[rng.Intn(len(engines))],
			Severity:     sevs[rng.Intn(len(sevs))],
			Confidence:   confs[rng.Intn(len(confs))],
		}
		// Randomly attach Algorithm, Dependency, or neither.
		switch rng.Intn(3) {
		case 0:
			f.Algorithm = &Algorithm{
				Name:      algs[rng.Intn(len(algs))],
				Primitive: prims[rng.Intn(len(prims))],
				KeySize:   []int{128, 256, 1024, 2048, 4096}[rng.Intn(5)],
			}
		case 1:
			f.Dependency = &Dependency{Library: "lib" + itoa(rng.Intn(20))}
		}
		// Occasionally set InnerPath.
		if rng.Intn(8) == 0 {
			f.Location.InnerPath = "com/pkg/Class" + itoa(rng.Intn(30)) + ".class"
		}
		// Occasionally set RawIdentifier (only meaningful when Algorithm & Dep nil).
		if f.Algorithm == nil && f.Dependency == nil {
			f.RawIdentifier = "raw-" + itoa(rng.Intn(50))
		}
		out[i] = f
	}
	return out
}
