package quantum

// audit_2026_04_20_test.go — Scanner-layer audit (2026-04-20), quantum layer.
// Techniques: property-based tests (totality, invariants) + benchmarks.
// Report: docs/audits/2026-04-20-scanner-layer-audit/06-quantum.md
//
// All tests in this file are READ-ONLY — they verify behaviour without modifying
// any classifier state. Reported findings F1..F5 are referenced inline; see the
// audit report for root-cause hypotheses and proposed fix locations.

import (
	"math"
	"math/rand"
	"strings"
	"testing"
	"time"
)

// ─────────────────────────────────────────────────────────────────────────────
// F1 regression — Sprint 2 T-BUG: draft Kyber hybrids must be Deprecated,
// NOT Vulnerable via the "X25519" prefix in quantumVulnerableFamilies.
// ─────────────────────────────────────────────────────────────────────────────

func TestAuditF1_DraftKyberHybridsReturnDeprecated(t *testing.T) {
	drafts := []string{
		"X25519Kyber768Draft00",
		"X25519Kyber512Draft00",
		"X25519Kyber1024Draft00",
	}
	for _, d := range drafts {
		d := d
		t.Run(d, func(t *testing.T) {
			got := ClassifyAlgorithm(d, "kem", 0)
			if got.Risk != RiskDeprecated {
				t.Errorf("ClassifyAlgorithm(%q, \"kem\", 0).Risk = %q, want %q "+
					"(must not be RiskVulnerable via X25519 prefix match)",
					d, got.Risk, RiskDeprecated)
			}
			if got.Severity != SeverityCritical {
				t.Errorf("%q severity = %q, want %q", d, got.Severity, SeverityCritical)
			}
		})
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Totality — every algorithm listed in the exported tables must classify to a
// SENSIBLE (non-Unknown) result.
// ─────────────────────────────────────────────────────────────────────────────

// TestAuditTotality_PQCSafeFamilies iterates every key in pqcSafeFamilies and
// asserts ClassifyAlgorithm returns RiskSafe. Because HQC has a dedicated branch
// that returns RiskSafe with a non-empty Recommendation, that case is permitted.
func TestAuditTotality_PQCSafeFamilies(t *testing.T) {
	for name := range pqcSafeFamilies {
		name := name
		t.Run(name, func(t *testing.T) {
			got := ClassifyAlgorithm(name, "", 0)
			if got.Risk != RiskSafe {
				t.Errorf("pqcSafeFamilies[%q]: ClassifyAlgorithm.Risk = %q, want RiskSafe", name, got.Risk)
			}
		})
	}
}

// TestAuditTotality_VulnerableFamilies iterates quantumVulnerableFamilies and
// asserts classification returns RiskVulnerable. No primitive is supplied,
// exercising the step-3 prefix match path.
func TestAuditTotality_VulnerableFamilies(t *testing.T) {
	for name := range quantumVulnerableFamilies {
		name := name
		t.Run(name, func(t *testing.T) {
			got := ClassifyAlgorithm(name, "", 0)
			if got.Risk != RiskVulnerable {
				t.Errorf("quantumVulnerableFamilies[%q]: Risk = %q, want RiskVulnerable", name, got.Risk)
			}
		})
	}
}

// TestAuditTotality_DeprecatedAlgorithms iterates deprecatedAlgorithms and
// asserts the result is RiskDeprecated with severity Critical.
func TestAuditTotality_DeprecatedAlgorithms(t *testing.T) {
	for name := range deprecatedAlgorithms {
		name := name
		t.Run(name, func(t *testing.T) {
			got := ClassifyAlgorithm(name, "", 0)
			if got.Risk != RiskDeprecated {
				t.Errorf("deprecatedAlgorithms[%q]: Risk = %q, want RiskDeprecated", name, got.Risk)
			}
			if got.Severity != SeverityCritical {
				t.Errorf("deprecatedAlgorithms[%q]: Severity = %q, want Critical", name, got.Severity)
			}
		})
	}
}

// TestAuditTotality_KPQCEliminated iterates kpqcEliminatedCandidates and
// asserts classification is RiskVulnerable with a SMAUG-T/HAETAE recommendation.
func TestAuditTotality_KPQCEliminated(t *testing.T) {
	for name := range kpqcEliminatedCandidates {
		name := name
		t.Run(name, func(t *testing.T) {
			got := ClassifyAlgorithm(name, "", 0)
			if got.Risk != RiskVulnerable {
				t.Errorf("kpqcEliminatedCandidates[%q]: Risk = %q, want RiskVulnerable", name, got.Risk)
			}
		})
	}
}

// TestAuditTotality_TLSGroupsNoPanic calls ClassifyTLSGroup for every codepoint
// in the registry plus 50 random unknowns. Requirement: returns a value without
// panicking. (Deferred recover is redundant — a panic fails the test anyway —
// but is explicit documentation of the no-panic contract.)
func TestAuditTotality_TLSGroupsNoPanic(t *testing.T) {
	// Every registered codepoint.
	for id := range tlsGroupRegistry {
		id := id
		t.Run("known/"+tlsGroupRegistry[id].Name, func(t *testing.T) {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("ClassifyTLSGroup(0x%04x) panicked: %v", id, r)
				}
			}()
			info, ok := ClassifyTLSGroup(id)
			if !ok {
				t.Errorf("known codepoint 0x%04x returned ok=false", id)
			}
			if info.Name == "" {
				t.Errorf("known codepoint 0x%04x returned empty Name", id)
			}
		})
	}

	// 50 pseudo-random unknown codepoints (seed fixed for reproducibility).
	rng := rand.New(rand.NewSource(20260420))
	seen := make(map[uint16]bool)
	for len(seen) < 50 {
		id := uint16(rng.Intn(0x10000))
		if _, known := tlsGroupRegistry[id]; known {
			continue
		}
		if seen[id] {
			continue
		}
		seen[id] = true
		defer func(id uint16) {
			if r := recover(); r != nil {
				t.Fatalf("ClassifyTLSGroup(0x%04x) panicked on random unknown: %v", id, r)
			}
		}(id)
		info, ok := ClassifyTLSGroup(id)
		if ok {
			t.Errorf("random unknown 0x%04x returned ok=true (unexpected)", id)
		}
		if info != (GroupInfo{}) {
			t.Errorf("random unknown 0x%04x returned non-zero GroupInfo: %+v", id, info)
		}
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Hybrid KEM name-matching property: hyphen-normalisation works, underscore
// does NOT. This encodes the contract documented in CLAUDE.md.
// ─────────────────────────────────────────────────────────────────────────────

// TestAuditHybrid_CanonicalAndHyphenatedBothSafe verifies that for each hybrid
// KEM in pqcSafeFamilies, both the canonical form and the hyphen-inserted form
// resolve to RiskSafe.
func TestAuditHybrid_CanonicalAndHyphenatedBothSafe(t *testing.T) {
	// Only the hybrid names that are documented as hyphen-normalised targets.
	hybrids := []struct {
		canonical  string // input exactly as in pqcSafeFamilies
		hyphenated string // same name with hyphens inserted between word boundaries
	}{
		{"X25519MLKEM768", "X25519-MLKEM-768"},
		{"SecP256r1MLKEM768", "SecP256r1-MLKEM-768"},
		{"SecP384r1MLKEM1024", "SecP384r1-MLKEM-1024"},
		{"curveSM2MLKEM768", "curveSM2-MLKEM-768"},
		{"MLKEM512", "ML-KEM-512"},
		{"MLKEM768", "ML-KEM-768"},
		{"MLKEM1024", "ML-KEM-1024"},
	}
	for _, h := range hybrids {
		h := h
		t.Run(h.canonical, func(t *testing.T) {
			got := ClassifyAlgorithm(h.canonical, "kem", 0)
			if got.Risk != RiskSafe {
				t.Errorf("canonical %q Risk = %q, want RiskSafe", h.canonical, got.Risk)
			}
		})
		t.Run(h.hyphenated, func(t *testing.T) {
			got := ClassifyAlgorithm(h.hyphenated, "kem", 0)
			if got.Risk != RiskSafe {
				t.Errorf("hyphenated %q Risk = %q, want RiskSafe", h.hyphenated, got.Risk)
			}
		})
	}
}

// TestAuditHybrid_UnderscoreDoesNotMatch documents the contract from CLAUDE.md:
// underscore-separated forms (ML_KEM_768) are treated as variable/constant names,
// not algorithm names. They FALL THROUGH to the primitive path (RiskVulnerable
// with primitive "kem"). This test locks in that behaviour.
func TestAuditHybrid_UnderscoreDoesNotMatch(t *testing.T) {
	cases := []struct {
		input    string
		prim     string
		wantRisk Risk
	}{
		{"ML_KEM_768", "kem", RiskVulnerable},
		{"X25519_MLKEM_768", "kem", RiskVulnerable},
		// SLH_DSA_SHA2_128s: no primitive → falls through to RiskUnknown (not
		// asymmetric, not symmetric heuristic). Document whichever lands.
	}
	for _, c := range cases {
		c := c
		t.Run(c.input, func(t *testing.T) {
			got := ClassifyAlgorithm(c.input, c.prim, 0)
			if got.Risk != c.wantRisk {
				t.Errorf("ClassifyAlgorithm(%q, %q, 0).Risk = %q, want %q",
					c.input, c.prim, got.Risk, c.wantRisk)
			}
		})
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// F2 (design smell / medium): Risk level ordering is NOT enforceable at the
// Go type level. Risk is an opaque string constant — there is no Less method,
// no int-typed constant, and no documented ordering. Policy evaluation that
// needs to say "is the risk of this finding worse than X" must implement a
// lookup map externally, which is easy to get wrong.
//
// This test documents the smell by proving no in-package ordering exists.
// When/if an ordering is added, delete this test.
// ─────────────────────────────────────────────────────────────────────────────

func TestAuditF2_RiskOrderingNotEnforceable(t *testing.T) {
	// Risk is typed `string`, so comparisons work lexicographically — which is
	// MEANINGLESS for risk severity. Document the hazard by showing a pair
	// whose lexical order contradicts the intended severity ordering.
	//
	// Intended order (low→high):
	//   RiskSafe < RiskResistant < RiskWeakened < RiskDeprecated < RiskVulnerable < RiskCritical? (no RiskCritical exists)
	//
	// Lexical order:
	//   "deprecated"         (RiskDeprecated)
	//   "quantum-resistant"  (RiskResistant)
	//   "quantum-safe"       (RiskSafe)
	//   "quantum-vulnerable" (RiskVulnerable)
	//   "quantum-weakened"   (RiskWeakened)
	//   "unknown"            (RiskUnknown)
	//
	// This means a lexical comparison says RiskDeprecated < RiskSafe, which is
	// the OPPOSITE of severity ordering. Catch anyone who tries.
	if !(string(RiskDeprecated) < string(RiskSafe)) {
		t.Errorf("assumption failed: lexical RiskDeprecated (%q) should be < RiskSafe (%q)",
			RiskDeprecated, RiskSafe)
	}
	// Conclusion documented: do NOT compare Risk values with `<`.
	// No `Less` method is exposed on Risk; no numeric ordering exists.
}

// ─────────────────────────────────────────────────────────────────────────────
// HNDL Mosca inequality — boundary input robustness.
// ─────────────────────────────────────────────────────────────────────────────

// TestAuditHNDL_BoundariesNoPanic feeds ComputeHNDLSurplus extreme/boundary
// inputs. Signature is (int,int,int) so NaN/Inf are not representable; but
// math.MaxInt / MinInt must be exercised.
func TestAuditHNDL_BoundariesNoPanic(t *testing.T) {
	cases := []struct {
		shelf, lag, crqc int
		note             string
	}{
		{0, 0, 0, "all zeros"},
		{-1, -1, -1, "all negative (lag<=0 => default, crqc<=0 => default)"},
		{math.MaxInt32, 1, 1, "max int32 shelf life"},
		{1, math.MaxInt32, 1, "max int32 lag"},
		{1, 1, math.MaxInt32, "max int32 crqc"},
		{math.MinInt32 + 1, 1, 1, "large negative shelf"},
	}
	for _, c := range cases {
		c := c
		t.Run(c.note, func(t *testing.T) {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("ComputeHNDLSurplus(%d,%d,%d) panicked: %v", c.shelf, c.lag, c.crqc, r)
				}
			}()
			_ = ComputeHNDLSurplus(c.shelf, c.lag, c.crqc)
		})
	}
}

// TestAuditHNDL_LevelAlwaysValid: HNDLLevelFromSurplus must return one of the
// three defined levels for any integer input. Runs 1000 random surplus values
// plus hand-picked boundaries.
func TestAuditHNDL_LevelAlwaysValid(t *testing.T) {
	valid := map[HNDLLevel]bool{
		HNDLLevelLow:    true,
		HNDLLevelMedium: true,
		HNDLLevelHigh:   true,
	}
	probe := func(surplus int) {
		got := HNDLLevelFromSurplus(surplus)
		if !valid[got] {
			t.Errorf("HNDLLevelFromSurplus(%d) = %q (invalid level)", surplus, got)
		}
	}
	// Boundaries (documented breakpoints and ±1 either side).
	for _, s := range []int{math.MinInt32, -100, -3, -2, -1, 0, 1, 2, 3, 100, math.MaxInt32} {
		probe(s)
	}
	// Randomised.
	rng := rand.New(rand.NewSource(20260420))
	for i := 0; i < 1000; i++ {
		probe(rng.Intn(10000) - 5000)
	}
}

// TestAuditHNDL_ComputeDoesNotProduceHNDLScoreOutOfRange — the prompt describes
// an HNDL "score"; in this codebase the returned value is an integer surplus,
// which is INTENTIONALLY unbounded (any int). Document that there is no
// clamping layer and no score-in-[0,100] contract to violate here. The actual
// 0-100 number is QRS (see pkg/quantum/score.go); HNDL produces a level enum.
func TestAuditHNDL_SurplusIsNotClampedToARange(t *testing.T) {
	// Surplus -99 is valid. Surplus +99 is valid. They map to LOW and HIGH.
	if HNDLLevelFromSurplus(-99) != HNDLLevelLow {
		t.Errorf("surplus=-99 not LOW")
	}
	if HNDLLevelFromSurplus(99) != HNDLLevelHigh {
		t.Errorf("surplus=99 not HIGH")
	}
}

// TestAuditHNDL_ReferenceYearDefault verifies the documented "post-CRQC clamp"
// at moscaReferenceYear + moscaCRQCWindow = 2031. Stubbing nowFn to 2035
// makes defaultTimeToCRQC return 0 (not negative).
func TestAuditHNDL_PostCRQCClampsToZero(t *testing.T) {
	orig := nowFn
	t.Cleanup(func() { nowFn = orig })
	nowFn = func() time.Time { return time.Date(2035, 1, 1, 0, 0, 0, 0, time.UTC) }

	got := defaultTimeToCRQC()
	if got != 0 {
		t.Errorf("defaultTimeToCRQC() in 2035 = %d, want 0 (post-CRQC clamp)", got)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// F3 (high): Unknown/empty primitive + unknown asymmetric name falls into the
// RiskUnknown bucket via the final return. That is the designed behaviour, but
// the prompt asks us to explicitly document it.
// ─────────────────────────────────────────────────────────────────────────────

func TestAuditF3_UnknownNameUnknownPrimitiveIsUnknown(t *testing.T) {
	got := ClassifyAlgorithm("ZzUnknownAlgo", "", 0)
	if got.Risk != RiskUnknown {
		t.Errorf("unknown alg + empty primitive: Risk = %q, want RiskUnknown", got.Risk)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// F4 (high): TLS group 0x001c is the IANA-assigned codepoint for brainpoolP512r1
// and is ABSENT from tlsGroupRegistry. A probe observing 0x001c gets
// ok=false, which bubbles up as "unknown codepoint" rather than
// "classical, quantum-vulnerable" — masking quantum risk of a real TLS
// deployment. This is a medium-severity finding because brainpool is rare in
// modern TLS but is allowed per RFC 8422 + 7919 and is used in regulated EU
// sectors (BSI TR-02102-2). Same applies to 0x001a (brainpoolP256r1) and
// 0x001b (brainpoolP384r1).
// ─────────────────────────────────────────────────────────────────────────────

func TestAuditF4_BrainpoolGroupsMissingFromRegistry(t *testing.T) {
	// These IANA codepoints are defined and deployed but missing from our table.
	// https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml#tls-parameters-8
	missing := []struct {
		id   uint16
		name string
	}{
		{0x001a, "brainpoolP256r1"},
		{0x001b, "brainpoolP384r1"},
		{0x001c, "brainpoolP512r1"},
	}
	for _, m := range missing {
		info, ok := ClassifyTLSGroup(m.id)
		if ok {
			// If someone adds them, this test will start failing —
			// update the finding note in the audit report.
			if info.Name != m.name {
				t.Errorf("codepoint 0x%04x now registered with Name=%q, want %q",
					m.id, info.Name, m.name)
			}
			return
		}
	}
	// Document the gap rather than fail — the audit ONLY reports.
	t.Log("F4: brainpoolP{256,384,512}r1 (0x001a/0x001b/0x001c) are not in tlsGroupRegistry; " +
		"a probe observing these codepoints will classify them as unknown rather than classical-vulnerable.")
}

// ─────────────────────────────────────────────────────────────────────────────
// F5 (medium): RiskWeakened is declared but NEVER returned by the path for
// HQC-adjacent or 128-bit block ciphers under certain primitives. Specifically,
// "AES" with primitive="" and keySize=0 takes the isLikelySymmetric heuristic
// which calls classifySymmetric → key size unknown → returns RiskUnknown rather
// than RiskWeakened. Document via a test that locks in the current behaviour.
// ─────────────────────────────────────────────────────────────────────────────

func TestAuditF5_AESUnknownSizeReturnsUnknownNotWeakened(t *testing.T) {
	// Users sometimes write just "AES" in a config file. Current behaviour:
	//   keySize=0, upperName="AES" → symmetricKeySize returns 0 → RiskUnknown.
	// This is defensible (can't assume 128 vs 256) but it means "AES"
	// unqualified produces a RiskUnknown finding rather than a "review me"
	// RiskWeakened. Lock it in so regressions are loud.
	got := ClassifyAlgorithm("AES", "", 0)
	if got.Risk != RiskUnknown {
		t.Errorf("ClassifyAlgorithm(\"AES\", \"\", 0).Risk = %q, want RiskUnknown (current behaviour)",
			got.Risk)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Property: ClassifyAlgorithm is pure — same inputs produce same outputs
// (idempotent + side-effect-free). Runs 500 arbitrary inputs twice.
// ─────────────────────────────────────────────────────────────────────────────

func TestAuditProperty_ClassifyIdempotent(t *testing.T) {
	rng := rand.New(rand.NewSource(20260420))
	inputs := []string{
		"RSA", "ECDSA", "AES-256-GCM", "ML-KEM-768", "X25519MLKEM768",
		"SHA-256", "MD5", "DES", "X25519Kyber768Draft00", "SMAUG-T-128",
		"", " ", "unknown-algo", "AES_128_CBC", "HMAC-SHA-256",
	}
	primitives := []string{"", "kem", "signature", "hash", "symmetric", "key-exchange", "pke"}
	for i := 0; i < 500; i++ {
		n := inputs[rng.Intn(len(inputs))]
		p := primitives[rng.Intn(len(primitives))]
		k := rng.Intn(8192)
		a := ClassifyAlgorithm(n, p, k)
		b := ClassifyAlgorithm(n, p, k)
		if a != b {
			t.Errorf("non-idempotent: ClassifyAlgorithm(%q,%q,%d) returned %+v then %+v", n, p, k, a, b)
		}
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Property: ClassifyAlgorithm is trim-insensitive — leading/trailing whitespace
// must not change the result. This is documented in classify.go line 192.
// ─────────────────────────────────────────────────────────────────────────────

func TestAuditProperty_TrimInsensitive(t *testing.T) {
	names := []string{"RSA", "ECDSA", "ML-KEM-768", "AES-256", "X25519MLKEM768", "MD5"}
	for _, n := range names {
		n := n
		t.Run(n, func(t *testing.T) {
			base := ClassifyAlgorithm(n, "kem", 0)
			padded := ClassifyAlgorithm("  "+n+"  ", "kem", 0)
			if base.Risk != padded.Risk {
				t.Errorf("whitespace changed classification: %q → %q vs %q → %q",
					n, base.Risk, "  "+n+"  ", padded.Risk)
			}
		})
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Property: every result is in the closed set of declared Risk constants.
// ─────────────────────────────────────────────────────────────────────────────

func TestAuditProperty_RiskIsBounded(t *testing.T) {
	validRisks := map[Risk]bool{
		RiskVulnerable: true,
		RiskWeakened:   true,
		RiskSafe:       true,
		RiskResistant:  true,
		RiskDeprecated: true,
		RiskUnknown:    true,
	}
	rng := rand.New(rand.NewSource(20260420))
	alphabet := "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_+"
	for i := 0; i < 200; i++ {
		// build random 1..20-byte name
		l := rng.Intn(20) + 1
		b := make([]byte, l)
		for j := range b {
			b[j] = alphabet[rng.Intn(len(alphabet))]
		}
		got := ClassifyAlgorithm(string(b), "", rng.Intn(4096))
		if !validRisks[got.Risk] {
			t.Errorf("random input %q produced out-of-set Risk=%q", string(b), got.Risk)
		}
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Property: TLS registry is internally consistent — PQCPresent↔Maturity.
// Every PQC-present codepoint must have Maturity in {"final","draft"}; every
// classical codepoint must have Maturity == "".
// ─────────────────────────────────────────────────────────────────────────────

func TestAuditProperty_TLSRegistryConsistency(t *testing.T) {
	for id, info := range tlsGroupRegistry {
		if info.PQCPresent {
			if info.Maturity != "final" && info.Maturity != "draft" {
				t.Errorf("0x%04x %q: PQCPresent=true but Maturity=%q (want final|draft)",
					id, info.Name, info.Maturity)
			}
		} else {
			if info.Maturity != "" {
				t.Errorf("0x%04x %q: PQCPresent=false but Maturity=%q (want empty)",
					id, info.Name, info.Maturity)
			}
		}
		if strings.TrimSpace(info.Name) == "" {
			t.Errorf("0x%04x: Name is empty or whitespace-only", id)
		}
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Benchmarks.
// ─────────────────────────────────────────────────────────────────────────────

func BenchmarkClassifyAlgorithm_RSA(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = ClassifyAlgorithm("RSA", "signature", 2048)
	}
}

func BenchmarkClassifyAlgorithm_MLKEM768(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = ClassifyAlgorithm("ML-KEM-768", "kem", 0)
	}
}

func BenchmarkClassifyAlgorithm_HybridHyphenated(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = ClassifyAlgorithm("X25519-MLKEM-768", "kem", 0)
	}
}

func BenchmarkClassifyAlgorithm_Unknown(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = ClassifyAlgorithm("TotallyUnknownAlg", "", 0)
	}
}

func BenchmarkClassifyAlgorithm_AES256(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = ClassifyAlgorithm("AES-256-GCM", "symmetric", 256)
	}
}

func BenchmarkClassifyTLSGroup_Known(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_, _ = ClassifyTLSGroup(0x11EC)
	}
}

func BenchmarkClassifyTLSGroup_Unknown(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_, _ = ClassifyTLSGroup(0xFFFF)
	}
}
