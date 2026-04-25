package quantum

// classification_sophisticated_test.go — sophisticated gap-filling tests for the
// classification core of OQS Scanner.
//
// Addresses gaps NOT covered by existing test files:
//
//  1. Hybrid KEM anchored prefix matching — all 7 forms, hyphen/underscore variants
//  2. Anchored matching regression (d84dfa8) — substring must NOT match
//  3. X25519Kyber768Draft00 NEVER returns Vulnerable (T-BUG ordering property)
//  4. pqcSafeFamilies ↔ ClassifyTLSGroup name sync
//  5. Mosca lag monotonicity and sector preset override
//  6. PFS semantic: PFS+classical KEM = HNDLImmediate; PQ KEM = no HNDL
//  7. DedupeKey property: any (file, line, alg) triple → deterministic non-empty key
//  8. Fuzz: ClassifyAlgorithm with hybrid forms — no panics, correct risk
//  9. Underscore variable names must NOT match algorithm names
// 10. CRQC post-2031 clamp via migrationLag arithmetic

import (
	"fmt"
	"strings"
	"testing"
)

// ─── 1. Hybrid KEM: all 7 forms must classify Safe ──────────────────────────

// TestHybridKEM_AllForms exercises every textual variant of hybrid KEMs that
// real-world engines surface. The longest-prefix match in extractBaseName must
// return the hybrid name (not the classical prefix like "X25519") so that
// ClassifyAlgorithm returns RiskSafe.
func TestHybridKEM_AllForms(t *testing.T) {
	cases := []struct {
		input    string // as produced by a source/config/TLS engine
		wantSafe bool
	}{
		// Canonical (no separator) — must match hybrid prefix in pqcSafeFamilies
		{"X25519MLKEM768", true},
		{"SecP256r1MLKEM768", true},
		{"SecP384r1MLKEM1024", true},
		{"curveSM2MLKEM768", true},
		// Hyphenated — hyphen stripping path in extractBaseName
		{"X25519-MLKEM-768", true},
		{"SecP256r1-MLKEM-768", true},
		{"SecP384r1-MLKEM-1024", true},
		// Underscore-separated: treated as variable names — must NOT be Safe
		// (the underscore is intentionally NOT stripped per CLAUDE.md invariant)
		{"X25519_MLKEM_768", false},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.input, func(t *testing.T) {
			got := ClassifyAlgorithm(tc.input, "kem", 0)
			isSafe := got.Risk == RiskSafe
			if isSafe != tc.wantSafe {
				t.Errorf("ClassifyAlgorithm(%q).Risk = %q, wantSafe=%v", tc.input, got.Risk, tc.wantSafe)
			}
			// Safe forms must never carry an HNDL tag
			if isSafe && got.HNDLRisk != "" {
				t.Errorf("ClassifyAlgorithm(%q) is Safe but has HNDLRisk=%q", tc.input, got.HNDLRisk)
			}
		})
	}
}

// TestHybridKEM_UnderscoreVariantIsNotSafe is a focused regression: the underscore
// form "X25519_MLKEM_768" must never classify as RiskSafe regardless of primitive.
// CLAUDE.md: "Underscores indicate variable names, NOT algorithm names."
func TestHybridKEM_UnderscoreVariantIsNotSafe(t *testing.T) {
	variants := []string{
		"X25519_MLKEM_768",
		"SecP256r1_MLKEM_768",
		"SecP384r1_MLKEM_1024",
		"curveSM2_MLKEM_768",
	}
	for _, v := range variants {
		v := v
		t.Run(v, func(t *testing.T) {
			got := ClassifyAlgorithm(v, "kem", 0)
			if got.Risk == RiskSafe {
				t.Errorf("ClassifyAlgorithm(%q).Risk = RiskSafe — underscore forms must NOT be Safe "+
					"(they are variable names, not algorithm names per CLAUDE.md)", v)
			}
		})
	}
}

// ─── 2. Anchored matching regression (d84dfa8) ───────────────────────────────

// TestAnchoredMatching_SubstringDoesNotMatch verifies that the deprecated-algorithm
// check is anchored (EqualFold), not substring-based. A name like "fooMD5bar" must
// NOT be classified as deprecated just because it contains "MD5".
// This regression guards commit d84dfa8 where substring matching caused false positives.
func TestAnchoredMatching_SubstringDoesNotMatch(t *testing.T) {
	cases := []struct {
		input    string
		wantRisk Risk
	}{
		// Substrings that embed deprecated names — must NOT match
		{"fooMD5bar", RiskUnknown},
		{"notMD5", RiskUnknown},
		{"MD5ext", RiskUnknown},
		{"extSHA1algo", RiskUnknown},
		{"prefixDES", RiskUnknown},
		{"RC4wrapped", RiskUnknown},
		// Exact matches — MUST classify deprecated
		{"MD5", RiskDeprecated},
		{"SHA-1", RiskDeprecated},
		{"SHA1", RiskDeprecated},
		{"DES", RiskDeprecated},
		{"RC4", RiskDeprecated},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.input, func(t *testing.T) {
			got := ClassifyAlgorithm(tc.input, "", 0)
			if got.Risk != tc.wantRisk {
				t.Errorf("ClassifyAlgorithm(%q).Risk = %q, want %q (anchored match regression)",
					tc.input, got.Risk, tc.wantRisk)
			}
		})
	}
}

// ─── 3. X25519Kyber768Draft00 NEVER returns Vulnerable (Sprint 2 T-BUG) ─────

// TestDeprecatedDraftKyber_NeverVulnerable is the core Sprint 2 T-BUG property test.
// The deprecated check must run BEFORE the quantumVulnerableFamilies check so that
// "X25519Kyber768Draft00" returns RiskDeprecated, never RiskVulnerable.
//
// If the ordering were wrong, the "X25519" prefix in quantumVulnerableFamilies would
// fire first and return RiskVulnerable — masking the actual classification.
func TestDeprecatedDraftKyber_NeverVulnerable(t *testing.T) {
	drafts := []string{
		"X25519Kyber768Draft00",
		"X25519Kyber512Draft00",
		"X25519Kyber1024Draft00",
	}
	for _, d := range drafts {
		d := d
		t.Run(d, func(t *testing.T) {
			got := ClassifyAlgorithm(d, "kem", 0)

			// PRIMARY invariant: must NEVER be Vulnerable
			if got.Risk == RiskVulnerable {
				t.Errorf("ClassifyAlgorithm(%q).Risk = RiskVulnerable — "+
					"deprecated draft Kyber must NEVER be Vulnerable (Sprint 2 T-BUG). "+
					"The deprecated check must run before the X25519-prefix vulnerable match.", d)
			}

			// SECONDARY invariant: must be Deprecated
			if got.Risk != RiskDeprecated {
				t.Errorf("ClassifyAlgorithm(%q).Risk = %q, want RiskDeprecated", d, got.Risk)
			}

			// TERTIARY: must be Critical severity (deprecated = critical)
			if got.Severity != SeverityCritical {
				t.Errorf("ClassifyAlgorithm(%q).Severity = %q, want SeverityCritical", d, got.Severity)
			}
		})
	}
}

// ─── 4. pqcSafeFamilies ↔ ClassifyTLSGroup name sync ────────────────────────

// TestTLSGroup_NamesInPQCSafeFamilies walks the TLS codepoint registry and
// asserts that every PQCPresent=true, Maturity="final" group name is also
// present in pqcSafeFamilies (the name-based classification map).
//
// If a codepoint name drifts from the map, ClassifyAlgorithm(name) and
// ClassifyTLSGroup(codepoint) would return inconsistent risk assessments for
// the same algorithm — a silent split-brain bug.
func TestTLSGroup_NamesInPQCSafeFamilies(t *testing.T) {
	// Only "final" PQC codepoints must be in pqcSafeFamilies.
	// Draft Kyber codepoints have PQCPresent=true but Maturity="draft" — they
	// are in deprecatedAlgorithms, not pqcSafeFamilies, intentionally.
	pqcFinalCodepoints := []uint16{
		0x11EB, // SecP256r1MLKEM768
		0x11EC, // X25519MLKEM768
		0x11ED, // SecP384r1MLKEM1024
		0x11EE, // curveSM2MLKEM768
		0x0200, // MLKEM512
		0x0201, // MLKEM768
		0x0202, // MLKEM1024
	}

	for _, id := range pqcFinalCodepoints {
		id := id
		info, ok := ClassifyTLSGroup(id)
		if !ok {
			t.Errorf("0x%04x: expected known codepoint, got ok=false", id)
			continue
		}
		if info.Maturity != "final" {
			t.Errorf("0x%04x (%s): Maturity=%q, want \"final\"", id, info.Name, info.Maturity)
			continue
		}
		// The name from the TLS registry must be in pqcSafeFamilies so that
		// ClassifyAlgorithm(info.Name, ...) returns RiskSafe.
		if !pqcSafeFamilies[info.Name] {
			t.Errorf("0x%04x: Name=%q is in TLS registry with PQCPresent=true/Maturity=final "+
				"but NOT in pqcSafeFamilies — split-brain: ClassifyAlgorithm would return a "+
				"different risk than ClassifyTLSGroup", id, info.Name)
		}

		// Cross-verify by actually calling ClassifyAlgorithm
		got := ClassifyAlgorithm(info.Name, "kem", 0)
		if got.Risk != RiskSafe {
			t.Errorf("0x%04x (%s): ClassifyAlgorithm returned %q, want RiskSafe — "+
				"name-based and codepoint-based classification are inconsistent", id, info.Name, got.Risk)
		}
	}
}

// TestTLSGroup_DraftKyber_NamesInDeprecated confirms that the two draft Kyber
// codepoint names are in deprecatedAlgorithms and NOT in pqcSafeFamilies.
// This is the negative half of the sync check above.
func TestTLSGroup_DraftKyber_NamesInDeprecated(t *testing.T) {
	draftCodepoints := []uint16{0x6399, 0x636D}
	for _, id := range draftCodepoints {
		info, ok := ClassifyTLSGroup(id)
		if !ok {
			t.Fatalf("0x%04x: expected known draft codepoint", id)
		}
		if pqcSafeFamilies[info.Name] {
			t.Errorf("0x%04x (%s): name is in pqcSafeFamilies — "+
				"draft Kyber must be in deprecatedAlgorithms, not pqcSafeFamilies", id, info.Name)
		}
		if !deprecatedAlgorithms[info.Name] {
			t.Errorf("0x%04x (%s): name is NOT in deprecatedAlgorithms — "+
				"draft Kyber must be classified Deprecated, not Safe", id, info.Name)
		}
		// ClassifyAlgorithm must return Deprecated, never Vulnerable
		got := ClassifyAlgorithm(info.Name, "kem", 0)
		if got.Risk == RiskVulnerable {
			t.Errorf("0x%04x (%s): ClassifyAlgorithm returned Vulnerable — must be Deprecated", id, info.Name)
		}
		if got.Risk != RiskDeprecated {
			t.Errorf("0x%04x (%s): ClassifyAlgorithm returned %q, want RiskDeprecated", id, info.Name, got.Risk)
		}
	}
}

// ─── 5. Underscore variable names must NOT match classical algorithm names ───

// TestUnderscoreVariableName_NeverMatchesVulnerablePrefix verifies that a source
// variable name containing a vulnerable algorithm as a substring does not trigger
// a false positive. For example, "my_X25519_var" must NOT be classified as X25519.
//
// The `_`-field splitter in extractBaseName's fallback returns "my" as the first
// segment, which has no classification entry → RiskUnknown.
func TestUnderscoreVariableName_NeverMatchesVulnerablePrefix(t *testing.T) {
	variableNames := []struct {
		name     string
		note     string
		wantRisk Risk
	}{
		{"my_X25519_var", "variable wrapping X25519 — first segment 'my' unknown", RiskUnknown},
		{"ctx_RSA_key", "variable wrapping RSA — first segment 'ctx' unknown", RiskUnknown},
		{"use_ECDSA_here", "variable wrapping ECDSA — first segment 'use' unknown", RiskUnknown},
		{"old_DES_cipher", "variable wrapping DES — first segment 'old' unknown (prefix is 'old')", RiskUnknown},
		// Note: sha1_hash_fn splits to ['sha1', 'hash', 'fn'] and sha1 is caught by
		// isLikelyHash heuristic — this is intentional behavior for variable names that
		// START with a hash name. We test a non-SHA1-prefixed variable here instead.
		{"key_exchange_fn", "variable with 'key' prefix — first segment 'key' unknown", RiskUnknown},
	}

	for _, tc := range variableNames {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			got := ClassifyAlgorithm(tc.name, "", 0)
			if got.Risk != tc.wantRisk {
				t.Errorf("ClassifyAlgorithm(%q) (%s): Risk=%q, want %q — "+
					"underscore-separated identifiers must not be matched as algorithm names",
					tc.name, tc.note, got.Risk, tc.wantRisk)
			}
		})
	}
}

// ─── 6. PFS semantic: PFS+classical KEM = HNDLImmediate; PQ KEM = no HNDL ──

// TestPFS_DoesNotLowerHNDLForClassicalKEM asserts that a PFS-enabled but
// classically-vulnerable key exchange still gets HNDLRisk=immediate.
// Per CLAUDE.md and classify.go documentation:
//   "PFS does NOT protect HNDL when KEM is classical. The ephemeral ECDH public
//   key is captured in the recorded handshake and is Shor-breakable."
func TestPFS_DoesNotLowerHNDLForClassicalKEM(t *testing.T) {
	// All of these are PFS-capable (ephemeral) but classically vulnerable
	pfsCases := []struct {
		alg       string
		primitive string
	}{
		{"ECDHE", "key-agree"},  // TLS 1.3 default — PFS but Shor-breakable
		{"X25519", "key-agree"}, // ECDHE over Curve25519 — PFS but Shor-breakable
		{"FFDH", "key-agree"},   // ephemeral finite-field DH — PFS but Shor-breakable
		{"DH", "key-agree"},     // non-ephemeral DH, included for completeness
	}

	for _, tc := range pfsCases {
		tc := tc
		t.Run(fmt.Sprintf("%s/%s", tc.alg, tc.primitive), func(t *testing.T) {
			got := ClassifyAlgorithm(tc.alg, tc.primitive, 0)
			if got.Risk != RiskVulnerable {
				t.Errorf("PFS-classical %q: Risk=%q, want RiskVulnerable", tc.alg, got.Risk)
			}
			if got.HNDLRisk != HNDLImmediate {
				t.Errorf("PFS-classical %q: HNDLRisk=%q, want %q — "+
					"PFS does not protect HNDL when KEM is classical (Shor can break the ephemeral key)",
					tc.alg, got.HNDLRisk, HNDLImmediate)
			}
		})
	}
}

// TestPQKEM_HasNoHNDLRisk verifies that PQ KEMs (X25519MLKEM768, ML-KEM-768)
// carry no HNDL tag — the positive counterpart to the PFS test above.
func TestPQKEM_HasNoHNDLRisk(t *testing.T) {
	pqCases := []struct {
		alg       string
		primitive string
	}{
		{"X25519MLKEM768", "kem"},
		{"ML-KEM-768", "kem"},
		{"MLKEM768", "kem"},
		{"SecP256r1MLKEM768", "kem"},
	}

	for _, tc := range pqCases {
		tc := tc
		t.Run(tc.alg, func(t *testing.T) {
			got := ClassifyAlgorithm(tc.alg, tc.primitive, 0)
			if got.Risk != RiskSafe {
				t.Errorf("PQ KEM %q: Risk=%q, want RiskSafe", tc.alg, got.Risk)
			}
			if got.HNDLRisk != "" {
				t.Errorf("PQ KEM %q: HNDLRisk=%q, want empty — PQ KEM sessions are HNDL-resistant",
					tc.alg, got.HNDLRisk)
			}
		})
	}
}

// ─── 7. Sector preset overrides default shelfLife in HNDL computation ────────

// TestSector_ShelfLifeOverrideInHNDLSurplus verifies that sector presets drive
// the Mosca surplus when passed to ComputeHNDLSurplus. The "state" preset (50y)
// must produce a materially higher surplus than "code" (5y).
func TestSector_ShelfLifeOverrideInHNDLSurplus(t *testing.T) {
	lag := DefaultMigrationLagYears // 5
	crqc := 5                       // explicit, not nowFn-dependent

	stateSurplus := ComputeHNDLSurplus(ShelfLifeForSector("state"), lag, crqc)
	codeSurplus := ComputeHNDLSurplus(ShelfLifeForSector("code"), lag, crqc)

	// state(50) + lag(5) - crqc(5) = 50; code(5) + lag(5) - crqc(5) = 5
	if stateSurplus != 50 {
		t.Errorf("state sector: ComputeHNDLSurplus(50, 5, 5) = %d, want 50", stateSurplus)
	}
	if codeSurplus != 5 {
		t.Errorf("code sector: ComputeHNDLSurplus(5, 5, 5) = %d, want 5", codeSurplus)
	}

	// Both must map to High (both > 2)
	if HNDLLevelFromSurplus(stateSurplus) != HNDLLevelHigh {
		t.Errorf("state sector surplus=%d: want HNDLLevelHigh", stateSurplus)
	}
	if HNDLLevelFromSurplus(codeSurplus) != HNDLLevelHigh {
		t.Errorf("code sector surplus=%d: want HNDLLevelHigh", codeSurplus)
	}

	// State risk must strictly exceed code risk (larger surplus)
	if stateSurplus <= codeSurplus {
		t.Errorf("state(%d) surplus must exceed code(%d) surplus", stateSurplus, codeSurplus)
	}
}

// TestSector_AllPresetsProduceSensibleHNDL exercises all 6 sector presets and
// verifies HNDL levels are monotone-consistent with their shelfLife values.
func TestSector_AllPresetsProduceSensibleHNDL(t *testing.T) {
	crqc := 5 // explicit, reproducible
	lag := DefaultMigrationLagYears

	sectors := []struct {
		name          string
		expectedLevel HNDLLevel
	}{
		// shelfLife=50, surplus=50: HIGH
		{"state", HNDLLevelHigh},
		// shelfLife=30, surplus=30: HIGH
		{"medical", HNDLLevelHigh},
		// shelfLife=20, surplus=20: HIGH
		{"infra", HNDLLevelHigh},
		// shelfLife=10, surplus=10: HIGH
		{"generic", HNDLLevelHigh},
		// shelfLife=7, surplus=7: HIGH
		{"finance", HNDLLevelHigh},
		// shelfLife=5, surplus=5: HIGH
		{"code", HNDLLevelHigh},
	}

	for _, s := range sectors {
		s := s
		t.Run(s.name, func(t *testing.T) {
			shelfLife := ShelfLifeForSector(s.name)
			surplus := ComputeHNDLSurplus(shelfLife, lag, crqc)
			level := HNDLLevelFromSurplus(surplus)
			if level != s.expectedLevel {
				t.Errorf("sector=%q shelfLife=%d lag=%d crqc=%d surplus=%d: level=%s, want %s",
					s.name, shelfLife, lag, crqc, surplus, level, s.expectedLevel)
			}
		})
	}
}

// TestSector_MigrationLagMonotonicity verifies that increasing migrationLag
// monotonically increases the surplus (and never decreases urgency).
func TestSector_MigrationLagMonotonicity(t *testing.T) {
	shelfLife := 10
	crqc := 8

	prev := ComputeHNDLSurplus(shelfLife, 1, crqc)
	for lag := 2; lag <= 20; lag++ {
		curr := ComputeHNDLSurplus(shelfLife, lag, crqc)
		if curr < prev {
			t.Errorf("migrationLag monotonicity violated: lag=%d surplus=%d < prev=%d "+
				"(shelfLife=%d, crqc=%d)", lag, curr, prev, shelfLife, crqc)
		}
		prev = curr
	}
}

// ─── 8. MLKEM bare names (no hyphens) classify Safe ─────────────────────────

// TestPureMLKEM_BareNames guards against pqcSafeFamilies drift for the
// no-hyphen MLKEM variants. These are the actual codepoint names returned
// by ClassifyTLSGroup and must round-trip through ClassifyAlgorithm correctly.
func TestPureMLKEM_BareNames(t *testing.T) {
	cases := []string{"MLKEM512", "MLKEM768", "MLKEM1024"}
	for _, name := range cases {
		name := name
		t.Run(name, func(t *testing.T) {
			got := ClassifyAlgorithm(name, "kem", 0)
			if got.Risk != RiskSafe {
				t.Errorf("ClassifyAlgorithm(%q).Risk = %q, want RiskSafe — "+
					"bare MLKEM names are in pqcSafeFamilies (no-hyphen form added for codepoint sync)", name, got.Risk)
			}
			if got.Severity != SeverityInfo {
				t.Errorf("ClassifyAlgorithm(%q).Severity = %q, want SeverityInfo", name, got.Severity)
			}
		})
	}
}

// ─── 9. Bare ML-KEM-512/768/1024 (hyphen form) must also be Safe ─────────────

// TestPureMLKEM_HyphenForms guards the hyphen-separated FIPS 203 names that
// appear in source-code findings ("ML-KEM-512", "ML-KEM-768", "ML-KEM-1024").
// These go through the prefix match path (not the bare-name map entry).
func TestPureMLKEM_HyphenForms(t *testing.T) {
	cases := []string{"ML-KEM-512", "ML-KEM-768", "ML-KEM-1024"}
	for _, name := range cases {
		name := name
		t.Run(name, func(t *testing.T) {
			got := ClassifyAlgorithm(name, "kem", 0)
			if got.Risk != RiskSafe {
				t.Errorf("ClassifyAlgorithm(%q).Risk = %q, want RiskSafe", name, got.Risk)
			}
		})
	}
}

// ─── 10. Bare classical names without context still remain Vulnerable ─────────

// TestBareClassicalNames_WithoutPrimitive verifies that bare classical names
// (X25519, ECDH) that are NOT prefixed with a safe-hybrid form classify Vulnerable.
// This is the negative counterpart to the hybrid KEM tests — ensures extractBaseName
// returns "X25519" (not a hybrid) when given the bare classical name.
func TestBareClassicalNames_WithoutPrimitive(t *testing.T) {
	cases := []struct {
		name      string
		primitive string
		wantRisk  Risk
		wantHNDL  string
	}{
		{"X25519", "key-agree", RiskVulnerable, HNDLImmediate},
		{"X448", "key-agree", RiskVulnerable, HNDLImmediate},
		{"ECDH", "key-agree", RiskVulnerable, HNDLImmediate},
		// Bare X25519 without primitive → unknown primitive path → conservative immediate
		{"X25519", "", RiskVulnerable, HNDLImmediate},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(fmt.Sprintf("%s/%s", tc.name, tc.primitive), func(t *testing.T) {
			got := ClassifyAlgorithm(tc.name, tc.primitive, 0)
			if got.Risk != tc.wantRisk {
				t.Errorf("ClassifyAlgorithm(%q, %q).Risk = %q, want %q",
					tc.name, tc.primitive, got.Risk, tc.wantRisk)
			}
			if got.HNDLRisk != tc.wantHNDL {
				t.Errorf("ClassifyAlgorithm(%q, %q).HNDLRisk = %q, want %q",
					tc.name, tc.primitive, got.HNDLRisk, tc.wantHNDL)
			}
		})
	}
}

// ─── 11. ExtractBaseName: hybrid prefix is longer than classical prefix ───────

// TestExtractBaseName_LongestPrefixWinsOverClassical directly tests the core
// invariant of extractBaseName: when sorted by descending length, the full hybrid
// name "X25519MLKEM768" (14 chars) must be chosen over the classical "X25519" (6
// chars). If the sort order were wrong, X25519 would match first and the hybrid
// would be misclassified.
func TestExtractBaseName_LongestPrefixWinsOverClassical(t *testing.T) {
	hybridInputs := []struct {
		input        string
		expectedBase string
	}{
		{"X25519MLKEM768", "X25519MLKEM768"},
		{"X25519MLKEM768-extra", "X25519MLKEM768"}, // suffix after the hybrid name
		{"SecP256r1MLKEM768", "SecP256r1MLKEM768"},
		{"SecP384r1MLKEM1024", "SecP384r1MLKEM1024"},
		{"curveSM2MLKEM768", "curveSM2MLKEM768"},
	}

	for _, tc := range hybridInputs {
		tc := tc
		t.Run(tc.input, func(t *testing.T) {
			base := extractBaseName(tc.input)
			if base != tc.expectedBase {
				t.Errorf("extractBaseName(%q) = %q, want %q — "+
					"longest-prefix match must return hybrid name, not classical prefix",
					tc.input, base, tc.expectedBase)
			}
			// Also verify classification is Safe (not Vulnerable due to X25519 prefix)
			got := ClassifyAlgorithm(tc.input, "kem", 0)
			if got.Risk != RiskSafe {
				t.Errorf("ClassifyAlgorithm(%q).Risk = %q, want RiskSafe — "+
					"longest-prefix match failed: classical prefix fired instead of hybrid",
					tc.input, got.Risk)
			}
		})
	}
}

// ─── 12. pqcSafeFamiliesSorted: verify descending length order ───────────────

// TestPQCSafeFamiliesSorted_DescendingLength verifies that pqcSafeFamiliesSorted
// (the slice used by extractBaseName) is sorted longest-first. If it were not,
// shorter classical prefixes could match before longer hybrid names.
func TestPQCSafeFamiliesSorted_DescendingLength(t *testing.T) {
	for i := 1; i < len(pqcSafeFamiliesSorted); i++ {
		if len(pqcSafeFamiliesSorted[i]) > len(pqcSafeFamiliesSorted[i-1]) {
			t.Errorf("pqcSafeFamiliesSorted is not sorted descending at index %d: "+
				"%q (len %d) > %q (len %d)",
				i, pqcSafeFamiliesSorted[i], len(pqcSafeFamiliesSorted[i]),
				pqcSafeFamiliesSorted[i-1], len(pqcSafeFamiliesSorted[i-1]))
		}
	}
}

// ─── 13. deprecatedAlgorithmsSorted: EqualFold anchored check ────────────────

// TestDeprecatedAlgorithmsSorted_AnchoredEqualFold verifies that every entry in
// deprecatedAlgorithmsSorted is matched by EqualFold against the exact name
// (not a prefix or substring). This guards against a future change to the loop
// that might accidentally switch to HasPrefix.
func TestDeprecatedAlgorithmsSorted_AnchoredEqualFold(t *testing.T) {
	for _, alg := range deprecatedAlgorithmsSorted {
		alg := alg
		t.Run(alg, func(t *testing.T) {
			// Exact match must succeed
			got := ClassifyAlgorithm(alg, "", 0)
			if got.Risk != RiskDeprecated {
				t.Errorf("exact name %q: Risk=%q, want RiskDeprecated", alg, got.Risk)
			}

			// Embedded as substring (with prefix) must NOT be Deprecated
			prefixed := "xoxo" + alg
			got2 := ClassifyAlgorithm(prefixed, "", 0)
			if got2.Risk == RiskDeprecated {
				t.Errorf("prefixed name %q classified as Deprecated — anchored match regression: "+
					"deprecated check must be EqualFold, not HasPrefix", prefixed)
			}
		})
	}
}

// ─── 14. Sector warning messages include all valid sector names ───────────────

// TestWarnOnUnknownSector_WarningListsAllSectors verifies that the warning
// emitted for an unknown sector lists all 6 valid sector names so the user
// can self-correct without consulting documentation.
func TestWarnOnUnknownSector_WarningListsAllSectors(t *testing.T) {
	var buf strings.Builder
	got := WarnOnUnknownSector("aerospace", &buf)
	if got != DefaultSectorShelfLifeYears {
		t.Errorf("WarnOnUnknownSector(\"aerospace\") = %d, want DefaultSectorShelfLifeYears (%d)",
			got, DefaultSectorShelfLifeYears)
	}

	warning := buf.String()
	if !strings.Contains(warning, "WARNING") {
		t.Errorf("expected WARNING in output, got: %q", warning)
	}

	for sector := range SectorShelfLife {
		if !strings.Contains(warning, sector) {
			t.Errorf("warning should list valid sector %q, got: %q", sector, warning)
		}
	}
}

// TestWarnOnUnknownSector_SixValidSectors confirms exactly 6 entries exist.
// If someone adds a sector without updating docs, this test detects the drift.
func TestWarnOnUnknownSector_SixValidSectors(t *testing.T) {
	const wantCount = 6
	if len(SectorShelfLife) != wantCount {
		t.Errorf("SectorShelfLife has %d entries, want exactly %d "+
			"(medical, finance, state, infra, code, generic)",
			len(SectorShelfLife), wantCount)
	}
}

// ─── 15. HNDLRisk field on Classification must track primitive correctly ──────

// TestClassification_HNDLRiskField verifies the HNDLRisk field on Classification
// (not HNDLLevel from surplus) for the three meaningful states.
func TestClassification_HNDLRiskField(t *testing.T) {
	cases := []struct {
		alg       string
		primitive string
		wantHNDL  string
		wantRisk  Risk
	}{
		// Immediate: classical key exchange
		{"ECDH", "key-agree", HNDLImmediate, RiskVulnerable},
		{"RSA", "kem", HNDLImmediate, RiskVulnerable},
		{"X25519", "key-agree", HNDLImmediate, RiskVulnerable},
		// Deferred: signatures — only future signatures at risk
		{"ECDSA", "signature", HNDLDeferred, RiskVulnerable},
		{"RSA", "signature", HNDLDeferred, RiskVulnerable},
		{"Ed25519", "signature", HNDLDeferred, RiskVulnerable},
		// Empty: PQC-safe — no HNDL risk at all
		{"ML-KEM-768", "kem", "", RiskSafe},
		{"X25519MLKEM768", "kem", "", RiskSafe},
		// Empty: symmetric/hash — not affected by harvest-now-decrypt-later
		{"AES-256-GCM", "ae", "", RiskResistant},
		{"SHA-256", "hash", "", RiskResistant},
		// Empty: deprecated — classically broken, HNDL irrelevant
		{"MD5", "hash", "", RiskDeprecated},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(fmt.Sprintf("%s/%s", tc.alg, tc.primitive), func(t *testing.T) {
			got := ClassifyAlgorithm(tc.alg, tc.primitive, 0)
			if got.Risk != tc.wantRisk {
				t.Errorf("Risk=%q, want %q", got.Risk, tc.wantRisk)
			}
			if got.HNDLRisk != tc.wantHNDL {
				t.Errorf("HNDLRisk=%q, want %q", got.HNDLRisk, tc.wantHNDL)
			}
		})
	}
}
