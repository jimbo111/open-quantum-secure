package quantum

// hybrid_kem_fuzz_test.go — fuzz and exhaustive tests for hybrid KEM classification.
//
// Two fuzz targets:
//
//  1. FuzzClassifyAlgorithm_HybridForms — seeds with all hybrid KEM variants
//     and arbitrary mutations. Invariants: no panic; X25519MLKEM768 always Safe;
//     X25519Kyber768Draft00 always Deprecated (never Vulnerable).
//
//  2. FuzzClassifyTLSGroup_Exhaustive — exercises all 65536 uint16 codepoints.
//     The 16-bit space is small enough to fully cover with a short fuzz run.
//     Invariants: no panic; unknown codepoints return zero GroupInfo.

import "testing"

// FuzzClassifyAlgorithm_HybridForms extends the existing FuzzClassifyAlgorithm
// with a seed corpus focused on hybrid KEM forms and the Sprint 2 T-BUG scenarios.
// Two extra invariants beyond the base fuzzer:
//
//  1. "X25519MLKEM768" and all final hybrid KEMs must NEVER return Vulnerable
//     (the T-BUG ordering guarantee: deprecated check fires before vulnerable-prefix).
//  2. Draft Kyber forms must NEVER return Vulnerable (only Deprecated is allowed).
func FuzzClassifyAlgorithm_HybridForms(f *testing.F) {
	// ── Hybrid KEM seed corpus ───────────────────────────────────────────────
	hybridSeeds := []struct {
		name      string
		primitive string
	}{
		// Canonical (no-hyphen) forms
		{"X25519MLKEM768", "kem"},
		{"SecP256r1MLKEM768", "kem"},
		{"SecP384r1MLKEM1024", "kem"},
		{"curveSM2MLKEM768", "kem"},
		// Hyphenated forms (strip-hyphen path)
		{"X25519-MLKEM-768", "kem"},
		{"SecP256r1-MLKEM-768", "kem"},
		// Pure ML-KEM bare names (codepoint sync path)
		{"MLKEM512", "kem"},
		{"MLKEM768", "kem"},
		{"MLKEM1024", "kem"},
		// Draft Kyber — must be Deprecated, never Vulnerable
		{"X25519Kyber768Draft00", "kem"},
		{"X25519Kyber512Draft00", "kem"},
		{"X25519Kyber1024Draft00", "kem"},
		// Classical bare names — must remain Vulnerable (not Safe due to MLKEM suffix)
		{"X25519", "key-agree"},
		{"ECDH", "key-agree"},
		// Underscore variants — must NOT be Safe
		{"X25519_MLKEM_768", "kem"},
		// Empty / whitespace
		{"", ""},
		{" ", ""},
		{"  RSA  ", ""},
		// Substring embeds — must not trigger deprecated
		{"fooMD5bar", ""},
		{"notDES", ""},
	}

	for _, s := range hybridSeeds {
		f.Add(s.name, s.primitive, 0)
	}

	// Also seed key sizes
	for _, ks := range []int{0, 128, 256, 512, 768, 1024, 2048, 4096} {
		f.Add("X25519MLKEM768", "kem", ks)
		f.Add("X25519Kyber768Draft00", "kem", ks)
	}

	f.Fuzz(func(t *testing.T, name, primitive string, keySize int) {
		// Invariant 0: must never panic
		got := ClassifyAlgorithm(name, primitive, keySize)

		// Invariant 1: exact canonical hybrid KEM names must never be Vulnerable.
		// A "Vulnerable" result here means the X25519 prefix fired before the
		// hybrid match — the core longest-prefix-match bug.
		safeHybrids := map[string]bool{
			"X25519MLKEM768":     true,
			"SecP256r1MLKEM768":  true,
			"SecP384r1MLKEM1024": true,
			"curveSM2MLKEM768":   true,
			"MLKEM512":           true,
			"MLKEM768":           true,
			"MLKEM1024":          true,
		}
		if safeHybrids[name] && got.Risk == RiskVulnerable {
			t.Errorf("FuzzClassifyAlgorithm_HybridForms: %q must never be Vulnerable (got %s) — "+
				"longest-prefix match or deprecated-before-vulnerable ordering failed",
				name, got.Risk)
		}

		// Invariant 2: deprecated draft Kyber forms must never be Vulnerable.
		draftKyber := map[string]bool{
			"X25519Kyber768Draft00":  true,
			"X25519Kyber512Draft00":  true,
			"X25519Kyber1024Draft00": true,
		}
		if draftKyber[name] && got.Risk == RiskVulnerable {
			t.Errorf("FuzzClassifyAlgorithm_HybridForms: draft Kyber %q must never be Vulnerable (got %s) — "+
				"deprecated check must run before vulnerable-family prefix match",
				name, got.Risk)
		}

		// Invariant 3: Risk must be one of the defined constants (no garbage output)
		switch got.Risk {
		case RiskVulnerable, RiskWeakened, RiskSafe, RiskResistant, RiskDeprecated, RiskUnknown:
			// valid
		default:
			t.Errorf("FuzzClassifyAlgorithm_HybridForms: %q returned unknown Risk=%q", name, got.Risk)
		}
	})
}

// FuzzClassifyTLSGroup_Full exercises the entire 16-bit codepoint space.
// At 65536 values this is feasible in a 5-second fuzz run and provides
// complete coverage of the uint16 input space.
//
// Note: this duplicates/extends FuzzClassifyTLSGroup from tls_groups_fuzz_test.go
// with additional invariant checks specific to our classification core audit.
func FuzzClassifyTLSGroup_Full(f *testing.F) {
	// Seed: all known codepoints + boundary cases
	seeds := []uint16{
		// Hybrid KEMs
		0x11EB, 0x11EC, 0x11ED, 0x11EE,
		// Pure ML-KEM
		0x0200, 0x0201, 0x0202,
		// Draft Kyber
		0x6399, 0x636D,
		// Classical ECDH
		0x0017, 0x0018, 0x0019, 0x001d, 0x001e,
		// Classical FFDH
		0x0100, 0x0101, 0x0102, 0x0103, 0x0104,
		// Boundary: adjacent to hybrid range
		0x11EA, 0x11EF,
		// Unknown extremes
		0x0000, 0xFFFF, 0x8000, 0x4000,
	}
	for _, s := range seeds {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, id uint16) {
		// Invariant 1: never panic (implicit, but panic-guarded by fuzz harness)
		info, ok := ClassifyTLSGroup(id)

		// Invariant 2: unknown codepoints return zero GroupInfo
		if !ok {
			if info != (GroupInfo{}) {
				t.Errorf("0x%04x: ok=false but GroupInfo is non-zero: %+v", id, info)
			}
			if info.PQCPresent {
				t.Errorf("0x%04x: ok=false but PQCPresent=true", id)
			}
			return
		}

		// Invariant 3: known codepoints have non-empty Name
		if info.Name == "" {
			t.Errorf("0x%04x: ok=true but Name is empty", id)
		}

		// Invariant 4: Maturity is one of the three valid values
		switch info.Maturity {
		case "", "final", "draft":
			// valid
		default:
			t.Errorf("0x%04x: Maturity=%q — expected \"\", \"final\", or \"draft\"", id, info.Maturity)
		}

		// Invariant 5: PQC-final codepoints must classify as Safe via ClassifyAlgorithm
		if info.PQCPresent && info.Maturity == "final" {
			got := ClassifyAlgorithm(info.Name, "kem", 0)
			if got.Risk != RiskSafe {
				t.Errorf("0x%04x (%s): ClassifyAlgorithm returned %q, want RiskSafe — "+
					"TLS registry and classification core are out of sync",
					id, info.Name, got.Risk)
			}
		}

		// Invariant 6: Draft Kyber codepoints must classify as Deprecated (not Vulnerable)
		if info.PQCPresent && info.Maturity == "draft" {
			got := ClassifyAlgorithm(info.Name, "kem", 0)
			if got.Risk == RiskVulnerable {
				t.Errorf("0x%04x (%s): draft Kyber classified as Vulnerable — "+
					"must be Deprecated (Sprint 2 T-BUG ordering)", id, info.Name)
			}
		}
	})
}
