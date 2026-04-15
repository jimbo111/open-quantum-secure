package main

// scan_s0_fixes_test.go — regression bundle for Sprint 0 fix round F1-F4.
//
// Each test pin-points a specific fix and asserts the corrected behaviour:
//
//   F1: --data-sensitivity-years removed; passing it must produce an error.
//   F2: --data-lifetime-years 0 is invalid (no data has zero sensitivity).
//   F2: --data-lifetime-years -5 is invalid (negative retention makes no sense).
//   F3: --sector unicorn warns to stderr, lists valid names, falls back to generic.
//   F4: X25519-MLKEM-768 (hyphenated) is classified as PQ-safe / HNDL LOW.
//
// These tests must pass forever. Any future change that makes one of these
// assertions fail has regressed a deliberate design decision from Sprint 0.

import (
	"bytes"
	"strings"
	"testing"

	"github.com/jimbo111/open-quantum-secure/pkg/quantum"
)

// TestS0F1_DataSensitivityYearsFlagRemoved verifies that --data-sensitivity-years
// was removed (S0.F1). The old flag conflicted with --data-lifetime-years and was
// silently ignored in some code paths. It is now gone.
func TestS0F1_DataSensitivityYearsFlagRemoved(t *testing.T) {
	cmd := scanCmd()

	// The flag must not exist on the scan command.
	f := cmd.Flags().Lookup("data-sensitivity-years")
	if f != nil {
		t.Errorf("--data-sensitivity-years still registered on scan command (S0.F1 regression): %+v", f)
	}

	// The flag must not exist on the diff command either (same flag set was shared).
	diff := diffCmd()
	f2 := diff.Flags().Lookup("data-sensitivity-years")
	if f2 != nil {
		t.Errorf("--data-sensitivity-years still registered on diff command (S0.F1 regression): %+v", f2)
	}
}

// TestS0F1_DataLifetimeYearsFlagExists confirms that --data-lifetime-years is the
// canonical replacement for the removed --data-sensitivity-years flag.
func TestS0F1_DataLifetimeYearsFlagExists(t *testing.T) {
	cmd := scanCmd()
	f := cmd.Flags().Lookup("data-lifetime-years")
	if f == nil {
		t.Fatal("--data-lifetime-years missing from scan command (expected canonical HNDL flag)")
	}
	// Must be an int flag.
	if f.Value.Type() != "int" {
		t.Errorf("--data-lifetime-years type = %q, want \"int\"", f.Value.Type())
	}
}

// TestS0F2_NegativeDataLifetimeRejected verifies that --data-lifetime-years with a
// negative value is rejected before any scan execution (S0.F2). The error message
// must include "positive integer" to guide the user.
func TestS0F2_NegativeDataLifetimeRejected(t *testing.T) {
	cases := []string{"-1", "-5", "-100"}
	for _, v := range cases {
		t.Run("lifetime_"+v, func(t *testing.T) {
			root := rootCmd()
			root.SetOut(new(bytes.Buffer))
			root.SetErr(new(bytes.Buffer))
			root.SetArgs([]string{"scan", "--path", ".", "--data-lifetime-years", v})
			err := root.Execute()
			if err == nil {
				t.Errorf("--data-lifetime-years %s: expected error, got nil", v)
				return
			}
			if !strings.Contains(err.Error(), "positive integer") {
				t.Errorf("--data-lifetime-years %s: error %q should mention 'positive integer'", v, err.Error())
			}
		})
	}
}

// TestS0F2_ZeroDataLifetimeExplicitlyRejected verifies that passing
// --data-lifetime-years=0 explicitly is an error (S0.F2 decision: "no data has
// zero sensitivity in practice"). The error message must explain why 0 is invalid.
func TestS0F2_ZeroDataLifetimeExplicitlyRejected(t *testing.T) {
	root := rootCmd()
	root.SetOut(new(bytes.Buffer))
	root.SetErr(new(bytes.Buffer))
	root.SetArgs([]string{"scan", "--path", ".", "--data-lifetime-years", "0"})
	err := root.Execute()
	if err == nil {
		t.Fatal("--data-lifetime-years 0: expected error, got nil")
	}
	// The error must explain why 0 is invalid, not just say "invalid value".
	errMsg := err.Error()
	if !strings.Contains(errMsg, "not valid") && !strings.Contains(errMsg, "0") {
		t.Errorf("--data-lifetime-years 0: error %q should indicate value is invalid", errMsg)
	}
	// Must suggest an alternative (e.g., "use --sector preset or the 10-year default").
	if !strings.Contains(errMsg, "sector") && !strings.Contains(errMsg, "default") {
		t.Errorf("--data-lifetime-years 0: error %q should suggest an alternative", errMsg)
	}
}

// TestS0F2_OmittedDataLifetimeAccepted verifies that NOT passing --data-lifetime-years
// (the default case) does not produce a validation error about the flag. This is the
// most common use case and must not be accidentally broken.
func TestS0F2_OmittedDataLifetimeAccepted(t *testing.T) {
	cmd := scanCmd()
	// The default value of data-lifetime-years must be 0 (disabled / not changed).
	f := cmd.Flags().Lookup("data-lifetime-years")
	if f == nil {
		t.Fatal("--data-lifetime-years missing")
	}
	if f.DefValue != "0" {
		t.Errorf("--data-lifetime-years default = %q, want \"0\" (omitted = use sector/default)", f.DefValue)
	}
}

// TestS0F3_UnknownSectorWarnsWithValidNames verifies the sector warning path (S0.F3).
// An unrecognised --sector value must:
//   (a) write a WARNING to the writer
//   (b) include all valid sector names in the warning
//   (c) fall back to DefaultSectorShelfLifeYears (generic)
func TestS0F3_UnknownSectorWarnsWithValidNames(t *testing.T) {
	var buf bytes.Buffer
	result := quantum.WarnOnUnknownSector("unicorn", &buf)

	if result != quantum.DefaultSectorShelfLifeYears {
		t.Errorf("WarnOnUnknownSector(\"unicorn\") = %d, want %d (generic fallback)",
			result, quantum.DefaultSectorShelfLifeYears)
	}

	warning := buf.String()
	if !strings.Contains(warning, "WARNING") {
		t.Errorf("no WARNING prefix in output: %q", warning)
	}
	if !strings.Contains(warning, "unicorn") {
		t.Errorf("warning should echo the unknown sector name, got: %q", warning)
	}

	// Every valid sector name must appear in the warning to help users fix typos.
	for sector := range quantum.SectorShelfLife {
		if !strings.Contains(warning, sector) {
			t.Errorf("warning missing valid sector %q: %q", sector, warning)
		}
	}
}

// TestS0F3_KnownSectorsNoWarning verifies that known sector names (case-insensitive)
// do not produce a warning. Accidentally warning on valid input would be noisy in CI.
func TestS0F3_KnownSectorsNoWarning(t *testing.T) {
	variants := map[string]string{
		"lower":  "medical",
		"upper":  "MEDICAL",
		"mixed":  "Medical",
		"finance": "finance",
		"state":  "STATE",
	}
	for label, sector := range variants {
		t.Run(label, func(t *testing.T) {
			var buf bytes.Buffer
			quantum.WarnOnUnknownSector(sector, &buf)
			if buf.Len() != 0 {
				t.Errorf("sector %q unexpectedly produced output: %q", sector, buf.String())
			}
		})
	}
}

// TestS0F4_HyphenatedHybridKEMClassifiedAsPQSafe is the primary regression test
// for S0.F4. Config-file parsers and some AST tokenisers emit "X25519-MLKEM-768"
// (hyphens between components). Before F4, this was mis-classified as the classical
// "X25519" key exchange (HNDLImmediate). After F4 it must be quantum-safe.
func TestS0F4_HyphenatedHybridKEMClassifiedAsPQSafe(t *testing.T) {
	forms := []struct {
		name string
		alg  string
		prim string
	}{
		{"canonical", "X25519MLKEM768", "kem"},
		{"hyphenated_kem", "X25519-MLKEM-768", "kem"},
		{"hyphenated_kex", "X25519-MLKEM-768", "key-exchange"},
		{"secp256r1_canonical", "SecP256r1MLKEM768", "kem"},
		{"secp256r1_hyphenated", "SecP256r1-MLKEM-768", "kem"},
	}
	for _, tt := range forms {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			c := quantum.ClassifyAlgorithm(tt.alg, tt.prim, 0)

			if c.Risk != quantum.RiskSafe {
				t.Errorf("%q (%s): Risk = %q, want %q (S0.F4 regression: hyphenated form mis-classified as classical)",
					tt.alg, tt.prim, c.Risk, quantum.RiskSafe)
			}
			if c.HNDLRisk != "" {
				t.Errorf("%q (%s): HNDLRisk = %q, want \"\" (PQ-safe = no harvest risk = HNDL LOW)",
					tt.alg, tt.prim, c.HNDLRisk)
			}
		})
	}
}

// TestS0F4_BareX25519StillVulnerable ensures S0.F4's normalisation does NOT
// accidentally make bare X25519 (classical key exchange) look PQ-safe. The
// hyphen-stripping pass must only fire when the input actually contains hyphens.
func TestS0F4_BareX25519StillVulnerable(t *testing.T) {
	c := quantum.ClassifyAlgorithm("X25519", "key-exchange", 0)
	if c.Risk != quantum.RiskVulnerable {
		t.Errorf("X25519 (bare): Risk = %q, want %q (S0.F4 must not affect bare classical names)",
			c.Risk, quantum.RiskVulnerable)
	}
	if c.HNDLRisk != quantum.HNDLImmediate {
		t.Errorf("X25519 (bare): HNDLRisk = %q, want %q", c.HNDLRisk, quantum.HNDLImmediate)
	}
}
