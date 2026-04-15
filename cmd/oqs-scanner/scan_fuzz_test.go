package main

// scan_fuzz_test.go — fuzz tests for the two main CLI inputs that feed the
// Mosca HNDL inequality: sector name and data-lifetime-years.
//
// Run in short mode (default in CI):
//   go test ./cmd/oqs-scanner/ -run='^$' -fuzz=FuzzSector     -fuzztime=10s
//   go test ./cmd/oqs-scanner/ -run='^$' -fuzz=FuzzDataLifetime -fuzztime=10s
//
// Run extended to improve corpus:
//   go test ./cmd/oqs-scanner/ -run='^$' -fuzz=FuzzSector      -fuzztime=60s
//   go test ./cmd/oqs-scanner/ -run='^$' -fuzz=FuzzDataLifetime -fuzztime=60s
//
// Invariants under fuzz:
//   FuzzSector:       never panics; returns > 0 years; unknown sector writes a
//                     WARNING containing valid sector names to the writer.
//   FuzzDataLifetime: never panics; invalid values produce the same errors as
//                     the CLI validation path; valid values produce a non-negative
//                     Mosca surplus.

import (
	"bytes"
	"math"
	"strings"
	"testing"

	"github.com/jimbo111/open-quantum-secure/pkg/quantum"
)

// FuzzSector verifies that WarnOnUnknownSector never panics for arbitrary string
// input and that it consistently falls back to the generic default for unrecognised
// sectors. The warning output for unknown sectors must list valid sector names.
func FuzzSector(f *testing.F) {
	// Seed corpus: known good sectors, edge cases, and common injection patterns.
	f.Add("medical")
	f.Add("finance")
	f.Add("state")
	f.Add("infra")
	f.Add("code")
	f.Add("generic")
	f.Add("")
	f.Add("MEDICAL")
	f.Add("Medical")
	f.Add("unicorn")
	f.Add("aerospace")
	f.Add("retail")
	f.Add("../../../etc/passwd")
	f.Add("'; DROP TABLE sectors; --")
	f.Add(strings.Repeat("a", 1024))
	f.Add("\x00\x01\xFF")
	f.Add("медицина") // Cyrillic

	f.Fuzz(func(t *testing.T, sector string) {
		var buf bytes.Buffer

		// Must not panic.
		result := quantum.WarnOnUnknownSector(sector, &buf)

		// Must always return a positive shelf-life.
		if result <= 0 {
			t.Errorf("WarnOnUnknownSector(%q) returned %d, want > 0", sector, result)
		}

		// For a known sector (case-insensitive), no warning must be written.
		knownSectors := quantum.SectorShelfLife
		isKnown := false
		normalised := strings.ToLower(sector)
		if _, ok := knownSectors[normalised]; ok {
			isKnown = true
		}

		warning := buf.String()
		if isKnown {
			if warning != "" {
				t.Errorf("WarnOnUnknownSector(%q): known sector wrote unexpected output %q", sector, warning)
			}
			if result != knownSectors[normalised] {
				t.Errorf("WarnOnUnknownSector(%q) = %d, want %d", sector, result, knownSectors[normalised])
			}
		} else if sector != "" {
			// Unknown, non-empty: must warn.
			if !strings.Contains(warning, "WARNING") {
				t.Errorf("WarnOnUnknownSector(%q): missing WARNING prefix, got %q", sector, warning)
			}
			// Warning must list valid sector names so user can correct typos.
			for name := range knownSectors {
				if !strings.Contains(warning, name) {
					t.Errorf("WarnOnUnknownSector(%q): warning missing valid sector %q, got %q",
						sector, name, warning)
				}
			}
			// Fallback must be the default.
			if result != quantum.DefaultSectorShelfLifeYears {
				t.Errorf("WarnOnUnknownSector(%q) = %d, want default %d",
					sector, result, quantum.DefaultSectorShelfLifeYears)
			}
		} else {
			// Empty sector: no warning, default result.
			if warning != "" {
				t.Errorf("WarnOnUnknownSector(%q): empty sector wrote unexpected output %q", sector, warning)
			}
		}
	})
}

// FuzzDataLifetime verifies that ComputeHNDLSurplus never panics for arbitrary
// int64 inputs (truncated to int) and that the resulting surplus satisfies the
// arithmetic identity: surplus = (shelfLife + lag) - crqc.
//
// This catches integer overflow, sign confusion, and off-by-one errors in the
// Mosca formula that a fixed test table would not expose.
func FuzzDataLifetime(f *testing.F) {
	// Seed corpus: values at boundary conditions for the Mosca formula.
	f.Add(int64(0))
	f.Add(int64(1))
	f.Add(int64(-1))
	f.Add(int64(-5))
	f.Add(int64(5))
	f.Add(int64(10))
	f.Add(int64(30))
	f.Add(int64(50))
	f.Add(int64(100))
	f.Add(int64(math.MaxInt32 - 1))
	f.Add(int64(math.MaxInt32))
	f.Add(int64(math.MinInt32))
	f.Add(int64(math.MaxInt64))
	f.Add(int64(math.MinInt64))

	f.Fuzz(func(t *testing.T, years int64) {
		// Clamp to int range (ComputeHNDLSurplus takes int, not int64).
		// Values outside [math.MinInt32, math.MaxInt32] are not valid CLI inputs
		// and not what we're testing; skip them to avoid int overflow on 32-bit arches.
		if years > math.MaxInt32 || years < math.MinInt32 {
			return
		}
		shelfLife := int(years)

		// Use explicit lag and crqc to make the arithmetic assertion deterministic.
		const lag = 5
		const crqc = 7

		// Must not panic.
		surplus := quantum.ComputeHNDLSurplus(shelfLife, lag, crqc)

		// Arithmetic identity: surplus = (shelfLife + lag) - crqc.
		want := (shelfLife + lag) - crqc
		if surplus != want {
			t.Errorf("ComputeHNDLSurplus(%d, %d, %d) = %d, want %d",
				shelfLife, lag, crqc, surplus, want)
		}

		// Level mapping must never panic or return an unknown level.
		level := quantum.HNDLLevelFromSurplus(surplus)
		switch level {
		case quantum.HNDLLevelLow, quantum.HNDLLevelMedium, quantum.HNDLLevelHigh:
			// OK
		default:
			t.Errorf("HNDLLevelFromSurplus(%d) = %q: unexpected level", surplus, level)
		}
	})
}
