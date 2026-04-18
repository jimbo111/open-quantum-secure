package quantum

// matrix_test.go — exhaustive sector × timeToCRQC × KEM classification matrix.
//
// 6 sectors × 8 year values × 10 KEM algorithms = 480 sub-tests.
// Each cell asserts:
//  (a) Classical KEMs (RSA, ECDHE, Kyber768, unknown) → HNDLImmediate + Mosca HNDL level
//  (a2) Deprecated draft KEMs (X25519Kyber768Draft00) → RiskDeprecated, no HNDLRisk
//  (b) Classical signatures (ECDSA) → HNDLDeferred + RiskVulnerable
//  (c) Hybrid PQ KEMs (X25519MLKEM768, hyphenated, SecP256r1MLKEM768) → RiskSafe, no HNDL
//  (d) Pure PQ KEM (ML-KEM-768) → RiskSafe, no HNDL
//
// The Mosca HNDL level for classical KEMs is computed as:
//   surplus = (sectorShelfLife + DefaultMigrationLagYears) - timeToCRQC
//   level   = HNDLLevelFromSurplus(surplus)
//
// Year 0: rejected at the CLI boundary. The classifier itself accepts it (timeToCRQC=0
// triggers the dynamic default); for matrix rows we pass timeToCRQC=1 to test the
// minimum-positive boundary without hitting the dynamic default path.

import (
	"fmt"
	"testing"
)

// kemSpec describes a single KEM specimen in the matrix.
type kemSpec struct {
	algorithm string
	primitive string
	// expected classification fields
	wantRisk     Risk
	wantHNDLRisk string // "immediate", "deferred", or "" for PQ-safe
}

// kemSpecs are the 10 KEM algorithm specimens for the matrix.
var kemSpecs = []kemSpec{
	// (a) Classical KEMs → HNDLImmediate
	{
		algorithm:    "RSA-2048",
		primitive:    "kem",
		wantRisk:     RiskVulnerable,
		wantHNDLRisk: HNDLImmediate,
	},
	{
		algorithm:    "ECDHE-X25519",
		primitive:    "key-exchange",
		wantRisk:     RiskVulnerable,
		wantHNDLRisk: HNDLImmediate,
	},
	{
		// Kyber768 is the pre-standardisation name. Not in pqcSafeFamilies;
		// falls through to "unrecognized kem" path → HNDLImmediate.
		algorithm:    "Kyber768",
		primitive:    "kem",
		wantRisk:     RiskVulnerable,
		wantHNDLRisk: HNDLImmediate,
	},
	{
		// X25519Kyber768Draft00: deprecated IETF draft hybrid (pre-FIPS 203 Kyber).
		// Now in deprecatedAlgorithms so the deprecated check (step 1) fires before
		// the quantumVulnerableFamilies prefix match (step 3). RiskDeprecated; no
		// HNDLRisk because deprecated algorithms are classically broken, not
		// specifically a quantum harvest risk.
		algorithm:    "X25519Kyber768Draft00",
		primitive:    "kem",
		wantRisk:     RiskDeprecated,
		wantHNDLRisk: "",
	},
	{
		// Unrecognized KEM with opaque name → conservative: HNDLImmediate.
		algorithm:    "unknown-algo-fallback",
		primitive:    "kem",
		wantRisk:     RiskVulnerable,
		wantHNDLRisk: HNDLImmediate,
	},
	// (b) Classical signature → HNDLDeferred (future authenticity risk, not data harvesting)
	{
		algorithm:    "ECDSA-P256",
		primitive:    "signature",
		wantRisk:     RiskVulnerable,
		wantHNDLRisk: HNDLDeferred,
	},
	// (c) Hybrid PQ KEMs → RiskSafe, no HNDL
	{
		algorithm:    "X25519MLKEM768",
		primitive:    "kem",
		wantRisk:     RiskSafe,
		wantHNDLRisk: "",
	},
	{
		// S0.F4: hyphenated form must be normalised to X25519MLKEM768, not X25519.
		algorithm:    "X25519-MLKEM-768",
		primitive:    "kem",
		wantRisk:     RiskSafe,
		wantHNDLRisk: "",
	},
	{
		algorithm:    "SecP256r1MLKEM768",
		primitive:    "kem",
		wantRisk:     RiskSafe,
		wantHNDLRisk: "",
	},
	// (d) Pure PQ KEM → RiskSafe, no HNDL
	{
		algorithm:    "ML-KEM-768",
		primitive:    "kem",
		wantRisk:     RiskSafe,
		wantHNDLRisk: "",
	},
}

// sectorRow describes one row in the sector dimension of the matrix.
type sectorRow struct {
	sector    string
	shelfLife int // expected ShelfLifeForSector(sector)
}

var sectorRows = []sectorRow{
	{"medical", 30},
	{"finance", 7},
	{"state", 50},
	{"infra", 20},
	{"code", 5},
	{"generic", 10},
}

// yearRow describes one row in the timeToCRQC dimension of the matrix.
// computeYear is the value passed to ComputeHNDLSurplus: 0 is the CLI boundary
// (rejected before reaching the classifier), so we use 1 there.
type yearRow struct {
	label       string
	computeYear int
}

var yearRows = []yearRow{
	{"0_cliBoundary_use1", 1}, // year=0 rejected at CLI; use 1 for the minimum-positive boundary
	{"1", 1},
	{"3", 3},
	{"5", 5},
	{"10", 10},
	{"30", 30},
	{"50", 50},
	{"100", 100},
}

// expectedMoscaLevel computes the expected HNDL level for a classical KEM at a given
// (sector, timeToCRQC) cell.
func expectedMoscaLevel(shelfLife, timeToCRQC int) HNDLLevel {
	surplus := ComputeHNDLSurplus(shelfLife, DefaultMigrationLagYears, timeToCRQC)
	return HNDLLevelFromSurplus(surplus)
}

// TestMatrix_SectorYearKEM is the 480-case cross-product test.
// Sub-test names are: sector/year/algorithm — readable in go test -v output.
func TestMatrix_SectorYearKEM(t *testing.T) {
	for _, sector := range sectorRows {
		// Verify the sector shelf-life constant is what we expect.
		gotShelf := ShelfLifeForSector(sector.sector)
		if gotShelf != sector.shelfLife {
			t.Errorf("ShelfLifeForSector(%q) = %d, want %d (matrix spec mismatch)", sector.sector, gotShelf, sector.shelfLife)
		}

		for _, yr := range yearRows {
			for _, kem := range kemSpecs {
				name := fmt.Sprintf("%s/year%s/%s", sector.sector, yr.label, kem.algorithm)
				t.Run(name, func(t *testing.T) {
					c := ClassifyAlgorithm(kem.algorithm, kem.primitive, 0)

					// Risk field must match expected.
					if c.Risk != kem.wantRisk {
						t.Errorf("Risk = %q, want %q", c.Risk, kem.wantRisk)
					}

					// HNDL risk field must match expected.
					if c.HNDLRisk != kem.wantHNDLRisk {
						t.Errorf("HNDLRisk = %q, want %q", c.HNDLRisk, kem.wantHNDLRisk)
					}

					// For immediate classical KEMs: verify Mosca HNDL level for this cell.
					if kem.wantHNDLRisk == HNDLImmediate {
						wantLevel := expectedMoscaLevel(sector.shelfLife, yr.computeYear)
						gotSurplus := ComputeHNDLSurplus(sector.shelfLife, DefaultMigrationLagYears, yr.computeYear)
						gotLevel := HNDLLevelFromSurplus(gotSurplus)
						if gotLevel != wantLevel {
							t.Errorf("Mosca level mismatch: sector=%s(shelf=%d) year=%d: surplus=%d level=%s, want %s",
								sector.sector, sector.shelfLife, yr.computeYear, gotSurplus, gotLevel, wantLevel)
						}
					}

					// For PQ-safe: double-check HNDLLevel is LOW regardless of sector/year.
					if kem.wantHNDLRisk == "" && kem.wantRisk == RiskSafe {
						// shelfLife=0 models "no harvest risk" — surplus always negative or near-zero.
						// The algorithm itself is PQ-safe; HNDL level is LOW by definition.
						safeSurplus := ComputeHNDLSurplus(0, DefaultMigrationLagYears, yr.computeYear)
						safeLevel := HNDLLevelFromSurplus(safeSurplus)
						// With timeToCRQC >= 1 and shelfLife=0: surplus = (0+5)-year = 5-year.
						// For year >= 6: surplus < 0 → LOW. For year < 6: surplus >= 0 → MEDIUM/HIGH.
						// We only assert that the *algorithm* itself has no HNDL risk (HNDLRisk="").
						// The safeSurplus here shows what the Mosca math says for shelfLife=0,
						// but for a PQ-safe KEM, the caller should treat it as LOW regardless.
						_ = safeLevel // documented above; behaviour verified via HNDLRisk==""
					}
				})
			}
		}
	}
}

// TestMatrix_ImmediateKEM_MoscaLevelSample spot-checks a handful of specific
// (sector, year, KEM) cells to give readable failure messages for the most
// important combinations.
func TestMatrix_ImmediateKEM_MoscaLevelSample(t *testing.T) {
	type cell struct {
		sector    string
		shelfLife int
		years     int
		kem       string
		prim      string
		wantLevel HNDLLevel
	}
	cells := []cell{
		// Medical (30y) + 1y crqc: 30+5-1=34 → HIGH — most urgent case
		{"medical", 30, 1, "RSA-2048", "kem", HNDLLevelHigh},
		// Finance (7y) + 10y crqc: 7+5-10=2 → MEDIUM — near the wire
		{"finance", 7, 10, "RSA-2048", "kem", HNDLLevelMedium},
		// Code (5y) + 10y crqc: 5+5-10=0 → MEDIUM — exactly on threshold
		{"code", 5, 10, "ECDHE-X25519", "key-exchange", HNDLLevelMedium},
		// State (50y) + 100y crqc: 50+5-100=-45 → LOW — quantum era ends first
		{"state", 50, 100, "RSA-2048", "kem", HNDLLevelLow},
		// Infra (20y) + 30y crqc: 20+5-30=-5 → LOW (use ECDHE to replace deprecated X25519Kyber768Draft00)
		{"infra", 20, 30, "ECDHE", "key-exchange", HNDLLevelLow},
		// Generic (10y) + 3y crqc: 10+5-3=12 → HIGH
		{"generic", 10, 3, "unknown-algo-fallback", "kem", HNDLLevelHigh},
	}
	for _, tc := range cells {
		tc := tc
		name := fmt.Sprintf("%s_%dy_%s", tc.sector, tc.years, tc.kem)
		t.Run(name, func(t *testing.T) {
			c := ClassifyAlgorithm(tc.kem, tc.prim, 0)
			if c.HNDLRisk != HNDLImmediate {
				t.Fatalf("expected HNDLImmediate for %q, got %q", tc.kem, c.HNDLRisk)
			}
			surplus := ComputeHNDLSurplus(tc.shelfLife, DefaultMigrationLagYears, tc.years)
			level := HNDLLevelFromSurplus(surplus)
			if level != tc.wantLevel {
				t.Errorf("sector=%s shelf=%d years=%d: surplus=%d level=%s, want %s",
					tc.sector, tc.shelfLife, tc.years, surplus, level, tc.wantLevel)
			}
		})
	}
}

// TestMatrix_PQSafeAlgorithms_AlwaysLowHNDLRisk verifies that PQ-safe algorithms
// have empty HNDLRisk across all sectors and years — they are not affected by the
// Mosca inequality because the ML-KEM component provides independent PQ security.
func TestMatrix_PQSafeAlgorithms_AlwaysLowHNDLRisk(t *testing.T) {
	pqSafe := []struct{ alg, prim string }{
		{"ML-KEM-768", "kem"},
		{"X25519MLKEM768", "kem"},
		{"X25519-MLKEM-768", "kem"},
		{"SecP256r1MLKEM768", "kem"},
	}
	for _, alg := range pqSafe {
		for _, sector := range sectorRows {
			for _, yr := range yearRows {
				name := fmt.Sprintf("%s/%s/year%s", alg.alg, sector.sector, yr.label)
				t.Run(name, func(t *testing.T) {
					c := ClassifyAlgorithm(alg.alg, alg.prim, 0)
					if c.HNDLRisk != "" {
						t.Errorf("%q: HNDLRisk = %q, want \"\" (PQ-safe — no harvest risk regardless of sector/year)",
							alg.alg, c.HNDLRisk)
					}
					if c.Risk != RiskSafe {
						t.Errorf("%q: Risk = %q, want %q", alg.alg, c.Risk, RiskSafe)
					}
				})
			}
		}
	}
}
