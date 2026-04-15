package quantum

// hndl_time_test.go — time-travel tests for defaultTimeToCRQC.
//
// Addresses the code-reviewer's "silent clamp after 2031" concern:
//   - At year 2031: crqcYear (2031) - 2031 = 0, return 0 (threshold year, not clamped).
//   - At year 2032+: crqcYear - year = negative → clamped to 0.
//
// We override the package-level nowFn variable (added alongside this test) to inject
// a fake clock. This is the cleanest approach: no build tags, no go:linkname, no
// interface wrapping. The variable is documented as test-only in hndl.go.
//
// Academic basis: Mosca, IEEE S&P 2018. crqcYear = moscaReferenceYear(2022) + moscaCRQCWindow(9) = 2031.

import (
	"fmt"
	"testing"
	"time"
)

// fakeNow returns a time.Time whose Year() == year.
func fakeNow(year int) func() time.Time {
	return func() time.Time {
		return time.Date(year, time.January, 1, 0, 0, 0, 0, time.UTC)
	}
}

// withFakeYear overrides nowFn for the duration of the test and restores it on cleanup.
func withFakeYear(t *testing.T, year int) {
	t.Helper()
	old := nowFn
	nowFn = fakeNow(year)
	t.Cleanup(func() { nowFn = old })
}

// TestDefaultTimeToCRQC_SpecificYears verifies the function at landmark years.
//
//	crqcYear = 2022 + 9 = 2031
//	remaining = crqcYear - nowFn().Year()
//	clamped to 0 when negative.
func TestDefaultTimeToCRQC_SpecificYears(t *testing.T) {
	tests := []struct {
		year int
		want int
		note string
	}{
		{2026, 5, "reference year of test suite (5y to CRQC)"},
		{2030, 1, "one year before CRQC horizon"},
		{2031, 0, "threshold year: 2031-2031=0, not clamped"},
		{2032, 0, "first post-threshold year: -1 clamped to 0"},
		{2033, 0, "second post-threshold year: -2 clamped to 0"},
		{2050, 0, "well past threshold: -19 clamped to 0"},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(fmt.Sprintf("year_%d", tt.year), func(t *testing.T) {
			withFakeYear(t, tt.year)
			got := defaultTimeToCRQC()
			if got != tt.want {
				t.Errorf("year=%d defaultTimeToCRQC()=%d, want %d (%s)",
					tt.year, got, tt.want, tt.note)
			}
		})
	}
}

// TestDefaultTimeToCRQC_ClampIsNonNegative verifies the clamp guarantee: the function
// never returns a negative value, even decades past the CRQC threshold.
func TestDefaultTimeToCRQC_ClampIsNonNegative(t *testing.T) {
	for year := 2026; year <= 2100; year++ {
		withFakeYear(t, year)
		got := defaultTimeToCRQC()
		if got < 0 {
			t.Errorf("year=%d defaultTimeToCRQC()=%d, want >= 0 (post-threshold clamp violated)", year, got)
		}
	}
}

// TestDefaultTimeToCRQC_HNDLLevelTransitionsAcrossThreshold verifies that
// HNDL urgency for long-lived data correctly transitions across the CRQC threshold.
//
//   shelfLife=10, lag=5: surplus = (10+5) - crqc = 15 - crqc
//     crqc=12: surplus=3  → HIGH   (crqcYear - fakeYear = 12, i.e. year=2019)
//     crqc=15: surplus=0  → MEDIUM (crqcYear - fakeYear = 15, i.e. year=2016)
//     crqc=16: surplus=-1 → LOW    (crqcYear - fakeYear = 16, i.e. year=2015)
//
// Post-2031: crqc is clamped to 0; surplus = (10+5)-0 = 15 → HIGH — the urgency
// is maximum once the CRQC has arrived, not zero.
func TestDefaultTimeToCRQC_HNDLLevelTransitionsAcrossThreshold(t *testing.T) {
	tests := []struct {
		fakeYear  int
		wantCRQC  int
		shelfLife int
		lag       int
		wantLevel HNDLLevel
		note      string
	}{
		// Pre-threshold: crqc > 0, Mosca surplus varies
		{2019, 12, 10, 5, HNDLLevelHigh, "crqc=12 → surplus=3 → HIGH"},
		{2016, 15, 10, 5, HNDLLevelMedium, "crqc=15 → surplus=0 → MEDIUM"},
		{2015, 16, 10, 5, HNDLLevelLow, "crqc=16 → surplus=-1 → LOW"},
		// Post-threshold: crqc clamped to 0 → surplus = shelfLife+lag = 15 → HIGH
		{2032, 0, 10, 5, HNDLLevelHigh, "post-2031: crqc=0 → surplus=15 → HIGH"},
		{2050, 0, 10, 5, HNDLLevelHigh, "year 2050: crqc=0 → surplus=15 → HIGH"},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(fmt.Sprintf("year%d", tt.fakeYear), func(t *testing.T) {
			withFakeYear(t, tt.fakeYear)
			gotCRQC := defaultTimeToCRQC()
			if gotCRQC != tt.wantCRQC {
				t.Fatalf("year=%d: defaultTimeToCRQC()=%d, want %d", tt.fakeYear, gotCRQC, tt.wantCRQC)
			}
			surplus := ComputeHNDLSurplus(tt.shelfLife, tt.lag, gotCRQC)
			level := HNDLLevelFromSurplus(surplus)
			if level != tt.wantLevel {
				t.Errorf("year=%d shelfLife=%d lag=%d crqc=%d: surplus=%d level=%s, want %s (%s)",
					tt.fakeYear, tt.shelfLife, tt.lag, gotCRQC, surplus, level, tt.wantLevel, tt.note)
			}
		})
	}
}

// TestComputeHNDLSurplus_WithDefaultCRQC_AtKeyYears verifies ComputeHNDLSurplus
// end-to-end (crqc=0 → uses nowFn) at specific clock years with medical shelf life.
//
//   medical shelfLife=30, lag=5(default): surplus = 35 - crqc
func TestComputeHNDLSurplus_WithDefaultCRQC_AtKeyYears(t *testing.T) {
	tests := []struct {
		year      int
		wantLevel HNDLLevel
	}{
		{2026, HNDLLevelHigh},   // crqc=5, surplus=30 → HIGH
		{2031, HNDLLevelHigh},   // crqc=0, surplus=35 → HIGH
		{2100, HNDLLevelHigh},   // crqc=0, surplus=35 → HIGH (CRQC has arrived)
	}
	for _, tt := range tests {
		tt := tt
		t.Run(fmt.Sprintf("medical_year%d", tt.year), func(t *testing.T) {
			withFakeYear(t, tt.year)
			// shelfLife=30 (medical), migLag=0 (→default 5), crqc=0 (→nowFn)
			surplus := ComputeHNDLSurplus(30, 0, 0)
			level := HNDLLevelFromSurplus(surplus)
			if level != tt.wantLevel {
				t.Errorf("year=%d medical(30y): surplus=%d level=%s, want %s",
					tt.year, surplus, level, tt.wantLevel)
			}
		})
	}
}

