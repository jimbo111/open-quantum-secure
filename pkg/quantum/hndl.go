package quantum

import "time"

// Mosca inequality constants.
// The Mosca inequality states: if (data shelf life + migration lag) > time to CRQC,
// the organisation is at risk. See: Mosca, IEEE S&P 2018.
const (
	// moscaReferenceYear is the base year of Mosca's 50% CRQC probability estimate.
	moscaReferenceYear = 2022
	// moscaCRQCWindow is the number of years from moscaReferenceYear to the 50%
	// probability CRQC threshold (2031). Adjusted for the current year at runtime.
	moscaCRQCWindow = 9

	// DefaultMigrationLagYears is the typical enterprise PQC migration lag. Derived
	// from NIST IR 8547 timeline: organisations targeting the 2030 CNSA 2.0 deadline
	// typically begin large-scale migration 4–6 years before the cutoff.
	DefaultMigrationLagYears = 5
)

// HNDLLevel classifies the urgency of a Harvest Now, Decrypt Later threat using
// the Mosca inequality. Values are ordered: High > Medium > Low.
type HNDLLevel string

const (
	// HNDLLevelHigh means the Mosca surplus is > 2 years: data lifetime + migration
	// lag exceeds the CRQC horizon by a comfortable margin. Immediate action required.
	HNDLLevelHigh HNDLLevel = "high"

	// HNDLLevelMedium means surplus is in [0, 2]: at or near the CRQC threshold.
	// Migration should be underway; further delay risks missing the window.
	HNDLLevelMedium HNDLLevel = "medium"

	// HNDLLevelLow means surplus is negative: data will be retired before the CRQC
	// horizon, or the KEM is already quantum-resistant. No harvest risk.
	HNDLLevelLow HNDLLevel = "low"
)

// nowFn is the time source for defaultTimeToCRQC. Replaceable in tests to simulate
// specific years (e.g. 2031 to verify the post-CRQC clamp, 2026 for the reference year).
// Production code must never override this; use t.Cleanup to restore in tests.
var nowFn = time.Now

// defaultTimeToCRQC returns the estimated remaining years until a cryptographically
// relevant quantum computer (CRQC) arrives, based on Mosca's 50% probability estimate
// of 2031 (from 2022 reference). Returns 0 if the estimate has already elapsed.
func defaultTimeToCRQC() int {
	crqcYear := moscaReferenceYear + moscaCRQCWindow
	remaining := crqcYear - nowFn().Year()
	if remaining < 0 {
		return 0
	}
	return remaining
}

// ComputeHNDLSurplus implements the Mosca inequality:
//
//	surplus = (dataShelfLifeYears + migrationLagYears) - timeToCRQCYears
//
// Interpretation:
//
//	surplus > 2  → HNDL HIGH:   data lifetime + migration lag significantly exceeds CRQC horizon
//	surplus 0..2 → HNDL MEDIUM: at or near the threshold; migration should be underway
//	surplus < 0  → HNDL LOW:    data expires before CRQC, or KEM is PQ-resistant; no harvest risk
//
// Caller conventions:
//   - Pass migrationLagYears <= 0 to use DefaultMigrationLagYears (5 years).
//   - Pass timeToCRQCYears <= 0 to use the dynamic default derived from Mosca's
//     50%-probability 2031 estimate, adjusted for the current year.
//   - dataShelfLifeYears should reflect the actual retention period; 0 means
//     "no retention" (surplus will be negative or zero, mapping to LOW/MEDIUM).
//
// Academic basis: Mosca, IEEE S&P 2018; Blanco-Romero et al., arXiv:2603.01091 (2026).
func ComputeHNDLSurplus(dataShelfLifeYears, migrationLagYears, timeToCRQCYears int) int {
	lag := migrationLagYears
	if lag <= 0 {
		lag = DefaultMigrationLagYears
	}
	crqc := timeToCRQCYears
	if crqc <= 0 {
		crqc = defaultTimeToCRQC()
	}
	return (dataShelfLifeYears + lag) - crqc
}

// HNDLLevelFromSurplus maps a Mosca surplus value to a HNDLLevel.
//
//	surplus > 2  → HNDLLevelHigh
//	surplus 0..2 → HNDLLevelMedium
//	surplus < 0  → HNDLLevelLow
func HNDLLevelFromSurplus(surplus int) HNDLLevel {
	if surplus > 2 {
		return HNDLLevelHigh
	}
	if surplus >= 0 {
		return HNDLLevelMedium
	}
	return HNDLLevelLow
}
