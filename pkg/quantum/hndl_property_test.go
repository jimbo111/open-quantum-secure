package quantum

// hndl_property_test.go — property-based and invariant tests for the Mosca HNDL model.
//
// These tests catch latent bugs that table-driven golden tests miss by verifying
// mathematical properties that must hold across arbitrary inputs:
//
//   - Monotonicity: surplus is non-decreasing in shelfLife, non-increasing in crqc
//   - Idempotence: HNDLLevelFromSurplus produces the same result on repeated calls
//   - Level ordering: a higher surplus never maps to a lower-urgency level
//   - Boundary stability: the exact breakpoints (-1, 0, 1, 2, 3) behave as documented

import (
	"math/rand"
	"testing"
)

// TestHNDLSurplus_ShelfLifeMonotonicity verifies that for fixed lag and crqc,
// incrementing shelfLife by 1 never decreases the surplus.
// Surplus = (shelfLife + lag) - crqc, so it is strictly increasing in shelfLife.
func TestHNDLSurplus_ShelfLifeMonotonicity(t *testing.T) {
	lag := 5
	crqc := 7
	prev := ComputeHNDLSurplus(0, lag, crqc)
	for shelfLife := 1; shelfLife <= 100; shelfLife++ {
		curr := ComputeHNDLSurplus(shelfLife, lag, crqc)
		if curr < prev {
			t.Errorf("monotonicity violated: shelfLife=%d surplus=%d < prev=%d (lag=%d, crqc=%d)",
				shelfLife, curr, prev, lag, crqc)
		}
		prev = curr
	}
}

// TestHNDLSurplus_CRQCMonotonicity verifies that for fixed shelfLife and lag,
// incrementing crqc by 1 never increases the surplus.
// Surplus = (shelfLife + lag) - crqc, so it is strictly decreasing in crqc.
func TestHNDLSurplus_CRQCMonotonicity(t *testing.T) {
	shelfLife := 15
	lag := 5
	prev := ComputeHNDLSurplus(shelfLife, lag, 1)
	for crqc := 2; crqc <= 100; crqc++ {
		curr := ComputeHNDLSurplus(shelfLife, lag, crqc)
		if curr > prev {
			t.Errorf("monotonicity violated: crqc=%d surplus=%d > prev=%d (shelfLife=%d, lag=%d)",
				crqc, curr, prev, shelfLife, lag)
		}
		prev = curr
	}
}

// TestHNDLLevelFromSurplus_Idempotent verifies that HNDLLevelFromSurplus produces
// the same result when called twice with the same input — golden for any future refactor
// that might introduce side effects or non-deterministic state.
func TestHNDLLevelFromSurplus_Idempotent(t *testing.T) {
	for surplus := -20; surplus <= 20; surplus++ {
		a := HNDLLevelFromSurplus(surplus)
		b := HNDLLevelFromSurplus(surplus)
		if a != b {
			t.Errorf("HNDLLevelFromSurplus(%d) not idempotent: first=%q second=%q", surplus, a, b)
		}
	}
}

// TestHNDLLevelFromSurplus_BoundaryStability asserts the exact documented breakpoints:
//
//	surplus < 0  → HNDLLevelLow
//	surplus 0..2 → HNDLLevelMedium
//	surplus > 2  → HNDLLevelHigh
//
// These are the canonical boundaries from the Mosca inequality. If they shift,
// this test is the canary.
func TestHNDLLevelFromSurplus_BoundaryStability(t *testing.T) {
	tests := []struct {
		surplus int
		want    HNDLLevel
	}{
		{-1000000, HNDLLevelLow},
		{-100, HNDLLevelLow},
		{-2, HNDLLevelLow},
		{-1, HNDLLevelLow},   // just below MEDIUM threshold
		{0, HNDLLevelMedium}, // lower MEDIUM boundary (inclusive)
		{1, HNDLLevelMedium},
		{2, HNDLLevelMedium}, // upper MEDIUM boundary (inclusive)
		{3, HNDLLevelHigh},   // just above MEDIUM → HIGH
		{4, HNDLLevelHigh},
		{100, HNDLLevelHigh},
		{1000000, HNDLLevelHigh},
	}
	for _, tt := range tests {
		got := HNDLLevelFromSurplus(tt.surplus)
		if got != tt.want {
			t.Errorf("HNDLLevelFromSurplus(%d) = %q, want %q", tt.surplus, got, tt.want)
		}
	}
}

// TestHNDLSurplus_RandomShelfLifeMonotonicity runs 100 random (lag, crqc) pairs
// and verifies monotone non-decreasing in shelfLife for each. This guards against
// off-by-one errors that deterministic table tests might not trigger.
func TestHNDLSurplus_RandomShelfLifeMonotonicity(t *testing.T) {
	rng := rand.New(rand.NewSource(42))
	for i := 0; i < 100; i++ {
		lag := rng.Intn(20) + 1  // 1..20
		crqc := rng.Intn(20) + 1 // 1..20
		prev := ComputeHNDLSurplus(0, lag, crqc)
		for shelfLife := 1; shelfLife <= 50; shelfLife++ {
			curr := ComputeHNDLSurplus(shelfLife, lag, crqc)
			if curr < prev {
				t.Errorf("iteration %d: shelfLife=%d surplus=%d < prev=%d (lag=%d, crqc=%d)",
					i, shelfLife, curr, prev, lag, crqc)
			}
			prev = curr
		}
	}
}

// TestHNDLLevelFromSurplus_LevelOrderConsistency verifies that urgency is non-decreasing:
// a higher surplus must never map to a lower-urgency level than a lower surplus.
// Urgency ordering: Low=0, Medium=1, High=2.
func TestHNDLLevelFromSurplus_LevelOrderConsistency(t *testing.T) {
	urgency := map[HNDLLevel]int{
		HNDLLevelLow:    0,
		HNDLLevelMedium: 1,
		HNDLLevelHigh:   2,
	}
	prev := urgency[HNDLLevelFromSurplus(-50)]
	for surplus := -49; surplus <= 50; surplus++ {
		level := HNDLLevelFromSurplus(surplus)
		curr := urgency[level]
		if curr < prev {
			t.Errorf("level ordering violated at surplus=%d: level %q (urgency %d) < previous urgency %d",
				surplus, level, curr, prev)
		}
		prev = curr
	}
}

// TestComputeHNDLSurplus_Linearity verifies the linear structure of the Mosca formula:
// surplus(n+1) - surplus(n) == 1 when only shelfLife changes by 1.
func TestComputeHNDLSurplus_Linearity(t *testing.T) {
	lag := 5
	crqc := 8
	for shelfLife := 0; shelfLife < 50; shelfLife++ {
		a := ComputeHNDLSurplus(shelfLife, lag, crqc)
		b := ComputeHNDLSurplus(shelfLife+1, lag, crqc)
		if b-a != 1 {
			t.Errorf("linearity violated at shelfLife=%d: delta=%d (want 1), surplus(%d)=%d, surplus(%d)=%d",
				shelfLife, b-a, shelfLife, a, shelfLife+1, b)
		}
	}
}
