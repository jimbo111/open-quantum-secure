// Package impact — property-based audit tests.
//
// Uses testing/quick to probe invariants of the blast-radius formula,
// constraints encoding math, and propagator output shape.
package impact_test

import (
	"context"
	"math"
	"testing"
	"testing/quick"

	"github.com/jimbo111/open-quantum-secure/pkg/findings"
	"github.com/jimbo111/open-quantum-secure/pkg/impact"
	"github.com/jimbo111/open-quantum-secure/pkg/impact/blast"
	"github.com/jimbo111/open-quantum-secure/pkg/impact/constraints"
	"github.com/jimbo111/open-quantum-secure/pkg/impact/forward"
)

// Property: blast.Calculate result always in [0, 100].
func TestProp_BlastCalculate_Range(t *testing.T) {
	f := func(hop uint16, cv uint16, pv uint16, ratio float64) bool {
		// Clamp float to a finite reasonable range.
		if math.IsNaN(ratio) || math.IsInf(ratio, 0) {
			return true
		}
		score, _ := blast.Calculate(blast.Input{
			HopCount:             int(hop),
			ConstraintViolations: int(cv),
			ProtocolViolations:   int(pv),
			SizeRatio:            ratio,
		})
		return score >= 0 && score <= 100
	}
	if err := quick.Check(f, &quick.Config{MaxCount: 1000}); err != nil {
		t.Error(err)
	}
}

// Property: blast.Calculate grade is one of the 4 known strings.
func TestProp_BlastCalculate_GradeEnum(t *testing.T) {
	validGrades := map[string]bool{
		"Minimal": true, "Contained": true, "Significant": true, "Critical": true,
	}
	f := func(score int) bool {
		g := blast.ScoreToGrade(score)
		return validGrades[g]
	}
	if err := quick.Check(f, &quick.Config{MaxCount: 500}); err != nil {
		t.Error(err)
	}
}

// Property: blast.Calculate is monotone non-decreasing in each input
// (holding others fixed). Adding more violations should not decrease score.
func TestProp_BlastCalculate_MonotoneInConstraints(t *testing.T) {
	for base := 0; base < 5; base++ {
		for hop := 0; hop < 20; hop += 5 {
			s1, _ := blast.Calculate(blast.Input{HopCount: hop, ConstraintViolations: base})
			s2, _ := blast.Calculate(blast.Input{HopCount: hop, ConstraintViolations: base + 1})
			if s2 < s1 {
				t.Errorf("monotone violation: base=%d hop=%d s1=%d s2=%d", base, hop, s1, s2)
			}
		}
	}
}

// Property: CalculateEncodedSize with raw=0 returns 0 for all non-PEM encodings.
// PEM adds a 52-byte envelope even for empty input.
func TestProp_CalculateEncodedSize_ZeroInput(t *testing.T) {
	cases := map[string]int{
		"":       0,
		"raw":    0,
		"base64": 0,
		"hex":    0,
		"der":    8, // n+8
		"pem":    52 + 0,
	}
	for enc, want := range cases {
		got := constraints.CalculateEncodedSize(0, enc)
		if got != want {
			t.Errorf("CalculateEncodedSize(0, %q) = %d, want %d", enc, got, want)
		}
	}
}

// Property: CalculateEncodedSize is monotone non-decreasing in raw size
// for all non-negative raw values.
func TestProp_CalculateEncodedSize_Monotone(t *testing.T) {
	encs := []string{"raw", "base64", "hex", "pem", "der"}
	for _, enc := range encs {
		for n := 0; n < 1000; n++ {
			a := constraints.CalculateEncodedSize(n, enc)
			b := constraints.CalculateEncodedSize(n+1, enc)
			if b < a {
				t.Errorf("enc=%q: non-monotone at n=%d → n+1=%d (%d vs %d)", enc, n, n+1, a, b)
			}
		}
	}
}

// Property: Propagator always returns len(ForwardEdges) <= len(findings)*maxHops.
func TestProp_Propagator_EdgeCountBounded(t *testing.T) {
	f := func(hopCountByte byte, findingCountByte byte) bool {
		maxHops := int(hopCountByte)%30 + 1
		findingCount := int(findingCountByte) % 20
		if findingCount == 0 {
			return true
		}
		steps := make([]findings.FlowStep, 10)
		for i := range steps {
			steps[i] = findings.FlowStep{File: "a.go", Line: i + 1}
		}
		ff := make([]findings.UnifiedFinding, findingCount)
		for i := range ff {
			ff[i] = rsaFindingForTest("r.go", i, steps)
		}
		r, _ := forward.New(maxHops).Analyze(context.Background(), ff, impact.ImpactOpts{})
		// Each finding contributes min(maxHops, len(steps)) edges
		perFinding := maxHops
		if perFinding > len(steps) {
			perFinding = len(steps)
		}
		return len(r.ForwardEdges) == findingCount*perFinding
	}
	if err := quick.Check(f, &quick.Config{MaxCount: 200}); err != nil {
		t.Error(err)
	}
}

// Property: ImpactDataForFinding returns a zone whose FindingKey equals the
// queried key, or nil.
func TestProp_ImpactDataForFinding_KeyInvariant(t *testing.T) {
	zones := []impact.ImpactZone{
		{FindingKey: "k1", BlastRadiusScore: 10},
		{FindingKey: "k2", BlastRadiusScore: 20},
		{FindingKey: "k3", BlastRadiusScore: 30},
	}
	r := &impact.Result{ImpactZones: zones}

	f := func(kBytes []byte) bool {
		key := string(kBytes)
		z := r.ImpactDataForFinding(key)
		if z == nil {
			// Key must not exist
			for _, zz := range zones {
				if zz.FindingKey == key {
					return false // should have been found
				}
			}
			return true
		}
		return z.FindingKey == key
	}
	if err := quick.Check(f, &quick.Config{MaxCount: 500}); err != nil {
		t.Error(err)
	}
}
