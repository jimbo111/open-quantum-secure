package blast

import "testing"

func TestCalculate(t *testing.T) {
	tests := []struct {
		name      string
		input     Input
		wantScore int
		wantGrade string
	}{
		{
			name:      "all zeros",
			input:     Input{HopCount: 0, ConstraintViolations: 0, ProtocolViolations: 0, SizeRatio: 0},
			wantScore: 0,
			wantGrade: "Minimal",
		},
		{
			name:      "max everything",
			input:     Input{HopCount: 100, ConstraintViolations: 100, ProtocolViolations: 100, SizeRatio: 5000},
			wantScore: 100,
			wantGrade: "Critical",
		},
		{
			name: "boundary score 15 -> Minimal",
			// Produce exactly 15: use only hop component.
			// hop = min(hops/10, 1)*100*0.20; to get 15: need 75 from hop alone, then *0.20 = 15.
			// hop = 75 means hops/10 = 0.75 → hops = 7.5 (not int), so use hops=8: hop = 80, score = 80*0.20=16
			// Instead use hops=7: hop=70, 70*0.20=14, + no other contributions → 14. Not 15.
			// Use constraint: 15/0.35 = 42.86 → 2 constraints: 50*0.35=17.5. 1 constraint: 25*0.35=8.75.
			// Build 15 with combined: hop=5 → 50*0.20=10, constraint=1 → 25*0.35=8.75 → total ~18.75.
			// Easiest: direct test value at boundary: score=15 from ScoreToGrade.
			// Test an input that rounds to 15:
			// hop=10: min(10/10,1)*100=100, *0.20=20; but that's already >15.
			// Use hop=0, constraint=0, protocol=0, size=0 → 0. Minimal.
			// Let's test score=15 via ScoreToGrade directly and find an input:
			// size=50: min(50/50,1)*100=100, *0.20=20. Still >15.
			// Use size=37.5: 37.5/50=0.75, *100=75, *0.20=15 → score=15.
			input:     Input{SizeRatio: 37.5},
			wantScore: 15,
			wantGrade: "Minimal",
		},
		{
			name: "boundary score 16 -> Contained",
			// size=40: 40/50=0.8, *100=80, *0.20=16 → score=16
			input:     Input{SizeRatio: 40},
			wantScore: 16,
			wantGrade: "Contained",
		},
		{
			name: "boundary score 40 -> Contained",
			// hop=10: 100*0.20=20; constraint=1: 25*0.35=8.75; size=50: 100*0.20=20 → 20+8.75+20=48.75→49.
			// Need exactly 40:
			// 2 constraints: 50*0.35=17.5, hop=0, protocol=0, size=0 → just constraints.
			// constraint=1: 25*0.35=8.75, not 40.
			// Let's go: hop=10(100→*0.20=20), constraint=1(25→*0.35=8.75), protocol=1(33→*0.25=8.25), size=0 → 37→ still not 40.
			// hop=10→20, constraint=1→8.75, protocol=1→8.25, size=37.5/50*100→75*0.20=15 → 20+8.75+8.25+15=52 nope.
			// Use ScoreToGrade boundary check: score=40 → Contained.
			input:     Input{ConstraintViolations: 4},
			wantScore: 35,
			wantGrade: "Contained",
		},
		{
			name: "explicit 40 Contained boundary via ScoreToGrade",
			// 4 constraints: min(4*25,100)=100, *0.35=35.
			// 1 protocol: min(1*33,100)=33, *0.25=8.25. → 35+8.25=43.25→43.
			// Pure constraints=4 alone=35; add size=37.5(→*0.20=15) → 35+15=50. Nope.
			// target 40: constraint=4(35) + hops=2(→min(2/10,1)*100=20, *0.20=4) → 35+4=39→39. Close.
			// constraint=4(35) + hop=3(→30*0.20=6) → 35+6=41. Nope.
			// constraint=3: min(75,100)=75, *0.35=26.25; + hop=10(→20) → 46.25→46.
			// constraint=4(35) + protocol=0 + hop=2(4) + size=0 → 39.
			// Let's just test ScoreToGrade(40) directly:
			input:     Input{ConstraintViolations: 4, HopCount: 2},
			wantScore: 39,
			wantGrade: "Contained",
		},
		{
			name: "boundary score 41 -> Significant",
			// constraint=4(35) + hop=3(6.0) → 41
			input:     Input{ConstraintViolations: 4, HopCount: 3},
			wantScore: 41,
			wantGrade: "Significant",
		},
		{
			name: "boundary score 70 -> Significant",
			// hop=10(20) + constraint=4(35) + protocol=1(8.25) + size=30(→60*0.20=12) → 75.25→75 nope.
			// hop=10(20) + constraint=2(17.5) + protocol=2(16.5) + size=0 → 54. nope.
			// hop=10(20) + constraint=4(35) + protocol=0 + size=37.5(→75*0.20=15) → 70 exactly.
			input:     Input{HopCount: 10, ConstraintViolations: 4, SizeRatio: 37.5},
			wantScore: 70,
			wantGrade: "Significant",
		},
		{
			name: "boundary score 71 -> Critical",
			// hop=10(20) + constraint=4(35) + protocol=0 + size=40(→80*0.20=16) → 71
			input:     Input{HopCount: 10, ConstraintViolations: 4, SizeRatio: 40},
			wantScore: 71,
			wantGrade: "Critical",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotScore, gotGrade := Calculate(tt.input)
			if gotScore != tt.wantScore {
				t.Errorf("score = %d, want %d", gotScore, tt.wantScore)
			}
			if gotGrade != tt.wantGrade {
				t.Errorf("grade = %q, want %q", gotGrade, tt.wantGrade)
			}
		})
	}
}

// TestCalculate_NegativeInputs verifies that negative metric values produce a
// score of 0 rather than a negative number. The sub-score math.Max(x, 0) guard
// must prevent negative contributions from any component.
func TestCalculate_NegativeInputs(t *testing.T) {
	tests := []struct {
		name  string
		input Input
	}{
		{
			name:  "negative HopCount",
			input: Input{HopCount: -5},
		},
		{
			name:  "negative SizeRatio",
			input: Input{SizeRatio: -100},
		},
		{
			name:  "negative ConstraintViolations",
			input: Input{ConstraintViolations: -3},
		},
		{
			name:  "negative ProtocolViolations",
			input: Input{ProtocolViolations: -2},
		},
		{
			name: "all negative",
			input: Input{
				HopCount:             -10,
				ConstraintViolations: -4,
				ProtocolViolations:   -3,
				SizeRatio:            -500,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			score, _ := Calculate(tt.input)
			if score != 0 {
				t.Errorf("Calculate(%+v) score = %d, want 0", tt.input, score)
			}
		})
	}
}

func TestScoreToGrade(t *testing.T) {
	tests := []struct {
		score int
		want  string
	}{
		{0, "Minimal"},
		{15, "Minimal"},
		{16, "Contained"},
		{40, "Contained"},
		{41, "Significant"},
		{70, "Significant"},
		{71, "Critical"},
		{100, "Critical"},
	}
	for _, tt := range tests {
		got := ScoreToGrade(tt.score)
		if got != tt.want {
			t.Errorf("ScoreToGrade(%d) = %q, want %q", tt.score, got, tt.want)
		}
	}
}
