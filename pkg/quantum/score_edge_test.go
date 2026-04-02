package quantum

import (
	"testing"

	"github.com/jimbo111/open-quantum-secure/pkg/findings"
)

// makeVulnerable returns a single quantum-vulnerable finding with the given severity.
func makeVulnerable(sev findings.Severity) findings.UnifiedFinding {
	return findings.UnifiedFinding{
		Algorithm:   &findings.Algorithm{Name: "RSA-2048"},
		QuantumRisk: findings.QRVulnerable,
		Severity:    sev,
	}
}

// makeCorroborated wraps a finding with a corroborating source, triggering the 1.5x multiplier.
func makeCorroborated(f findings.UnifiedFinding) findings.UnifiedFinding {
	f.CorroboratedBy = []string{"cryptoscan"}
	return f
}

// --------------------------------------------------------------------------
// 1. Grade boundary values — one finding that lands exactly on each boundary.
// --------------------------------------------------------------------------

func TestCalculateQRS_GradeBoundaries(t *testing.T) {
	// Each sub-test constructs a finding list whose raw floating-point score
	// equals exactly one of the grade thresholds (95, 85, 70, 50, 30) after
	// applying math.Round, then verifies both the integer score and the grade.
	tests := []struct {
		name        string
		ff          []findings.UnifiedFinding
		wantScore   int
		wantGrade   string
		description string
	}{
		{
			// 100 - 5*1.0 (medium vulnerable) = 95 → A+
			name:      "boundary_95_A+",
			wantScore: 95,
			wantGrade: "A+",
			ff: func() []findings.UnifiedFinding {
				out := make([]findings.UnifiedFinding, 5)
				for i := range out {
					out[i] = findings.UnifiedFinding{
						Algorithm:   &findings.Algorithm{Name: "RSA-2048"},
						QuantumRisk: findings.QRVulnerable,
						Severity:    findings.SevMedium,
					}
				}
				return out
			}(),
		},
		{
			// 100 - 15*1.0 (medium vulnerable) = 85 → A
			name:      "boundary_85_A",
			wantScore: 85,
			wantGrade: "A",
			ff: func() []findings.UnifiedFinding {
				out := make([]findings.UnifiedFinding, 15)
				for i := range out {
					out[i] = findings.UnifiedFinding{
						Algorithm:   &findings.Algorithm{Name: "RSA-2048"},
						QuantumRisk: findings.QRVulnerable,
						Severity:    findings.SevMedium,
					}
				}
				return out
			}(),
		},
		{
			// 100 - 30*1.0 (medium vulnerable) = 70 → B
			name:      "boundary_70_B",
			wantScore: 70,
			wantGrade: "B",
			ff: func() []findings.UnifiedFinding {
				out := make([]findings.UnifiedFinding, 30)
				for i := range out {
					out[i] = findings.UnifiedFinding{
						Algorithm:   &findings.Algorithm{Name: "RSA-2048"},
						QuantumRisk: findings.QRVulnerable,
						Severity:    findings.SevMedium,
					}
				}
				return out
			}(),
		},
		{
			// 100 - 50*1.0 (medium vulnerable) = 50 → C
			name:      "boundary_50_C",
			wantScore: 50,
			wantGrade: "C",
			ff: func() []findings.UnifiedFinding {
				out := make([]findings.UnifiedFinding, 50)
				for i := range out {
					out[i] = findings.UnifiedFinding{
						Algorithm:   &findings.Algorithm{Name: "RSA-2048"},
						QuantumRisk: findings.QRVulnerable,
						Severity:    findings.SevMedium,
					}
				}
				return out
			}(),
		},
		{
			// 100 - 70*1.0 (medium vulnerable) = 30 → D
			name:      "boundary_30_D",
			wantScore: 30,
			wantGrade: "D",
			ff: func() []findings.UnifiedFinding {
				out := make([]findings.UnifiedFinding, 70)
				for i := range out {
					out[i] = findings.UnifiedFinding{
						Algorithm:   &findings.Algorithm{Name: "RSA-2048"},
						QuantumRisk: findings.QRVulnerable,
						Severity:    findings.SevMedium,
					}
				}
				return out
			}(),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			qrs := CalculateQRS(tt.ff)
			if qrs.Score != tt.wantScore {
				t.Errorf("score = %d, want %d", qrs.Score, tt.wantScore)
			}
			if qrs.Grade != tt.wantGrade {
				t.Errorf("grade = %q, want %q", qrs.Grade, tt.wantGrade)
			}
		})
	}
}

// --------------------------------------------------------------------------
// 2. Score rounding — math.Round must fire at .5 boundaries.
//
// Verified against the spec: only findings whose combined raw score produces
// a .5 fraction exercise this code path. With multiplier=1.5 and a 1.0
// penalty, each corroborated medium-vulnerable finding costs 1.5 pts.
//
// 4 corroborated medium-vulnerable findings → 100 - 4*1.5 = 94.0 (no rounding needed).
// 1 corroborated medium-vulnerable + 1 non-corroborated medium-vulnerable
//   → 100 - 1.5 - 1.0 = 97.5 → math.Round → 98 (not 97).
// --------------------------------------------------------------------------

func TestCalculateQRS_RoundingAtHalfPoint(t *testing.T) {
	// Raw score = 97.5 — verifies math.Round rounds up rather than truncating.
	ff := []findings.UnifiedFinding{
		makeCorroborated(makeVulnerable(findings.SevMedium)), // -1.5
		makeVulnerable(findings.SevMedium),                   // -1.0
	}
	qrs := CalculateQRS(ff)
	// math.Round(97.5) = 98  (Go rounds half away from zero)
	if qrs.Score != 98 {
		t.Errorf("expected rounding of 97.5 → 98, got %d", qrs.Score)
	}
	if qrs.Grade != "A+" {
		t.Errorf("grade = %q, want A+", qrs.Grade)
	}
}

func TestCalculateQRS_RoundingProducesA_Plus_AtExactly94_5(t *testing.T) {
	// Raw = 100 - 3*1.5 (corroborated medium) - 1*1.0 (plain medium) = 100 - 4.5 - 1.0 = 94.5
	// math.Round(94.5) = 95 → grade A+
	ff := []findings.UnifiedFinding{
		makeCorroborated(makeVulnerable(findings.SevMedium)), // -1.5
		makeCorroborated(makeVulnerable(findings.SevMedium)), // -1.5
		makeCorroborated(makeVulnerable(findings.SevMedium)), // -1.5
		makeVulnerable(findings.SevMedium),                   // -1.0
	}
	qrs := CalculateQRS(ff)
	if qrs.Score != 95 {
		t.Errorf("expected math.Round(94.5) = 95, got %d", qrs.Score)
	}
	if qrs.Grade != "A+" {
		t.Errorf("grade at score 95 = %q, want A+", qrs.Grade)
	}
}

// --------------------------------------------------------------------------
// 3. Single finding of each type.
// --------------------------------------------------------------------------

func TestCalculateQRS_SingleFinding(t *testing.T) {
	tests := []struct {
		name      string
		f         findings.UnifiedFinding
		wantScore int
		wantGrade string
	}{
		{
			name: "single_vulnerable_critical",
			f: findings.UnifiedFinding{
				Algorithm:   &findings.Algorithm{Name: "RSA-2048"},
				QuantumRisk: findings.QRVulnerable,
				Severity:    findings.SevCritical,
			},
			// 100 - 2.0 = 98
			wantScore: 98,
			wantGrade: "A+",
		},
		{
			name: "single_weakened",
			f: findings.UnifiedFinding{
				Algorithm:   &findings.Algorithm{Name: "AES-128"},
				QuantumRisk: findings.QRWeakened,
				Severity:    findings.SevLow,
			},
			// 100 - 0.5 = 99.5 → math.Round(99.5) = 100 (rounds half away from zero)
			wantScore: 100,
			wantGrade: "A+",
		},
		{
			name: "single_deprecated",
			f: findings.UnifiedFinding{
				Algorithm:   &findings.Algorithm{Name: "MD5"},
				QuantumRisk: findings.QRDeprecated,
				Severity:    findings.SevCritical,
			},
			// 100 - 1.5 = 98.5 → math.Round(98.5) = 99 (rounds half away from zero)
			wantScore: 99,
			wantGrade: "A+",
		},
		{
			name: "single_safe",
			f: findings.UnifiedFinding{
				Algorithm:   &findings.Algorithm{Name: "ML-KEM-768"},
				QuantumRisk: findings.QRSafe,
				Severity:    findings.SevInfo,
			},
			// 100 + 0.5 = 100.5 → clamped to 100
			wantScore: 100,
			wantGrade: "A+",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			qrs := CalculateQRS([]findings.UnifiedFinding{tt.f})
			if qrs.Score != tt.wantScore {
				t.Errorf("score = %d, want %d", qrs.Score, tt.wantScore)
			}
			if qrs.Grade != tt.wantGrade {
				t.Errorf("grade = %q, want %q", qrs.Grade, tt.wantGrade)
			}
		})
	}
}

// --------------------------------------------------------------------------
// 4. Large number of safe findings — bonus cannot push score above 100.
// --------------------------------------------------------------------------

func TestCalculateQRS_ManyPQCSafe_CapsAt100(t *testing.T) {
	// 200 safe findings → raw = 100 + 200*0.5 = 200, clamped to 100.
	ff := make([]findings.UnifiedFinding, 200)
	for i := range ff {
		ff[i] = findings.UnifiedFinding{
			Algorithm:   &findings.Algorithm{Name: "ML-KEM-768"},
			QuantumRisk: findings.QRSafe,
			Severity:    findings.SevInfo,
		}
	}
	qrs := CalculateQRS(ff)
	if qrs.Score != 100 {
		t.Errorf("200 safe findings: score = %d, want 100 (capped)", qrs.Score)
	}
	if qrs.Grade != "A+" {
		t.Errorf("200 safe findings: grade = %q, want A+", qrs.Grade)
	}
}

func TestCalculateQRS_OnePQCSafe_CapsAt100(t *testing.T) {
	// Even a single safe finding from a base of 100 must not push past 100.
	ff := []findings.UnifiedFinding{
		{
			Algorithm:   &findings.Algorithm{Name: "ML-DSA-65"},
			QuantumRisk: findings.QRSafe,
			Severity:    findings.SevInfo,
		},
	}
	qrs := CalculateQRS(ff)
	if qrs.Score > 100 {
		t.Errorf("score = %d, exceeds cap of 100", qrs.Score)
	}
	if qrs.Score != 100 {
		t.Errorf("score = %d, want 100", qrs.Score)
	}
}

// --------------------------------------------------------------------------
// 5. Mixed corroborated + non-corroborated — 1.5x multiplier applies only
//    to corroborated findings.
// --------------------------------------------------------------------------

func TestCalculateQRS_CorroboratedMultiplierApplied(t *testing.T) {
	// Non-corroborated critical vulnerable: -2.0
	plain := makeVulnerable(findings.SevCritical)
	// Corroborated critical vulnerable:     -2.0 * 1.5 = -3.0
	corr := makeCorroborated(makeVulnerable(findings.SevCritical))

	qrsPlain := CalculateQRS([]findings.UnifiedFinding{plain})
	qrsCorr := CalculateQRS([]findings.UnifiedFinding{corr})

	// plain: 100 - 2.0 = 98
	if qrsPlain.Score != 98 {
		t.Errorf("plain critical: score = %d, want 98", qrsPlain.Score)
	}
	// corroborated: 100 - 3.0 = 97
	if qrsCorr.Score != 97 {
		t.Errorf("corroborated critical: score = %d, want 97", qrsCorr.Score)
	}
	// The corroborated score must be strictly lower.
	if qrsCorr.Score >= qrsPlain.Score {
		t.Errorf("corroborated (%d) should be lower than plain (%d)", qrsCorr.Score, qrsPlain.Score)
	}
}

func TestCalculateQRS_MixedCorroboratedAndPlain(t *testing.T) {
	// Two findings: one corroborated high (-1.5*1.5 = -2.25), one plain high (-1.5).
	// Raw = 100 - 2.25 - 1.5 = 96.25 → math.Round → 96.
	ff := []findings.UnifiedFinding{
		makeCorroborated(makeVulnerable(findings.SevHigh)),
		makeVulnerable(findings.SevHigh),
	}
	qrs := CalculateQRS(ff)
	if qrs.Score != 96 {
		t.Errorf("mixed corroborated+plain high: score = %d, want 96", qrs.Score)
	}
	if qrs.Grade != "A+" {
		t.Errorf("grade = %q, want A+", qrs.Grade)
	}
}

// --------------------------------------------------------------------------
// 6. All findings safe — score must be >= 100, clamped to 100, grade A+.
// --------------------------------------------------------------------------

func TestCalculateQRS_AllSafe_GradeIsAPlus(t *testing.T) {
	counts := []int{1, 5, 10, 50}
	for _, n := range counts {
		ff := make([]findings.UnifiedFinding, n)
		for i := range ff {
			ff[i] = findings.UnifiedFinding{
				Algorithm:   &findings.Algorithm{Name: "ML-KEM-1024"},
				QuantumRisk: findings.QRSafe,
				Severity:    findings.SevInfo,
			}
		}
		qrs := CalculateQRS(ff)
		if qrs.Score != 100 {
			t.Errorf("%d safe findings: score = %d, want 100", n, qrs.Score)
		}
		if qrs.Grade != "A+" {
			t.Errorf("%d safe findings: grade = %q, want A+", n, qrs.Grade)
		}
	}
}

// --------------------------------------------------------------------------
// 7. Exactly one critical vulnerable finding — penalty = 2.0, score = 98.
// --------------------------------------------------------------------------

func TestCalculateQRS_OneCriticalVulnerable(t *testing.T) {
	ff := []findings.UnifiedFinding{makeVulnerable(findings.SevCritical)}
	qrs := CalculateQRS(ff)

	// 100 - 2.0 * 1.0 = 98
	if qrs.Score != 98 {
		t.Errorf("one critical vulnerable: score = %d, want 98", qrs.Score)
	}
	if qrs.Grade != "A+" {
		t.Errorf("one critical vulnerable: grade = %q, want A+", qrs.Grade)
	}
}

// --------------------------------------------------------------------------
// 8. vulnerablePenalty — every severity level returns the correct base penalty.
// --------------------------------------------------------------------------

func TestVulnerablePenalty_AllSeverities(t *testing.T) {
	tests := []struct {
		severity findings.Severity
		want     float64
	}{
		{findings.SevCritical, 2.0},
		{findings.SevHigh, 1.5},
		{findings.SevMedium, 1.0},
		{findings.SevLow, 1.0},    // default case
		{findings.SevInfo, 1.0},   // default case
		{"unknown", 1.0},          // completely unknown severity → default
	}

	for _, tt := range tests {
		t.Run(string(tt.severity), func(t *testing.T) {
			f := findings.UnifiedFinding{
				Algorithm:   &findings.Algorithm{Name: "RSA-2048"},
				QuantumRisk: findings.QRVulnerable,
				Severity:    tt.severity,
			}
			got := vulnerablePenalty(f)
			if got != tt.want {
				t.Errorf("vulnerablePenalty(%q) = %.2f, want %.2f", tt.severity, got, tt.want)
			}
		})
	}
}

// --------------------------------------------------------------------------
// Supplementary: QRResistant findings contribute neither bonus nor penalty.
// --------------------------------------------------------------------------

func TestCalculateQRS_ResistantIsNeutral(t *testing.T) {
	// AES-256 is quantum-resistant — should not change the score from 100.
	ff := []findings.UnifiedFinding{
		{
			Algorithm:   &findings.Algorithm{Name: "AES-256"},
			QuantumRisk: findings.QRResistant,
			Severity:    findings.SevInfo,
		},
	}
	qrs := CalculateQRS(ff)
	if qrs.Score != 100 {
		t.Errorf("resistant finding: score = %d, want 100", qrs.Score)
	}
}

// --------------------------------------------------------------------------
// Supplementary: Verify deprecated corroborated penalty is 1.5 * 1.5 = 2.25.
// --------------------------------------------------------------------------

func TestCalculateQRS_CorroboratedDeprecated(t *testing.T) {
	plain := findings.UnifiedFinding{
		Algorithm:   &findings.Algorithm{Name: "MD5"},
		QuantumRisk: findings.QRDeprecated,
		Severity:    findings.SevCritical,
	}
	corr := plain
	corr.CorroboratedBy = []string{"another-scanner"}

	qrsPlain := CalculateQRS([]findings.UnifiedFinding{plain})
	qrsCorr := CalculateQRS([]findings.UnifiedFinding{corr})

	// plain deprecated: 100 - 1.5 = 98.5 → math.Round(98.5) = 99
	if qrsPlain.Score != 99 {
		t.Errorf("plain deprecated: score = %d, want 99 (round 98.5)", qrsPlain.Score)
	}
	// corroborated deprecated: 100 - 1.5*1.5 = 100 - 2.25 = 97.75 → math.Round(97.75) = 98
	if qrsCorr.Score != 98 {
		t.Errorf("corroborated deprecated: score = %d, want 98 (round 97.75)", qrsCorr.Score)
	}
	// Corroborated must have a strictly lower score than plain.
	if qrsCorr.Score >= qrsPlain.Score {
		t.Errorf("corroborated score (%d) should be lower than plain score (%d)", qrsCorr.Score, qrsPlain.Score)
	}
}

// --------------------------------------------------------------------------
// Supplementary: Score floor — many corroborated critical findings clamp at 0.
// --------------------------------------------------------------------------

func TestCalculateQRS_ScoreFloorIsZero(t *testing.T) {
	// 50 corroborated critical findings → 100 - 50*3.0 = -50 → clamped to 0.
	ff := make([]findings.UnifiedFinding, 50)
	for i := range ff {
		ff[i] = makeCorroborated(makeVulnerable(findings.SevCritical))
	}
	qrs := CalculateQRS(ff)
	if qrs.Score != 0 {
		t.Errorf("50 corroborated critical: score = %d, want 0", qrs.Score)
	}
	if qrs.Grade != "F" {
		t.Errorf("50 corroborated critical: grade = %q, want F", qrs.Grade)
	}
}
