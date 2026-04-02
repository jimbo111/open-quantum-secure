package blast

import "math"

// Input holds the raw metrics used to compute a blast radius score.
type Input struct {
	HopCount             int
	ConstraintViolations int
	ProtocolViolations   int
	SizeRatio            float64
}

// Calculate returns a blast radius score in [0, 100] and a grade string.
//
// Scoring formula (weighted sum):
//   - Hop component:        min(hops/10.0, 1.0) × 100  → weight 20%
//   - Constraint component: min(count×25.0, 100.0)      → weight 35%
//   - Protocol component:   min(count×33.0, 100.0)      → weight 25%
//   - Size component:       min(ratio/50.0, 1.0) × 100  → weight 20%
func Calculate(input Input) (score int, grade string) {
	hop := math.Min(math.Max(float64(input.HopCount)/10.0, 0), 1.0) * 100.0
	constraint := math.Min(math.Max(float64(input.ConstraintViolations)*25.0, 0), 100.0)
	protocol := math.Min(math.Max(float64(input.ProtocolViolations)*33.0, 0), 100.0)
	size := math.Min(math.Max(input.SizeRatio/50.0, 0), 1.0) * 100.0

	raw := hop*0.20 + constraint*0.35 + protocol*0.25 + size*0.20
	s := int(math.Round(raw))
	if s < 0 {
		s = 0
	}
	if s > 100 {
		s = 100
	}
	return s, ScoreToGrade(s)
}
