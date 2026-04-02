package blast

// ScoreToGrade converts a blast radius score [0, 100] to a human-readable grade.
//
// Grades:
//   - ≤15: "Minimal"
//   - ≤40: "Contained"
//   - ≤70: "Significant"
//   - >70: "Critical"
func ScoreToGrade(score int) string {
	switch {
	case score <= 15:
		return "Minimal"
	case score <= 40:
		return "Contained"
	case score <= 70:
		return "Significant"
	default:
		return "Critical"
	}
}
