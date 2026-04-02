// Package trends computes trend data from a series of scan records,
// enabling callers to track quantum readiness improvement over time.
package trends

import (
	"fmt"

	"github.com/jimbo111/open-quantum-secure/pkg/store"
)

// TrendData holds computed trend information for a project.
type TrendData struct {
	Project    string      `json:"project"`
	DataPoints []DataPoint `json:"dataPoints"`
	Delta      Delta       `json:"delta"`
	Summary    string      `json:"summary"` // human-readable: "QRS improved 45→52 (+7) over 3 scans"
}

// DataPoint represents a single scan's contribution to the trend.
//
// Vulnerable, Deprecated, and Safe are derived from the FindingSummary
// severity fields stored in ScanRecord, since quantum-risk counts are not
// persisted separately:
//   - Vulnerable  = Critical + High
//   - Deprecated  = Medium
//   - Safe        = Low + Info
type DataPoint struct {
	Timestamp  string `json:"timestamp"`
	QRS        int    `json:"qrs"`
	Grade      string `json:"grade"`
	Findings   int    `json:"findings"`
	Vulnerable int    `json:"vulnerable"`
	Deprecated int    `json:"deprecated"`
	Safe       int    `json:"safe"`
}

// Delta records the change between the first and last DataPoint.
type Delta struct {
	QRS        int  `json:"qrs"`        // change from first to last
	Findings   int  `json:"findings"`
	Vulnerable int  `json:"vulnerable"`
	Deprecated int  `json:"deprecated"`
	Improving  bool `json:"improving"`  // true if QRS increased OR vulnerable decreased
}

// Compute calculates trend data from scan records.
// Records are expected oldest-first (as returned by LocalStore.ListScans).
// Returns an empty TrendData (with non-nil DataPoints slice) when records is empty.
func Compute(project string, records []store.ScanRecord) TrendData {
	td := TrendData{
		Project:    project,
		DataPoints: make([]DataPoint, 0, len(records)),
	}

	for _, r := range records {
		td.DataPoints = append(td.DataPoints, toDataPoint(r))
	}

	if len(td.DataPoints) == 0 {
		td.Summary = "No scan data available."
		return td
	}

	if len(td.DataPoints) == 1 {
		dp := td.DataPoints[0]
		td.Summary = fmt.Sprintf("QRS %d (%s) — 1 scan recorded.", dp.QRS, dp.Grade)
		return td
	}

	first := td.DataPoints[0]
	last := td.DataPoints[len(td.DataPoints)-1]

	td.Delta = Delta{
		QRS:        last.QRS - first.QRS,
		Findings:   last.Findings - first.Findings,
		Vulnerable: last.Vulnerable - first.Vulnerable,
		Deprecated: last.Deprecated - first.Deprecated,
		Improving:  last.QRS > first.QRS || last.Vulnerable < first.Vulnerable,
	}

	td.Summary = buildSummary(first, last, td.Delta, len(td.DataPoints))
	return td
}

// toDataPoint converts a ScanRecord to a DataPoint.
// Uses quantum-risk counts when available (new records), falls back to
// severity-based approximation for backward compatibility with old records.
func toDataPoint(r store.ScanRecord) DataPoint {
	fs := r.FindingSummary

	vulnerable := fs.QuantumVulnerable
	deprecated := fs.Deprecated
	safe := fs.QuantumSafe + fs.QuantumResistant

	// Backward compat: if quantum-risk counts are all zero but there are findings,
	// fall back to severity-based approximation (old records before this field existed).
	if vulnerable == 0 && deprecated == 0 && safe == 0 && fs.Total > 0 {
		vulnerable = fs.Critical + fs.High
		deprecated = fs.Medium
		safe = fs.Low + fs.Info
	}

	return DataPoint{
		Timestamp:  r.Timestamp,
		QRS:        r.QuantumReadinessScore,
		Grade:      r.QuantumReadinessGrade,
		Findings:   fs.Total,
		Vulnerable: vulnerable,
		Deprecated: deprecated,
		Safe:       safe,
	}
}

// buildSummary generates a human-readable summary string.
func buildSummary(first, last DataPoint, d Delta, n int) string {
	direction := "unchanged"
	if d.QRS > 0 {
		direction = "improved"
	} else if d.QRS < 0 {
		direction = "degraded"
	}

	scanWord := "scans"
	if n == 1 {
		scanWord = "scan"
	}

	sign := "+"
	if d.QRS < 0 {
		sign = ""
	}

	s := fmt.Sprintf("QRS %s %d→%d (%s%d) over %d %s.",
		direction, first.QRS, last.QRS, sign, d.QRS, n, scanWord)

	if d.Vulnerable < 0 {
		s += fmt.Sprintf(" Vulnerable findings decreased by %d.", -d.Vulnerable)
	} else if d.Vulnerable > 0 {
		s += fmt.Sprintf(" Vulnerable findings increased by %d.", d.Vulnerable)
	}

	if d.Improving {
		s += " Improving."
	} else if d.QRS == 0 && d.Vulnerable == 0 {
		s += " Stable."
	} else {
		s += " Not improving."
	}

	return s
}
