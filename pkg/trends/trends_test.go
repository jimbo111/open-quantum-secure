package trends

import (
	"strings"
	"testing"

	"github.com/jimbo111/open-quantum-secure/pkg/store"
)

func makeRecord(timestamp string, qrs int, grade string, total, critical, high, medium, low, info int) store.ScanRecord {
	return store.ScanRecord{
		Timestamp:             timestamp,
		QuantumReadinessScore: qrs,
		QuantumReadinessGrade: grade,
		FindingSummary: store.FindingSummary{
			Total:    total,
			Critical: critical,
			High:     high,
			Medium:   medium,
			Low:      low,
			Info:     info,
		},
	}
}

// makeRecordQR creates a ScanRecord with explicit quantum-risk counts.
func makeRecordQR(timestamp string, qrs int, grade string, total, vulnerable, deprecated, safe int) store.ScanRecord {
	return store.ScanRecord{
		Timestamp:             timestamp,
		QuantumReadinessScore: qrs,
		QuantumReadinessGrade: grade,
		FindingSummary: store.FindingSummary{
			Total:             total,
			QuantumVulnerable: vulnerable,
			Deprecated:        deprecated,
			QuantumSafe:       safe / 2,
			QuantumResistant:  safe - safe/2,
		},
	}
}

func TestCompute(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name           string
		records        []store.ScanRecord
		wantDataPoints int
		wantDeltaQRS   int
		wantImproving  bool
		wantSummaryHas string
		wantVulnerable int // last DataPoint.Vulnerable
		wantDeltaVuln  int
	}{
		{
			name:           "empty records",
			records:        []store.ScanRecord{},
			wantDataPoints: 0,
			wantDeltaQRS:   0,
			wantImproving:  false,
			wantSummaryHas: "No scan data",
		},
		{
			name: "single record",
			records: []store.ScanRecord{
				makeRecord("2026-04-01T00:00:00Z", 45, "D", 120, 20, 30, 40, 20, 10),
			},
			wantDataPoints: 1,
			wantDeltaQRS:   0,
			wantImproving:  false,
			wantSummaryHas: "1 scan recorded",
			wantVulnerable: 50, // critical(20) + high(30)
		},
		{
			name: "two records improving",
			records: []store.ScanRecord{
				makeRecord("2026-04-01T00:00:00Z", 45, "D", 120, 20, 30, 40, 20, 10),
				makeRecord("2026-04-02T00:00:00Z", 52, "C", 115, 18, 27, 38, 22, 10),
			},
			wantDataPoints: 2,
			wantDeltaQRS:   7,
			wantImproving:  true,
			wantSummaryHas: "45→52",
			wantVulnerable: 45, // critical(18) + high(27)
			wantDeltaVuln:  -5, // 45 - 50
		},
		{
			name: "two records degrading",
			records: []store.ScanRecord{
				makeRecord("2026-04-01T00:00:00Z", 60, "C", 80, 10, 15, 30, 20, 5),
				makeRecord("2026-04-02T00:00:00Z", 50, "D", 100, 20, 25, 35, 15, 5),
			},
			wantDataPoints: 2,
			wantDeltaQRS:   -10,
			wantImproving:  false, // QRS fell, vulnerable rose
			wantSummaryHas: "degraded",
			wantVulnerable: 45, // critical(20) + high(25)
			wantDeltaVuln:  20, // 45 - 25
		},
		{
			name: "multiple records first-to-last delta",
			records: []store.ScanRecord{
				makeRecord("2026-03-01T00:00:00Z", 30, "F", 200, 50, 60, 60, 20, 10),
				makeRecord("2026-03-15T00:00:00Z", 40, "D", 160, 40, 50, 45, 18, 7),
				makeRecord("2026-04-01T00:00:00Z", 55, "C", 130, 25, 35, 40, 22, 8),
			},
			wantDataPoints: 3,
			wantDeltaQRS:   25, // 55 - 30
			wantImproving:  true,
			wantSummaryHas: "over 3 scans",
			wantVulnerable: 60, // critical(25) + high(35)
			wantDeltaVuln:  -50, // 60 - 110
		},
		{
			name: "records with zero findings",
			records: []store.ScanRecord{
				makeRecord("2026-04-01T00:00:00Z", 100, "A+", 0, 0, 0, 0, 0, 0),
				makeRecord("2026-04-02T00:00:00Z", 100, "A+", 0, 0, 0, 0, 0, 0),
			},
			wantDataPoints: 2,
			wantDeltaQRS:   0,
			wantImproving:  false, // QRS unchanged, vulnerable unchanged (0 == 0, not decreased)
			wantSummaryHas: "unchanged",
			wantVulnerable: 0,
			wantDeltaVuln:  0,
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			td := Compute("test-project", tc.records)

			if td.Project != "test-project" {
				t.Errorf("Project = %q, want %q", td.Project, "test-project")
			}
			if len(td.DataPoints) != tc.wantDataPoints {
				t.Errorf("DataPoints count = %d, want %d", len(td.DataPoints), tc.wantDataPoints)
			}
			if td.Delta.QRS != tc.wantDeltaQRS {
				t.Errorf("Delta.QRS = %d, want %d", td.Delta.QRS, tc.wantDeltaQRS)
			}
			if td.Delta.Improving != tc.wantImproving {
				t.Errorf("Delta.Improving = %v, want %v", td.Delta.Improving, tc.wantImproving)
			}
			if !strings.Contains(td.Summary, tc.wantSummaryHas) {
				t.Errorf("Summary = %q, want it to contain %q", td.Summary, tc.wantSummaryHas)
			}

			if tc.wantDataPoints > 0 {
				last := td.DataPoints[len(td.DataPoints)-1]
				if last.Vulnerable != tc.wantVulnerable {
					t.Errorf("last DataPoint.Vulnerable = %d, want %d", last.Vulnerable, tc.wantVulnerable)
				}
			}
			if tc.wantDataPoints >= 2 {
				if td.Delta.Vulnerable != tc.wantDeltaVuln {
					t.Errorf("Delta.Vulnerable = %d, want %d", td.Delta.Vulnerable, tc.wantDeltaVuln)
				}
			}
		})
	}
}

func TestComputeDataPointFields(t *testing.T) {
	t.Parallel()

	r := makeRecord("2026-04-01T12:00:00Z", 72, "B", 90, 5, 10, 30, 35, 10)
	td := Compute("proj", []store.ScanRecord{r})

	if len(td.DataPoints) != 1 {
		t.Fatalf("expected 1 DataPoint, got %d", len(td.DataPoints))
	}
	dp := td.DataPoints[0]

	if dp.Timestamp != "2026-04-01T12:00:00Z" {
		t.Errorf("Timestamp = %q, want %q", dp.Timestamp, "2026-04-01T12:00:00Z")
	}
	if dp.QRS != 72 {
		t.Errorf("QRS = %d, want 72", dp.QRS)
	}
	if dp.Grade != "B" {
		t.Errorf("Grade = %q, want B", dp.Grade)
	}
	if dp.Findings != 90 {
		t.Errorf("Findings = %d, want 90", dp.Findings)
	}
	// Vulnerable = Critical(5) + High(10)
	if dp.Vulnerable != 15 {
		t.Errorf("Vulnerable = %d, want 15 (critical+high)", dp.Vulnerable)
	}
	// Deprecated = Medium(30)
	if dp.Deprecated != 30 {
		t.Errorf("Deprecated = %d, want 30 (medium)", dp.Deprecated)
	}
	// Safe = Low(35) + Info(10)
	if dp.Safe != 45 {
		t.Errorf("Safe = %d, want 45 (low+info)", dp.Safe)
	}
}

func TestComputeDeltaFindingsAndDeprecated(t *testing.T) {
	t.Parallel()

	records := []store.ScanRecord{
		makeRecord("2026-04-01T00:00:00Z", 40, "D", 100, 10, 20, 50, 15, 5),
		makeRecord("2026-04-02T00:00:00Z", 48, "D", 90, 8, 18, 40, 18, 6),
	}
	td := Compute("proj", records)

	// Delta.Findings = 90 - 100 = -10
	if td.Delta.Findings != -10 {
		t.Errorf("Delta.Findings = %d, want -10", td.Delta.Findings)
	}
	// Delta.Deprecated = Medium(40) - Medium(50) = -10
	if td.Delta.Deprecated != -10 {
		t.Errorf("Delta.Deprecated = %d, want -10", td.Delta.Deprecated)
	}
}

func TestComputeImprovingQRSOnly(t *testing.T) {
	t.Parallel()

	// QRS increased but vulnerable also increased — still improving (QRS is primary)
	records := []store.ScanRecord{
		makeRecord("2026-04-01T00:00:00Z", 40, "D", 80, 5, 10, 30, 25, 10),
		makeRecord("2026-04-02T00:00:00Z", 50, "D", 90, 8, 15, 35, 22, 10),
	}
	td := Compute("proj", records)

	if !td.Delta.Improving {
		t.Error("Delta.Improving = false, want true (QRS increased)")
	}
}

func TestComputeImprovingVulnerableOnly(t *testing.T) {
	t.Parallel()

	// QRS unchanged, but vulnerable decreased — still improving
	records := []store.ScanRecord{
		makeRecord("2026-04-01T00:00:00Z", 50, "D", 100, 20, 30, 30, 15, 5),
		makeRecord("2026-04-02T00:00:00Z", 50, "D", 90, 10, 20, 35, 20, 5),
	}
	td := Compute("proj", records)

	if !td.Delta.Improving {
		t.Error("Delta.Improving = false, want true (vulnerable decreased)")
	}
}

func TestComputeSummaryVulnerableDecreased(t *testing.T) {
	t.Parallel()

	records := []store.ScanRecord{
		makeRecord("2026-04-01T00:00:00Z", 45, "D", 120, 20, 30, 40, 20, 10),
		makeRecord("2026-04-02T00:00:00Z", 52, "C", 115, 18, 27, 38, 22, 10),
	}
	td := Compute("proj", records)

	if !strings.Contains(td.Summary, "decreased by 5") {
		t.Errorf("Summary = %q, want it to mention 'decreased by 5'", td.Summary)
	}
}

func TestComputeNilDataPointsNeverNil(t *testing.T) {
	t.Parallel()

	td := Compute("proj", []store.ScanRecord{})
	if td.DataPoints == nil {
		t.Error("DataPoints should be non-nil even for empty records")
	}
}
