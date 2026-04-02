package output

import (
	"embed"
	"fmt"
	"html/template"
	"io"
	"path/filepath"
	"strings"
	"time"

	"github.com/jimbo111/open-quantum-secure/pkg/findings"
)

//go:embed templates/report.html.tmpl
var htmlTemplateFS embed.FS

// WriteHTML writes findings as a self-contained HTML report.
func WriteHTML(w io.Writer, result ScanResult) error {
	funcMap := template.FuncMap{
		"joinStrings":  joinStringsFunc,
		"gradeColor":   gradeColorFunc,
		"riskColor":    riskColorFunc,
		"riskLabel":    riskLabelFunc,
		"sevColor":     sevColorFunc,
		"now":          func() string { return time.Now().Format("2006-01-02 15:04:05 MST") },
		"hasFlowPath":  func(path []findings.FlowStep) bool { return len(path) > 0 },
		"reachBadge": reachBadgeFunc,
		"reachLabel": reachLabelFunc,
		"reachSort":  reachSortFunc,
		"shortPath":  shortPathFunc,
	}

	tmpl, err := template.New("report.html.tmpl").Funcs(funcMap).ParseFS(htmlTemplateFS, "templates/report.html.tmpl")
	if err != nil {
		return fmt.Errorf("parse HTML template: %w", err)
	}
	return tmpl.Execute(w, result)
}

func joinStringsFunc(ss []string, sep string) string {
	return strings.Join(ss, sep)
}

// reachBadgeFunc returns the CSS class suffix for a reachability value.
// The returned value is used as: badge-{value}.
func reachBadgeFunc(r findings.Reachability) string {
	switch r {
	case findings.ReachableYes:
		return "reachable"
	case findings.ReachableNo:
		return "unreachable"
	default:
		return "unknown"
	}
}

// reachLabelFunc returns the human-readable label for a reachability value.
func reachLabelFunc(r findings.Reachability) string {
	switch r {
	case findings.ReachableYes:
		return "Yes"
	case findings.ReachableNo:
		return "No"
	default:
		return "Unknown"
	}
}

// reachSortFunc returns a numeric sort key for reachability.
// Yes=0 (most urgent — confirmed exposure), Unknown=1, No=2 (least urgent).
// Ascending sort surfaces actionable findings first for triage workflow.
func reachSortFunc(r findings.Reachability) int {
	switch r {
	case findings.ReachableYes:
		return 0
	case findings.ReachableNo:
		return 2
	default:
		return 1
	}
}

// gradeColorFunc returns a CSS color for a QRS grade letter.
func gradeColorFunc(grade string) string {
	switch {
	case strings.HasPrefix(grade, "A"):
		return "#22c55e"
	case strings.HasPrefix(grade, "B"):
		return "#3b82f6"
	case strings.HasPrefix(grade, "C"):
		return "#eab308"
	case strings.HasPrefix(grade, "D"):
		return "#f97316"
	default: // F
		return "#ef4444"
	}
}

// riskColorFunc returns the CSS class suffix for a quantum risk level.
// The returned value is used as: badge-{value}.
func riskColorFunc(risk findings.QuantumRisk) string {
	switch risk {
	case findings.QRVulnerable:
		return "vulnerable"
	case findings.QRWeakened:
		return "weakened"
	case findings.QRSafe:
		return "safe"
	case findings.QRResistant:
		return "resistant"
	case findings.QRDeprecated:
		return "deprecated"
	default:
		return "unknown"
	}
}

// riskLabelFunc returns the human-readable label for a quantum risk level.
func riskLabelFunc(risk findings.QuantumRisk) string {
	switch risk {
	case findings.QRVulnerable:
		return "Vulnerable"
	case findings.QRWeakened:
		return "Weakened"
	case findings.QRSafe:
		return "Safe"
	case findings.QRResistant:
		return "Resistant"
	case findings.QRDeprecated:
		return "Deprecated"
	default:
		return "Unknown"
	}
}

// sevColorFunc returns the CSS class suffix for a severity level.
// The returned value is used as: badge-{value}.
func sevColorFunc(sev findings.Severity) string {
	switch sev {
	case findings.SevCritical:
		return "critical"
	case findings.SevHigh:
		return "high"
	case findings.SevMedium:
		return "medium"
	case findings.SevLow:
		return "low"
	case findings.SevInfo:
		return "info"
	default:
		return "unknown"
	}
}

// shortPathFunc returns the last 2 path segments of p, prefixed with "…/".
// This ensures the table cell shows the meaningful tail of the path instead
// of a common prefix that gets clipped by CSS overflow: hidden truncation.
// If the path has 2 or fewer segments the original value is returned unchanged.
func shortPathFunc(p string) string {
	parts := strings.Split(filepath.ToSlash(p), "/")
	if len(parts) <= 2 {
		return p
	}
	return "\u2026/" + strings.Join(parts[len(parts)-2:], "/")
}
