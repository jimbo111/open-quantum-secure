package compliance

import (
	"fmt"
	"io"
	"sort"
	"strings"
	"time"

	"github.com/jimbo111/open-quantum-secure/pkg/findings"
)

// ReportData holds all information needed to generate a compliance report.
type ReportData struct {
	Standard      string // e.g. "CNSA 2.0"
	FrameworkDesc string // e.g. "NSA CNSA 2.0 (May 2025)"
	Project       string
	ScanDate      time.Time
	ScannerVer    string
	TotalFindings int
	Violations    []Violation
	Algorithms    []AlgorithmSummary // unique algorithms found, deduped by name
	Compliant     bool
	ApprovedAlgos []ApprovedAlgoRef // reference table from the framework
	Deadlines     []DeadlineRef     // transition deadlines from the framework
}

// AlgorithmSummary is a deduplicated view of a single algorithm across all findings.
type AlgorithmSummary struct {
	Name        string `json:"name"`
	Risk        string `json:"risk"`        // human-readable quantum risk label
	Effort      string `json:"effort"`      // migration effort: simple, moderate, complex, or "-"
	Compliant   bool   `json:"compliant"`   // true when no violation exists for this algorithm
	Occurrences int    `json:"occurrences"` // number of findings that reference this algorithm
}

// BuildReportData constructs a ReportData from a Framework, raw scan findings, and
// the violations returned by fw.Evaluate. It deduplicates algorithms by name and
// counts occurrences.
//
// project and scannerVer may be empty; ScanDate defaults to time.Now() when
// the zero value is passed.
func BuildReportData(
	fw Framework,
	ff []findings.UnifiedFinding,
	violations []Violation,
	project string,
	scannerVer string,
	scanDate time.Time,
) ReportData {
	if scanDate.IsZero() {
		scanDate = time.Now()
	}

	// Build a set of algorithm names that have at least one violation.
	violatedAlgs := make(map[string]struct{}, len(violations))
	for _, v := range violations {
		if v.Algorithm != "" {
			violatedAlgs[v.Algorithm] = struct{}{}
		}
	}

	// Accumulate per-algorithm occurrence counts and risk labels.
	type algMeta struct {
		risk        string
		effort      string
		occurrences int
	}
	algMap := make(map[string]*algMeta)

	for i := range ff {
		f := &ff[i]
		var name, risk, effort string
		if f.Algorithm != nil && f.Algorithm.Name != "" {
			name = f.Algorithm.Name
		} else if f.Dependency != nil && f.Dependency.Library != "" {
			name = f.Dependency.Library
		} else if f.RawIdentifier != "" {
			name = f.RawIdentifier
		}
		if name == "" {
			continue
		}
		risk = quantumRiskLabel(f.QuantumRisk)
		effort = f.MigrationEffort
		if effort == "" {
			effort = "-"
		}

		if m, ok := algMap[name]; ok {
			m.occurrences++
			// Prefer the most informative risk label (non-unknown wins).
			if m.risk == "Unknown" && risk != "Unknown" {
				m.risk = risk
			}
			// Prefer a real effort value.
			if m.effort == "-" && effort != "-" {
				m.effort = effort
			}
		} else {
			algMap[name] = &algMeta{risk: risk, effort: effort, occurrences: 1}
		}
	}

	// Sort algorithm names for deterministic output.
	algNames := make([]string, 0, len(algMap))
	for n := range algMap {
		algNames = append(algNames, n)
	}
	sort.Strings(algNames)

	algSummaries := make([]AlgorithmSummary, 0, len(algNames))
	for _, n := range algNames {
		m := algMap[n]
		_, violated := violatedAlgs[n]
		algSummaries = append(algSummaries, AlgorithmSummary{
			Name:        n,
			Risk:        m.risk,
			Effort:      m.effort,
			Compliant:   !violated,
			Occurrences: m.occurrences,
		})
	}

	return ReportData{
		Standard:      fw.Name(),
		FrameworkDesc: fw.Description(),
		Project:       project,
		ScanDate:      scanDate,
		ScannerVer:    scannerVer,
		TotalFindings: len(ff),
		Violations:    violations,
		Algorithms:    algSummaries,
		Compliant:     len(violations) == 0,
		ApprovedAlgos: fw.ApprovedAlgos(),
		Deadlines:     fw.Deadlines(),
	}
}

// GenerateMarkdown writes a formal compliance report in markdown to w.
// It is framework-agnostic: all framework-specific strings come from data fields.
func GenerateMarkdown(w io.Writer, data ReportData) error {
	status := "PASS"
	statusDetail := "no violations"
	if !data.Compliant {
		n := len(data.Violations)
		status = "FAIL"
		if n == 1 {
			statusDetail = "1 violation"
		} else {
			statusDetail = fmt.Sprintf("%d violations", n)
		}
	}

	scanDateStr := data.ScanDate.Format("2006-01-02")
	versionStr := data.ScannerVer
	if versionStr != "" && !strings.HasPrefix(versionStr, "v") {
		versionStr = "v" + versionStr
	}

	frameworkDesc := data.FrameworkDesc
	if frameworkDesc == "" {
		frameworkDesc = data.Standard
	}

	// --- Header block ---
	if _, err := fmt.Fprintf(w,
		"# %s Compliance Report\n\n"+
			"**Organization:** %s\n"+
			"**Date:** %s\n"+
			"**Scanner Version:** OQS Scanner %s\n"+
			"**Standard:** %s\n"+
			"**Status:** %s (%s)\n\n"+
			"---\n\n",
		data.Standard,
		projectOrDefault(data.Project),
		scanDateStr,
		versionStr,
		frameworkDesc,
		status,
		statusDetail,
	); err != nil {
		return err
	}

	// --- Executive Summary ---
	uniqueCount := len(data.Algorithms)
	var summaryBody string
	if uniqueCount == 0 {
		summaryBody = "No cryptographic algorithms were found during the scan."
	} else {
		total := data.TotalFindings
		algWord := "algorithms"
		if uniqueCount == 1 {
			algWord = "algorithm"
		}
		usageWord := "usages"
		if total == 1 {
			usageWord = "usage"
		}
		base := fmt.Sprintf(
			"%s was scanned for %s compliance on %s. The scan found\n%d cryptographic algorithm %s across %d unique %s.\n",
			projectOrDefault(data.Project), data.Standard, scanDateStr, total, usageWord, uniqueCount, algWord,
		)
		if data.Compliant {
			base += "All algorithms meet " + data.Standard + " requirements."
		} else {
			n := len(data.Violations)
			if n == 1 {
				base += "1 violation was found requiring remediation."
			} else {
				base += fmt.Sprintf("%d violations were found requiring remediation.", n)
			}
		}
		summaryBody = base
	}

	if _, err := fmt.Fprintf(w, "## Executive Summary\n\n%s\n\n", summaryBody); err != nil {
		return err
	}

	// --- Compliance Status table ---
	if _, err := fmt.Fprint(w, "## Compliance Status\n\n"); err != nil {
		return err
	}
	statusHeader := data.Standard + " Status"
	if _, err := fmt.Fprintf(w,
		"| Algorithm | Risk | %s | Migration Effort | Occurrences |\n"+
			"|-----------|------|%s|-----------------|-------------|\n",
		statusHeader,
		strings.Repeat("-", len(statusHeader)+2),
	); err != nil {
		return err
	}
	if len(data.Algorithms) == 0 {
		if _, err := fmt.Fprint(w, "| — | — | — | — | — |\n"); err != nil {
			return err
		}
	}
	for _, a := range data.Algorithms {
		fwStatus := "Approved"
		if !a.Compliant {
			fwStatus = "NOT APPROVED"
		}
		effort := a.Effort
		if effort == "" {
			effort = "-"
		}
		if _, err := fmt.Fprintf(w, "| %s | %s | %s | %s | %d |\n",
			mdEscape(a.Name), mdEscape(a.Risk), fwStatus, effort, a.Occurrences,
		); err != nil {
			return err
		}
	}
	if _, err := fmt.Fprint(w, "\n"); err != nil {
		return err
	}

	// --- Violations ---
	if _, err := fmt.Fprint(w, "## Violations\n\n"); err != nil {
		return err
	}
	if len(data.Violations) == 0 {
		if _, err := fmt.Fprint(w, "No violations found.\n\n"); err != nil {
			return err
		}
	}
	for i, v := range data.Violations {
		algName := v.Algorithm
		if algName == "" {
			algName = "(unknown)"
		}
		remediation := v.Remediation
		if remediation == "" {
			remediation = v.Message
		}
		severity := v.Severity
		if severity == "" {
			severity = "error"
		}
		if _, err := fmt.Fprintf(w,
			"### [%d] %s\n\n"+
				"**Severity:** %s\n"+
				"**Algorithm:** %s\n"+
				"**Rule:** %s\n"+
				"**Deadline:** %s\n"+
				"**Remediation:** %s\n\n",
			i+1,
			mdEscape(v.Rule),
			mdEscape(severity),
			mdEscape(algName),
			mdEscape(v.Message),
			mdEscape(v.Deadline),
			mdEscape(remediation),
		); err != nil {
			return err
		}
	}

	// --- Approved Algorithms Reference ---
	if len(data.ApprovedAlgos) > 0 {
		if _, err := fmt.Fprintf(w,
			"## %s Approved Algorithms Reference\n\n"+
				"| Use Case | Approved Algorithm | Standard |\n"+
				"|----------|-------------------|----------|\n",
			data.Standard,
		); err != nil {
			return err
		}
		for _, a := range data.ApprovedAlgos {
			if _, err := fmt.Fprintf(w, "| %s | %s | %s |\n",
				mdEscape(a.UseCase), mdEscape(a.Algorithm), mdEscape(a.Standard),
			); err != nil {
				return err
			}
		}
		if _, err := fmt.Fprint(w, "\n"); err != nil {
			return err
		}
	}

	// --- Key Deadlines ---
	if len(data.Deadlines) > 0 {
		if _, err := fmt.Fprint(w, "## Key Deadlines\n\n"); err != nil {
			return err
		}
		for _, d := range data.Deadlines {
			if _, err := fmt.Fprintf(w, "- **%s:** %s\n", d.Date, d.Description); err != nil {
				return err
			}
		}
		if _, err := fmt.Fprint(w, "\n---\n\n"); err != nil {
			return err
		}
	} else {
		if _, err := fmt.Fprint(w, "---\n\n"); err != nil {
			return err
		}
	}

	// --- Footer ---
	_, err := fmt.Fprintf(w,
		"*Generated by OQS Scanner %s on %s*\n",
		versionStr,
		data.ScanDate.Format("2006-01-02 15:04:05 MST"),
	)
	return err
}

// mdEscape escapes pipe characters and newlines that would break markdown tables.
func mdEscape(s string) string {
	s = strings.ReplaceAll(s, "|", "\\|")
	s = strings.ReplaceAll(s, "\n", " ")
	s = strings.ReplaceAll(s, "\r", "")
	return s
}

// quantumRiskLabel converts a QuantumRisk value to a display-friendly string.
func quantumRiskLabel(qr findings.QuantumRisk) string {
	switch qr {
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

// projectOrDefault returns the project name or a placeholder when empty.
func projectOrDefault(project string) string {
	if project == "" {
		return "(unspecified)"
	}
	return project
}
