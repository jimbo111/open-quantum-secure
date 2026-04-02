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
	Standard      string    // e.g. "CNSA 2.0"
	Project       string
	ScanDate      time.Time
	ScannerVer    string
	TotalFindings int
	Violations    []Violation
	Algorithms    []AlgorithmSummary // unique algorithms found, deduped by name
	Compliant     bool
}

// AlgorithmSummary is a deduplicated view of a single algorithm across all findings.
type AlgorithmSummary struct {
	Name        string `json:"name"`
	Risk        string `json:"risk"`        // human-readable quantum risk label
	Effort      string `json:"effort"`      // migration effort: simple, moderate, complex, or "-"
	Compliant   bool   `json:"compliant"`   // true when no violation exists for this algorithm
	Occurrences int    `json:"occurrences"` // number of findings that reference this algorithm
}

// BuildReportData constructs a ReportData from raw scan findings and the
// violations returned by Evaluate. It deduplicates algorithms by name and
// counts occurrences.
//
// project and scannerVer may be empty; ScanDate defaults to time.Now() when
// the zero value is passed.
func BuildReportData(
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
		Standard:      "CNSA 2.0",
		Project:       project,
		ScanDate:      scanDate,
		ScannerVer:    scannerVer,
		TotalFindings: len(ff),
		Violations:    violations,
		Algorithms:    algSummaries,
		Compliant:     len(violations) == 0,
	}
}

// GenerateMarkdown writes a formal CNSA 2.0 compliance report in markdown to w.
// mdEscape escapes pipe characters and newlines that would break markdown tables.
func mdEscape(s string) string {
	s = strings.ReplaceAll(s, "|", "\\|")
	s = strings.ReplaceAll(s, "\n", " ")
	s = strings.ReplaceAll(s, "\r", "")
	return s
}

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

	// --- Header block ---
	if _, err := fmt.Fprintf(w,
		"# CNSA 2.0 Compliance Report\n\n"+
			"**Organization:** %s\n"+
			"**Date:** %s\n"+
			"**Scanner Version:** OQS Scanner %s\n"+
			"**Standard:** NSA CNSA 2.0 (May 2025)\n"+
			"**Status:** %s (%s)\n\n"+
			"---\n\n",
		projectOrDefault(data.Project),
		scanDateStr,
		versionStr,
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
			"%s was scanned for CNSA 2.0 compliance on %s. The scan found\n%d cryptographic algorithm %s across %d unique %s.\n",
			projectOrDefault(data.Project), scanDateStr, total, usageWord, uniqueCount, algWord,
		)
		if data.Compliant {
			base += "All algorithms meet CNSA 2.0 requirements."
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
	if _, err := fmt.Fprint(w,
		"| Algorithm | Risk | CNSA 2.0 Status | Migration Effort | Occurrences |\n"+
			"|-----------|------|-----------------|-----------------|-------------|\n",
	); err != nil {
		return err
	}
	if len(data.Algorithms) == 0 {
		if _, err := fmt.Fprint(w, "| — | — | — | — | — |\n"); err != nil {
			return err
		}
	}
	for _, a := range data.Algorithms {
		cnsa20Status := "Approved"
		if !a.Compliant {
			cnsa20Status = "NOT APPROVED"
		}
		effort := a.Effort
		if effort == "" {
			effort = "-"
		}
		if _, err := fmt.Fprintf(w, "| %s | %s | %s | %s | %d |\n",
			mdEscape(a.Name), mdEscape(a.Risk), cnsa20Status, effort, a.Occurrences,
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
		if _, err := fmt.Fprintf(w,
			"### [%d] %s\n\n"+
				"**Algorithm:** %s\n"+
				"**Rule:** %s\n"+
				"**Deadline:** %s\n"+
				"**Remediation:** %s\n\n",
			i+1,
			v.Rule,
			algName,
			v.Message,
			v.Deadline,
			remediationForRule(v.Rule, v.Algorithm),
		); err != nil {
			return err
		}
	}

	// --- Approved Algorithms Reference ---
	if _, err := fmt.Fprint(w,
		"## CNSA 2.0 Approved Algorithms Reference\n\n"+
			"| Use Case | Approved Algorithm | NIST Standard |\n"+
			"|----------|-------------------|---------------|\n"+
			"| Key Exchange | ML-KEM-1024 | FIPS 203 |\n"+
			"| Digital Signatures | ML-DSA-87 | FIPS 204 |\n"+
			"| Firmware/Software Signing | LMS/HSS, XMSS/XMSS^MT | SP 800-208 |\n"+
			"| Symmetric Encryption | AES-256 | FIPS 197 |\n"+
			"| Hashing | SHA-384, SHA-512 | FIPS 180-4 |\n\n",
	); err != nil {
		return err
	}

	// --- Key Deadlines ---
	if _, err := fmt.Fprint(w,
		"## Key Deadlines\n\n"+
			"- **2030-01-01:** All key exchange must use ML-KEM-1024\n"+
			"- **2035-12-31:** Full CNSA 2.0 transition complete\n\n"+
			"---\n\n",
	); err != nil {
		return err
	}

	// --- Footer ---
	_, err := fmt.Fprintf(w,
		"*Generated by OQS Scanner %s on %s*\n",
		versionStr,
		data.ScanDate.Format("2006-01-02 15:04:05 MST"),
	)
	return err
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

// remediationForRule returns actionable remediation text for a known CNSA 2.0 rule.
func remediationForRule(rule, algorithm string) string {
	switch rule {
	case "cnsa2-quantum-vulnerable":
		upper := strings.ToUpper(algorithm)
		switch {
		case strings.HasPrefix(upper, "RSA"), strings.HasPrefix(upper, "DH"),
			strings.Contains(upper, "DIFFIE"):
			return "Migrate to ML-KEM-1024 for key exchange or ML-DSA-87 for digital signatures"
		case strings.HasPrefix(upper, "EC"), strings.HasPrefix(upper, "ECDH"),
			strings.HasPrefix(upper, "ECDSA"):
			return "Migrate to ML-KEM-1024 for key exchange or ML-DSA-87 for digital signatures"
		case strings.HasPrefix(upper, "DSA"):
			return "Migrate to ML-DSA-87 for digital signatures"
		default:
			return "Replace with an approved CNSA 2.0 algorithm (ML-KEM-1024, ML-DSA-87, AES-256, SHA-384/SHA-512)"
		}
	case "cnsa2-ml-kem-key-size":
		return "Upgrade to ML-KEM-1024; ML-KEM-512 and ML-KEM-768 do not meet CNSA 2.0 minimum"
	case "cnsa2-ml-dsa-param-set":
		return "Upgrade to ML-DSA-87; ML-DSA-44 and ML-DSA-65 do not meet CNSA 2.0 minimum"
	case "cnsa2-slh-dsa-excluded":
		return "Replace with ML-DSA-87; SLH-DSA (FIPS 205) is excluded from CNSA 2.0 despite NIST approval"
	case "cnsa2-hashml-dsa-excluded":
		return "Replace with ML-DSA-87; HashML-DSA is not approved for CNSA 2.0"
	case "cnsa2-symmetric-key-size":
		return "Upgrade to AES-256; smaller AES key sizes do not meet CNSA 2.0 requirements"
	case "cnsa2-symmetric-unapproved":
		return "Replace with AES-256; only AES is approved for symmetric encryption under CNSA 2.0"
	case "cnsa2-hash-output-size":
		return "Upgrade to SHA-384 or SHA-512; shorter hash outputs do not meet CNSA 2.0 requirements"
	case "cnsa2-hash-unapproved":
		return "Replace with SHA-384 or SHA-512 (SHA-2 family only); SHA-3 and other hash families are not approved"
	default:
		return "Review and remediate per NSA CNSA 2.0 guidance"
	}
}

// projectOrDefault returns the project name or a placeholder when empty.
func projectOrDefault(project string) string {
	if project == "" {
		return "(unspecified)"
	}
	return project
}
