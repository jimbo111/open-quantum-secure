package output

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"unicode/utf8"
)

var useColor = os.Getenv("NO_COLOR") == "" && os.Getenv("TERM") != "dumb"

func colorize(code, s string) string {
	if !useColor {
		return s
	}
	return "\033[" + code + "m" + s + "\033[0m"
}

// WriteTable writes findings as a human-readable table.
func WriteTable(w io.Writer, result ScanResult) error {
	if len(result.Findings) == 0 {
		fmt.Fprintf(w, "No findings detected in %s\n", result.Target)
		if len(result.Engines) > 0 {
			fmt.Fprintf(w, "Scanned with: %s\n", strings.Join(result.Engines, ", "))
		}
		fmt.Fprintf(w, "%s\n", colorize("90", "Tip: run 'oqs-scanner engines doctor' to verify engine coverage."))
		return nil
	}

	// Header
	fmt.Fprintf(w, "\nOQS Scanner v%s — %s\n", result.Version, result.Target)
	fmt.Fprintf(w, "Engines: %s\n", strings.Join(result.Engines, ", "))
	fmt.Fprintf(w, "%s\n", strings.Repeat("─", 80))
	fmt.Fprintf(w, "%s\n", colorize("90", "Legend: [QV]=Vulnerable [QW]=Weakened [QS]=Safe [QR]=Resistant [DEP]=Deprecated [HNDL:IMM/DEF]=Harvest-Now-Decrypt-Later [PQC]=PQC-negotiated"))
	fmt.Fprintln(w)

	// Column widths
	const (
		typeW = 12
		nameW = 28
		fileW = 30
		locW  = 8
	)

	// Header row
	fmt.Fprintf(w, "%-*s %-*s %-*s %-*s %s\n",
		typeW, "TYPE",
		nameW, "IDENTIFIER",
		fileW, "FILE",
		locW, "LINE",
		"DETAILS",
	)
	fmt.Fprintf(w, "%s\n", strings.Repeat("─", 80))

	for _, f := range result.Findings {
		typ := "algorithm"
		name := ""
		details := ""

		if f.Dependency != nil {
			typ = "dependency"
			name = f.Dependency.Library
		}

		if f.Algorithm != nil {
			typ = "algorithm"
			name = f.Algorithm.Name
			var parts []string
			if f.Algorithm.Primitive != "" {
				parts = append(parts, f.Algorithm.Primitive)
			}
			if f.Algorithm.KeySize > 0 {
				parts = append(parts, fmt.Sprintf("%d-bit", f.Algorithm.KeySize))
			}
			if f.Algorithm.Mode != "" {
				parts = append(parts, f.Algorithm.Mode)
			}
			if f.Algorithm.Curve != "" {
				parts = append(parts, f.Algorithm.Curve)
			}
			details = strings.Join(parts, ", ")
		}

		// Quantum risk badge
		if f.QuantumRisk != "" && string(f.QuantumRisk) != "unknown" {
			badge := riskBadge(string(f.QuantumRisk))
			if details != "" {
				details += " "
			}
			details += badge
		}

		// HNDL risk badge
		if f.HNDLRisk != "" {
			hndlBadge := "[HNDL:IMM]"
			if f.HNDLRisk == "deferred" {
				hndlBadge = "[HNDL:DEF]"
			}
			if details != "" {
				details += " "
			}
			details += hndlBadge
		}

		// PQC-presence badge (tls-probe findings only)
		if f.PQCPresent {
			pqcBadge := colorize("32", "[PQC]")
			if f.PQCMaturity == "draft" {
				pqcBadge = colorize("33", "[PQC:DRAFT]")
			}
			if details != "" {
				details += " "
			}
			details += pqcBadge
		}

		// Binary artifact badge
		if f.Location.ArtifactType != "" {
			if details != "" {
				details += " "
			}
			details += "[BIN]"
		}

		// Config scanner badge
		if f.SourceEngine == "config-scanner" {
			if details != "" {
				details += " "
			}
			details += "[CFG]"
		}

		// Migration effort badge
		if badge := effortBadge(f.MigrationEffort); badge != "" {
			if details != "" {
				details += " "
			}
			details += badge
		}

		if len(f.CorroboratedBy) > 0 {
			if details != "" {
				details += " "
			}
			details += "[+" + strings.Join(f.CorroboratedBy, ",") + "]"
		}

		shortFile := shortenPath(f.Location.File, fileW)

		fmt.Fprintf(w, "%-*s %-*s %-*s %-*d %s\n",
			typeW, typ,
			nameW, truncate(name, nameW),
			fileW, shortFile,
			locW, f.Location.Line,
			details,
		)
	}

	// Summary
	fmt.Fprintf(w, "\n%s\n", strings.Repeat("─", 80))
	summary := fmt.Sprintf("Total: %d findings (%d algorithms, %d dependencies",
		result.Summary.TotalFindings,
		result.Summary.Algorithms,
		result.Summary.Dependencies,
	)
	if result.Summary.Corroborated > 0 {
		summary += fmt.Sprintf(", %d corroborated", result.Summary.Corroborated)
	}
	summary += ")"
	fmt.Fprintln(w, summary)

	// Quantum risk breakdown
	if result.Summary.QuantumVulnerable > 0 || result.Summary.Deprecated > 0 {
		fmt.Fprintf(w, "Quantum: %d vulnerable, %d weakened, %d safe/resistant, %d deprecated\n",
			result.Summary.QuantumVulnerable,
			result.Summary.QuantumWeakened,
			result.Summary.QuantumSafe+result.Summary.QuantumResistant,
			result.Summary.Deprecated,
		)
	}

	// HNDL count
	var hndlImm, hndlDef int
	for _, f := range result.Findings {
		switch f.HNDLRisk {
		case "immediate":
			hndlImm++
		case "deferred":
			hndlDef++
		}
	}
	if hndlImm > 0 || hndlDef > 0 {
		fmt.Fprintf(w, "HNDL Risk: %s immediate (key exchange, by 2030), %s deferred (signatures, by 2035)\n",
			colorize("1;31", fmt.Sprintf("%d", hndlImm)),
			colorize("33", fmt.Sprintf("%d", hndlDef)))
	}

	// QRS (Quantum Readiness Score)
	if result.QRS != nil {
		gradeColor := "0"
		switch {
		case result.QRS.Score >= 85:
			gradeColor = "1;32" // bold green
		case result.QRS.Score >= 70:
			gradeColor = "34" // blue
		case result.QRS.Score >= 50:
			gradeColor = "33" // yellow
		case result.QRS.Score >= 30:
			gradeColor = "1;33" // bold yellow
		default:
			gradeColor = "1;31" // bold red
		}
		fmt.Fprintf(w, "Quantum Readiness Score: %s (Grade: %s)\n",
			colorize(gradeColor, fmt.Sprintf("%d/100", result.QRS.Score)),
			colorize(gradeColor, result.QRS.Grade))

		if result.Summary.QuantumVulnerable > 0 {
			fmt.Fprintf(w, "\n%s\n", colorize("90", "Tip: run with --format html for a detailed report, or --compliance cnsa-2.0 to evaluate CNSA 2.0 posture."))
		}
	}

	return nil
}

// truncate clips s so the visible width is at most maxLen runes, appending
// an ellipsis when truncation occurs. Width is measured in runes — not bytes
// — so multi-byte input (Korean filenames, accented identifiers) is never
// cut mid-rune. A naive byte slice was producing invalid UTF-8 in the table
// output for non-ASCII paths.
func truncate(s string, maxLen int) string {
	if maxLen <= 0 {
		return ""
	}
	if utf8.RuneCountInString(s) <= maxLen {
		return s
	}
	// Reserve one rune for the ellipsis.
	runes := []rune(s)
	if maxLen == 1 {
		return "…"
	}
	return string(runes[:maxLen-1]) + "…"
}

func riskBadge(risk string) string {
	switch risk {
	case "quantum-vulnerable":
		return colorize("1;31", "[QV]") // bold red
	case "quantum-weakened":
		return colorize("33", "[QW]") // yellow
	case "quantum-safe":
		return colorize("32", "[QS]") // green
	case "quantum-resistant":
		return colorize("34", "[QR]") // blue
	case "deprecated":
		return colorize("90", "[DEP]") // gray
	default:
		return ""
	}
}

func effortBadge(effort string) string {
	switch effort {
	case "simple":
		return colorize("32", "[EFFORT:S]")
	case "moderate":
		return colorize("33", "[EFFORT:M]")
	case "complex":
		return colorize("1;31", "[EFFORT:C]")
	}
	return ""
}

// shortenPath returns a short rendering of path that fits within maxLen runes.
// Width is measured in runes (not bytes) so non-ASCII filenames render
// correctly and never split a multi-byte UTF-8 sequence.
func shortenPath(path string, maxLen int) string {
	if utf8.RuneCountInString(path) <= maxLen {
		return path
	}
	// Show just filename or last two components.
	short := filepath.Join("…", filepath.Base(filepath.Dir(path)), filepath.Base(path))
	if utf8.RuneCountInString(short) > maxLen {
		short = filepath.Base(path)
	}
	return truncate(short, maxLen)
}
