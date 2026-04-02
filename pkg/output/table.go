package output

import (
	"fmt"
	"io"
	"path/filepath"
	"strings"
)

// WriteTable writes findings as a human-readable table.
func WriteTable(w io.Writer, result ScanResult) error {
	if len(result.Findings) == 0 {
		fmt.Fprintf(w, "No findings detected in %s\n", result.Target)
		return nil
	}

	// Header
	fmt.Fprintf(w, "\nOQS Scanner v%s — %s\n", result.Version, result.Target)
	fmt.Fprintf(w, "Engines: %s\n", strings.Join(result.Engines, ", "))
	fmt.Fprintf(w, "%s\n\n", strings.Repeat("─", 80))

	// Column widths
	const (
		typeW   = 12
		nameW   = 28
		fileW   = 30
		locW    = 8
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

	// QRS (Quantum Readiness Score)
	if result.QRS != nil {
		fmt.Fprintf(w, "Quantum Readiness Score: %d/100 (Grade: %s)\n", result.QRS.Score, result.QRS.Grade)
	}

	return nil
}

func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen-1] + "…"
}

func riskBadge(risk string) string {
	switch risk {
	case "quantum-vulnerable":
		return "[QV]"
	case "quantum-weakened":
		return "[QW]"
	case "quantum-safe":
		return "[QS]"
	case "quantum-resistant":
		return "[QR]"
	case "deprecated":
		return "[DEP]"
	default:
		return ""
	}
}

func effortBadge(effort string) string {
	switch effort {
	case "simple":
		return "[EFFORT:S]"
	case "moderate":
		return "[EFFORT:M]"
	case "complex":
		return "[EFFORT:C]"
	}
	return ""
}

func shortenPath(path string, maxLen int) string {
	if len(path) <= maxLen {
		return path
	}
	// Show just filename or last two components
	short := filepath.Join("…", filepath.Base(filepath.Dir(path)), filepath.Base(path))
	if len(short) > maxLen {
		short = filepath.Base(path)
	}
	return truncate(short, maxLen)
}
