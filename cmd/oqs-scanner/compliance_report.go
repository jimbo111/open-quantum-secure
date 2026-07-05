// compliance_report.go implements the `compliance-report` subcommand.

package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/jimbo111/open-quantum-secure/pkg/compliance"
	"github.com/jimbo111/open-quantum-secure/pkg/config"
	"github.com/jimbo111/open-quantum-secure/pkg/engines"
)

func complianceReportCmd() *cobra.Command {
	var (
		targetPath      string
		outputFile      string
		projectOvr      string
		reportStandards []string
		engineNames     []string
		excludePatterns []string
		timeout         int
		maxFileMB       int
		noConfig        bool
	)
	cmd := &cobra.Command{
		Use:   "compliance-report",
		Short: "Generate a compliance report in markdown for one or more frameworks",
		Long: `Scan a directory for cryptographic usage and generate a formal compliance
report in markdown format for the selected framework(s) (default: cnsa-2.0). When multiple
frameworks are specified the reports are concatenated with --- separators. Each report
includes an executive summary, per-algorithm compliance status, violation details,
approved algorithm reference, and key deadlines. Output can be written to a file or stdout.

Supported frameworks: ` + strings.Join(compliance.SupportedIDs(), ", "),
		RunE: func(cmd *cobra.Command, args []string) error {
			// Expand "all" sentinel before validation so downstream evaluation sees
			// concrete framework IDs.
			reportStandards = expandComplianceAll(reportStandards)
			if len(reportStandards) == 0 {
				reportStandards = []string{string(compliance.StandardCNSA20)}
			}

			// Validate all framework IDs before scanning so the user gets a complete
			// error message listing every unknown ID rather than a first-match failure.
			if err := validateComplianceFlags(reportStandards); err != nil {
				return err
			}

			absPath, err := filepath.Abs(targetPath)
			if err != nil {
				return fmt.Errorf("resolve path: %w", err)
			}

			// Load project config (unless --no-config) and apply fallbacks for flags
			// that the user did not set explicitly. Mirrors the scan command so
			// .oqs-scanner.yaml applies to compliance-report too.
			cfg := config.Config{}
			if !noConfig {
				loaded, err := config.Load(absPath)
				if err == nil {
					cfg = loaded
				}
			}
			unused := ""
			applyCommonConfigFallbacks(cmd, cfg, &unused, &timeout, &maxFileMB, &engineNames, &excludePatterns, &unused)

			// Determine project name: flag > git > directory basename.
			project := projectOvr
			if project == "" {
				project = resolveProject(context.Background(), "", absPath)
			}

			orch := buildOrchestrator()

			ctx := context.Background()
			if timeout > 0 {
				var cancel context.CancelFunc
				ctx, cancel = context.WithTimeout(ctx, time.Duration(timeout)*time.Second)
				defer cancel()
			}

			opts := engines.ScanOptions{
				TargetPath:      absPath,
				Mode:            engines.ModeFull,
				EngineNames:     engineNames,
				ExcludePatterns: excludePatterns,
				MaxFileMB:       maxFileMB,
				Timeout:         timeout,
			}

			selected := orch.EffectiveEngines(opts)
			if len(selected) == 0 {
				return fmt.Errorf("no scanner engines found — run 'oqs-scanner engines install --all' or ensure binaries are in PATH")
			}
			fmt.Fprintf(os.Stderr, "Scanning %s with %d engine(s) for compliance report (%s)...\n",
				absPath, len(selected), strings.Join(reportStandards, ", "))

			scanStart := time.Now()
			ff, _, err := orch.ScanWithImpact(ctx, opts)
			scanDuration := time.Since(scanStart)
			if err != nil {
				return fmt.Errorf("scan failed: %w", err)
			}
			fmt.Fprintf(os.Stderr, "Scan completed in %s — %d findings\n", scanDuration.Round(time.Millisecond), len(ff))

			var w io.Writer = os.Stdout
			var outFile *os.File
			if outputFile != "" {
				f, err := os.Create(outputFile)
				if err != nil {
					return fmt.Errorf("create output file: %w", err)
				}
				outFile = f
				w = f
			}

			scanDate := time.Now()
			var totalViolations int
			anyFail := false
			for i, fwID := range reportStandards {
				fw, _ := compliance.Get(fwID) // already validated above
				violations := fw.Evaluate(ff)
				data := compliance.BuildReportData(fw, ff, violations, project, version, scanDate)
				if i > 0 {
					if _, err := fmt.Fprint(w, "\n---\n\n"); err != nil {
						if outFile != nil {
							outFile.Close()
						}
						return fmt.Errorf("write separator: %w", err)
					}
				}
				if err := compliance.GenerateMarkdown(w, data); err != nil {
					if outFile != nil {
						outFile.Close()
					}
					return fmt.Errorf("generate report for %s: %w", fwID, err)
				}
				totalViolations += len(violations)
				if !data.Compliant {
					anyFail = true
				}
			}

			if outFile != nil {
				if err := outFile.Sync(); err != nil {
					outFile.Close()
					return fmt.Errorf("sync output: %w", err)
				}
				if err := outFile.Close(); err != nil {
					return fmt.Errorf("close output: %w", err)
				}
			}

			if outputFile != "" {
				status := "PASS"
				if anyFail {
					status = fmt.Sprintf("FAIL (%d total violation(s))", totalViolations)
				}
				fmt.Fprintf(os.Stderr, "Compliance report written to %s — %s\n", outputFile, status)
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&targetPath, "path", ".", "Directory to scan")
	cmd.Flags().StringVar(&outputFile, "output", "", "Output file path (default: stdout)")
	cmd.Flags().StringVar(&projectOvr, "project", "", "Project name for report header (default: inferred from git)")
	cmd.Flags().StringSliceVar(&reportStandards, "compliance", []string{string(compliance.StandardCNSA20)},
		"Compliance framework(s) to report on, comma-separated or repeated (supported: "+strings.Join(compliance.SupportedIDs(), ", ")+", or \"all\")")
	cmd.Flags().StringSliceVar(&engineNames, "engine", nil, "Engines to use (default: all available). Example: --engine cipherscope,cryptoscan")
	cmd.Flags().StringSliceVar(&excludePatterns, "exclude", nil, "Glob patterns to exclude from scan (comma-separated)")
	cmd.Flags().IntVar(&timeout, "timeout", 300, "Scan timeout in seconds (0 = no timeout)")
	cmd.Flags().IntVar(&maxFileMB, "max-file-mb", 50, "Skip files larger than this (MB)")
	cmd.Flags().BoolVar(&noConfig, "no-config", false, "Skip loading .oqs-scanner.yaml config (use in CI to prevent policy bypass)")
	return cmd
}
