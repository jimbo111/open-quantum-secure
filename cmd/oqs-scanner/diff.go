// diff.go implements the `diff` (PR mode) subcommand.

package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/jimbo111/open-quantum-secure/pkg/api"
	"github.com/jimbo111/open-quantum-secure/pkg/compliance"
	"github.com/jimbo111/open-quantum-secure/pkg/config"
	"github.com/jimbo111/open-quantum-secure/pkg/engines"
	"github.com/jimbo111/open-quantum-secure/pkg/gitutil"
	"github.com/jimbo111/open-quantum-secure/pkg/output"
	"github.com/jimbo111/open-quantum-secure/pkg/quantum"
)

func diffCmd() *cobra.Command {
	var (
		targetPath        string
		diffBase          string
		format            string
		timeout           int
		maxFileMB         int
		engineNames       []string
		failOn            string
		outputFile        string
		excludePatterns   []string
		noConfig          bool
		incremental       bool
		cachePath         string
		complianceFlags   []string
		noCache           bool
		remoteCache       bool
		remoteCacheBranch string
		apiKeyFlag        string
		ciMode            string
		webhookURL        string
		dataLifetimeYears int
		tlsTargets        []string
		tlsInsecure       bool
		tlsStrict         bool
		tlsDetectECH      bool
		tlsDeepProbe      bool
		tlsEnumGroups     bool
		tlsEnumSigAlgs    bool
		tlsDetectPref     bool
		tlsMaxProbes      int
		verbose           bool
		ctLookupTargets   []string
		ctLookupFromECH   bool
		noNetwork         bool
		sshTargets        []string
		sshStrict         bool
		skipTLS12Fallback bool
		zeekSSLPath       string
		zeekX509Path      string
		suricataEvePath   string
	)

	cmd := &cobra.Command{
		Use:   "diff",
		Short: "Scan only changed files between a git ref and HEAD (PR mode)",
		Long: `Scan only files changed between a base git ref and HEAD.
This is designed for CI/CD pull request checks where only
modified files need to be scanned. Only Tier 1 (fast AST)
engines are used for speed.

Example:
  oqs-scanner diff --path . --base main --format sarif`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if targetPath == "" {
				return fmt.Errorf("--path is required")
			}
			if err := validateLifetimeAndProbeFlags(cmd, dataLifetimeYears, tlsDetectPref, tlsEnumGroups, tlsDeepProbe); err != nil {
				return err
			}
			if diffBase == "" {
				return fmt.Errorf("--base is required (e.g. main, origin/main, a commit SHA)")
			}

			absPath, err := filepath.Abs(targetPath)
			if err != nil {
				return fmt.Errorf("resolve path: %w", err)
			}

			// Load config before creating context so config timeout takes effect.
			// --no-config skips config loading (prevents untrusted repo policy bypass).
			var cfg config.Config
			if !noConfig {
				var err error
				cfg, err = config.Load(absPath)
				if err != nil {
					return fmt.Errorf("load config: %w", err)
				}
			}
			applyCommonConfigFallbacks(cmd, cfg, &format, &timeout, &maxFileMB, &engineNames, &excludePatterns, &failOn)
			if err := validateFailOn(failOn); err != nil {
				return err
			}
			complianceFlags = expandComplianceAll(complianceFlags)
			if err := validateComplianceFlags(complianceFlags); err != nil {
				return err
			}
			if err := validateCIMode(ciMode); err != nil {
				return err
			}

			ctx := context.Background()
			if timeout > 0 {
				var cancel context.CancelFunc
				ctx, cancel = context.WithTimeout(ctx, time.Duration(timeout)*time.Second)
				defer cancel()
			}

			// Get changed files from git
			if !gitutil.IsGitRepo(ctx, absPath) {
				return fmt.Errorf("%s is not a git repository — diff mode requires git", absPath)
			}

			changedFiles, err := gitutil.ChangedFiles(ctx, absPath, diffBase)
			if err != nil {
				return fmt.Errorf("get changed files: %w", err)
			}

			if len(changedFiles) == 0 {
				fmt.Fprintf(os.Stderr, "No files changed between %s and HEAD — nothing to scan.\n", diffBase)
				// Still produce empty output
				scanResult := output.BuildResult(version, absPath, nil, nil)
				return writeOutput(cmd, format, outputFile, scanResult, false)
			}

			fmt.Fprintf(os.Stderr, "Diff mode: %d files changed between %s and HEAD\n", len(changedFiles), diffBase)
			for _, f := range changedFiles {
				fmt.Fprintf(os.Stderr, "  • %s\n", f)
			}

			// Apply config fallback for remote cache.
			if !cmd.Flags().Changed("remote-cache") && cfg.Cache.Remote {
				remoteCache = true
			}
			if !cmd.Flags().Changed("remote-cache-branch") && cfg.Cache.RemoteBranch != "" {
				remoteCacheBranch = cfg.Cache.RemoteBranch
			}

			// --remote-cache requires --incremental. Auto-enable with a warning.
			if remoteCache && !incremental {
				fmt.Fprintf(os.Stderr, "WARNING: --remote-cache requires incremental mode — enabling --incremental automatically.\n")
				incremental = true
			}

			// Cache platform availability and project info once (before context creation
			// so git calls are not subject to scan timeout).
			platformAvailable := isPlatformAvailable(cfg)
			projInfo, _ := gitutil.InferProject(context.Background(), absPath)

			orch := buildOrchestrator()

			// Reject typos in --engine BEFORE the orchestrator filter
			// silently reduces the engine set to 0. See scanCmd for context.
			knownEngineNames := allEngineNames(orch)
			if err := validateEngineNames(knownEngineNames, engineNames); err != nil {
				return err
			}

			if incremental && noCache {
				fmt.Fprintln(os.Stderr, "WARNING: --incremental with --no-cache: performing normal diff scan (--no-cache overrides)")
			}

			// Apply config fallbacks for TLS probe in diff mode.
			if !cmd.Flags().Changed("tls-targets") && len(cfg.TLS.Targets) > 0 {
				tlsTargets = cfg.TLS.Targets
			}
			if !cmd.Flags().Changed("tls-insecure") && cfg.TLS.Insecure {
				tlsInsecure = true
			}
			// Tristate resolution — see scanCmd for full rationale.
			if !cmd.Flags().Changed("tls-strict") && cfg.TLS.Strict != nil {
				tlsStrict = *cfg.TLS.Strict
			}

			// --deep-probe requires at least one TLS target; fail early.
			if tlsDeepProbe && len(tlsTargets) == 0 {
				return fmt.Errorf("--deep-probe requires --tls-targets (no TLS targets provided)")
			}

			if err := validateNetworkInputs(ctLookupTargets, sshTargets, zeekSSLPath, zeekX509Path, suricataEvePath); err != nil {
				return err
			}

			opts := engines.ScanOptions{
				TargetPath:             absPath,
				Timeout:                timeout,
				MaxFileMB:              maxFileMB,
				EngineNames:            engineNames,
				Mode:                   engines.ModeDiff,
				ChangedFiles:           changedFiles,
				ExcludePatterns:        excludePatterns,
				Incremental:            incremental,
				CachePath:              cachePath,
				NoCache:                noCache,
				TLSTargets:             tlsTargets,
				TLSInsecure:            tlsInsecure,
				TLSDenyPrivate:         tlsStrict,
				TLSDetectECH:           tlsDetectECH,
				TLSTimeout:             cfg.TLS.Timeout,
				TLSCACert:              cfg.TLS.CACert,
				DeepProbe:              tlsDeepProbe,
				EnumerateGroups:        tlsEnumGroups,
				EnumerateSigAlgs:       tlsEnumSigAlgs,
				DetectServerPreference: tlsDetectPref,
				MaxProbesPerTarget:     tlsMaxProbes,
				SkipTLS12Fallback:      skipTLS12Fallback,
				Verbose:                verbose,
				NoNetwork:              noNetwork,
				CTLookupTargets:        ctLookupTargets,
				CTLookupFromECH:        ctLookupFromECH,
				SSHTargets:             sshTargets,
				SSHDenyPrivate:         sshStrict,
				ZeekSSLPath:            zeekSSLPath,
				ZeekX509Path:           zeekX509Path,
				SuricataEvePath:        suricataEvePath,
			}

			selected := orch.EffectiveEngines(opts)
			if len(selected) == 0 {
				return fmt.Errorf("no scanner engines found — run 'oqs-scanner engines install --all' or ensure binaries are in PATH")
			}

			warnIfNoSourceEngine(selected)

			fmt.Fprintf(os.Stderr, "Running %d Tier 1 engine(s) on changed files...\n", len(selected))

			// Remote cache pre-scan: download cache if authenticated and enabled.
			var (
				evHash           string
				rcProject        string
				rcBranch         string
				rcLocalCachePath string
				rcClient         *api.Client
			)
			if remoteCache && !noCache && platformAvailable && isAuthenticated(ctx, cfg, apiKeyFlag) {
				evHash = engineVersionsHash(selected)
				rcProject = resolveProjectFromInfo(cfg.Upload.Project, projInfo, absPath)
				rcBranch = resolveRemoteBranchFromInfo(remoteCacheBranch, cfg.Cache.RemoteBranch, projInfo)
				rcLocalCachePath = resolveCachePath(cachePath, absPath)
				var clientErr error
				rcClient, clientErr = newAPIClient(cfg, apiKeyFlag)
				if clientErr != nil {
					fmt.Fprintf(os.Stderr, "WARNING: remote cache disabled: %v\n", clientErr)
				} else {
					performRemoteCacheDownload(ctx, rcClient, rcProject, rcBranch, evHash, rcLocalCachePath)
				}
			}

			scanStart := time.Now()
			results, err := orch.Scan(ctx, opts)
			scanDuration := time.Since(scanStart)
			if err != nil {
				return fmt.Errorf("scan failed: %w", err)
			}

			var usedEngineNames []string
			for _, e := range selected {
				usedEngineNames = append(usedEngineNames, e.Name())
			}

			fmt.Fprintf(os.Stderr, "Diff scan completed in %s — %d findings in changed files\n",
				scanDuration.Round(time.Millisecond), len(results))

			// Data lifetime: log and compute multiplier before building the result.
			diffLifetimeMult := quantum.DataLifetimeMultiplier(dataLifetimeYears)
			if dataLifetimeYears > 0 {
				fmt.Fprintf(os.Stderr, "Data lifetime: %d years (QRS multiplier: %.2f)\n", dataLifetimeYears, diffLifetimeMult)
			}

			scanResult := output.BuildResult(version, absPath, usedEngineNames, results,
				output.WithDuration(scanDuration),
				output.WithLifetimeMultiplier(diffLifetimeMult),
			)

			if err := writeOutput(cmd, format, outputFile, scanResult, false); err != nil {
				return err
			}

			// Remote cache post-scan: upload updated cache (non-fatal).
			if remoteCache && !noCache && rcClient != nil {
				performRemoteCacheUpload(ctx, rcClient, rcProject, rcBranch, evHash, rcLocalCachePath)
			}

			// Compute compliance violations count for webhook.
			diffComplianceViolations := 0
			for _, fwID := range complianceFlags {
				if fw, ok := compliance.Get(fwID); ok {
					diffComplianceViolations += len(fw.Evaluate(results))
				}
			}

			// Webhook: POST scan results with compliance data (non-fatal).
			if webhookURL != "" {
				wPayload := buildWebhookPayload(
					scanResult,
					resolveProjectFromInfo(cfg.Upload.Project, projInfo, absPath),
					resolveRemoteBranchFromInfo("", cfg.Cache.RemoteBranch, projInfo),
					"diff",
					diffComplianceViolations,
					strings.Join(complianceFlags, ","),
				)
				sendWebhook(webhookURL, wPayload)
			}

			// Run both evaluations — compliance violations are always printed
			// even if policy also fails (both produce exit code 1).
			switch ciMode {
			case "silent":
				// Skip policy and compliance output; findings saved to history only.
			case "advisory":
				evaluatePolicyAdvisory(cfg, failOn, results, scanResult)
				evaluateComplianceAdvisory(complianceFlags, results)
			default: // "blocking"
				policyErr := evaluatePolicy(cfg, failOn, results, scanResult)
				complianceErr := evaluateCompliance(complianceFlags, results)
				if policyErr != nil {
					return policyErr
				}
				return complianceErr
			}
			return nil
		},
	}

	cmd.Flags().StringVar(&targetPath, "path", "", "Directory to scan (must be a git repository)")
	cmd.Flags().StringVar(&diffBase, "base", "", "Git ref to diff against (e.g. main, origin/main, a commit SHA)")
	cmd.Flags().StringVar(&format, "format", "table", "Output format: json, table, sarif, cbom, html, csv")
	cmd.Flags().IntVar(&timeout, "timeout", 120, "Scan timeout in seconds")
	cmd.Flags().IntVar(&maxFileMB, "max-file-mb", 50, "Skip files larger than this (MB)")
	cmd.Flags().StringSliceVar(&engineNames, "engine", nil, "Engines to use (default: all available Tier 1)")
	cmd.Flags().StringVar(&failOn, "fail-on", "", "Exit code 1 if findings at this severity or above")
	cmd.Flags().StringVar(&outputFile, "output", "", "Write output to file instead of stdout")
	cmd.Flags().StringSliceVar(&excludePatterns, "exclude", nil, "Glob patterns to exclude")
	cmd.Flags().BoolVar(&noConfig, "no-config", false, "Skip loading .oqs-scanner.yaml config (use in CI to prevent policy bypass)")
	cmd.Flags().BoolVar(&incremental, "incremental", false, "Enable incremental mode: cache scan results and skip unchanged files on repeat runs")
	cmd.Flags().StringVar(&cachePath, "cache-path", "", "Override the cache file path (default: <path>/.oqs-scanner-cache.json)")
	cmd.Flags().BoolVar(&noCache, "no-cache", false, "Force full diff scan, ignore and do not update the incremental cache")
	cmd.Flags().BoolVar(&remoteCache, "remote-cache", false, "Enable remote cache: download before scan and upload after (requires authentication)")
	cmd.Flags().StringVar(&remoteCacheBranch, "remote-cache-branch", "", "Branch for remote cache key (default: auto-detect from git)")
	cmd.Flags().StringVar(&apiKeyFlag, "api-key", "", "API key for authentication (overrides stored credentials)")
	cmd.Flags().StringSliceVar(&complianceFlags, "compliance", nil, "Compliance framework(s) to enforce (comma-separated or repeated flag; e.g. cnsa-2.0,bsi-tr-02102). Supported: "+strings.Join(compliance.SupportedIDs(), ", ")+".")
	cmd.Flags().StringVar(&ciMode, "ci-mode", "blocking", "CI behavior: blocking (exit 1 on violations), advisory (warn only, exit 0), silent (no policy/compliance output, exit 0)")
	cmd.Flags().StringVar(&webhookURL, "webhook-url", "", "POST scan results to this HTTPS URL on completion (JSON payload)")
	cmd.Flags().IntVar(&dataLifetimeYears, "data-lifetime-years", 0,
		`Expected data retention period in years. Adjusts HNDL urgency in QRS scoring.
Industry guidelines: healthcare/medical=30, government/classified=25,
financial/banking=7, legal/contracts=10, web sessions/ephemeral=1.
0 = disabled (default). Values >10 amplify penalties, <5 reduce them.`)

	// Network engine probe flags (TLS + CT + SSH + Zeek + Suricata).
	// See cmd/oqs-scanner/scanflags.go for the canonical definitions.
	addNetworkProbeFlags(cmd, networkProbeFlagVars{
		TLSTargets:        &tlsTargets,
		TLSInsecure:       &tlsInsecure,
		TLSStrict:         &tlsStrict,
		TLSDetectECH:      &tlsDetectECH,
		TLSDeepProbe:      &tlsDeepProbe,
		TLSEnumGroups:     &tlsEnumGroups,
		TLSEnumSigAlgs:    &tlsEnumSigAlgs,
		TLSDetectPref:     &tlsDetectPref,
		TLSMaxProbes:      &tlsMaxProbes,
		SkipTLS12Fallback: &skipTLS12Fallback,
		Verbose:           &verbose,
		CTLookupTargets:   &ctLookupTargets,
		CTLookupFromECH:   &ctLookupFromECH,
		NoNetwork:         &noNetwork,
		SSHTargets:        &sshTargets,
		SSHStrict:         &sshStrict,
		ZeekSSLPath:       &zeekSSLPath,
		ZeekX509Path:      &zeekX509Path,
		SuricataEvePath:   &suricataEvePath,
	})

	return cmd
}
