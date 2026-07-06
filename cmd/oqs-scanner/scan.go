// scan.go implements the `scan` subcommand and its network-input validators.

package main

import (
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/jimbo111/open-quantum-secure/pkg/api"
	"github.com/jimbo111/open-quantum-secure/pkg/compliance"
	"github.com/jimbo111/open-quantum-secure/pkg/config"
	"github.com/jimbo111/open-quantum-secure/pkg/engines"
	"github.com/jimbo111/open-quantum-secure/pkg/engines/ctlookup"
	"github.com/jimbo111/open-quantum-secure/pkg/gitutil"
	"github.com/jimbo111/open-quantum-secure/pkg/output"
	"github.com/jimbo111/open-quantum-secure/pkg/quantum"
)

func scanCmd() *cobra.Command {
	var (
		targetPath        string
		format            string
		timeout           int
		maxFileMB         int
		engineNames       []string
		failOn            string
		outputFile        string
		excludePatterns   []string
		noConfig          bool
		uploadFlag        bool
		apiKeyFlag        string
		impactGraph       bool
		impactMaxHops     int
		scanType          string
		binaryPaths       []string
		incremental       bool
		cachePath         string
		noCache           bool
		remoteCache       bool
		remoteCacheBranch string
		complianceFlags   []string
		ciMode            string
		webhookURL        string
		dataLifetimeYears int
		signCBOM          bool
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
		sector            string
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
		Use:   "scan",
		Short: "Scan a directory for cryptographic usage",
		Long: `Scan a directory for cryptographic usage and assess quantum readiness.

Example with data lifetime adjustment for healthcare:
  oqs-scanner scan --path . --data-lifetime-years 30`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if targetPath == "" {
				return fmt.Errorf("--path is required")
			}
			if err := validateLifetimeAndProbeFlags(cmd, dataLifetimeYears, tlsDetectPref, tlsEnumGroups, tlsDeepProbe); err != nil {
				return err
			}
			if err := validateImpactMaxHops(impactMaxHops); err != nil {
				return err
			}

			absPath, err := filepath.Abs(targetPath)
			if err != nil {
				return fmt.Errorf("resolve path: %w", err)
			}

			// Load config file — missing file is not an error.
			// --no-config skips config loading (use in CI to prevent untrusted repos
			// from disabling policy enforcement via a checked-in .oqs-scanner.yaml).
			var cfg config.Config
			if !noConfig {
				var err error
				cfg, err = config.Load(absPath)
				if err != nil {
					return fmt.Errorf("load config: %w", err)
				}
			}

			// Apply config file as defaults; CLI flags override when explicitly set.
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

			// Apply config fallback for scan-type
			if !cmd.Flags().Changed("scan-type") && cfg.Scan.ScanType != "" {
				scanType = cfg.Scan.ScanType
			}

			// Validate --scan-type value
			if scanType != "" {
				valid := map[string]bool{"source": true, "binary": true, "all": true}
				if !valid[scanType] {
					return fmt.Errorf("--scan-type must be one of: source, binary, all")
				}
			}

			// Apply config fallback for remote cache.
			if !cmd.Flags().Changed("remote-cache") && cfg.Cache.Remote {
				remoteCache = true
			}
			if !cmd.Flags().Changed("remote-cache-branch") && cfg.Cache.RemoteBranch != "" {
				remoteCacheBranch = cfg.Cache.RemoteBranch
			}

			// Cache platform availability and project info once for the entire command.
			platformAvailable := isPlatformAvailable(cfg)
			projInfo, _ := gitutil.InferProject(context.Background(), absPath)

			// --remote-cache requires --incremental. Auto-enable with a warning.
			if remoteCache && !incremental {
				fmt.Fprintf(os.Stderr, "WARNING: --remote-cache requires incremental mode — enabling --incremental automatically.\n")
				incremental = true
			}

			// Apply config fallbacks for TLS probe (global config only).
			if !cmd.Flags().Changed("tls-targets") && len(cfg.TLS.Targets) > 0 {
				tlsTargets = cfg.TLS.Targets
			}
			if !cmd.Flags().Changed("tls-insecure") && cfg.TLS.Insecure {
				tlsInsecure = true
			}
			// Tristate resolution: precedence is CLI > config > hardcoded
			// default (true). cfg.TLS.Strict is *bool — nil means "config
			// didn't mention it" (keep default); non-nil means user
			// explicitly chose true OR false in YAML. Previously this used
			// the OR-up `&& cfg.TLS.Strict` pattern which could only flip
			// false→true, so `tls.strict: false` in YAML was ignored.
			if !cmd.Flags().Changed("tls-strict") && cfg.TLS.Strict != nil {
				tlsStrict = *cfg.TLS.Strict
			}

			// --deep-probe requires at least one TLS target; fail early so the
			// user gets a clear message instead of a no-op scan.
			if tlsDeepProbe && len(tlsTargets) == 0 {
				return fmt.Errorf("--deep-probe requires --tls-targets (no TLS targets provided)")
			}

			// Resolve HNDL shelf-life for Mosca inequality.
			// --data-lifetime-years is the single source of truth for both QRS penalty
			// multiplier and HNDL shelf life. --sector provides a preset when
			// --data-lifetime-years is not explicitly set by the caller.
			// Precedence: --data-lifetime-years (explicit) > --sector > default (10 years).
			hndlShelfLife := dataLifetimeYears
			if hndlShelfLife <= 0 && sector != "" {
				hndlShelfLife = quantum.WarnOnUnknownSector(sector, os.Stderr)
			}
			if hndlShelfLife <= 0 {
				hndlShelfLife = quantum.DefaultSectorShelfLifeYears
			}
			if cmd.Flags().Changed("data-lifetime-years") || sector != "" {
				surplus := quantum.ComputeHNDLSurplus(hndlShelfLife, 0, 0)
				level := quantum.HNDLLevelFromSurplus(surplus)
				fmt.Fprintf(os.Stderr, "HNDL sensitivity: %d years (Mosca surplus: %+d, level: %s)\n",
					hndlShelfLife, surplus, level)
			}

			if err := validateNetworkInputs(ctLookupTargets, sshTargets, zeekSSLPath, zeekX509Path, suricataEvePath); err != nil {
				return err
			}

			orch := buildOrchestrator()

			// Reject typos in --engine BEFORE the orchestrator filter
			// silently reduces the engine set to 0 (which would then
			// surface as the misleading "no scanner engines found" error).
			knownEngineNames := allEngineNames(orch)
			if err := validateEngineNames(knownEngineNames, engineNames); err != nil {
				return err
			}

			ctx := context.Background()
			if timeout > 0 {
				var cancel context.CancelFunc
				ctx, cancel = context.WithTimeout(ctx, time.Duration(timeout)*time.Second)
				defer cancel()
			}

			tlsTimeout := cfg.TLS.Timeout
			if tlsTimeout == 0 {
				tlsTimeout = 10
			}

			opts := engines.ScanOptions{
				TargetPath:             absPath,
				Mode:                   engines.ModeFull,
				Timeout:                timeout,
				MaxFileMB:              maxFileMB,
				EngineNames:            engineNames,
				ExcludePatterns:        excludePatterns,
				ImpactGraph:            impactGraph,
				MaxImpactHops:          impactMaxHops,
				ScanType:               scanType,
				BinaryPaths:            binaryPaths,
				Incremental:            incremental,
				CachePath:              cachePath,
				NoCache:                noCache,
				TLSTargets:             tlsTargets,
				TLSInsecure:            tlsInsecure,
				TLSDenyPrivate:         tlsStrict,
				TLSDetectECH:           tlsDetectECH,
				TLSTimeout:             tlsTimeout,
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

			if incremental && noCache {
				fmt.Fprintf(os.Stderr, "WARNING: --no-cache overrides --incremental, performing full scan.\n")
			} else if incremental {
				fmt.Fprintf(os.Stderr, "Incremental mode enabled — only changed files will be re-scanned.\n")
			}

			// Show which engines will actually be used (mirrors Scan's filtering)
			selected := orch.EffectiveEngines(opts)
			if len(selected) == 0 {
				return fmt.Errorf("no scanner engines found — run 'oqs-scanner engines install --all' or ensure binaries are in PATH")
			}
			warnIfNoSourceEngine(selected)

			fmt.Fprintf(os.Stderr, "Scanning %s with %d engine(s)...\n", absPath, len(selected))
			for _, e := range selected {
				fmt.Fprintf(os.Stderr, "  • %s (tier %s, %s)\n", e.Name(), e.Tier(), strings.Join(e.SupportedLanguages(), ", "))
			}

			// Remote cache pre-scan: download cache if authenticated and enabled.
			var (
				evHash           string
				rcProject        string
				rcBranch         string
				rcLocalCachePath string
				rcClient         *api.Client
			)
			if remoteCache && !noCache {
				if !platformAvailable {
					fmt.Fprintf(os.Stderr, "WARNING: --remote-cache requires a configured platform endpoint. Skipping remote cache.\n")
				} else if isAuthenticated(ctx, cfg, apiKeyFlag) {
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
			}

			scanStart := time.Now()
			results, impactResult, err := orch.ScanWithImpact(ctx, opts)
			scanDuration := time.Since(scanStart)
			if err != nil {
				return fmt.Errorf("scan failed: %w", err)
			}
			var usedEngineNames []string
			for _, e := range selected {
				usedEngineNames = append(usedEngineNames, e.Name())
			}

			fmt.Fprintf(os.Stderr, "Scan completed in %s — %d findings\n", scanDuration.Round(time.Millisecond), len(results))

			// Data lifetime: log and compute multiplier before building the result.
			lifetimeMult := quantum.DataLifetimeMultiplier(dataLifetimeYears)
			if dataLifetimeYears > 0 {
				fmt.Fprintf(os.Stderr, "Data lifetime: %d years (QRS multiplier: %.2f)\n", dataLifetimeYears, lifetimeMult)
			}

			scanResult := output.BuildResult(version, absPath, usedEngineNames, results,
				output.WithDuration(scanDuration),
				output.WithImpactResult(impactResult),
				output.WithLifetimeMultiplier(lifetimeMult),
			)

			if err := writeOutput(cmd, format, outputFile, scanResult, signCBOM); err != nil {
				return err
			}

			// Remote cache post-scan: upload updated cache (non-fatal).
			if remoteCache && !noCache && rcClient != nil {
				performRemoteCacheUpload(ctx, rcClient, rcProject, rcBranch, evHash, rcLocalCachePath)
			}

			// Auto-save scan record to local history (lightweight, non-fatal).
			scanStore := newScanStore(cfg, apiKeyFlag)
			projectName := resolveProjectFromInfo(cfg.Upload.Project, projInfo, absPath)
			record := buildScanRecordFromInfo(scanResult, projInfo, scanDuration, dataLifetimeYears)
			if saveErr := scanStore.SaveScan(ctx, projectName, record); saveErr != nil {
				fmt.Fprintf(os.Stderr, "WARNING: failed to save scan history: %s\n", saveErr)
			}

			// Compute compliance violations count for webhook (before ci-mode switch).
			complianceViolationCount := 0
			for _, fwID := range complianceFlags {
				if fw, ok := compliance.Get(fwID); ok {
					complianceViolationCount += len(fw.Evaluate(results))
				}
			}

			// Webhook: POST scan results with compliance data (non-fatal).
			if webhookURL != "" {
				wPayload := buildWebhookPayload(
					scanResult,
					projectName,
					resolveRemoteBranchFromInfo("", cfg.Cache.RemoteBranch, projInfo),
					"full",
					complianceViolationCount,
					strings.Join(complianceFlags, ","),
				)
				sendWebhook(webhookURL, wPayload)
			}

			// Upload CBOM to platform if requested.
			shouldUpload := uploadFlag || cfg.Upload.AutoUpload
			if shouldUpload {
				if platformAvailable {
					if uploadErr := performUploadWithInfo(ctx, cfg, apiKeyFlag, absPath, projInfo, scanResult); uploadErr != nil {
						fmt.Fprintf(os.Stderr, "Upload failed: %s\n", uploadErr)
						// Non-fatal — scan succeeded, upload is optional.
					}
				} else {
					if saveErr := saveLocalCBOMFromResult(scanResult, projectName); saveErr != nil {
						fmt.Fprintf(os.Stderr, "Local CBOM save failed: %s\n", saveErr)
					}
				}
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

	cmd.Flags().StringVar(&targetPath, "path", "", "Directory to scan")
	cmd.Flags().StringVar(&format, "format", "table", "Output format: json, table, sarif, cbom, html, csv")
	cmd.Flags().IntVar(&timeout, "timeout", 300, "Scan timeout in seconds (0 = no timeout)")
	cmd.Flags().IntVar(&maxFileMB, "max-file-mb", 50, "Skip files larger than this (MB)")
	cmd.Flags().StringSliceVar(&engineNames, "engine", nil, "Engines to use (default: all available). Example: --engine cipherscope,cryptoscan")
	cmd.Flags().StringVar(&failOn, "fail-on", "", "Exit with code 1 if any finding is at or above this severity (critical, high, medium, low)")
	cmd.Flags().StringVar(&outputFile, "output", "", "Write output to file instead of stdout")
	cmd.Flags().StringSliceVar(&excludePatterns, "exclude", nil, "Glob patterns to exclude from scan (comma-separated)")
	cmd.Flags().BoolVar(&noConfig, "no-config", false, "Skip loading .oqs-scanner.yaml config (use in CI to prevent policy bypass)")
	cmd.Flags().BoolVar(&uploadFlag, "upload", false, "Upload CBOM to OQS platform after scan")
	cmd.Flags().StringVar(&apiKeyFlag, "api-key", "", "API key for authentication (overrides stored credentials)")
	cmd.Flags().BoolVar(&impactGraph, "impact-graph", true, "Enable forward impact analysis (Crypto Impact Graph)")
	cmd.Flags().IntVar(&impactMaxHops, "impact-max-hops", 10, "Maximum forward hops for impact analysis")
	cmd.Flags().StringVar(&scanType, "scan-type", "source", "Scan type: source (default), binary, or all")
	cmd.Flags().StringSliceVar(&binaryPaths, "binary-path", nil, "Binary artifact paths to scan (repeatable)")
	cmd.Flags().BoolVar(&incremental, "incremental", false, "Enable incremental mode: only re-scan changed files using a local cache")
	cmd.Flags().StringVar(&cachePath, "cache-path", "", "Override the cache file path (default: <path>/.oqs-scanner-cache.json)")
	cmd.Flags().BoolVar(&noCache, "no-cache", false, "Force full scan, ignore and do not update the incremental cache")
	cmd.Flags().BoolVar(&remoteCache, "remote-cache", false, "Enable remote cache: download before scan and upload after (requires authentication)")
	cmd.Flags().StringVar(&remoteCacheBranch, "remote-cache-branch", "", "Branch for remote cache key (default: auto-detect from git)")
	cmd.Flags().StringSliceVar(&complianceFlags, "compliance", nil, "Compliance framework(s) to enforce (comma-separated or repeated flag; e.g. cnsa-2.0,bsi-tr-02102). Supported: "+strings.Join(compliance.SupportedIDs(), ", ")+".")
	cmd.Flags().StringVar(&ciMode, "ci-mode", "blocking", "CI behavior: blocking (exit 1 on violations), advisory (warn only, exit 0), silent (no policy/compliance output, exit 0)")
	cmd.Flags().StringVar(&webhookURL, "webhook-url", "", "POST scan results to this HTTPS URL on completion (JSON payload)")
	cmd.Flags().BoolVar(&signCBOM, "sign-cbom", false, "Sign the CBOM output with an ephemeral Ed25519 key pair (only applies when --format cbom)")
	cmd.Flags().IntVar(&dataLifetimeYears, "data-lifetime-years", 0,
		`Expected data retention period in years. Used for both QRS penalty adjustment and
the Mosca HNDL inequality calculation (surplus = shelf_life + migration_lag - time_to_CRQC).
Industry guidelines: medical=30, state=50, infra=20, finance=7, code=5, generic=10.
0 = disabled (default; HNDL uses --sector preset or 10y fallback for Mosca).
Values >10 amplify QRS penalties, <5 reduce them. Must be > 0 if explicitly set.
Overrides --sector when both are provided.`)

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

	// HNDL Mosca sector preset flag
	cmd.Flags().StringVar(&sector, "sector", "",
		`Industry sector preset for Mosca HNDL shelf-life (case-insensitive).
Presets: medical=30y, finance=7y, state=50y, infra=20y, code=5y, generic=10y.
--data-lifetime-years takes precedence when both are set.`)

	return cmd
}

// validateZeekLogPath rejects --zeek-ssl-log / --zeek-x509-log values that
// contain null bytes (which the OS would reject anyway, but caught here for
// a clear user-facing error before any file open attempt).
func validateZeekLogPath(path string) error {
	if path == "" {
		return nil
	}
	if strings.ContainsRune(path, 0) {
		return fmt.Errorf("path contains null byte")
	}
	return nil
}

// validateSSHTarget validates a single --ssh-targets entry. It must be in
// "host:port" form with a valid port number (1–65535) and either a valid
// hostname (RFC 1123 DNS labels) or an IP literal.
func validateSSHTarget(target string) error {
	host, portStr, err := net.SplitHostPort(target)
	if err != nil {
		return fmt.Errorf("must be in host:port format: %w", err)
	}
	if host == "" {
		return fmt.Errorf("empty host")
	}
	portNum, convErr := strconv.Atoi(portStr)
	if convErr != nil || portNum < 1 || portNum > 65535 {
		return fmt.Errorf("invalid port %q (must be 1-65535)", portStr)
	}
	// IP literals are valid SSH targets; skip hostname validation for them.
	if net.ParseIP(host) != nil {
		return nil
	}
	return ctlookup.ValidateHostname(host)
}

// validateSuricataEvePath rejects --suricata-eve values that contain null bytes
// (which the OS would reject anyway, but caught here for a clear user-facing error
// before any file open attempt).
func validateSuricataEvePath(path string) error {
	if path == "" {
		return nil
	}
	if strings.ContainsRune(path, 0) {
		return fmt.Errorf("path contains null byte")
	}
	return nil
}
