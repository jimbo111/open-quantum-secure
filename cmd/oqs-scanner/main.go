package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"

	"github.com/jimbo111/open-quantum-secure/pkg/api"
	"github.com/jimbo111/open-quantum-secure/pkg/auth"
	"github.com/jimbo111/open-quantum-secure/pkg/cache"
	"github.com/jimbo111/open-quantum-secure/pkg/cbomutil"
	"github.com/jimbo111/open-quantum-secure/pkg/config"
	"github.com/jimbo111/open-quantum-secure/pkg/dashboard"
	"github.com/jimbo111/open-quantum-secure/pkg/enginemgr"
	"github.com/jimbo111/open-quantum-secure/pkg/engines"
	"github.com/jimbo111/open-quantum-secure/pkg/engines/astgrep"
	"github.com/jimbo111/open-quantum-secure/pkg/engines/binaryscanner"
	"github.com/jimbo111/open-quantum-secure/pkg/engines/cbomkit"
	"github.com/jimbo111/open-quantum-secure/pkg/engines/configscanner"
	"github.com/jimbo111/open-quantum-secure/pkg/engines/cdxgen"
	"github.com/jimbo111/open-quantum-secure/pkg/engines/cipherscope"
	"github.com/jimbo111/open-quantum-secure/pkg/engines/cryptodeps"
	"github.com/jimbo111/open-quantum-secure/pkg/engines/cryptoscan"
	"github.com/jimbo111/open-quantum-secure/pkg/engines/semgrep"
	"github.com/jimbo111/open-quantum-secure/pkg/engines/syft"
	"github.com/jimbo111/open-quantum-secure/pkg/compliance"
	"github.com/jimbo111/open-quantum-secure/pkg/findings"
	"github.com/jimbo111/open-quantum-secure/pkg/gitutil"
	"github.com/jimbo111/open-quantum-secure/pkg/orchestrator"
	"github.com/jimbo111/open-quantum-secure/pkg/output"
	"github.com/jimbo111/open-quantum-secure/pkg/policy"
	"github.com/jimbo111/open-quantum-secure/pkg/quantum"
	"github.com/jimbo111/open-quantum-secure/pkg/sanitize"
	"github.com/jimbo111/open-quantum-secure/pkg/store"
	"github.com/jimbo111/open-quantum-secure/pkg/trends"
)

var version = "0.1.0"

// errFailOn is returned when policy violations are detected, causing exit code 1.
var errFailOn = errors.New("policy violations detected")

func main() {
	orchestrator.SetScannerVersion(version)
	if err := rootCmd().Execute(); err != nil {
		if !errors.Is(err, errFailOn) {
			fmt.Fprintf(os.Stderr, "Error: %s\n", err)
		}
		os.Exit(1)
	}
}

func rootCmd() *cobra.Command {
	root := &cobra.Command{
		Use:           "oqs-scanner",
		Short:         "Post-Quantum Cryptography scanner — detect crypto usage across codebases",
		SilenceErrors: true, // we handle errors in main()
		SilenceUsage:  true, // don't print usage on RunE errors
	}

	root.AddCommand(scanCmd())
	root.AddCommand(diffCmd())
	root.AddCommand(versionCmd())
	root.AddCommand(enginesCmd())
	root.AddCommand(loginCmd())
	root.AddCommand(logoutCmd())
	root.AddCommand(whoamiCmd())
	root.AddCommand(uploadCmd())
	root.AddCommand(historyCmd())
	root.AddCommand(trendsCmd())
	root.AddCommand(apikeyCmd())
	root.AddCommand(configCmd())
	root.AddCommand(complianceReportCmd())
	root.AddCommand(dashboardCmd())

	return root
}

func engineDir() string {
	exe, err := os.Executable()
	if err != nil {
		return ""
	}
	return filepath.Join(filepath.Dir(exe), "engines")
}

func buildOrchestrator() *orchestrator.Orchestrator {
	dirs := enginesSearchDirs()

	// Tier 1: Pattern/AST engines
	cs := cipherscope.New(dirs...)
	cscan := cryptoscan.New(dirs...)
	ag := astgrep.New(dirs...)

	// Tier 2: Taint/flow engines
	sg := semgrep.New(dirs...)

	// Tier 3: SCA / supply-chain engines
	cdeps := cryptodeps.New(dirs...)
	cdx := cdxgen.New(dirs...)
	sy := syft.New(dirs...)
	cbk := cbomkit.New(dirs...)

	// Tier 4: Binary scanning engine (pure Go, always available)
	bs := binaryscanner.New()

	// Tier 1: Config file scanner (pure Go, always available)
	cfgs := configscanner.New()

	return orchestrator.New(cs, cscan, ag, sg, cdeps, cdx, sy, cbk, bs, cfgs)
}

// engineVersionsHash computes a stable SHA-256 hex digest over the
// name→version map of the provided engines. The sort order is deterministic
// (sorted by name) so the same set of engine versions always produces the
// same hash, regardless of map iteration order.
func engineVersionsHash(engs []engines.Engine) string {
	type kv struct{ k, v string }
	pairs := make([]kv, 0, len(engs))
	for _, e := range engs {
		pairs = append(pairs, kv{e.Name(), e.Version()})
	}
	sort.Slice(pairs, func(i, j int) bool { return pairs[i].k < pairs[j].k })

	var sb strings.Builder
	for _, p := range pairs {
		sb.WriteString(p.k)
		sb.WriteByte('=')
		sb.WriteString(p.v)
		sb.WriteByte('\n')
	}
	sum := sha256.Sum256([]byte(sb.String()))
	return hex.EncodeToString(sum[:])
}

// resolveRemoteBranch returns the branch to use for remote cache scoping.
// Priority: explicit flag > config > git auto-detect > "main".
func resolveRemoteBranch(ctx context.Context, flagBranch, cfgBranch, scanPath string) string {
	if flagBranch != "" {
		return flagBranch
	}
	if cfgBranch != "" {
		return cfgBranch
	}
	if projInfo, err := gitutil.InferProject(ctx, scanPath); err == nil {
		return projInfo.Branch
	}
	return "main"
}

// resolveRemoteBranchFromInfo is like resolveRemoteBranch but uses a pre-fetched ProjectInfo
// to avoid redundant git subprocess calls.
func resolveRemoteBranchFromInfo(flagBranch, cfgBranch string, projInfo *gitutil.ProjectInfo) string {
	if flagBranch != "" {
		return flagBranch
	}
	if cfgBranch != "" {
		return cfgBranch
	}
	if projInfo != nil {
		return projInfo.Branch
	}
	return "main"
}

// resolveProject returns the project name for remote cache scoping.
// Priority: config > git auto-detect > base directory name.
func resolveProject(ctx context.Context, cfgProject, scanPath string) string {
	if cfgProject != "" {
		return cfgProject
	}
	if projInfo, err := gitutil.InferProject(ctx, scanPath); err == nil {
		return projInfo.Project
	}
	return filepath.Base(scanPath)
}

// resolveProjectFromInfo is like resolveProject but uses a pre-fetched ProjectInfo
// to avoid redundant git subprocess calls.
func resolveProjectFromInfo(cfgProject string, projInfo *gitutil.ProjectInfo, scanPath string) string {
	if cfgProject != "" {
		return cfgProject
	}
	if projInfo != nil {
		return projInfo.Project
	}
	return filepath.Base(scanPath)
}

// resolveCachePath returns the effective local cache file path.
func resolveCachePath(override, scanPath string) string {
	if override != "" {
		return override
	}
	return filepath.Join(scanPath, ".oqs-scanner-cache.json")
}

// newResolver builds an auth.Resolver with the full RefreshFn wiring.
// Used by both isAuthenticated and newAPIClient to avoid divergence.
func newResolver(cfg config.Config, apiKeyFlag string) *auth.Resolver {
	s := &auth.Store{}
	endpoint := resolveEndpoint(cfg)
	return &auth.Resolver{
		APIKeyFlag: apiKeyFlag,
		Store:      s,
		RefreshFn: func(ctx context.Context, ep, refreshToken string) (*auth.Credential, error) {
			if ep == "" {
				ep = endpoint
			}
			da := &auth.DeviceAuth{Endpoint: ep}
			tok, err := da.RefreshToken(ctx, refreshToken)
			if err != nil {
				return nil, err
			}
			return &auth.Credential{
				AccessToken:  tok.AccessToken,
				RefreshToken: tok.RefreshToken,
				ExpiresAt:    time.Now().Add(time.Duration(tok.ExpiresIn) * time.Second),
				Endpoint:     ep,
			}, nil
		},
	}
}

// isAuthenticated checks whether the current session has a non-empty token.
// It is a lightweight best-effort check — authentication failures during the
// actual API call are handled by the remote cache helpers.
func isAuthenticated(ctx context.Context, cfg config.Config, apiKeyFlag string) bool {
	resolver := newResolver(cfg, apiKeyFlag)
	token, _, err := resolver.Resolve(ctx)
	return err == nil && token != ""
}

// performRemoteCacheDownload downloads the remote cache and writes it to the
// local cache path. Returns true if a cache was successfully fetched and
// written. All errors are non-fatal and are logged to stderr.
func performRemoteCacheDownload(ctx context.Context, client *api.Client, project, branch, evHash, localCachePath string) bool {
	data, err := client.DownloadCache(ctx, api.CacheDownloadRequest{
		Project:            project,
		Branch:             branch,
		EngineVersionsHash: evHash,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "WARNING: remote cache download failed: %s\n", err)
		return false
	}
	if data == nil {
		hashDisplay := evHash
		if len(hashDisplay) > 8 {
			hashDisplay = hashDisplay[:8]
		}
		fmt.Fprintf(os.Stderr, "Remote cache: no cache found for branch=%s hash=%s\n", branch, hashDisplay)
		return false
	}

	// Decompress and save to local cache path so the incremental mode picks it up.
	sc, err := cache.UnmarshalGzip(data)
	if err != nil {
		fmt.Fprintf(os.Stderr, "WARNING: remote cache corrupt (cannot decompress): %s\n", err)
		return false
	}
	if err := sc.Save(localCachePath); err != nil {
		fmt.Fprintf(os.Stderr, "WARNING: remote cache: failed to write local cache: %s\n", err)
		return false
	}
	fmt.Fprintf(os.Stderr, "Remote cache: downloaded and applied (branch=%s)\n", branch)
	return true
}

// performRemoteCacheUpload reads the local cache, gzip-compresses it, and
// uploads it to the remote platform. All errors are non-fatal.
func performRemoteCacheUpload(ctx context.Context, client *api.Client, project, branch, evHash, localCachePath string) {
	sc, err := cache.Load(localCachePath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "WARNING: remote cache upload: failed to load local cache: %s\n", err)
		return
	}

	data, err := sc.MarshalGzip()
	if err != nil {
		fmt.Fprintf(os.Stderr, "WARNING: remote cache upload: failed to compress cache: %s\n", err)
		return
	}

	_, err = client.UploadCache(ctx, api.CacheUploadRequest{
		Project:            project,
		Branch:             branch,
		EngineVersionsHash: evHash,
		Data:               data,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "WARNING: remote cache upload failed: %s\n", err)
		return
	}
	fmt.Fprintf(os.Stderr, "Remote cache: uploaded (%d bytes gzip)\n", len(data))
}

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
		complianceFlag    string
		ciMode            string
		webhookURL        string
		dataLifetimeYears int
		signCBOM          bool
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
			if dataLifetimeYears < 0 {
				return fmt.Errorf("--data-lifetime-years must be >= 0 (got %d)", dataLifetimeYears)
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
				Timeout:         timeout,
				MaxFileMB:       maxFileMB,
				EngineNames:     engineNames,
				ExcludePatterns: excludePatterns,
				ImpactGraph:     impactGraph,
				MaxImpactHops:   impactMaxHops,
				ScanType:        scanType,
				BinaryPaths:     binaryPaths,
				Incremental:     incremental,
				CachePath:       cachePath,
				NoCache:         noCache,
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
			fmt.Fprintf(os.Stderr, "Scanning %s with %d engine(s)...\n", absPath, len(selected))
			for _, e := range selected {
				fmt.Fprintf(os.Stderr, "  • %s (tier %s, %s)\n", e.Name(), e.Tier(), strings.Join(e.SupportedLanguages(), ", "))
			}

			// Remote cache pre-scan: download cache if authenticated and enabled.
			var (
				evHash          string
				rcProject       string
				rcBranch        string
				rcLocalCachePath string
				rcClient        *api.Client
			)
			if remoteCache && !noCache {
				if !platformAvailable {
					fmt.Fprintf(os.Stderr, "WARNING: --remote-cache requires a configured platform endpoint. Skipping remote cache.\n")
				} else if isAuthenticated(ctx, cfg, apiKeyFlag) {
					evHash = engineVersionsHash(selected)
					rcProject = resolveProjectFromInfo(cfg.Upload.Project, projInfo, absPath)
					rcBranch = resolveRemoteBranchFromInfo(remoteCacheBranch, cfg.Cache.RemoteBranch, projInfo)
					rcLocalCachePath = resolveCachePath(cachePath, absPath)
					rcClient = newAPIClient(cfg, apiKeyFlag)
					performRemoteCacheDownload(ctx, rcClient, rcProject, rcBranch, evHash, rcLocalCachePath)
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
			if complianceFlag != "" {
				violations := compliance.Evaluate(results)
				complianceViolationCount = len(violations)
			}

			// Webhook: POST scan results with compliance data (non-fatal).
			if webhookURL != "" {
				wPayload := buildWebhookPayload(
					scanResult,
					projectName,
					resolveRemoteBranchFromInfo("", cfg.Cache.RemoteBranch, projInfo),
					"full",
					complianceViolationCount,
					complianceFlag,
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
				evaluateComplianceAdvisory(complianceFlag, results)
			default: // "blocking"
				policyErr := evaluatePolicy(cfg, failOn, results, scanResult)
				complianceErr := evaluateCompliance(complianceFlag, results)
				if policyErr != nil {
					return policyErr
				}
				return complianceErr
			}
			return nil
		},
	}

	cmd.Flags().StringVar(&targetPath, "path", "", "Directory to scan")
	cmd.Flags().StringVar(&format, "format", "table", "Output format: json, table, sarif, cbom, html")
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
	cmd.Flags().StringVar(&complianceFlag, "compliance", "", "Compliance standard to enforce (supported: cnsa-2.0). Prints violations and exits 1 if any are found.")
	cmd.Flags().StringVar(&ciMode, "ci-mode", "blocking", "CI behavior: blocking (exit 1 on violations), advisory (warn only, exit 0), silent (no policy/compliance output, exit 0)")
	cmd.Flags().StringVar(&webhookURL, "webhook-url", "", "POST scan results to this HTTPS URL on completion (JSON payload)")
	cmd.Flags().BoolVar(&signCBOM, "sign-cbom", false, "Sign the CBOM output with an ephemeral Ed25519 key pair (only applies when --format cbom)")
	cmd.Flags().IntVar(&dataLifetimeYears, "data-lifetime-years", 0,
		`Expected data retention period in years. Adjusts HNDL urgency in QRS scoring.
Industry guidelines: healthcare/medical=30, government/classified=25,
financial/banking=7, legal/contracts=10, web sessions/ephemeral=1.
0 = disabled (default). Values >10 amplify penalties, <5 reduce them.`)

	return cmd
}

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
		complianceFlag    string
		noCache           bool
		remoteCache       bool
		remoteCacheBranch string
		apiKeyFlag        string
		ciMode            string
		webhookURL        string
		dataLifetimeYears int
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
			if dataLifetimeYears < 0 {
				return fmt.Errorf("--data-lifetime-years must be >= 0 (got %d)", dataLifetimeYears)
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

			if incremental && noCache {
				fmt.Fprintln(os.Stderr, "WARNING: --incremental with --no-cache: performing normal diff scan (--no-cache overrides)")
			}

			opts := engines.ScanOptions{
				TargetPath:      absPath,
				Timeout:         timeout,
				MaxFileMB:       maxFileMB,
				EngineNames:     engineNames,
				Mode:            engines.ModeDiff,
				ChangedFiles:    changedFiles,
				ExcludePatterns: excludePatterns,
				Incremental:     incremental,
				CachePath:       cachePath,
				NoCache:         noCache,
			}

			selected := orch.EffectiveEngines(opts)
			if len(selected) == 0 {
				return fmt.Errorf("no scanner engines found — run 'oqs-scanner engines install --all' or ensure binaries are in PATH")
			}
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
				rcClient = newAPIClient(cfg, apiKeyFlag)
				performRemoteCacheDownload(ctx, rcClient, rcProject, rcBranch, evHash, rcLocalCachePath)
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
			if complianceFlag != "" {
				violations := compliance.Evaluate(results)
				diffComplianceViolations = len(violations)
			}

			// Webhook: POST scan results with compliance data (non-fatal).
			if webhookURL != "" {
				wPayload := buildWebhookPayload(
					scanResult,
					resolveProjectFromInfo(cfg.Upload.Project, projInfo, absPath),
					resolveRemoteBranchFromInfo("", cfg.Cache.RemoteBranch, projInfo),
					"diff",
					diffComplianceViolations,
					complianceFlag,
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
				evaluateComplianceAdvisory(complianceFlag, results)
			default: // "blocking"
				policyErr := evaluatePolicy(cfg, failOn, results, scanResult)
				complianceErr := evaluateCompliance(complianceFlag, results)
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
	cmd.Flags().StringVar(&format, "format", "table", "Output format: json, table, sarif, cbom, html")
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
	cmd.Flags().StringVar(&complianceFlag, "compliance", "", "Compliance standard to enforce (supported: cnsa-2.0). Prints violations and exits 1 if any are found.")
	cmd.Flags().StringVar(&ciMode, "ci-mode", "blocking", "CI behavior: blocking (exit 1 on violations), advisory (warn only, exit 0), silent (no policy/compliance output, exit 0)")
	cmd.Flags().StringVar(&webhookURL, "webhook-url", "", "POST scan results to this HTTPS URL on completion (JSON payload)")
	cmd.Flags().IntVar(&dataLifetimeYears, "data-lifetime-years", 0,
		`Expected data retention period in years. Adjusts HNDL urgency in QRS scoring.
Industry guidelines: healthcare/medical=30, government/classified=25,
financial/banking=7, legal/contracts=10, web sessions/ephemeral=1.
0 = disabled (default). Values >10 amplify penalties, <5 reduce them.`)

	return cmd
}

// writeOutput writes the scan result in the specified format to the given destination.
// When signCBOM is true and format is "cbom"/"cyclonedx", the CBOM is signed with an
// ephemeral Ed25519 key pair and the SignedCBOM envelope is written instead of raw CBOM.
func writeOutput(_ *cobra.Command, format, outputFile string, scanResult output.ScanResult, signCBOM bool) error {
	// Validate format before creating the file to avoid truncating existing output.
	switch format {
	case "json", "table", "sarif", "cbom", "cyclonedx", "html":
		// valid
	default:
		return fmt.Errorf("unknown format: %s (use 'json', 'table', 'sarif', 'cbom', or 'html')", format)
	}

	var w io.Writer = os.Stdout
	var f *os.File
	if outputFile != "" {
		var err error
		f, err = os.Create(outputFile)
		if err != nil {
			return fmt.Errorf("create output file: %w", err)
		}
		w = f
	}

	var writeErr error
	switch format {
	case "json":
		writeErr = output.WriteJSON(w, scanResult)
	case "table":
		writeErr = output.WriteTable(w, scanResult)
	case "sarif":
		writeErr = output.WriteSARIF(w, scanResult)
	case "cbom", "cyclonedx":
		if signCBOM {
			writeErr = writeSignedCBOM(w, scanResult)
		} else {
			writeErr = output.WriteCBOM(w, scanResult)
		}
	case "html":
		writeErr = output.WriteHTML(w, scanResult)
	}

	if writeErr != nil {
		if f != nil {
			f.Close() // best-effort cleanup; original writeErr is more relevant
		}
		return writeErr
	}

	// Flush and check close error to catch write failures (e.g. disk full).
	if f != nil {
		if err := f.Close(); err != nil {
			return fmt.Errorf("close output file: %w", err)
		}
	}

	return nil
}

// writeSignedCBOM generates an ephemeral Ed25519 key pair, signs the CBOM, and
// writes the SignedCBOM JSON envelope to w. The public key is embedded in the
// envelope so consumers can verify provenance without a separate key store.
func writeSignedCBOM(w io.Writer, scanResult output.ScanResult) error {
	// Render the raw CBOM into a buffer first.
	var buf bytes.Buffer
	if err := output.WriteCBOM(&buf, scanResult); err != nil {
		return fmt.Errorf("generate CBOM for signing: %w", err)
	}

	// Generate a fresh ephemeral key pair for this scan.
	_, priv, err := cbomutil.GenerateKeyPair()
	if err != nil {
		return fmt.Errorf("generate signing key: %w", err)
	}

	// Sign the CBOM bytes.
	envelope, err := cbomutil.Sign(buf.Bytes(), priv)
	if err != nil {
		return fmt.Errorf("sign CBOM: %w", err)
	}

	// Write the SignedCBOM envelope as indented JSON.
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	if err := enc.Encode(envelope); err != nil {
		return fmt.Errorf("encode signed CBOM: %w", err)
	}

	fmt.Fprintf(os.Stderr, "CBOM signed with ephemeral Ed25519 key (public key: %s)\n", envelope.PublicKey)
	return nil
}

func versionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print version and detected engines",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Printf("oqs-scanner v%s\n\n", version)

			orch := buildOrchestrator()
			fmt.Println("Engines:")
			for _, e := range orch.Engines() {
				status := "unavailable"
				if e.Available() {
					status = "available"
				}
				fmt.Printf("  %-15s tier=%s  status=%s  languages=%s\n",
					e.Name(),
					e.Tier(),
					status,
					strings.Join(e.SupportedLanguages(), ","),
				)
			}
		},
	}
}

// enginesCmd returns the parent "engines" command with list/doctor/install subcommands.
func enginesCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "engines",
		Short: "Manage and inspect scanner engine binaries",
	}
	cmd.AddCommand(enginesListCmd())
	cmd.AddCommand(enginesDoctorCmd())
	cmd.AddCommand(enginesInstallCmd())
	cmd.AddCommand(enginesUpdateCmd())
	return cmd
}

func enginesSearchDirs() []string {
	cacheDir := config.EngineCacheDir()
	dir := engineDir()
	if dir == "" {
		return []string{cacheDir, "./engines"}
	}
	return []string{cacheDir, dir, "./engines"}
}

func enginesListCmd() *cobra.Command {
	var asJSON bool

	cmd := &cobra.Command{
		Use:   "list",
		Short: "List all known engines and their availability",
		RunE: func(cmd *cobra.Command, args []string) error {
			statuses := enginemgr.CheckAll(enginesSearchDirs())
			reg := enginemgr.Registry()

			if asJSON {
				enc := json.NewEncoder(os.Stdout)
				enc.SetIndent("", "  ")
				return enc.Encode(statuses)
			}

			w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
			fmt.Fprintln(w, "ENGINE\tTIER\tSTATUS\tVERSION\tLANGUAGES")

			// Build a lookup for registry info by name.
			infoByName := make(map[string]enginemgr.EngineInfo, len(reg))
			for _, e := range reg {
				infoByName[e.Name] = e
			}

			for _, s := range statuses {
				info := infoByName[s.Name]

				statusStr := "missing"
				versionStr := "—"
				if s.Available {
					statusStr = "available"
					versionStr = s.Version
				}

				langs := strings.Join(info.Languages, ", ")
				fmt.Fprintf(w, "%s\t%d\t%s\t%s\t%s\n",
					s.Name, info.Tier, statusStr, versionStr, langs)
			}

			return w.Flush()
		},
	}

	cmd.Flags().BoolVar(&asJSON, "json", false, "Output as JSON array")
	return cmd
}

func enginesDoctorCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "doctor",
		Short: "Run health checks on all engines and report issues",
		RunE: func(cmd *cobra.Command, args []string) error {
			reg := enginemgr.Registry()
			statuses := enginemgr.CheckAll(enginesSearchDirs())

			// Build registry lookup.
			infoByName := make(map[string]enginemgr.EngineInfo, len(reg))
			for _, e := range reg {
				infoByName[e.Name] = e
			}

			fmt.Fprintln(os.Stderr, "Checking engines...")

			available := 0
			for _, s := range statuses {
				info := infoByName[s.Name]
				if s.Available {
					available++
					fmt.Fprintf(os.Stderr, "  \u2713 %-16s %-10s %s\n", s.Name, s.Version, s.Path)
				} else {
					fmt.Fprintf(os.Stderr, "  \u2717 %-16s not found \u2014 install with: %s\n",
						s.Name, info.InstallHint)
				}
			}

			fmt.Fprintf(os.Stderr, "\n%d/%d engines available\n", available, len(statuses))
			return nil
		},
	}
}

func enginesInstallCmd() *cobra.Command {
	var (
		all         bool
		force       bool
		manifestURL string
		offline     bool
	)

	cmd := &cobra.Command{
		Use:   "install [name...]",
		Short: "Download and install engine binaries to ~/.oqs/cache/engines/",
		Long: `Download pre-built engine binaries to ~/.oqs/cache/engines/.

Engines marked as not downloadable (e.g. semgrep, cdxgen) will print
installation instructions instead. Embedded engines (binary-scanner,
config-scanner) are silently skipped.

Examples:
  oqs-scanner engines install --all
  oqs-scanner engines install cipherscope cryptoscan
  oqs-scanner engines install --all --force`,
		RunE: func(cmd *cobra.Command, args []string) error {
			reg := enginemgr.Registry()

			installDir, err := enginemgr.InstallDir()
			if err != nil {
				return fmt.Errorf("resolve install dir: %w", err)
			}

			// Build registry lookup.
			infoByName := make(map[string]enginemgr.EngineInfo, len(reg))
			for _, e := range reg {
				infoByName[e.Name] = e
			}

			var targets []enginemgr.EngineInfo
			if all {
				targets = reg
			} else {
				if len(args) == 0 {
					return fmt.Errorf("specify at least one engine name or use --all\n\nAvailable engines: %s",
						engineNames(reg))
				}
				for _, name := range args {
					info, ok := infoByName[name]
					if !ok {
						return fmt.Errorf("unknown engine %q — available: %s", name, engineNames(reg))
					}
					targets = append(targets, info)
				}
			}

			// Load manifest (remote with fallback to embedded).
			ctx := context.Background()

			// Use separate clients: short timeout for manifest fetch, long for downloads.
			var manifestClient *http.Client
			if !offline {
				manifestClient = enginemgr.SecureHTTPClient(30 * time.Second)
			}
			url := manifestURL
			if offline {
				url = ""
			}

			manifest, fallback, remoteErr, err := enginemgr.LoadManifest(ctx, url, manifestClient)
			if err != nil {
				return fmt.Errorf("load manifest: %w", err)
			}
			if fallback && !offline {
				msg := "Using embedded manifest (remote fetch failed)"
				if remoteErr != nil {
					msg += ": " + remoteErr.Error()
				}
				fmt.Fprintf(os.Stderr, "%s.\n", msg)
			}

			// Separate downloadable, hint-only, and embedded engines.
			var downloadable []enginemgr.EngineInfo
			var hintOnly []enginemgr.EngineInfo
			var embedded []string

			for _, info := range targets {
				if info.BinaryName == "" {
					embedded = append(embedded, info.Name)
					continue
				}
				entry, ok := manifest.Engines[info.Name]
				if !ok || !entry.DownloadSupported {
					hintOnly = append(hintOnly, info)
					continue
				}
				downloadable = append(downloadable, info)
			}

			// Print install hints for non-downloadable engines.
			for _, info := range hintOnly {
				hint := info.InstallHint
				if entry, ok := manifest.Engines[info.Name]; ok && entry.InstallHintOverride != "" {
					hint = entry.InstallHintOverride
				}
				fmt.Fprintf(os.Stderr, "%s: not available for download. Install manually:\n", info.Name)
				for _, line := range strings.Split(hint, "\n") {
					fmt.Fprintf(os.Stderr, "  %s\n", line)
				}
				fmt.Fprintln(os.Stderr)
			}

			if len(downloadable) == 0 {
				if len(embedded) > 0 {
					fmt.Fprintf(os.Stderr, "Note: %s already built-in (no download needed).\n",
						strings.Join(embedded, ", "))
				}
				if len(hintOnly) > 0 && len(embedded) == 0 {
					return fmt.Errorf("no engines available for download")
				}
				if len(hintOnly) == 0 && len(embedded) == 0 {
					fmt.Fprintln(os.Stderr, "Nothing to download.")
				}
				return nil
			}

			// In offline mode, we can't download binaries.
			if offline {
				fmt.Fprintln(os.Stderr, "Offline mode: skipping binary downloads.")
				for _, info := range downloadable {
					fmt.Fprintf(os.Stderr, "  — %s: would download (use without --offline)\n", info.Name)
				}
				return nil
			}

			// Long timeout for binary downloads with HTTPS redirect enforcement.
			downloadClient := enginemgr.SecureHTTPClient(5 * time.Minute)

			fmt.Fprintf(os.Stderr, "Downloading %d engine(s) to %s...\n", len(downloadable), installDir)

			// Mutex protects concurrent progress writes to stderr.
			var progressMu sync.Mutex
			results := enginemgr.DownloadEngines(ctx, downloadable, manifest, enginemgr.DownloadOptions{
				InstallDir: installDir,
				Force:      force,
				HTTPClient: downloadClient,
				ProgressFunc: func(engine string, bytesRead int64) {
					progressMu.Lock()
					fmt.Fprintf(os.Stderr, "\r  %s: %d bytes downloaded", engine, bytesRead)
					progressMu.Unlock()
				},
			})

			// Print results.
			hasErr := false
			for _, r := range results {
				if r.Err != nil {
					fmt.Fprintf(os.Stderr, "\n  ✗ %s: %s\n", r.Name, r.ErrMsg)
					hasErr = true
				} else if r.Skipped {
					fmt.Fprintf(os.Stderr, "\n  — %s v%s: already installed (use --force to reinstall)\n", r.Name, r.Version)
				} else {
					fmt.Fprintf(os.Stderr, "\n  ✓ %s v%s: installed (%d bytes)\n", r.Name, r.Version, r.BytesRead)
					if r.WarnMsg != "" {
						fmt.Fprintf(os.Stderr, "    ⚠ %s\n", r.WarnMsg)
					}
				}
			}

			if len(embedded) > 0 {
				fmt.Fprintf(os.Stderr, "\nNote: %s already built-in (no download needed).\n",
					strings.Join(embedded, ", "))
			}

			if hasErr {
				return fmt.Errorf("some engines failed to install")
			}
			return nil
		},
	}

	cmd.Flags().BoolVar(&all, "all", false, "Install all downloadable engines")
	cmd.Flags().BoolVar(&force, "force", false, "Re-download even if binary already exists")
	cmd.Flags().StringVar(&manifestURL, "manifest-url", "https://releases.oqs.dev/engines/manifest.json", "URL for the engine manifest")
	cmd.Flags().BoolVar(&offline, "offline", false, "Use embedded manifest only (no remote fetch)")

	return cmd
}

func enginesUpdateCmd() *cobra.Command {
	var (
		all         bool
		manifestURL string
		offline     bool
		asJSON      bool
		dryRun      bool
	)

	cmd := &cobra.Command{
		Use:   "update [name...]",
		Short: "Update installed engines to latest versions from manifest",
		Long: `Check for newer engine versions in the manifest and download updates.

Only engines that are already installed AND have a newer version in the
manifest are updated. Non-downloadable engines (semgrep, cdxgen) show
the recommended install command for the manifest version.

Examples:
  oqs-scanner engines update --all
  oqs-scanner engines update cipherscope cryptoscan
  oqs-scanner engines update --all --dry-run`,
		RunE: func(cmd *cobra.Command, args []string) error {
			reg := enginemgr.Registry()

			// Build registry lookup.
			infoByName := make(map[string]enginemgr.EngineInfo, len(reg))
			for _, e := range reg {
				infoByName[e.Name] = e
			}

			var targets []enginemgr.EngineInfo
			if all {
				targets = reg
			} else {
				if len(args) == 0 {
					return fmt.Errorf("specify at least one engine name or use --all\n\nAvailable engines: %s",
						engineNames(reg))
				}
				for _, name := range args {
					info, ok := infoByName[name]
					if !ok {
						return fmt.Errorf("unknown engine %q — available: %s", name, engineNames(reg))
					}
					targets = append(targets, info)
				}
			}

			// Load manifest.
			ctx := context.Background()
			var manifestClient *http.Client
			if !offline {
				manifestClient = enginemgr.SecureHTTPClient(30 * time.Second)
			}
			url := manifestURL
			if offline {
				url = ""
			}

			manifest, fallback, remoteErr, err := enginemgr.LoadManifest(ctx, url, manifestClient)
			if err != nil {
				return fmt.Errorf("load manifest: %w", err)
			}
			if fallback && !offline {
				msg := "Using embedded manifest (remote fetch failed)"
				if remoteErr != nil {
					msg += ": " + remoteErr.Error()
				}
				fmt.Fprintf(os.Stderr, "%s.\n", msg)
			}

			// Check for updates.
			searchDirs := enginesSearchDirs()
			checks := enginemgr.CheckForUpdates(ctx, targets, manifest, searchDirs)

			if asJSON {
				enc := json.NewEncoder(os.Stdout)
				enc.SetIndent("", "  ")
				return enc.Encode(checks)
			}

			// Collect engines that need updating.
			var toUpdate []enginemgr.EngineInfo
			for _, uc := range checks {
				switch {
				case uc.UpdateAvailable:
					fmt.Fprintf(os.Stderr, "  ↑ %s: %s → %s\n", uc.Name, uc.InstalledVersion, uc.ManifestVersion)
					toUpdate = append(toUpdate, infoByName[uc.Name])
				case uc.Installed:
					fmt.Fprintf(os.Stderr, "  ✓ %s: %s (up to date)\n", uc.Name, uc.InstalledVersion)
				case uc.Reason == "not installed":
					fmt.Fprintf(os.Stderr, "  — %s: not installed (use 'engines install' first)\n", uc.Name)
				case uc.Reason == "not available for download":
					entry := manifest.Engines[uc.Name]
					hint := infoByName[uc.Name].InstallHint
					if entry.InstallHintOverride != "" {
						hint = entry.InstallHintOverride
					}
					fmt.Fprintf(os.Stderr, "  — %s: manual update needed (manifest: %s)\n", uc.Name, uc.ManifestVersion)
					for _, line := range strings.Split(hint, "\n") {
						fmt.Fprintf(os.Stderr, "    %s\n", line)
					}
				default:
					fmt.Fprintf(os.Stderr, "  — %s: %s\n", uc.Name, uc.Reason)
				}
			}

			if len(toUpdate) == 0 {
				fmt.Fprintln(os.Stderr, "\nAll engines are up to date.")
				return nil
			}

			if dryRun {
				fmt.Fprintf(os.Stderr, "\nDry run: %d engine(s) would be updated.\n", len(toUpdate))
				return nil
			}

			if offline {
				fmt.Fprintf(os.Stderr, "\nOffline mode: skipping binary downloads.\n")
				for _, info := range toUpdate {
					fmt.Fprintf(os.Stderr, "  — %s: would update (use without --offline)\n", info.Name)
				}
				return nil
			}

			// Download updates with Force=true.
			installDir, err := enginemgr.InstallDir()
			if err != nil {
				return fmt.Errorf("resolve install dir: %w", err)
			}

			downloadClient := enginemgr.SecureHTTPClient(5 * time.Minute)
			fmt.Fprintf(os.Stderr, "\nUpdating %d engine(s)...\n", len(toUpdate))

			var progressMu sync.Mutex
			results := enginemgr.DownloadEngines(ctx, toUpdate, manifest, enginemgr.DownloadOptions{
				InstallDir: installDir,
				Force:      true,
				HTTPClient: downloadClient,
				ProgressFunc: func(engine string, bytesRead int64) {
					progressMu.Lock()
					fmt.Fprintf(os.Stderr, "\r  %s: %d bytes downloaded", engine, bytesRead)
					progressMu.Unlock()
				},
			})

			hasErr := false
			for _, r := range results {
				if r.Err != nil {
					fmt.Fprintf(os.Stderr, "\n  ✗ %s: %s\n", r.Name, r.ErrMsg)
					hasErr = true
				} else {
					fmt.Fprintf(os.Stderr, "\n  ✓ %s v%s: updated (%d bytes)\n", r.Name, r.Version, r.BytesRead)
					if r.WarnMsg != "" {
						fmt.Fprintf(os.Stderr, "    ⚠ %s\n", r.WarnMsg)
					}
				}
			}

			if hasErr {
				return fmt.Errorf("some engines failed to update")
			}
			return nil
		},
	}

	cmd.Flags().BoolVar(&all, "all", false, "Check and update all engines")
	cmd.Flags().StringVar(&manifestURL, "manifest-url", "https://releases.oqs.dev/engines/manifest.json", "URL for the engine manifest")
	cmd.Flags().BoolVar(&offline, "offline", false, "Use embedded manifest only (no remote fetch)")
	cmd.Flags().BoolVar(&asJSON, "json", false, "Output update checks as JSON (no downloads)")
	cmd.Flags().BoolVar(&dryRun, "dry-run", false, "Check for updates without downloading")

	return cmd
}

// engineNames returns a comma-separated list of engine names from the registry.
func engineNames(reg []enginemgr.EngineInfo) string {
	names := make([]string, len(reg))
	for i, e := range reg {
		names[i] = e.Name
	}
	return strings.Join(names, ", ")
}

// defaultEndpoint is the default OQS platform API endpoint.
const defaultEndpoint = "https://api.oqs.dev"

// resolveEndpoint returns the endpoint from config, stored credentials, or the default.
// Priority: config > stored credential endpoint > defaultEndpoint.
func resolveEndpoint(cfg config.Config) string {
	if cfg.Endpoint != "" {
		return cfg.Endpoint
	}
	// Fall back to the endpoint stored during login — prevents sending
	// tokens to defaultEndpoint when the user authenticated against a
	// custom server.
	s := &auth.Store{}
	if cred, err := s.Load(); err == nil && cred.Endpoint != "" {
		return cred.Endpoint
	}
	return defaultEndpoint
}

// hasPlatformEndpoint reports whether a platform API endpoint has been
// explicitly configured. When cfg.Endpoint is empty, the scanner operates in
// local-only mode — the hardcoded defaultEndpoint is not treated as configured.
func hasPlatformEndpoint(cfg config.Config) bool {
	return cfg.Endpoint != ""
}

// isPlatformAvailable reports whether a platform API endpoint is reachable
// either via explicit config or stored credentials from a prior login.
func isPlatformAvailable(cfg config.Config) bool {
	if hasPlatformEndpoint(cfg) {
		return true
	}
	s := &auth.Store{}
	cred, err := s.Load()
	return err == nil && cred.AccessToken != "" && cred.Endpoint != ""
}

// newScanStore returns a ScanStore backed by local files (no platform) or the
// remote API (platform configured).
func newScanStore(cfg config.Config, apiKeyFlag string) store.ScanStore {
	if isPlatformAvailable(cfg) {
		client := newAPIClient(cfg, apiKeyFlag)
		return store.NewRemoteStore(client)
	}
	return store.NewLocalStore(config.ConfigDir())
}

// buildScanRecordFromInfo converts a ScanResult into a lightweight ScanRecord using
// pre-fetched ProjectInfo to avoid redundant git subprocess calls.
// dataLifetimeYears is stored on the record when > 0.
func buildScanRecordFromInfo(sr output.ScanResult, projInfo *gitutil.ProjectInfo, duration time.Duration, dataLifetimeYears int) store.ScanRecord {
	grade := ""
	score := 0
	if sr.QRS != nil {
		grade = sr.QRS.Grade
		score = sr.QRS.Score
	}

	var fs store.FindingSummary
	fs.Total = sr.Summary.TotalFindings
	for _, f := range sr.Findings {
		switch f.Severity {
		case findings.SevCritical:
			fs.Critical++
		case findings.SevHigh:
			fs.High++
		case findings.SevMedium:
			fs.Medium++
		case findings.SevLow:
			fs.Low++
		case findings.SevInfo:
			fs.Info++
		}
		switch f.QuantumRisk {
		case findings.QRVulnerable:
			fs.QuantumVulnerable++
		case findings.QRWeakened:
			fs.QuantumWeakened++
		case findings.QRSafe:
			fs.QuantumSafe++
		case findings.QRResistant:
			fs.QuantumResistant++
		case findings.QRDeprecated:
			fs.Deprecated++
		}
	}

	branch := ""
	commitSHA := ""
	if projInfo != nil {
		branch = projInfo.Branch
		commitSHA = projInfo.CommitSHA
	}

	// Build top findings for dashboard drill-down (capped at MaxTopFindings).
	// Priority order: critical first, then high, then by quantum risk.
	topFindings := make([]store.FindingDetail, 0, store.MaxTopFindings)
	for _, f := range sr.Findings {
		if len(topFindings) >= store.MaxTopFindings {
			break
		}
		alg := ""
		prim := ""
		if f.Algorithm != nil {
			alg = f.Algorithm.Name
			prim = f.Algorithm.Primitive
		} else if f.Dependency != nil {
			alg = f.Dependency.Library
			prim = "dependency"
		}
		if alg == "" {
			continue
		}
		// Shorten file path to last 2 segments for readability.
		file := f.Location.File
		parts := strings.Split(filepath.ToSlash(file), "/")
		if len(parts) > 2 {
			file = ".../" + strings.Join(parts[len(parts)-2:], "/")
		}
		topFindings = append(topFindings, store.FindingDetail{
			File:             file,
			Line:             f.Location.Line,
			Algorithm:        alg,
			Primitive:        prim,
			QuantumRisk:      string(f.QuantumRisk),
			Severity:         string(f.Severity),
			MigrationEffort:  f.MigrationEffort,
			HNDLRisk:         f.HNDLRisk,
			Recommendation:   f.Recommendation,
			TargetAlgorithm:  f.TargetAlgorithm,
			TargetStandard:   f.TargetStandard,
			MigrationSnippet: toStoreSnippet(f.MigrationSnippet),
			SourceEngine:     f.SourceEngine,
		})
	}

	return store.ScanRecord{
		ScanID:                fmt.Sprintf("%x", sha256.Sum256([]byte(time.Now().UTC().Format(time.RFC3339Nano))))[:12],
		Timestamp:             time.Now().UTC().Format(time.RFC3339),
		Branch:                branch,
		CommitSHA:             commitSHA,
		ScanMode:              "full",
		QuantumReadinessScore: score,
		QuantumReadinessGrade: grade,
		FindingSummary:        fs,
		Duration:              duration.Round(time.Millisecond).String(),
		DataLifetimeYears:     dataLifetimeYears,
		TopFindings:           topFindings,
	}
}

// toStoreSnippet converts a findings.MigrationSnippet to a store.FindingSnippet.
// Returns nil when the input is nil so callers can use omitempty serialization.
func toStoreSnippet(s *findings.MigrationSnippet) *store.FindingSnippet {
	if s == nil {
		return nil
	}
	return &store.FindingSnippet{
		Language:    s.Language,
		Before:      s.Before,
		After:       s.After,
		Explanation: s.Explanation,
	}
}

// saveLocalCBOMFromResult generates, sanitizes, and saves a CBOM from a scan result.
func saveLocalCBOMFromResult(scanResult output.ScanResult, projectName string) error {
	var cbomBuf bytes.Buffer
	if err := output.WriteCBOM(&cbomBuf, scanResult); err != nil {
		return fmt.Errorf("generate CBOM: %w", err)
	}

	sanitized, err := sanitize.ForUpload(cbomBuf.Bytes())
	if err != nil {
		return fmt.Errorf("sanitize CBOM: %w", err)
	}

	return saveLocalCBOM(sanitized, projectName)
}

// saveLocalCBOM saves sanitized CBOM bytes to ~/.oqs/uploads/{project-slug}/{timestamp}.cbom.json
// for offline use. Uses atomic write with symlink guard (consistent with cache.Save, auth.Store.Save).
func saveLocalCBOM(data []byte, projectName string) error {
	slug := store.ProjectSlug(projectName)
	if slug == "" {
		slug = "default"
	}

	dir := filepath.Join(config.UploadsDir(), slug)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("create uploads dir: %w", err)
	}

	filename := time.Now().UTC().Format("20060102T150405Z") + ".cbom.json"
	destPath := filepath.Join(dir, filename)

	tmp, err := os.CreateTemp(dir, "*.tmp")
	if err != nil {
		return fmt.Errorf("create temp file: %w", err)
	}
	tmpPath := tmp.Name()
	cleanup := true
	defer func() {
		if cleanup {
			os.Remove(tmpPath)
		}
	}()

	// Use fd-based Chmod (not path-based os.Chmod) to prevent TOCTOU race.
	if err := tmp.Chmod(0600); err != nil {
		tmp.Close()
		return fmt.Errorf("chmod: %w", err)
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return fmt.Errorf("write: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return fmt.Errorf("sync: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close: %w", err)
	}

	// Symlink guard: reject symlink destinations (consistent with cache.Save, auth.Store.Save).
	if info, err := os.Lstat(destPath); err == nil && info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("refusing to write to symlink at %s", destPath)
	}

	if err := os.Rename(tmpPath, destPath); err != nil {
		return fmt.Errorf("rename: %w", err)
	}
	cleanup = false

	fmt.Fprintf(os.Stderr, "CBOM saved locally: %s\n", destPath)
	return nil
}

// applyCommonConfigFallbacks applies config-file defaults for flags shared between
// scanCmd and diffCmd. It only applies a default if the flag was not explicitly set.
func applyCommonConfigFallbacks(cmd *cobra.Command, cfg config.Config,
	format *string, timeout *int, maxFileMB *int, engineNames *[]string,
	excludePatterns *[]string, failOn *string,
) {
	if !cmd.Flags().Changed("format") && cfg.Output.Format != "" {
		*format = cfg.Output.Format
	}
	if !cmd.Flags().Changed("timeout") && cfg.Scan.Timeout != 0 {
		*timeout = cfg.Scan.Timeout
	}
	if !cmd.Flags().Changed("max-file-mb") && cfg.Scan.MaxFileMB != 0 {
		*maxFileMB = cfg.Scan.MaxFileMB
	}
	if !cmd.Flags().Changed("engine") && len(cfg.Scan.Engines) > 0 {
		*engineNames = cfg.Scan.Engines
	}
	if !cmd.Flags().Changed("exclude") && len(cfg.Scan.Exclude) > 0 {
		*excludePatterns = cfg.Scan.Exclude
	}
	if !cmd.Flags().Changed("fail-on") && cfg.Policy.FailOn != "" {
		*failOn = cfg.Policy.FailOn
	}
}

// validateFailOn validates the --fail-on flag value.
func validateFailOn(failOn string) error {
	if failOn == "" {
		return nil
	}
	valid := map[string]bool{"critical": true, "high": true, "medium": true, "low": true}
	if !valid[failOn] {
		return fmt.Errorf("--fail-on must be one of: critical, high, medium, low")
	}
	return nil
}

// evaluatePolicy runs policy evaluation and returns errFailOn if violations are found.
func evaluatePolicy(cfg config.Config, failOn string, results []findings.UnifiedFinding, scanResult output.ScanResult) error {
	pol := policy.Policy{
		FailOn:               failOn,
		AllowedAlgorithms:    cfg.Policy.AllowedAlgorithms,
		BlockedAlgorithms:    cfg.Policy.BlockedAlgorithms,
		RequirePQC:           cfg.Policy.RequirePQC,
		MaxQuantumVulnerable: cfg.Policy.MaxQuantumVulnerable,
		MinQRS:               cfg.Policy.MinQRS,
	}
	summary := policy.ScanSummary{
		QuantumVulnerable: scanResult.Summary.QuantumVulnerable,
		QuantumSafe:       scanResult.Summary.QuantumSafe,
		QuantumResistant:  scanResult.Summary.QuantumResistant,
	}
	policyResult := policy.Evaluate(pol, results, scanResult.QRS, summary)
	if !policyResult.Pass {
		for _, v := range policyResult.Violations {
			fmt.Fprintf(os.Stderr, "Policy violation [%s]: %s\n", v.Rule, v.Message)
		}
		return errFailOn
	}
	return nil
}

// evaluateCompliance runs CNSA 2.0 (or other supported) compliance evaluation
// against scan findings. It prints a summary to stderr and returns errFailOn if
// any violations are found. It is a no-op when standard is empty.
func evaluateCompliance(standard string, results []findings.UnifiedFinding) error {
	if standard == "" {
		return nil
	}
	if standard != string(compliance.StandardCNSA20) {
		return fmt.Errorf("--compliance: unsupported standard %q (supported: cnsa-2.0)", standard)
	}

	violations := compliance.Evaluate(results)
	if len(violations) == 0 {
		fmt.Fprintf(os.Stderr, "CNSA 2.0 Compliance: PASS\n")
		return nil
	}

	fmt.Fprintf(os.Stderr, "CNSA 2.0 Compliance: FAIL (%d violation(s))\n", len(violations))
	for _, v := range violations {
		fmt.Fprintf(os.Stderr, "  [%s] %s\n", v.Rule, v.Message)
	}
	return errFailOn
}

// validateCIMode validates the --ci-mode flag value.
func validateCIMode(mode string) error {
	switch mode {
	case "blocking", "advisory", "silent":
		return nil
	default:
		return fmt.Errorf("--ci-mode must be one of: blocking, advisory, silent")
	}
}

// evaluatePolicyAdvisory runs policy evaluation in advisory mode: violations are
// printed to stderr with an [ADVISORY] prefix but always return nil (exit 0).
func evaluatePolicyAdvisory(cfg config.Config, failOn string, results []findings.UnifiedFinding, scanResult output.ScanResult) {
	pol := policy.Policy{
		FailOn:               failOn,
		AllowedAlgorithms:    cfg.Policy.AllowedAlgorithms,
		BlockedAlgorithms:    cfg.Policy.BlockedAlgorithms,
		RequirePQC:           cfg.Policy.RequirePQC,
		MaxQuantumVulnerable: cfg.Policy.MaxQuantumVulnerable,
		MinQRS:               cfg.Policy.MinQRS,
	}
	summary := policy.ScanSummary{
		QuantumVulnerable: scanResult.Summary.QuantumVulnerable,
		QuantumSafe:       scanResult.Summary.QuantumSafe,
		QuantumResistant:  scanResult.Summary.QuantumResistant,
	}
	policyResult := policy.Evaluate(pol, results, scanResult.QRS, summary)
	if !policyResult.Pass {
		for _, v := range policyResult.Violations {
			fmt.Fprintf(os.Stderr, "[ADVISORY] Policy violation [%s]: %s\n", v.Rule, v.Message)
		}
	}
}

// evaluateComplianceAdvisory runs compliance evaluation in advisory mode: violations
// are printed to stderr with an [ADVISORY] prefix but always return nil (exit 0).
func evaluateComplianceAdvisory(standard string, results []findings.UnifiedFinding) {
	if standard == "" {
		return
	}
	if standard != string(compliance.StandardCNSA20) {
		fmt.Fprintf(os.Stderr, "[ADVISORY] --compliance: unsupported standard %q (supported: cnsa-2.0)\n", standard)
		return
	}

	violations := compliance.Evaluate(results)
	if len(violations) == 0 {
		fmt.Fprintf(os.Stderr, "[ADVISORY] CNSA 2.0 Compliance: PASS\n")
		return
	}

	fmt.Fprintf(os.Stderr, "[ADVISORY] CNSA 2.0 Compliance: FAIL (%d violation(s))\n", len(violations))
	for _, v := range violations {
		fmt.Fprintf(os.Stderr, "[ADVISORY]   [%s] %s\n", v.Rule, v.Message)
	}
}

// noPlatformMessage is the standard guidance shown when auth/platform commands
// are used without a configured platform endpoint.
const noPlatformMessage = `No OQS platform configured. The scanner works fully offline.

To connect to a platform:
  oqs-scanner config set endpoint https://your-platform.example.com
  oqs-scanner login`

// newAPIClient creates an API client using the shared resolver and config.
func newAPIClient(cfg config.Config, apiKeyFlag string) *api.Client {
	resolver := newResolver(cfg, apiKeyFlag)
	endpoint := resolveEndpoint(cfg)

	tokenFn := func(ctx context.Context) (string, error) {
		token, _, err := resolver.Resolve(ctx)
		return token, err
	}

	var opts []api.ClientOption
	if cfg.CACert != "" {
		opts = append(opts, api.WithCACert(cfg.CACert))
	}

	return api.NewClient(endpoint, version, tokenFn, opts...)
}

// performUploadWithInfo uploads a CBOM using pre-fetched ProjectInfo to avoid
// redundant git subprocess calls.
func performUploadWithInfo(ctx context.Context, cfg config.Config, apiKeyFlag, scanPath string, projInfo *gitutil.ProjectInfo, scanResult output.ScanResult) error {
	var cbomBuf bytes.Buffer
	if err := output.WriteCBOM(&cbomBuf, scanResult); err != nil {
		return fmt.Errorf("generate CBOM: %w", err)
	}

	sanitized, err := sanitize.ForUpload(cbomBuf.Bytes())
	if err != nil {
		return fmt.Errorf("sanitize CBOM: %w", err)
	}

	projectName := cfg.Upload.Project
	branch := ""
	commitSHA := ""
	if projInfo != nil {
		if projectName == "" {
			projectName = projInfo.Project
		}
		branch = projInfo.Branch
		commitSHA = projInfo.CommitSHA
	}
	if projectName == "" {
		projectName = filepath.Base(scanPath)
	}

	var cbomDoc interface{}
	if err := json.Unmarshal(sanitized, &cbomDoc); err != nil {
		return fmt.Errorf("parse sanitized CBOM: %w", err)
	}

	client := newAPIClient(cfg, apiKeyFlag)
	resp, err := client.UploadCBOM(ctx, api.UploadRequest{
		Project:   projectName,
		Branch:    branch,
		CommitSHA: commitSHA,
		ScanMode:  "full",
		CBOM:      cbomDoc,
	})
	if err != nil {
		return err
	}

	fmt.Fprintf(os.Stderr, "Uploaded CBOM to OQS platform.\n")
	fmt.Fprintf(os.Stderr, "Dashboard: %s\n", resp.DashboardURL)
	fmt.Fprintf(os.Stderr, "Quantum Readiness Score: %d/100 (Grade: %s)\n",
		resp.QuantumReadinessScore, resp.QuantumReadinessGrade)
	return nil
}

func loginCmd() *cobra.Command {
	var (
		endpoint  string
		noBrowser bool
	)

	cmd := &cobra.Command{
		Use:   "login",
		Short: "Authenticate with the OQS platform",
		Long: `Authenticate with the OQS platform using browser-based login.
In headless environments (SSH, CI), use --no-browser for device code flow.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			// If no explicit --endpoint and no configured endpoint, show guidance.
			// Only read global config (~/.oqs/config.yaml) — never project-level
			// .oqs-scanner.yaml, which could redirect OAuth to an attacker's server.
			if !cmd.Flags().Changed("endpoint") {
				globalCfg, _ := config.LoadGlobal()
				if !hasPlatformEndpoint(globalCfg) {
					fmt.Fprintln(os.Stderr, noPlatformMessage)
					return nil
				}
				// Use globally configured endpoint instead of default.
				endpoint = globalCfg.Endpoint
			}

			ctx := context.Background()

			da := &auth.DeviceAuth{Endpoint: endpoint}

			dcResp, err := da.RequestDeviceCode(ctx)
			if err != nil {
				return fmt.Errorf("login failed: %w", err)
			}

			// Try to open browser unless --no-browser was set.
			if !noBrowser {
				verifyURL := dcResp.VerificationURI
				if dcResp.UserCode != "" {
					verifyURL += "?code=" + url.QueryEscape(dcResp.UserCode)
				}
				if browserErr := auth.OpenBrowser(verifyURL); browserErr != nil {
					noBrowser = true // Fall through to device code display.
				} else {
					fmt.Fprintf(os.Stderr, "Opening browser for authentication...\n")
				}
			}

			if noBrowser {
				fmt.Fprintf(os.Stderr, "No browser detected. Use device code flow:\n")
				fmt.Fprintf(os.Stderr, "  1. Visit: %s\n", dcResp.VerificationURI)
				fmt.Fprintf(os.Stderr, "  2. Enter code: %s\n", dcResp.UserCode)
			}

			fmt.Fprintf(os.Stderr, "Waiting for authentication...")

			// Set a timeout for the device code poll.
			expiry := dcResp.ExpiresIn
			if expiry <= 0 {
				expiry = 900 // default 15 minutes
			}
			pollCtx, cancel := context.WithTimeout(ctx, time.Duration(expiry)*time.Second)
			defer cancel()

			tokResp, err := da.PollForToken(pollCtx, dcResp.DeviceCode, dcResp.Interval)
			if err != nil {
				fmt.Fprintln(os.Stderr, " failed")
				return fmt.Errorf("login failed: %w", err)
			}

			fmt.Fprintln(os.Stderr, " done")

			// Save credentials.
			store := &auth.Store{}
			cred := auth.Credential{
				AccessToken:  tokResp.AccessToken,
				RefreshToken: tokResp.RefreshToken,
				ExpiresAt:    time.Now().Add(time.Duration(tokResp.ExpiresIn) * time.Second),
				Endpoint:     endpoint,
			}

			// Fetch identity to populate user fields.
			client := api.NewClient(endpoint, version, func(_ context.Context) (string, error) {
				return tokResp.AccessToken, nil
			})
			identity, identErr := client.GetIdentity(ctx)
			if identErr == nil {
				cred.UserEmail = identity.Email
				cred.OrgName = identity.Org
				cred.Plan = identity.Plan
			}

			if err := store.Save(cred); err != nil {
				return fmt.Errorf("save credentials: %w", err)
			}

			if cred.UserEmail != "" {
				fmt.Fprintf(os.Stderr, "Authenticated as: %s\n", cred.UserEmail)
			} else {
				fmt.Fprintf(os.Stderr, "Authenticated successfully.\n")
			}
			if cred.OrgName != "" {
				fmt.Fprintf(os.Stderr, "Organization: %s\n", cred.OrgName)
			}
			if cred.Plan != "" {
				fmt.Fprintf(os.Stderr, "Plan: %s\n", cred.Plan)
			}
			fmt.Fprintf(os.Stderr, "Credentials saved to %s\n", config.CredentialsPath())
			return nil
		},
	}

	cmd.Flags().StringVar(&endpoint, "endpoint", defaultEndpoint, "API endpoint URL")
	cmd.Flags().BoolVar(&noBrowser, "no-browser", false, "Force device code flow (skip browser)")

	return cmd
}

func logoutCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "logout",
		Short: "Clear stored credentials and revoke tokens",
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := context.Background()
			store := &auth.Store{}

			// Try to revoke on server (best effort).
			cred, loadErr := store.Load()
			if loadErr == nil && cred.Endpoint != "" {
				da := &auth.DeviceAuth{Endpoint: cred.Endpoint}
				_ = da.RevokeToken(ctx, cred.AccessToken, cred.RefreshToken)
			}

			if err := store.Delete(); err != nil {
				return fmt.Errorf("delete credentials: %w", err)
			}

			fmt.Fprintln(os.Stderr, "Logged out successfully.")
			return nil
		},
	}
}

func whoamiCmd() *cobra.Command {
	var asJSON bool

	cmd := &cobra.Command{
		Use:   "whoami",
		Short: "Show current identity, organization, and plan",
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := context.Background()
			store := &auth.Store{}

			cred, err := store.Load()
			if err != nil {
				cfg, _ := config.Load(".")
				if !hasPlatformEndpoint(cfg) {
					fmt.Fprintln(os.Stderr, "Not connected to any OQS platform.")
					fmt.Fprintln(os.Stderr, "The scanner works fully offline — no login required for local scanning.")
					return nil
				}
				return fmt.Errorf("not authenticated. Run 'oqs-scanner login' first.")
			}

			endpoint := cred.Endpoint
			if endpoint == "" {
				endpoint = defaultEndpoint
			}

			// Fetch fresh identity from server using fully-wired resolver
			// (including RefreshFn so expired-but-refreshable tokens auto-refresh).
			cfg, _ := config.Load(".")
			client := newAPIClient(cfg, "")

			identity, err := client.GetIdentity(ctx)
			if err != nil {
				// Fall back to cached credential data.
				identity = &api.Identity{
					Email: cred.UserEmail,
					Org:   cred.OrgName,
					Plan:  cred.Plan,
				}
			}
			identity.Endpoint = endpoint

			if asJSON {
				enc := json.NewEncoder(os.Stdout)
				enc.SetIndent("", "  ")
				return enc.Encode(identity)
			}

			fmt.Printf("Email:        %s\n", identity.Email)
			fmt.Printf("Organization: %s\n", identity.Org)
			fmt.Printf("Plan:         %s\n", identity.Plan)
			fmt.Printf("API Endpoint: %s\n", identity.Endpoint)
			if !cred.ExpiresAt.IsZero() {
				remaining := time.Until(cred.ExpiresAt).Round(time.Minute)
				if remaining > 0 {
					fmt.Printf("Token Expires: %s (in %s)\n", cred.ExpiresAt.Format(time.RFC3339), remaining)
				} else {
					fmt.Printf("Token Expires: %s (expired)\n", cred.ExpiresAt.Format(time.RFC3339))
				}
			}
			return nil
		},
	}

	cmd.Flags().BoolVar(&asJSON, "json", false, "Output as JSON")
	return cmd
}

func uploadCmd() *cobra.Command {
	var (
		cbomPath   string
		projectOvr string
		apiKeyFlag string
	)

	cmd := &cobra.Command{
		Use:   "upload",
		Short: "Upload a CBOM file to the OQS platform dashboard",
		RunE: func(cmd *cobra.Command, args []string) error {
			if cbomPath == "" {
				return fmt.Errorf("--cbom is required")
			}

			ctx := context.Background()

			// Read CBOM file.
			cbomData, err := os.ReadFile(cbomPath)
			if err != nil {
				return fmt.Errorf("read CBOM file: %w", err)
			}

			// Sanitize before upload (hard enforcement).
			sanitized, err := sanitize.ForUpload(cbomData)
			if err != nil {
				return fmt.Errorf("sanitize CBOM: %w", err)
			}

			// Infer project metadata from git — always attempt for branch/commitSHA.
			// --project only overrides the project name, not git metadata.
			projectName := projectOvr
			branch := ""
			commitSHA := ""
			projInfo, gitErr := gitutil.InferProject(ctx, ".")
			if gitErr == nil {
				if projectName == "" {
					projectName = projInfo.Project
				}
				branch = projInfo.Branch
				commitSHA = projInfo.CommitSHA
			}
			if projectName == "" {
				cwd, _ := os.Getwd()
				projectName = filepath.Base(cwd)
			}

			// Parse CBOM JSON for the upload request.
			var cbomDoc interface{}
			if err := json.Unmarshal(sanitized, &cbomDoc); err != nil {
				return fmt.Errorf("parse sanitized CBOM: %w", err)
			}

			// Load config for endpoint.
			cfg, _ := config.Load(".")

			if !isPlatformAvailable(cfg) {
				// Save locally using atomic write (consistent with saveLocalCBOMFromResult).
				return saveLocalCBOM(sanitized, projectName)
			}

			client := newAPIClient(cfg, apiKeyFlag)

			resp, err := client.UploadCBOM(ctx, api.UploadRequest{
				Project:   projectName,
				Branch:    branch,
				CommitSHA: commitSHA,
				ScanMode:  "full",
				CBOM:      cbomDoc,
			})
			if err != nil {
				return fmt.Errorf("upload failed: %w", err)
			}

			fmt.Fprintf(os.Stderr, "Uploaded CBOM to OQS platform.\n")
			fmt.Fprintf(os.Stderr, "Dashboard: %s\n", resp.DashboardURL)
			fmt.Fprintf(os.Stderr, "Quantum Readiness Score: %d/100 (Grade: %s)\n",
				resp.QuantumReadinessScore, resp.QuantumReadinessGrade)
			return nil
		},
	}

	cmd.Flags().StringVar(&cbomPath, "cbom", "", "Path to CBOM file (required)")
	cmd.Flags().StringVar(&projectOvr, "project", "", "Project name override (default: inferred from git remote)")
	cmd.Flags().StringVar(&apiKeyFlag, "api-key", "", "API key for authentication (overrides stored credentials)")

	return cmd
}

func historyCmd() *cobra.Command {
	var (
		projectOvr string
		limit      int
		asJSON     bool
		apiKeyFlag string
	)

	cmd := &cobra.Command{
		Use:   "history",
		Short: "Show scan history for the current project",
		Long: `Show scan history for the current project.

When connected to an OQS platform, history is fetched from the remote API.
Otherwise, history is read from local storage (~/.oqs/history/).`,
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := context.Background()

			projectName := projectOvr
			if projectName == "" {
				projInfo, gitErr := gitutil.InferProject(ctx, ".")
				if gitErr == nil {
					projectName = projInfo.Project
				}
			}
			if projectName == "" {
				return fmt.Errorf("could not infer project name. Use --project or run from a git repository")
			}

			cfg, _ := config.Load(".")
			scanStore := newScanStore(cfg, apiKeyFlag)

			records, err := scanStore.ListScans(ctx, projectName, store.ListOptions{Limit: limit})
			if err != nil {
				return fmt.Errorf("fetch history: %w", err)
			}

			if asJSON {
				enc := json.NewEncoder(os.Stdout)
				enc.SetIndent("", "  ")
				return enc.Encode(records)
			}

			if len(records) == 0 {
				fmt.Fprintln(os.Stderr, "No scan history found.")
				return nil
			}

			w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
			fmt.Fprintln(w, "SCAN ID\tDATE\tQRS\tGRADE\tFINDINGS\tMODE")
			for _, s := range records {
				date := s.Timestamp
				if len(date) > 16 {
					date = date[:16] // Trim to "2006-01-02T15:04"
				}
				fmt.Fprintf(w, "%s\t%s\t%d\t%s\t%d\t%s\n",
					s.ScanID, date, s.QuantumReadinessScore,
					s.QuantumReadinessGrade, s.FindingSummary.Total, s.ScanMode)
			}
			return w.Flush()
		},
	}

	cmd.Flags().StringVar(&projectOvr, "project", "", "Project name (default: inferred from git)")
	cmd.Flags().IntVarP(&limit, "limit", "n", 10, "Number of entries to show")
	cmd.Flags().BoolVar(&asJSON, "json", false, "Output as JSON")
	cmd.Flags().StringVar(&apiKeyFlag, "api-key", "", "API key for authentication (overrides stored credentials)")

	return cmd
}

func trendsCmd() *cobra.Command {
	var (
		projectOvr string
		asJSON     bool
		limit      int
	)

	cmd := &cobra.Command{
		Use:   "trends",
		Short: "Show scan trend analysis for a project",
		Long: `Show scan trend analysis for the current project.

Reads local scan history (~/.oqs/history/) and computes a QRS trend over
the most recent N scans. Use --json for machine-readable output.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := context.Background()

			projectName := projectOvr
			if projectName == "" {
				projInfo, gitErr := gitutil.InferProject(ctx, ".")
				if gitErr == nil {
					projectName = projInfo.Project
				}
			}
			if projectName == "" {
				return fmt.Errorf("could not infer project name. Use --project or run from a git repository")
			}

			ls := store.NewLocalStore(config.ConfigDir())
			records, err := ls.ListScans(ctx, projectName, store.ListOptions{Limit: limit})
			if err != nil {
				return fmt.Errorf("load history: %w", err)
			}

			td := trends.Compute(projectName, records)

			if asJSON {
				enc := json.NewEncoder(os.Stdout)
				enc.SetIndent("", "  ")
				return enc.Encode(td)
			}

			if len(td.DataPoints) == 0 {
				fmt.Fprintln(os.Stderr, "No scan history found.")
				return nil
			}

			fmt.Fprintf(os.Stdout, "Trend Analysis: %s\n\n", projectName)

			w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
			fmt.Fprintln(w, "DATE\tQRS\tGRADE\tFINDINGS\tVULNERABLE\tDEPRECATED")
			for _, dp := range td.DataPoints {
				date := dp.Timestamp
				if len(date) > 10 {
					date = date[:10] // trim to YYYY-MM-DD
				}
				fmt.Fprintf(w, "%s\t%d\t%s\t%d\t%d\t%d\n",
					date, dp.QRS, dp.Grade, dp.Findings, dp.Vulnerable, dp.Deprecated)
			}
			if err := w.Flush(); err != nil {
				return err
			}

			fmt.Fprintf(os.Stdout, "\nSummary: %s\n", td.Summary)
			return nil
		},
	}

	cmd.Flags().StringVar(&projectOvr, "project", "", "Project name (default: inferred from git)")
	cmd.Flags().BoolVar(&asJSON, "json", false, "Output as JSON")
	cmd.Flags().IntVarP(&limit, "limit", "n", 20, "Number of scans to analyze")

	return cmd
}

// apikeyCmd returns the parent "apikey" command with create/list/revoke subcommands.
func apikeyCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "apikey",
		Short: "Manage API keys for CI/CD authentication",
		Long: `Create, list, and revoke API keys for programmatic access to the OQS platform.

API keys are suited for CI/CD pipelines where interactive browser login is not
possible. They carry the prefix "oqs_k_" and do not expire via OAuth refresh.

The raw key is shown exactly once at creation time — save it immediately.

Examples:
  oqs-scanner apikey create --name "github-actions-prod"
  oqs-scanner apikey list
  oqs-scanner apikey revoke oqs_k_Ab`,
	}
	cmd.AddCommand(apikeyCreateCmd())
	cmd.AddCommand(apikeyListCmd())
	cmd.AddCommand(apikeyRevokeCmd())
	return cmd
}

func apikeyCreateCmd() *cobra.Command {
	var (
		name       string
		apiKeyFlag string
	)

	cmd := &cobra.Command{
		Use:   "create",
		Short: "Create a new API key",
		RunE: func(cmd *cobra.Command, args []string) error {
			if name == "" {
				return fmt.Errorf("--name is required")
			}

			cfg, _ := config.Load(".")
			if !isPlatformAvailable(cfg) {
				fmt.Fprintln(os.Stderr, "API keys require a configured OQS platform endpoint.")
				fmt.Fprintln(os.Stderr, "  oqs-scanner config set endpoint https://your-platform.example.com")
				return nil
			}

			ctx := context.Background()
			client := newAPIClient(cfg, apiKeyFlag)

			result, err := client.CreateAPIKey(ctx, name)
			if err != nil {
				return fmt.Errorf("create API key: %w", err)
			}

			fmt.Fprintf(os.Stderr, "API key created successfully.\n")
			fmt.Printf("Key:    %s\n", result.RawKey)
			fmt.Printf("Prefix: %s\n", result.KeyPrefix)
			fmt.Printf("Name:   %s\n", result.Name)
			fmt.Fprintf(os.Stderr, "\nSave this key — it will not be shown again.\n")
			return nil
		},
	}

	cmd.Flags().StringVar(&name, "name", "", "Human-readable label for the API key (required)")
	cmd.Flags().StringVar(&apiKeyFlag, "api-key", "", "API key for authentication (overrides stored credentials)")
	return cmd
}

func apikeyListCmd() *cobra.Command {
	var (
		asJSON     bool
		apiKeyFlag string
	)

	cmd := &cobra.Command{
		Use:   "list",
		Short: "List all API keys (masked)",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, _ := config.Load(".")
			if !isPlatformAvailable(cfg) {
				fmt.Fprintln(os.Stderr, "API keys require a configured OQS platform endpoint.")
				fmt.Fprintln(os.Stderr, "  oqs-scanner config set endpoint https://your-platform.example.com")
				return nil
			}

			ctx := context.Background()
			client := newAPIClient(cfg, apiKeyFlag)

			result, err := client.ListAPIKeys(ctx)
			if err != nil {
				return fmt.Errorf("list API keys: %w", err)
			}

			if asJSON {
				enc := json.NewEncoder(os.Stdout)
				enc.SetIndent("", "  ")
				return enc.Encode(result)
			}

			if len(result.Keys) == 0 {
				fmt.Fprintln(os.Stderr, "No API keys found.")
				return nil
			}

			w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
			fmt.Fprintln(w, "PREFIX\tNAME\tLAST USED\tCREATED\tSTATUS")
			for _, k := range result.Keys {
				lastUsed := k.LastUsed
				if lastUsed == "" {
					lastUsed = "never"
				} else if len(lastUsed) > 16 {
					lastUsed = lastUsed[:16]
				}
				created := k.CreatedAt
				if len(created) > 16 {
					created = created[:16]
				}
				status := "active"
				if k.Revoked {
					status = "revoked"
				}
				fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\n",
					k.KeyPrefix, k.Name, lastUsed, created, status)
			}
			return w.Flush()
		},
	}

	cmd.Flags().BoolVar(&asJSON, "json", false, "Output as JSON")
	cmd.Flags().StringVar(&apiKeyFlag, "api-key", "", "API key for authentication (overrides stored credentials)")
	return cmd
}

func apikeyRevokeCmd() *cobra.Command {
	var apiKeyFlag string

	cmd := &cobra.Command{
		Use:   "revoke <key-prefix>",
		Short: "Revoke an API key by its prefix",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			keyPrefix := args[0]

			cfg, _ := config.Load(".")
			if !isPlatformAvailable(cfg) {
				fmt.Fprintln(os.Stderr, "API keys require a configured OQS platform endpoint.")
				fmt.Fprintln(os.Stderr, "  oqs-scanner config set endpoint https://your-platform.example.com")
				return nil
			}

			ctx := context.Background()
			client := newAPIClient(cfg, apiKeyFlag)

			if err := client.RevokeAPIKey(ctx, keyPrefix); err != nil {
				return fmt.Errorf("revoke API key: %w", err)
			}

			fmt.Fprintf(os.Stderr, "API key %q revoked.\n", keyPrefix)
			return nil
		},
	}

	cmd.Flags().StringVar(&apiKeyFlag, "api-key", "", "API key for authentication (overrides stored credentials)")
	return cmd
}

func configCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "config",
		Short: "Manage scanner configuration",
	}
	cmd.AddCommand(configShowCmd())
	cmd.AddCommand(configSetCmd())
	cmd.AddCommand(configInitCmd())
	return cmd
}

func configShowCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "show",
		Short: "Show the resolved configuration",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := config.Load(".")
			if err != nil {
				return fmt.Errorf("load config: %w", err)
			}
			enc := json.NewEncoder(os.Stdout)
			enc.SetIndent("", "  ")
			return enc.Encode(cfg)
		},
	}
}

func configSetCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "set <key> <value>",
		Short: "Set a global configuration value in ~/.oqs/config.yaml",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			key, value := args[0], args[1]

			if err := config.EnsureConfigDir(); err != nil {
				return fmt.Errorf("create config dir: %w", err)
			}

			// Load existing global config.
			cfg, err := config.LoadGlobal()
			if err != nil {
				return fmt.Errorf("load global config: %w", err)
			}

			// Set the value based on key.
			switch key {
			case "endpoint":
				cfg.Endpoint = value
			case "caCert", "ca-cert":
				cfg.CACert = value
			case "format":
				cfg.Output.Format = value
			default:
				return fmt.Errorf("unknown config key: %q (supported: endpoint, ca-cert, format)", key)
			}

			// Write back as YAML.
			data, err := yaml.Marshal(cfg)
			if err != nil {
				return err
			}

			path := config.GlobalConfigPath()
			dir := filepath.Dir(path)
			tmp, err := os.CreateTemp(dir, ".config-*.tmp")
			if err != nil {
				return fmt.Errorf("write config: %w", err)
			}
			tmpPath := tmp.Name()
			defer func() {
				if tmpPath != "" {
					os.Remove(tmpPath)
				}
			}()
			if err := tmp.Chmod(0600); err != nil {
				tmp.Close()
				return fmt.Errorf("write config: %w", err)
			}
			if _, err := tmp.Write(data); err != nil {
				tmp.Close()
				return fmt.Errorf("write config: %w", err)
			}
			if err := tmp.Sync(); err != nil {
				tmp.Close()
				return fmt.Errorf("write config: %w", err)
			}
			if err := tmp.Close(); err != nil {
				return fmt.Errorf("write config: %w", err)
			}
			// Symlink guard: reject symlinks at destination to prevent symlink-following.
			if fi, err := os.Lstat(path); err == nil && fi.Mode()&os.ModeSymlink != 0 {
				return fmt.Errorf("config path is a symlink (possible attack): %s", path)
			}
			if err := os.Rename(tmpPath, path); err != nil {
				return fmt.Errorf("write config: %w", err)
			}
			tmpPath = "" // prevent defer cleanup

			fmt.Fprintf(os.Stderr, "Set %s = %s in %s\n", key, value, path)
			return nil
		},
	}
}

func configInitCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "init",
		Short: "Create a .oqs-scanner.yaml config file in the current directory",
		RunE: func(cmd *cobra.Command, args []string) error {
			path := ".oqs-scanner.yaml"
			if _, err := os.Stat(path); err == nil {
				return fmt.Errorf("%s already exists", path)
			}

			defaultConfig := `# OQS Scanner configuration
# See: https://github.com/jimbo111/open-quantum-secure

scan:
  timeout: 300          # seconds
  # engines: []         # empty = all available
  # exclude:
  #   - "vendor/**"
  #   - "node_modules/**"

output:
  format: table         # json, table, sarif, cbom, html

policy:
  # failOn: critical    # critical, high, medium, low
  # blockedAlgorithms:
  #   - "MD5"
  #   - "SHA-1"
  # requirePQC: false
  # minQRS: 0

upload:
  # autoUpload: false   # auto-upload CBOM after scan
  # project: ""         # project name (default: inferred from git remote)
`

			if err := os.WriteFile(path, []byte(defaultConfig), 0644); err != nil {
				return fmt.Errorf("write config: %w", err)
			}

			fmt.Fprintf(os.Stderr, "Created %s with defaults.\n", path)
			return nil
		},
	}
}

func complianceReportCmd() *cobra.Command {
	var (
		targetPath string
		outputFile string
		projectOvr string
	)
	cmd := &cobra.Command{
		Use:   "compliance-report",
		Short: "Generate a CNSA 2.0 compliance report (markdown)",
		Long: `Scan a directory for cryptographic usage and generate a formal CNSA 2.0
compliance report in markdown format. The report includes an executive summary,
per-algorithm compliance status, violation details, and approved algorithm
reference. Output can be written to a file or stdout.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			absPath, err := filepath.Abs(targetPath)
			if err != nil {
				return fmt.Errorf("resolve path: %w", err)
			}

			// Determine project name: flag > git > directory basename.
			project := projectOvr
			if project == "" {
				project = resolveProject(context.Background(), "", absPath)
			}

			orch := buildOrchestrator()

			ctx := context.Background()

			opts := engines.ScanOptions{
				TargetPath: absPath,
				Mode:       engines.ModeFull,
			}

			selected := orch.EffectiveEngines(opts)
			if len(selected) == 0 {
				return fmt.Errorf("no scanner engines found — run 'oqs-scanner engines install --all' or ensure binaries are in PATH")
			}
			fmt.Fprintf(os.Stderr, "Scanning %s with %d engine(s) for compliance report...\n", absPath, len(selected))

			scanStart := time.Now()
			ff, _, err := orch.ScanWithImpact(ctx, opts)
			scanDuration := time.Since(scanStart)
			if err != nil {
				return fmt.Errorf("scan failed: %w", err)
			}
			fmt.Fprintf(os.Stderr, "Scan completed in %s — %d findings\n", scanDuration.Round(time.Millisecond), len(ff))

			violations := compliance.Evaluate(ff)
			data := compliance.BuildReportData(ff, violations, project, version, time.Now())

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

			if err := compliance.GenerateMarkdown(w, data); err != nil {
				if outFile != nil {
					outFile.Close()
				}
				return fmt.Errorf("generate report: %w", err)
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
				if !data.Compliant {
					status = fmt.Sprintf("FAIL (%d violation(s))", len(violations))
				}
				fmt.Fprintf(os.Stderr, "Compliance report written to %s — %s\n", outputFile, status)
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&targetPath, "path", ".", "Directory to scan")
	cmd.Flags().StringVar(&outputFile, "output", "", "Output file path (default: stdout)")
	cmd.Flags().StringVar(&projectOvr, "project", "", "Project name for report header (default: inferred from git)")
	return cmd
}

// dashboardCmd returns the "dashboard" command which starts a local web server
// that visualises scan history stored in ~/.oqs/history/.
func dashboardCmd() *cobra.Command {
	var addr string
	cmd := &cobra.Command{
		Use:   "dashboard",
		Short: "Start a local web dashboard to visualise scan history",
		Long: `Start a local web dashboard to visualise scan history.

Opens a lightweight HTTP server at the given address serving an interactive
dashboard with QRS trend charts, finding breakdowns, and recent scan tables.
History is read directly from local files — no backend server required.

Press Ctrl+C to stop the dashboard.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			histDir := config.HistoryDir()
			fmt.Fprintf(os.Stderr, "Dashboard running at http://localhost%s\n", addr)
			fmt.Fprintf(os.Stderr, "History directory: %s\n", histDir)
			fmt.Fprintf(os.Stderr, "Press Ctrl+C to stop.\n")
			return dashboard.Serve(addr, histDir)
		},
	}
	cmd.Flags().StringVar(&addr, "addr", ":8899", "Address to listen on (e.g. :8899 or 127.0.0.1:9000)")
	return cmd
}
