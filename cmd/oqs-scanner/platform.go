// platform.go implements OQS platform connectivity: endpoint resolution, remote
// cache sync, CBOM upload, and the upload/history/trends subcommands.

package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	"github.com/jimbo111/open-quantum-secure/pkg/api"
	"github.com/jimbo111/open-quantum-secure/pkg/auth"
	"github.com/jimbo111/open-quantum-secure/pkg/cache"
	"github.com/jimbo111/open-quantum-secure/pkg/config"
	"github.com/jimbo111/open-quantum-secure/pkg/findings"
	"github.com/jimbo111/open-quantum-secure/pkg/gitutil"
	"github.com/jimbo111/open-quantum-secure/pkg/output"
	"github.com/jimbo111/open-quantum-secure/pkg/sanitize"
	"github.com/jimbo111/open-quantum-secure/pkg/store"
	"github.com/jimbo111/open-quantum-secure/pkg/trends"
)

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
// remote API (platform configured). Falls back to the local store with a
// WARNING if API-client construction fails (bad CA cert path, etc.) so that
// scan functionality continues even when the platform integration is broken.
func newScanStore(cfg config.Config, apiKeyFlag string) store.ScanStore {
	if isPlatformAvailable(cfg) {
		client, err := newAPIClient(cfg, apiKeyFlag)
		if err != nil {
			fmt.Fprintf(os.Stderr, "WARNING: platform client unavailable, using local store: %v\n", err)
			return store.NewLocalStore(config.ConfigDir())
		}
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

// noPlatformMessage is the standard guidance shown when auth/platform commands
// are used without a configured platform endpoint.
const noPlatformMessage = `No OQS platform configured. The scanner works fully offline.

To connect to a platform:
  oqs-scanner config set endpoint https://your-platform.example.com
  oqs-scanner login`

// newAPIClient creates an API client using the shared resolver and config.
func newAPIClient(cfg config.Config, apiKeyFlag string) (*api.Client, error) {
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

	client, err := newAPIClient(cfg, apiKeyFlag)
	if err != nil {
		return fmt.Errorf("api client: %w", err)
	}
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

			client, err := newAPIClient(cfg, apiKeyFlag)
			if err != nil {
				return fmt.Errorf("api client: %w", err)
			}

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
