// engines.go implements the `engines` subcommand family (list/doctor/install/update).

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"sort"
	"strings"
	"sync"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	"github.com/jimbo111/open-quantum-secure/pkg/config"
	"github.com/jimbo111/open-quantum-secure/pkg/enginemgr"
	"github.com/jimbo111/open-quantum-secure/pkg/orchestrator"
)

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

// allEngineNames returns the canonical Name() of every engine registered
// in orch — including engines whose binary isn't currently available. Used
// by validateEngineNames to give a "did-you-mean" set on --engine typos.
func allEngineNames(orch *orchestrator.Orchestrator) []string {
	all := orch.Engines()
	names := make([]string, 0, len(all))
	for _, e := range all {
		names = append(names, e.Name())
	}
	sort.Strings(names)
	return names
}

// engineNames returns a comma-separated list of engine names from the registry.
func engineNames(reg []enginemgr.EngineInfo) string {
	names := make([]string, len(reg))
	for i, e := range reg {
		names[i] = e.Name
	}
	return strings.Join(names, ", ")
}
