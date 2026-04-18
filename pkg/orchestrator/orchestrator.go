package orchestrator

import (
	"context"
	"fmt"
	"io/fs"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/jimbo111/open-quantum-secure/pkg/cache"
	"github.com/jimbo111/open-quantum-secure/pkg/constresolver"
	"github.com/jimbo111/open-quantum-secure/pkg/engines"
	"github.com/jimbo111/open-quantum-secure/pkg/findings"
	"github.com/jimbo111/open-quantum-secure/pkg/impact"
	"github.com/jimbo111/open-quantum-secure/pkg/impact/forward"
	"github.com/jimbo111/open-quantum-secure/pkg/migration"
	"github.com/jimbo111/open-quantum-secure/pkg/quantum"
	"github.com/jimbo111/open-quantum-secure/pkg/registry"
	"github.com/jimbo111/open-quantum-secure/pkg/suppress"
)

// Orchestrator discovers and runs engines, collecting findings.
type Orchestrator struct {
	engines []engines.Engine
}

// New creates an orchestrator with the given engines.
func New(engs ...engines.Engine) *Orchestrator {
	return &Orchestrator{engines: engs}
}

// Engines returns all registered engines.
func (o *Orchestrator) Engines() []engines.Engine {
	return o.engines
}

// SelectedEngines returns available engines filtered by name (or all if names is empty).
func (o *Orchestrator) SelectedEngines(names []string) []engines.Engine {
	available := o.AvailableEngines()
	if len(names) > 0 {
		return filterEngines(available, names)
	}
	return available
}

// AvailableEngines returns engines whose binaries are detected.
func (o *Orchestrator) AvailableEngines() []engines.Engine {
	var available []engines.Engine
	for _, e := range o.engines {
		if e.Available() {
			available = append(available, e)
		}
	}
	return available
}

// EffectiveEngines returns the engines that would actually execute for the given options.
// This applies the same filtering as Scan: engine name filter + tier filter for diff/quick mode
// + ScanType gating for Tier 4 binary and Tier 5 network engines.
// When TLSTargets are explicitly provided, the tls-probe engine is included regardless of mode.
func (o *Orchestrator) EffectiveEngines(opts engines.ScanOptions) []engines.Engine {
	available := o.AvailableEngines()
	if len(opts.EngineNames) > 0 {
		available = filterEngines(available, opts.EngineNames)
	}
	if opts.Mode == engines.ModeDiff || opts.Mode == engines.ModeQuick {
		available = filterByTier(available, engines.Tier1Pattern)
	} else {
		available = applyScanTypeFilter(available, opts.ScanType)
	}
	// Include Tier5Network engines when TLS or CT lookup targets are explicitly
	// provided, even if they were excluded by tier/scanType filtering above.
	if len(opts.TLSTargets) > 0 || len(opts.CTLookupTargets) > 0 || opts.CTLookupFromECH {
		available = appendNetworkEnginesIfAbsent(available, o.AvailableEngines())
	}
	return available
}

// appendNetworkEnginesIfAbsent adds Tier5Network engines from all to dst if not already present.
func appendNetworkEnginesIfAbsent(dst, all []engines.Engine) []engines.Engine {
	has := make(map[string]bool, len(dst))
	for _, e := range dst {
		has[e.Name()] = true
	}
	for _, e := range all {
		if e.Tier() == engines.Tier5Network && !has[e.Name()] {
			dst = append(dst, e)
		}
	}
	return dst
}

// Scan runs available engines, deduplicates, and boosts confidence.
// If opts.EngineNames is set, only those engines are used.
// In diff mode (opts.Mode == ModeDiff), only Tier 1 engines run and
// findings are filtered to changed files only.
// Scan is a backward-compatible wrapper around ScanWithImpact that discards
// the impact result.
func (o *Orchestrator) Scan(ctx context.Context, opts engines.ScanOptions) ([]findings.UnifiedFinding, error) {
	ff, _, err := o.ScanWithImpact(ctx, opts)
	return ff, err
}

// ScanWithImpact runs the same pipeline as Scan and additionally performs
// forward impact analysis when opts.ImpactGraph is true and mode is "full".
// It returns the findings, an *impact.Result (nil when impact analysis is
// disabled or there are no qualifying findings), and any error.
func (o *Orchestrator) ScanWithImpact(ctx context.Context, opts engines.ScanOptions) ([]findings.UnifiedFinding, *impact.Result, error) {
	ff, ir, _, err := o.scanPipeline(ctx, opts)
	return ff, ir, err
}

// ScanWithMetrics runs the same pipeline as ScanWithImpact and additionally
// returns per-stage timing data. The ScanMetrics pointer is never nil on a
// non-error return.
func (o *Orchestrator) ScanWithMetrics(ctx context.Context, opts engines.ScanOptions) ([]findings.UnifiedFinding, *impact.Result, *ScanMetrics, error) {
	return o.scanPipeline(ctx, opts)
}

// defaultCachePath returns the default cache file location for a scan target.
func defaultCachePath(targetPath string) string {
	return filepath.Join(targetPath, ".oqs-scanner-cache.json")
}

// walkSourceFiles returns absolute paths of all regular files under dir,
// excluding hidden directories (names starting with ".").
func walkSourceFiles(dir string) ([]string, error) {
	var paths []string
	err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil // skip unreadable entries
		}
		if d.IsDir() {
			// Skip hidden directories (e.g. .git, .oqs-cache).
			if len(d.Name()) > 1 && d.Name()[0] == '.' {
				return filepath.SkipDir
			}
			return nil
		}
		if d.Type().IsRegular() {
			paths = append(paths, path)
		}
		return nil
	})
	return paths, err
}

// groupFindingsByFile partitions a flat findings slice into a map keyed by
// absolute file path. Each finding is placed under its Location.File path.
func groupFindingsByFile(ff []findings.UnifiedFinding) map[string][]findings.UnifiedFinding {
	out := make(map[string][]findings.UnifiedFinding)
	for _, f := range ff {
		out[f.Location.File] = append(out[f.Location.File], f)
	}
	return out
}

// engineVersions returns a map of engine name → version for engines that are
// available. Used by incremental cache to detect engine upgrades.
func engineVersions(engs []engines.Engine) map[string]string {
	m := make(map[string]string, len(engs))
	for _, e := range engs {
		m[e.Name()] = e.Version()
	}
	return m
}

// filterHashesByExtension returns a subset of allHashes containing only files
// relevant to the given extension set. Returns allHashes unchanged when exts
// is nil (engine scans all files).
func filterHashesByExtension(allHashes map[string]string, exts map[string]bool) map[string]string {
	if exts == nil {
		return allHashes
	}
	filtered := make(map[string]string)
	for path, hash := range allHashes {
		if engines.IsRelevantFile(path, exts) {
			filtered[path] = hash
		}
	}
	return filtered
}

// toRelativePaths converts absolute paths to relative paths rooted at basePath.
func toRelativePaths(absPaths []string, basePath string) []string {
	rel := make([]string, 0, len(absPaths))
	for _, p := range absPaths {
		r, err := filepath.Rel(basePath, p)
		if err != nil {
			r = p
		}
		rel = append(rel, r)
	}
	return rel
}

// runIncremental handles the per-engine incremental scan path (V2).
//
// It loads the cache, hashes all source files once, then for each engine:
//  1. Filters hashes to files matching the engine's language extensions.
//  2. Checks the per-engine cache validity (engine version match).
//  3. Separates unchanged (cached) files from changed files.
//  4. Runs only changed files through the engine.
//  5. Updates that engine's cache entries.
//
// Engines run in parallel goroutines. Cache mutations are serialized with a
// mutex (Go maps are not safe for concurrent writes).
//
// If the scanner version or cache format changed, the entire cache is
// invalidated and all engines do a full scan.
func (o *Orchestrator) runIncremental(ctx context.Context, opts engines.ScanOptions, available []engines.Engine, scannerVersion string) ([]findings.UnifiedFinding, error) {
	// Normalize target path to absolute so walkSourceFiles always returns
	// absolute paths and downstream path comparisons are consistent.
	targetPath, err := filepath.Abs(opts.TargetPath)
	if err != nil {
		return nil, fmt.Errorf("incremental: resolve target path: %w", err)
	}

	cachePath := opts.CachePath
	if cachePath == "" {
		cachePath = defaultCachePath(targetPath)
	}

	sc, _ := cache.Load(cachePath) // always returns non-nil

	// If format or scanner version changed, start fresh.
	if sc.Version != "2" || sc.ScannerVersion != scannerVersion {
		sc = cache.New()
		sc.ScannerVersion = scannerVersion
	}

	// Collect files to hash. In diff mode, only hash the git-changed files
	// (scoped incremental). In full mode, walk the entire tree.
	var allPaths []string
	if opts.Mode == engines.ModeDiff {
		// Convert relative changed-file paths to absolute for consistent hashing.
		for _, rel := range opts.ChangedFiles {
			abs := filepath.Join(targetPath, rel)
			// Only include files that actually exist on disk (deleted files
			// in the diff should be skipped).
			if info, statErr := os.Stat(abs); statErr == nil && info.Mode().IsRegular() {
				allPaths = append(allPaths, abs)
			}
		}
	} else {
		var walkErr error
		allPaths, walkErr = walkSourceFiles(targetPath)
		if walkErr != nil {
			return nil, fmt.Errorf("incremental: walk source files: %w", walkErr)
		}
	}

	allHashes, hashErr := cache.HashFiles(allPaths)
	if hashErr != nil {
		fmt.Fprintf(os.Stderr, "WARNING: incremental cache: hash errors (partial): %v\n", hashErr)
	}

	// Per-engine incremental scan in parallel.
	type engineResult struct {
		cached     []findings.UnifiedFinding
		fresh      []findings.UnifiedFinding
		err        error
		scanFailed bool
	}
	results := make([]engineResult, len(available))
	var wg sync.WaitGroup
	var mu sync.Mutex // protects errs slice only
	var errs []error

	// Pre-populate EngineEntries keys so goroutines only touch per-engine
	// inner maps (no outer map writes → concurrent reads are safe).
	for _, eng := range available {
		if sc.EngineEntries[eng.Name()] == nil {
			sc.EngineEntries[eng.Name()] = make(map[string]*cache.CacheEntry)
		}
	}

	for i, eng := range available {
		i, eng := i, eng
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer func() {
				if r := recover(); r != nil {
					panicErr := fmt.Errorf("%s: panic: %v\n%s", eng.Name(), r, debug.Stack())
					mu.Lock()
					errs = append(errs, panicErr)
					mu.Unlock()
					// Mark as failed so version is NOT recorded for this engine.
					// Without this, results[i] remains zero-valued with scanFailed=false,
					// causing stale version to be written to cache.
					results[i] = engineResult{scanFailed: true}
				}
			}()

			// 1. Extension filter → relevant hashes for this engine.
			exts := engines.ExtensionsForEngine(eng)
			engineHashes := filterHashesByExtension(allHashes, exts)

			// 2. Per-engine cache check.
			// sc.EngineVersions is read-only here (writes deferred to after wg.Wait).
			engineValid := sc.IsValidForEngine(eng.Name(), eng.Version())

			var cached []findings.UnifiedFinding
			var changedPaths []string

			if engineValid {
				cached, changedPaths = sc.GetUnchangedFindingsForEngine(eng.Name(), engineHashes)
			} else {
				// Engine version changed or new engine → re-scan all its files.
				for p := range engineHashes {
					changedPaths = append(changedPaths, p)
				}
			}

			// 3. Run engine only on changed files.
			var fresh []findings.UnifiedFinding
			scanFailed := false
			if len(changedPaths) > 0 {
				relChanged := toRelativePaths(changedPaths, targetPath)

				engOpts := opts
				engOpts.TargetPath = targetPath  // absolute path → engine output matches hash keys
				engOpts.Incremental = false      // prevent re-entry
				engOpts.ChangedFiles = relChanged

				res, scanErr := eng.Scan(ctx, engOpts)
				if scanErr != nil {
					mu.Lock()
					errs = append(errs, fmt.Errorf("%s: %w", eng.Name(), scanErr))
					mu.Unlock()
					scanFailed = true
				} else {
					fresh = filterByChangedFiles(res, targetPath, relChanged)
				}
			}

			// 4. Update this engine's inner cache map.
			// Skip cache update on scan error to preserve existing cached entries.
			// Safe without mutex: each goroutine writes to its own inner map
			// (pre-populated above), and no goroutine writes to the outer map.
			if !scanFailed {
				freshByFile := groupFindingsByFile(fresh)
				// Ensure files with zero findings still get cache entries
				// so they aren't perpetually re-scanned.
				for _, p := range changedPaths {
					if _, exists := freshByFile[p]; !exists {
						freshByFile[p] = nil
					}
				}
				// Only prune deleted files in full mode. In diff mode, engineHashes
			// is a partial set (only changed files) — pruning would destroy
			// valid cached entries for unchanged files.
			pruneDeleted := opts.Mode != engines.ModeDiff
			sc.UpdateEngine(eng.Name(), freshByFile, engineHashes, pruneDeleted)
			}

			results[i] = engineResult{cached: cached, fresh: fresh, scanFailed: scanFailed}
		}()
	}

	wg.Wait()

	// Update engine versions after all goroutines complete (single-threaded).
	// Skip version update for engines whose scan failed — preserves old
	// cache state so those engines get re-scanned next time.
	for i, eng := range available {
		if !results[i].scanFailed {
			sc.EngineVersions[eng.Name()] = eng.Version()
		}
	}

	if ctx.Err() != nil {
		return nil, fmt.Errorf("incremental scan aborted: %w", ctx.Err())
	}

	// Merge all per-engine results.
	var merged []findings.UnifiedFinding
	for _, r := range results {
		merged = append(merged, r.cached...)
		merged = append(merged, r.fresh...)
	}

	if len(errs) > 0 && len(merged) == 0 {
		return nil, fmt.Errorf("all engines failed during incremental scan: %v", errs)
	}
	for _, e := range errs {
		fmt.Fprintf(os.Stderr, "WARNING: incremental engine error (partial results): %s\n", e)
	}

	// Save updated cache.
	sc.ScannerVersion = scannerVersion
	if saveErr := sc.Save(cachePath); saveErr != nil {
		fmt.Fprintf(os.Stderr, "WARNING: failed to save incremental cache: %v\n", saveErr)
	}

	return merged, nil
}

// pkgScannerVersion is set by SetScannerVersion, used for incremental cache validation.
// Uses atomic.Value for goroutine-safe access.
var pkgScannerVersion atomic.Value

func init() { pkgScannerVersion.Store("unknown") }

// SetScannerVersion records the binary version for incremental cache validation.
// Call this once during startup from main.go.
func SetScannerVersion(v string) { pkgScannerVersion.Store(v) }

// scanPipeline is the internal implementation shared by ScanWithImpact and
// ScanWithMetrics. It runs all pipeline stages and records timing for each.
func (o *Orchestrator) scanPipeline(ctx context.Context, opts engines.ScanOptions) ([]findings.UnifiedFinding, *impact.Result, *ScanMetrics, error) {
	totalStart := time.Now()
	metrics := &ScanMetrics{}

	// Normalize target path to absolute for consistent path handling across
	// both incremental and non-incremental paths. filterByExcludePatterns and
	// filterByChangedFiles both use opts.TargetPath as the base for relative
	// path computation; runIncremental also resolves it independently, so
	// keeping them in sync prevents exclude-pattern mismatches.
	//
	// Only normalize when TargetPath is non-empty: an empty string signals
	// "no path specified" to downstream consumers (e.g. the impact forward
	// propagator skips its path filter when TargetPath == ""), and promoting
	// it to the CWD would silently activate that filter with an unintended base.
	if opts.TargetPath != "" {
		if abs, err := filepath.Abs(opts.TargetPath); err == nil {
			opts.TargetPath = abs
		}
	}

	available := o.AvailableEngines()
	if len(opts.EngineNames) > 0 {
		available = filterEngines(available, opts.EngineNames)
	}

	// In diff/quick mode, restrict to Tier 1 engines only
	if opts.Mode == engines.ModeDiff || opts.Mode == engines.ModeQuick {
		available = filterByTier(available, engines.Tier1Pattern)
	} else {
		// Apply ScanType gating for Tier 4 binary and Tier 5 network engines.
		available = applyScanTypeFilter(available, opts.ScanType)
	}

	// Include Tier5Network engines when TLS or CT lookup targets are explicitly
	// provided, overriding tier/scanType filtering (even in diff/quick mode).
	if len(opts.TLSTargets) > 0 || len(opts.CTLookupTargets) > 0 || opts.CTLookupFromECH {
		available = appendNetworkEnginesIfAbsent(available, o.AvailableEngines())
	}

	// Split file-based and network engines. Network engines (Tier5Network) run
	// outside the incremental cache loop since they don't operate on files.
	var fileEngines, networkEngines []engines.Engine
	for _, e := range available {
		if e.Tier() == engines.Tier5Network {
			networkEngines = append(networkEngines, e)
		} else {
			fileEngines = append(fileEngines, e)
		}
	}

	if len(fileEngines) == 0 && len(networkEngines) == 0 {
		return nil, nil, metrics, fmt.Errorf("no engines available")
	}

	var allFindings []findings.UnifiedFinding

	// -- Incremental path (file engines only) --
	// When Incremental=true and NoCache=false, use the file hash cache to skip
	// unchanged files. Supported in both ModeFull (all files) and ModeDiff
	// (only git-changed files). The merged findings flow through the same
	// post-processing stages below.
	if len(fileEngines) > 0 && opts.Incremental && !opts.NoCache && (opts.Mode == engines.ModeFull || opts.Mode == engines.ModeDiff) {
		var err error
		allFindings, err = o.runIncremental(ctx, opts, fileEngines, pkgScannerVersion.Load().(string))
		if err != nil {
			metrics.TotalDuration = time.Since(totalStart)
			return nil, nil, metrics, err
		}
		metrics.Engines = []EngineMetrics{{Name: "incremental-cache", Duration: time.Since(totalStart), Findings: len(allFindings)}}
	} else {
		// -- Normal full-scan path --
		// Run each engine in its own goroutine. Collect per-engine results into a
		// slice indexed by position so that final merge preserves engine order,
		// giving deterministic output regardless of goroutine scheduling.
		type engineResult struct {
			results []findings.UnifiedFinding
			err     error
			metrics EngineMetrics
		}
		perEngine := make([]engineResult, len(fileEngines))

		var wg sync.WaitGroup
		var mu sync.Mutex
		var errs []error

		for i, eng := range fileEngines {
			i, eng := i, eng // capture loop vars
			wg.Add(1)
			go func() {
				defer wg.Done()
				engStart := time.Now()
				defer func() {
					if r := recover(); r != nil {
						panicErr := fmt.Errorf("%s: panic: %v\n%s", eng.Name(), r, debug.Stack())
						mu.Lock()
						errs = append(errs, panicErr)
						mu.Unlock()
						perEngine[i].metrics = EngineMetrics{
							Name:     eng.Name(),
							Duration: time.Since(engStart),
							Error:    panicErr.Error(),
						}
					}
				}()
				res, err := eng.Scan(ctx, opts)
				dur := time.Since(engStart)
				em := EngineMetrics{
					Name:     eng.Name(),
					Duration: dur,
					Findings: len(res),
				}
				if err != nil {
					em.Error = err.Error()
				}
				// Store results per-engine (index is unique per goroutine — no lock needed).
				perEngine[i] = engineResult{results: res, err: err, metrics: em}
				if err != nil {
					mu.Lock()
					errs = append(errs, fmt.Errorf("%s: %w", eng.Name(), err))
					mu.Unlock()
				}
			}()
		}
		wg.Wait()

		// Collect engine metrics in order.
		metrics.Engines = make([]EngineMetrics, len(fileEngines))
		for i := range perEngine {
			metrics.Engines[i] = perEngine[i].metrics
		}

		// If the context was cancelled (timeout or explicit cancel), report that
		// instead of a misleading "all engines failed" error.
		if ctx.Err() != nil {
			metrics.TotalDuration = time.Since(totalStart)
			return nil, nil, metrics, fmt.Errorf("scan aborted: %w", ctx.Err())
		}

		// Merge in engine order to keep output deterministic. Clone each finding
		// so subsequent in-place pipeline stages (normalizeFindings, classify,
		// migration snippets) don't mutate engine-owned state — concurrent Scan
		// calls on the same Orchestrator would otherwise race on Algorithm.Name.
		for _, er := range perEngine {
			for i := range er.results {
				allFindings = append(allFindings, er.results[i].Clone())
			}
		}

		if len(errs) > 0 && len(allFindings) == 0 {
			metrics.TotalDuration = time.Since(totalStart)
			return nil, nil, metrics, fmt.Errorf("all engines failed: %v", errs)
		}

		// Warn about partial engine failures (some engines failed but others succeeded)
		if len(errs) > 0 {
			for _, e := range errs {
				fmt.Fprintf(os.Stderr, "WARNING: engine error (partial results): %s\n", e)
			}
		}
	}

	// -- Network engines (Tier5Network) run outside the file-based pipeline --
	// They do not participate in incremental caching or file-based filtering.
	//
	// Ordering guarantee: ct-lookup runs after all other network engines so that
	// when CTLookupFromECH is true, ECH-enabled findings from tls-probe are
	// available for hostname extraction before ct-lookup is invoked.
	var networkErrs []error

	// ctlookupOpts is a copy of opts that may be enriched with ECH hostnames
	// after tls-probe (and any other engine) has run.
	ctlookupOpts := opts

	// Pass 1: all Tier5Network engines except ct-lookup.
	for _, eng := range networkEngines {
		if eng.Name() == "ct-lookup" {
			continue
		}
		if ctx.Err() != nil {
			break
		}
		engStart := time.Now()
		res, err := eng.Scan(ctx, opts)
		dur := time.Since(engStart)
		em := EngineMetrics{Name: eng.Name(), Duration: dur, Findings: len(res)}
		if err != nil {
			em.Error = err.Error()
			fmt.Fprintf(os.Stderr, "WARNING: %s: %v\n", eng.Name(), err)
			networkErrs = append(networkErrs, fmt.Errorf("%s: %w", eng.Name(), err))
		}
		metrics.Engines = append(metrics.Engines, em)
		for i := range res {
			allFindings = append(allFindings, res[i].Clone())
		}
	}

	// If CTLookupFromECH, extract ECH-enabled hostnames from pass-1 findings and
	// add them to ctlookupOpts so ct-lookup can resolve what ECH hid.
	if opts.CTLookupFromECH {
		echHosts := echHostnamesFromFindings(allFindings)
		seen := make(map[string]bool, len(ctlookupOpts.CTLookupTargets))
		for _, h := range ctlookupOpts.CTLookupTargets {
			seen[h] = true
		}
		for _, h := range echHosts {
			if !seen[h] {
				ctlookupOpts.CTLookupTargets = append(ctlookupOpts.CTLookupTargets, h)
				seen[h] = true
			}
		}
	}

	// Pass 2: ct-lookup engine with (potentially ECH-enriched) opts.
	for _, eng := range networkEngines {
		if eng.Name() != "ct-lookup" {
			continue
		}
		if ctx.Err() != nil {
			break
		}
		engStart := time.Now()
		res, err := eng.Scan(ctx, ctlookupOpts)
		dur := time.Since(engStart)
		em := EngineMetrics{Name: eng.Name(), Duration: dur, Findings: len(res)}
		if err != nil {
			em.Error = err.Error()
			fmt.Fprintf(os.Stderr, "WARNING: %s: %v\n", eng.Name(), err)
			networkErrs = append(networkErrs, fmt.Errorf("%s: %w", eng.Name(), err))
		}
		metrics.Engines = append(metrics.Engines, em)
		for i := range res {
			allFindings = append(allFindings, res[i].Clone())
		}
	}
	// Propagate network engine errors when all network engines failed and
	// produced no findings (prevents silent pass in CI when TLS targets
	// are all unreachable).
	if len(networkErrs) > 0 && len(networkEngines) > 0 {
		hasNetworkFindings := false
		for _, eng := range networkEngines {
			for _, em := range metrics.Engines {
				if em.Name == eng.Name() && em.Findings > 0 {
					hasNetworkFindings = true
				}
			}
		}
		if !hasNetworkFindings {
			for _, e := range networkErrs {
				fmt.Fprintf(os.Stderr, "WARNING: network engine error (no results): %s\n", e)
			}
		}
	}

	// Filter out findings matching exclude patterns
	if len(opts.ExcludePatterns) > 0 {
		allFindings = filterByExcludePatterns(allFindings, opts.TargetPath, opts.ExcludePatterns)
	}

	// In diff mode, filter findings to only changed files
	if opts.Mode == engines.ModeDiff && len(opts.ChangedFiles) > 0 {
		allFindings = filterByChangedFiles(allFindings, opts.TargetPath, opts.ChangedFiles)
	}

	// Normalize algorithm names via CycloneDX registry for better cross-engine dedup.
	// MUST run before suppression so oqs:ignore[AES] matches canonical "AES" not raw "aes_gcm_256".
	normStart := time.Now()
	normalizeFindings(allFindings)
	metrics.NormalizeDur = time.Since(normStart)

	dedupeStart := time.Now()
	if len(available) > 1 {
		allFindings = dedupe(allFindings)
	}
	metrics.DedupeDur = time.Since(dedupeStart)

	// Apply suppression filtering AFTER normalization and dedup so algorithm names
	// are canonical and oqs:ignore[AES] correctly matches "AES" (not raw engine names).
	var suppressedCount int
	if !opts.NoSuppress && opts.TargetPath != "" {
		suppressScanner, suppressErr := suppress.NewScanner(opts.TargetPath)
		if suppressErr == nil {
			var kept []findings.UnifiedFinding
			for i := range allFindings {
				f := &allFindings[i]
				algoName := ""
				if f.Algorithm != nil {
					algoName = f.Algorithm.Name
				}
				if suppressScanner.IsSuppressed(f.Location.File, f.Location.Line, algoName) {
					suppressedCount++
				} else {
					kept = append(kept, *f)
				}
			}
			allFindings = kept
		}
	}

	// Enrich findings with cross-file constant resolution (fills missing KeySize).
	// Skip in diff mode for speed — constant resolution requires full-tree walk.
	if opts.Mode != engines.ModeDiff && opts.Mode != engines.ModeQuick {
		enrichStart := time.Now()
		func() {
			defer func() {
				if r := recover(); r != nil {
					fmt.Fprintf(os.Stderr, "WARNING: constresolver panic (skipping enrichment): %v\n%s\n", r, debug.Stack())
				}
			}()
			collector := constresolver.New()
			constMap := collector.Collect(ctx, opts.TargetPath)
			constresolver.EnrichFindings(allFindings, constMap)
		}()
		metrics.EnrichDur = time.Since(enrichStart)
	}

	// Classify quantum risk for each finding
	classifyStart := time.Now()
	classifyFindings(allFindings)
	attachMigrationSnippets(allFindings)
	metrics.ClassifyDur = time.Since(classifyStart)

	// Run impact analysis when requested and mode is full (not diff/quick).
	var impactResult *impact.Result
	if opts.ImpactGraph && opts.Mode == engines.ModeFull {
		impactStart := time.Now()
		maxHops := opts.MaxImpactHops
		if maxHops <= 0 {
			maxHops = 10
		}
		impactOpts := impact.ImpactOpts{
			MaxHops:    maxHops,
			TargetPath: opts.TargetPath,
		}
		var impactErr error
		impactResult, impactErr = forward.New(maxHops).Analyze(ctx, allFindings, impactOpts)
		metrics.ImpactDur = time.Since(impactStart)
		if impactErr != nil {
			fmt.Fprintf(os.Stderr, "WARNING: impact analysis failed: %v\n", impactErr)
		}
		// Nil-out empty results so JSON omitempty omits the field.
		if impactResult != nil && len(impactResult.ImpactZones) == 0 {
			impactResult = nil
		}
	}

	metrics.SuppressedCount = suppressedCount

	// Mark test and generated file findings.
	findings.MarkTestAndGenerated(allFindings)

	// Copy blast radius scores from impact zones into findings for priority calculation.
	if impactResult != nil {
		for i := range allFindings {
			key := allFindings[i].DedupeKey()
			if zone := impactResult.ImpactDataForFinding(key); zone != nil {
				allFindings[i].BlastRadius = zone.BlastRadiusScore
			}
		}
	}

	// Upgrade MigrationEffort for high-blast-radius findings (> 70).
	applyBlastRadiusEffortUpgrade(allFindings)

	// Calculate priority for each finding.
	for i := range allFindings {
		allFindings[i].Priority = findings.CalculatePriority(&allFindings[i])
	}

	// Sort by priority (P1 first).
	findings.SortByPriority(allFindings)

	metrics.TotalDuration = time.Since(totalStart)
	return allFindings, impactResult, metrics, nil
}

// dedupe merges findings from multiple engines. When two engines report the
// same algorithm at the same file+line, we keep the richer finding and record
// corroboration. Corroborated findings get boosted confidence.
func dedupe(all []findings.UnifiedFinding) []findings.UnifiedFinding {
	type entry struct {
		finding *findings.UnifiedFinding
		index   int
	}

	seen := make(map[string]*entry, len(all))
	order := make([]string, 0, len(all))

	for i := range all {
		f := &all[i]
		key := f.DedupeKey()

		if existing, ok := seen[key]; ok {
			// Merge: record corroboration
			winner := existing.finding
			if !contains(winner.CorroboratedBy, f.SourceEngine) && f.SourceEngine != winner.SourceEngine {
				winner.CorroboratedBy = append(winner.CorroboratedBy, f.SourceEngine)
			}

			// Pick the richer algorithm info
			mergeAlgorithm(winner, f)

			// Propagate reachability: ReachableYes > ReachableUnknown > ReachableNo.
			// Any engine confirming reachability overrides unknown/no.
			mergeReachability(winner, f)

			// Prefer the finding that has a DataFlowPath (Tier 2 taint data)
			if len(winner.DataFlowPath) == 0 && len(f.DataFlowPath) > 0 {
				winner.DataFlowPath = f.DataFlowPath
			}

			// Boost confidence when corroborated
			if len(winner.CorroboratedBy) > 0 && winner.Confidence != findings.ConfidenceHigh {
				winner.Confidence = boostConfidence(winner.Confidence)
			}
		} else {
			seen[key] = &entry{finding: f, index: i}
			order = append(order, key)
		}
	}

	result := make([]findings.UnifiedFinding, 0, len(order))
	for _, key := range order {
		result = append(result, *seen[key].finding)
	}
	return result
}

// mergeAlgorithm fills in missing fields from a secondary finding.
func mergeAlgorithm(winner, other *findings.UnifiedFinding) {
	if winner.Algorithm == nil || other.Algorithm == nil {
		return
	}
	a, b := winner.Algorithm, other.Algorithm
	if a.Primitive == "" && b.Primitive != "" {
		a.Primitive = b.Primitive
	}
	if a.KeySize == 0 && b.KeySize > 0 {
		a.KeySize = b.KeySize
	}
	if a.Mode == "" && b.Mode != "" {
		a.Mode = b.Mode
	}
	if a.Curve == "" && b.Curve != "" {
		a.Curve = b.Curve
	}
}

// mergeReachability propagates reachability from a secondary finding.
// Priority: ReachableYes > ReachableUnknown > ReachableNo.
// Any engine confirming reachability overrides unknown/no; unknown beats no.
func mergeReachability(winner, other *findings.UnifiedFinding) {
	if winner.Reachable == findings.ReachableYes {
		return // already best
	}
	if other.Reachable == findings.ReachableYes {
		winner.Reachable = findings.ReachableYes
		return
	}
	if winner.Reachable == findings.ReachableNo && other.Reachable == findings.ReachableUnknown {
		winner.Reachable = findings.ReachableUnknown
	}
}

func boostConfidence(c findings.Confidence) findings.Confidence {
	switch c {
	case findings.ConfidenceLow:
		return findings.ConfidenceMediumLow
	case findings.ConfidenceMediumLow:
		return findings.ConfidenceMedium
	case findings.ConfidenceMedium:
		return findings.ConfidenceMediumHigh
	case findings.ConfidenceMediumHigh:
		return findings.ConfidenceHigh
	default:
		return c
	}
}

func contains(ss []string, s string) bool {
	for _, v := range ss {
		if v == s {
			return true
		}
	}
	return false
}

// normalizeFindings uses the CycloneDX registry to resolve canonical algorithm names.
// This improves cross-engine dedup by ensuring "aes_gcm_256" and "AES-256-GCM"
// both resolve to the same canonical name before deduplication.
func normalizeFindings(ff []findings.UnifiedFinding) {
	reg := registry.Load()
	for i := range ff {
		f := &ff[i]
		if f.Algorithm == nil {
			continue
		}
		result := reg.Normalize(f.Algorithm.Name, f.Algorithm.KeySize, f.Algorithm.Mode)
		if result.MatchType != registry.MatchNone {
			f.Algorithm.Name = result.CanonicalName
			if f.Algorithm.Primitive == "" && result.Primitive != "" {
				f.Algorithm.Primitive = result.Primitive
			}
		}
		// Resolve curve aliases
		if f.Algorithm.Curve != "" {
			if cr, ok := reg.ResolveCurve(f.Algorithm.Curve); ok {
				f.Algorithm.Curve = cr.Canonical
			}
		}
	}
}

// classifyFindings applies quantum risk classification to each finding.
func classifyFindings(ff []findings.UnifiedFinding) {
	for i := range ff {
		f := &ff[i]
		if f.Algorithm != nil {
			c := quantum.ClassifyAlgorithm(f.Algorithm.Name, f.Algorithm.Primitive, f.Algorithm.KeySize)
			f.QuantumRisk = findings.QuantumRisk(c.Risk)
			f.Severity = findings.Severity(c.Severity)
			f.Recommendation = c.Recommendation
			f.HNDLRisk = c.HNDLRisk
			isConfig := f.SourceEngine == "config-scanner" || f.SourceEngine == "tls-probe"
			f.MigrationEffort = quantum.ClassifyEffort(c, f.Algorithm.Primitive, isConfig)
			f.TargetAlgorithm = c.TargetAlgorithm
			f.TargetStandard = c.TargetStandard
		} else if f.Dependency != nil {
			// Dependencies get unknown classification (need deeper analysis)
			f.QuantumRisk = findings.QRUnknown
			f.Severity = findings.SevInfo
		}
	}
}

// attachMigrationSnippets generates language-specific PQC migration code for each finding.
func attachMigrationSnippets(ff []findings.UnifiedFinding) {
	for i := range ff {
		f := &ff[i]
		if f.Algorithm == nil || f.TargetAlgorithm == "" {
			continue
		}
		snippet := migration.GenerateSnippet(
			f.Location.File,
			f.Algorithm.Name,
			f.Algorithm.Primitive,
			f.TargetAlgorithm,
		)
		if snippet != nil {
			f.MigrationSnippet = &findings.MigrationSnippet{
				Language:    snippet.Language,
				Before:      snippet.Before,
				After:       snippet.After,
				Explanation: snippet.Explanation,
			}
		}
	}
}

// applyBlastRadiusEffortUpgrade upgrades MigrationEffort by one level for findings
// whose BlastRadiusScore exceeds 70. Must be called after blast radius scores are
// copied from the impact result into findings.
func applyBlastRadiusEffortUpgrade(ff []findings.UnifiedFinding) {
	const blastRadiusThreshold = 70
	for i := range ff {
		f := &ff[i]
		if f.MigrationEffort != "" && f.BlastRadius > blastRadiusThreshold {
			f.MigrationEffort = quantum.UpgradeEffort(f.MigrationEffort)
		}
	}
}

// filterByTier returns only engines matching the given tier.
func filterByTier(all []engines.Engine, tier engines.Tier) []engines.Engine {
	var filtered []engines.Engine
	for _, e := range all {
		if e.Tier() == tier {
			filtered = append(filtered, e)
		}
	}
	return filtered
}

// normalizePath cleans and normalizes a file path for comparison.
// On Windows (case-insensitive FS), paths are lowercased.
// On Linux/macOS (case-sensitive FS), paths are compared as-is.
func normalizePath(p string) string {
	p = filepath.ToSlash(filepath.Clean(p))
	if runtime.GOOS == "windows" {
		p = strings.ToLower(p)
	}
	return p
}

// filterByChangedFiles keeps only findings whose location matches one of the
// changed files. Paths are compared after normalizing to be relative to targetPath.
func filterByChangedFiles(ff []findings.UnifiedFinding, targetPath string, changedFiles []string) []findings.UnifiedFinding {
	if targetPath == "" {
		targetPath = "."
	}

	// Build a set of normalized changed file paths for O(1) lookup
	changed := make(map[string]bool, len(changedFiles))
	for _, f := range changedFiles {
		changed[normalizePath(f)] = true
	}

	var filtered []findings.UnifiedFinding
	for _, f := range ff {
		filePath := f.Location.File

		// Preserve network engine findings (synthetic paths like "(tls-probe)/host:443#kex").
		// These are not tied to any filesystem path and must not be filtered by changed files.
		if strings.HasPrefix(filePath, "(") {
			filtered = append(filtered, f)
			continue
		}

		// Try to make the finding path relative to target
		if rel, err := filepath.Rel(targetPath, filePath); err == nil {
			filePath = rel
		}

		// Check if this file is in the changed set
		if changed[normalizePath(filePath)] {
			filtered = append(filtered, f)
		}
	}
	return filtered
}

// filterByExcludePatterns removes findings whose file path matches any of the
// given glob patterns. Patterns are matched against the path relative to targetPath.
//
// Matching strategy:
//   - "vendor/*" or "vendor/**" → prefix match: excludes all files under vendor/
//   - "*.min.js" → filename match: excludes files named *.min.js at any depth
//   - "test/*.go" → filepath.Match against relative path and each path suffix
func filterByExcludePatterns(ff []findings.UnifiedFinding, targetPath string, patterns []string) []findings.UnifiedFinding {
	var filtered []findings.UnifiedFinding
	for _, f := range ff {
		filePath := f.Location.File

		// Make path relative to target for consistent matching
		if rel, err := filepath.Rel(targetPath, filePath); err == nil {
			filePath = rel
		}
		// Normalize to forward slashes and lowercase for cross-platform matching
		filePath = strings.ToLower(filepath.ToSlash(filePath))

		excluded := false
		for _, pattern := range patterns {
			pattern = strings.ToLower(filepath.ToSlash(pattern))

			// Handle directory-recursive patterns: "dir/*" and "dir/**" mean
			// "everything under dir/" since filepath.Match doesn't support "**".
			if strings.HasSuffix(pattern, "/**") || strings.HasSuffix(pattern, "/*") {
				prefix := pattern[:strings.LastIndex(pattern, "/")]
				if strings.HasPrefix(filePath, prefix+"/") {
					excluded = true
					break
				}
				// Also check path suffixes for nested dirs
				parts := strings.Split(filePath, "/")
				for i := range parts {
					suffix := strings.Join(parts[i:], "/")
					if strings.HasPrefix(suffix, prefix+"/") {
						excluded = true
						break
					}
				}
				if excluded {
					break
				}
				continue
			}

			// Exact glob match against full relative path
			if matched, err := filepath.Match(pattern, filePath); err == nil && matched {
				excluded = true
				break
			}
			// Match against just the filename (e.g. "*.min.js")
			if matched, err := filepath.Match(pattern, filepath.Base(filePath)); err == nil && matched {
				excluded = true
				break
			}
			// Match against each path suffix (e.g. "test/*.go" matches "src/test/foo.go")
			parts := strings.Split(filePath, "/")
			for i := range parts {
				suffix := strings.Join(parts[i:], "/")
				if matched, err := filepath.Match(pattern, suffix); err == nil && matched {
					excluded = true
					break
				}
			}
			if excluded {
				break
			}
		}
		if !excluded {
			filtered = append(filtered, f)
		}
	}
	return filtered
}

// applyScanTypeFilter gates Tier 4 binary engines based on ScanType.
//   - "" or "source" → exclude Tier 4 (default: source-only scanning)
//   - "binary"        → include only Tier 4
//   - "all"           → include all tiers
func applyScanTypeFilter(all []engines.Engine, scanType string) []engines.Engine {
	switch scanType {
	case "binary":
		return filterByTier(all, engines.Tier4Binary)
	case "all":
		return all // no filtering
	default:
		// "" or "source" → exclude Tier 4 (binary) and Tier 5 (network)
		return excludeTier(excludeTier(all, engines.Tier4Binary), engines.Tier5Network)
	}
}

// excludeTier returns engines that do NOT match the given tier.
func excludeTier(all []engines.Engine, tier engines.Tier) []engines.Engine {
	var filtered []engines.Engine
	for _, e := range all {
		if e.Tier() != tier {
			filtered = append(filtered, e)
		}
	}
	return filtered
}

func filterEngines(all []engines.Engine, names []string) []engines.Engine {
	set := make(map[string]bool, len(names))
	for _, n := range names {
		set[n] = true
	}
	var filtered []engines.Engine
	for _, e := range all {
		if set[e.Name()] {
			filtered = append(filtered, e)
		}
	}
	return filtered
}

// echHostnamesFromFindings extracts deduplicated bare hostnames from findings
// that are annotated as partial inventory due to ECH. The orchestrator calls this
// between the tls-probe and ct-lookup engine runs when CTLookupFromECH is set.
// It mirrors the logic in pkg/engines/ctlookup.ExtractECHHostnames to avoid
// importing a specific engine implementation in the orchestrator.
func echHostnamesFromFindings(ff []findings.UnifiedFinding) []string {
	seen := make(map[string]bool)
	var hosts []string
	for _, f := range ff {
		if !f.PartialInventory || f.PartialInventoryReason != "ECH_ENABLED" {
			continue
		}
		file := f.Location.File
		// Strip engine prefix: "(tls-probe)/host:port#suffix" → "host:port#suffix".
		if idx := strings.Index(file, "/"); idx >= 0 {
			file = file[idx+1:]
		}
		// Strip fragment suffix: "host:port#suffix" → "host:port".
		if idx := strings.LastIndex(file, "#"); idx >= 0 {
			file = file[:idx]
		}
		host, _, err := net.SplitHostPort(file)
		if err != nil {
			host = file
		}
		if host != "" && !seen[host] {
			seen[host] = true
			hosts = append(hosts, host)
		}
	}
	return hosts
}
