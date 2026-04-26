package orchestrator

import (
	"context"
	"fmt"
	"os"
	"runtime/debug"
	"sync"
	"time"

	"github.com/jimbo111/open-quantum-secure/pkg/engines"
	"github.com/jimbo111/open-quantum-secure/pkg/findings"
)

// runFileEnginesParallel runs every file-based engine in its own goroutine
// and merges results in deterministic engine order. Returns the merged
// findings, per-engine metrics, and a non-nil error only when ALL engines
// failed (partial failures emit warnings to stderr but do not abort).
//
// Findings are Cloned before being merged so subsequent in-place pipeline
// stages (normalize, classify, snippet attach) never mutate engine-owned
// state — concurrent Scan calls on the same Orchestrator would otherwise
// race on Algorithm.Name and other shared pointers.
//
// Context cancellation (timeout / explicit cancel) is reported as an
// "aborted" error rather than the misleading "all engines failed".
func runFileEnginesParallel(ctx context.Context, fileEngines []engines.Engine, opts engines.ScanOptions) ([]findings.UnifiedFinding, []EngineMetrics, error) {
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
		i, eng := i, eng
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
			perEngine[i] = engineResult{results: res, err: err, metrics: em}
			if err != nil {
				mu.Lock()
				errs = append(errs, fmt.Errorf("%s: %w", eng.Name(), err))
				mu.Unlock()
			}
		}()
	}
	wg.Wait()

	engineMetrics := make([]EngineMetrics, len(fileEngines))
	for i := range perEngine {
		engineMetrics[i] = perEngine[i].metrics
	}

	if ctx.Err() != nil {
		return nil, engineMetrics, fmt.Errorf("scan aborted: %w", ctx.Err())
	}

	var allFindings []findings.UnifiedFinding
	for _, er := range perEngine {
		for i := range er.results {
			allFindings = append(allFindings, er.results[i].Clone())
		}
	}

	if len(errs) > 0 && len(allFindings) == 0 {
		return nil, engineMetrics, fmt.Errorf("all engines failed: %v", errs)
	}
	if len(errs) > 0 {
		for _, e := range errs {
			fmt.Fprintf(os.Stderr, "WARNING: engine error (partial results): %s\n", e)
		}
	}
	return allFindings, engineMetrics, nil
}

// runNetworkEnginesTwoPass runs Tier-5 network engines in two passes, with
// optional ECH-hostname enrichment for ct-lookup between them.
//
// Pass 1 runs every network engine except ct-lookup. The findings are
// appended to the main allFindings slice as they come in.
//
// Between passes, when opts.CTLookupFromECH is set, ECH-enabled findings
// from pass 1 (typically tls-probe) are mined for hostnames and appended
// to a copy of opts.CTLookupTargets. This is what lets the user say
// "scan tls-probe; for any ECH-protected target, also resolve the cert
// chain via CT logs" without naming hosts twice.
//
// Pass 2 runs ct-lookup with the (possibly-enriched) opts.
//
// Returns the appended findings list, per-engine metrics, and a slice of
// non-fatal errors. Errors are logged to stderr inside the function as
// well; callers use the error slice for the "all-network-engines-failed"
// summary check.
func runNetworkEnginesTwoPass(ctx context.Context, networkEngines []engines.Engine, opts engines.ScanOptions, allFindings []findings.UnifiedFinding) ([]findings.UnifiedFinding, []EngineMetrics, []error) {
	var engineMetrics []EngineMetrics
	var networkErrs []error
	ctlookupOpts := opts

	// Pass 1: every network engine except ct-lookup.
	for _, eng := range networkEngines {
		if eng.Name() == "ct-lookup" {
			continue
		}
		if ctx.Err() != nil {
			break
		}
		engStart := time.Now()
		res, err := scanNetworkEngineWithRecover(ctx, eng, opts)
		em := EngineMetrics{Name: eng.Name(), Duration: time.Since(engStart), Findings: len(res)}
		if err != nil {
			em.Error = err.Error()
			fmt.Fprintf(os.Stderr, "WARNING: %s: %v\n", eng.Name(), err)
			networkErrs = append(networkErrs, fmt.Errorf("%s: %w", eng.Name(), err))
		}
		engineMetrics = append(engineMetrics, em)
		for i := range res {
			allFindings = append(allFindings, res[i].Clone())
		}
	}

	// Enrich ct-lookup targets with ECH-enabled hostnames from pass 1.
	if opts.CTLookupFromECH {
		echHosts := echHostnamesFromFindings(allFindings)
		// Copy to avoid mutating caller's backing array via append.
		ctlookupOpts.CTLookupTargets = append([]string(nil), opts.CTLookupTargets...)
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

	// Pass 2: ct-lookup with ECH-enriched targets.
	for _, eng := range networkEngines {
		if eng.Name() != "ct-lookup" {
			continue
		}
		if ctx.Err() != nil {
			break
		}
		engStart := time.Now()
		res, err := scanNetworkEngineWithRecover(ctx, eng, ctlookupOpts)
		em := EngineMetrics{Name: eng.Name(), Duration: time.Since(engStart), Findings: len(res)}
		if err != nil {
			em.Error = err.Error()
			fmt.Fprintf(os.Stderr, "WARNING: %s: %v\n", eng.Name(), err)
			networkErrs = append(networkErrs, fmt.Errorf("%s: %w", eng.Name(), err))
		}
		engineMetrics = append(engineMetrics, em)
		for i := range res {
			allFindings = append(allFindings, res[i].Clone())
		}
	}

	return allFindings, engineMetrics, networkErrs
}

// selectFileAndNetworkEngines applies the engine-name filter, mode-based
// tier filter (diff/quick → Tier 1 only), scan-type gating, and the
// Tier-5 force-include rule (hasNetworkTargets). It then splits the result
// into file engines and network engines.
//
// Returns an error when neither slice has any engines — the caller should
// abort rather than running an empty pipeline.
func (o *Orchestrator) selectFileAndNetworkEngines(opts engines.ScanOptions) (fileEngines []engines.Engine, networkEngines []engines.Engine, err error) {
	available := o.AvailableEngines()
	if len(opts.EngineNames) > 0 {
		available = filterEngines(available, opts.EngineNames)
	}

	if opts.Mode == engines.ModeDiff || opts.Mode == engines.ModeQuick {
		available = filterByTier(available, engines.Tier1Pattern)
	} else {
		available = applyScanTypeFilter(available, opts.ScanType)
	}

	if hasNetworkTargets(opts) {
		available = appendNetworkEnginesIfAbsent(available, o.AvailableEngines())
	}

	for _, e := range available {
		if e.Tier() == engines.Tier5Network {
			networkEngines = append(networkEngines, e)
		} else {
			fileEngines = append(fileEngines, e)
		}
	}

	if len(fileEngines) == 0 && len(networkEngines) == 0 {
		return nil, nil, fmt.Errorf("no engines available")
	}
	return fileEngines, networkEngines, nil
}
