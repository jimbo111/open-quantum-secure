package tlsprobe

import (
	"context"
	"fmt"
	"net"
	"os"
	"sync"
	"time"

	"github.com/jimbo111/open-quantum-secure/pkg/engines"
	"github.com/jimbo111/open-quantum-secure/pkg/engines/tlsprobe/rawhello"
	"github.com/jimbo111/open-quantum-secure/pkg/findings"
	"github.com/jimbo111/open-quantum-secure/pkg/quantum"
)

// runInitialProbes performs the parallel TLS-handshake pass on every target.
// Concurrency is bounded by sem (capacity defaultConcurrency). The semaphore
// is acquired in the parent goroutine before launching the child — so a
// 100-target scan never bursts 100 goroutines (Sprint 2 M1).
//
// Results are returned in the same order as opts.TLSTargets. Per-target
// errors are stored in ProbeResult.Error rather than returned, so subsequent
// phases can run on reachable targets while skipping unreachable ones.
func runInitialProbes(ctx context.Context, targets []string, probeOpts ProbeOpts, sem chan struct{}) []ProbeResult {
	results := make([]ProbeResult, len(targets))
	var wg sync.WaitGroup
	for i, target := range targets {
		if ctx.Err() != nil {
			break
		}
		sem <- struct{}{}
		wg.Add(1)
		go func(idx int, t string) {
			defer wg.Done()
			defer func() { <-sem }()
			if ctx.Err() != nil {
				return
			}
			results[idx] = probeFn(ctx, t, probeOpts)
		}(i, target)
	}
	wg.Wait()
	return results
}

// runDeepProbe (Sprint 7) probes each reachable target's PQC group support
// using hand-crafted ClientHellos. Sequential per target — DefaultProbeGroups
// already iterates sequentially inside rawhello.DeepProbe, and parallelising
// targets here would risk rate limits.
//
// Mutates results[i] in place: AcceptedGroups, HRRGroups.
func runDeepProbe(ctx context.Context, results []ProbeResult, timeout time.Duration, verbose bool) {
	for i := range results {
		r := &results[i]
		if r.Error != nil || r.ResolvedIP == "" {
			continue
		}
		if ctx.Err() != nil {
			break
		}
		host, port, err := parseHostPort(r.Target)
		if err != nil {
			continue
		}
		addr := net.JoinHostPort(r.ResolvedIP, port)
		groupResults, deepErr := rawhello.DeepProbe(ctx, addr, host, timeout, rawhello.DefaultProbeGroups())
		if deepErr != nil && len(groupResults) == 0 {
			if verbose {
				fmt.Fprintf(os.Stderr, "deep-probe: %s: %v\n", r.Target, deepErr)
			}
			continue
		}
		for _, gr := range groupResults {
			switch gr.Outcome {
			case rawhello.OutcomeAccepted:
				r.DeepProbeAcceptedGroups = append(r.DeepProbeAcceptedGroups, gr.GroupID)
			case rawhello.OutcomeHRR:
				if gr.SelectedGroup != 0 {
					r.DeepProbeHRRGroups = append(r.DeepProbeHRRGroups, gr.SelectedGroup)
				}
			}
		}
		if verbose {
			fmt.Fprintf(os.Stderr, "deep-probe: %s — %d/%d groups accepted, %d HRR\n",
				r.Target, len(r.DeepProbeAcceptedGroups), len(groupResults), len(r.DeepProbeHRRGroups))
		}
	}
}

// runEnumeration (Sprint 8) runs --enumerate-groups, --enumerate-sigalgs,
// and --detect-server-preference passes for each reachable target. All three
// passes share a 60-second per-target context budget and the same probe
// budget (probesUsedPerTarget vs maxProbes) as the TLS 1.2 fallback phase.
//
// Holds the per-target semaphore slot so the 5-concurrency cap covers
// initial probe + deep probe + enum together.
//
// Mutates results[i]: EnumAccepted/HRR/SigAlgs/ServerPref* fields, and
// EnumTruncated/Reason on budget exhaustion or partial probe failure.
func runEnumeration(ctx context.Context, results []ProbeResult, opts engines.ScanOptions, timeout time.Duration, sem chan struct{}, probesUsedPerTarget []int, maxProbes int) {
	for i := range results {
		r := &results[i]
		if r.Error != nil || r.ResolvedIP == "" {
			continue
		}
		if ctx.Err() != nil {
			break
		}
		host, port, err := parseHostPort(r.Target)
		if err != nil {
			continue
		}
		addr := net.JoinHostPort(r.ResolvedIP, port)

		budgetExhausted := func() bool {
			return probesUsedPerTarget[i] >= maxProbes
		}
		markBudgetExhausted := func() {
			r.EnumTruncated = true
			r.EnumTruncationReason = "PROBE_BUDGET_EXHAUSTED"
		}

		sem <- struct{}{}
		enumCtx, enumCancel := context.WithTimeout(ctx, 60*time.Second)

		var modes []string

		if opts.EnumerateGroups {
			if budgetExhausted() {
				markBudgetExhausted()
			} else {
				gr, gErr := enumerateGroups(enumCtx, addr, host, timeout)
				hasGroups := len(gr.AcceptedGroups) > 0 || len(gr.HRRGroups) > 0
				probesUsedPerTarget[i] += len(gr.AcceptedGroups) + len(gr.HRRGroups) + len(gr.RejectedGroups)
				if gErr != nil && !hasGroups {
					if opts.Verbose {
						fmt.Fprintf(os.Stderr, "enumerate-groups: %s: %v\n", r.Target, gErr)
					}
				} else {
					r.EnumAcceptedGroups = gr.AcceptedGroups
					r.EnumHRRGroups = gr.HRRGroups
					modes = append(modes, "groups")
					if gErr != nil {
						r.EnumTruncated = true
						r.EnumTruncationReason = "enumerate-groups: " + gErr.Error()
					}
				}
			}
		}

		if opts.EnumerateSigAlgs {
			// TLS 1.3 encrypts sig-alg negotiation (CertificateVerify); probing is
			// only meaningful on TLS 1.3 connections. Skip TLS ≤ 1.2 to avoid
			// returning zero results that look like "no sig algs supported".
			const tls13Version = 0x0304
			if r.TLSVersion != 0 && r.TLSVersion < tls13Version {
				modes = append(modes, "sigalgs-skipped-tls12")
			} else if budgetExhausted() {
				markBudgetExhausted()
			} else {
				sr, sErr := enumerateSigAlgs(enumCtx, addr, host, timeout)
				probesUsedPerTarget[i] += len(sr.AcceptedSigAlgs) + len(sr.RejectedSigAlgs)
				if sErr != nil && len(sr.AcceptedSigAlgs) == 0 {
					if opts.Verbose {
						fmt.Fprintf(os.Stderr, "enumerate-sigalgs: %s: %v\n", r.Target, sErr)
					}
				} else {
					r.EnumSupportedSigAlgs = sr.AcceptedSigAlgs
					modes = append(modes, "sigalgs")
					if sErr != nil {
						r.EnumTruncated = true
						r.EnumTruncationReason = "enumerate-sigalgs: " + sErr.Error()
					}
				}
			}
		}

		if opts.DetectServerPreference {
			prefCandidates := r.EnumAcceptedGroups
			if len(prefCandidates) == 0 {
				prefCandidates = r.DeepProbeAcceptedGroups
			}
			// Preference probe costs 2 connections (forward + reverse ordering).
			if len(prefCandidates) >= 2 && !budgetExhausted() && probesUsedPerTarget[i]+2 <= maxProbes {
				prefResult, pErr := detectServerGroupPreference(enumCtx, addr, host, timeout, prefCandidates)
				probesUsedPerTarget[i] += 2
				if pErr != nil {
					if opts.Verbose {
						fmt.Fprintf(os.Stderr, "detect-server-preference: %s: %v\n", r.Target, pErr)
					}
				} else {
					r.EnumServerPrefGroup = prefResult.PreferredGroup
					r.EnumServerPrefMode = prefResult.Mode
					modes = append(modes, "preference")
				}
			} else if len(prefCandidates) >= 2 {
				markBudgetExhausted()
			}
		}

		if len(modes) > 0 {
			r.EnumerationMode = joinModes(modes)
		}

		enumCancel()
		<-sem
	}
}

// runTLS12Fallback (Sprint 9, Feature 3) probes each PQC-negotiating target
// for TLS 1.2 acceptance. A target that supports both TLS 1.3+PQC and TLS 1.2
// is downgrade-vulnerable: an attacker forcing TLS 1.2 strips PQC.
//
// Sequential per target (rate-limit rationale, same as deep-probe). Each PQC
// target consumes +1 from probesUsedPerTarget against maxProbes (shared
// budget with S8 enumeration).
//
// Mutates results[i]: AcceptedTLS12, TLS12CipherSuite, TLS12CipherSuiteName.
func runTLS12Fallback(ctx context.Context, results []ProbeResult, opts engines.ScanOptions, timeout time.Duration, sem chan struct{}, probesUsedPerTarget []int, maxProbes int, denyPrivate bool) {
	for i := range results {
		r := &results[i]
		if r.Error != nil || r.ResolvedIP == "" {
			continue
		}
		if ctx.Err() != nil {
			break
		}

		// Only probe targets that negotiated a PQC key-share in TLS 1.3.
		groupInfo, groupKnown := quantum.ClassifyTLSGroup(r.NegotiatedGroupID)
		if !groupKnown || !groupInfo.PQCPresent {
			continue
		}

		// Respect the probe budget shared with S8 enumeration.
		if maxProbes > 0 && probesUsedPerTarget[i] >= maxProbes {
			r.EnumTruncated = true
			r.EnumTruncationReason = "PROBE_BUDGET_EXHAUSTED"
			continue
		}

		host, port, err := parseHostPort(r.Target)
		if err != nil {
			continue
		}
		addr := net.JoinHostPort(r.ResolvedIP, port)

		// Acquire per-target semaphore slot (Sprint 2, 5-concurrent cap).
		// Targets run sequentially here, so the send never blocks longer
		// than one in-flight probe.
		sem <- struct{}{}
		tls12Res, tls12Err := tls12probeFn(ctx, addr, host, timeout, denyPrivate)
		<-sem

		if tls12Err != nil {
			if opts.Verbose {
				fmt.Fprintf(os.Stderr, "tls12-fallback: %s: %v\n", r.Target, tls12Err)
			}
			continue
		}
		probesUsedPerTarget[i]++
		r.AcceptedTLS12 = tls12Res.AcceptedTLS12
		r.TLS12CipherSuite = tls12Res.CipherSuiteID
		r.TLS12CipherSuiteName = tls12Res.CipherSuiteName
	}
}

// collectFindings converts ProbeResults into UnifiedFindings and emits
// a stderr summary. Returns an error when ALL targets were unreachable
// (all-or-nothing — partial reachability returns nil).
func collectFindings(results []ProbeResult, opts engines.ScanOptions, totalTargets int) ([]findings.UnifiedFinding, error) {
	var allFindings []findings.UnifiedFinding
	var reachable, unreachable int

	for _, r := range results {
		if r.Error != nil {
			unreachable++
			fmt.Fprintf(os.Stderr, "WARNING: tls-probe: %s: %v\n", r.Target, r.Error)
			continue
		}
		reachable++

		if !opts.TLSInsecure && r.VerifyError != "" {
			fmt.Fprintf(os.Stderr, "WARNING: tls-probe: %s: certificate verification failed: %s\n", r.Target, r.VerifyError)
		}

		allFindings = append(allFindings, observationToFindings(r)...)
	}

	fmt.Fprintf(os.Stderr, "TLS Probe: probed %d target(s) — %d reachable, %d unreachable\n",
		totalTargets, reachable, unreachable)

	if reachable == 0 && unreachable > 0 {
		return allFindings, fmt.Errorf("tls-probe: all %d target(s) unreachable", unreachable)
	}
	return allFindings, nil
}

// initialProbeBudget returns the starting per-target probe budget. Each
// target's count starts at 1 (initial handshake) plus DefaultProbeGroups()
// length when --deep-probe is enabled. Subsequent phases (enumeration, TLS
// 1.2 fallback) increment from this baseline.
func initialProbeBudget(targetCount int, deepProbe bool) []int {
	probesUsedPerTarget := make([]int, targetCount)
	deepProbeCost := 0
	if deepProbe {
		deepProbeCost = len(rawhello.DefaultProbeGroups())
	}
	for i := range probesUsedPerTarget {
		probesUsedPerTarget[i] = 1 + deepProbeCost
	}
	return probesUsedPerTarget
}
