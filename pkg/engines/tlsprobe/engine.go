// Package tlsprobe implements a Tier 5 (Network) engine that probes live TLS
// endpoints and detects quantum-vulnerable cryptography in their handshake
// parameters (cipher suites, certificate signing algorithms, key sizes).
// It is pure Go, always available, and requires no external binaries.
package tlsprobe

import (
	"context"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/jimbo111/open-quantum-secure/pkg/engines"
	"github.com/jimbo111/open-quantum-secure/pkg/engines/tlsprobe/rawhello"
	"github.com/jimbo111/open-quantum-secure/pkg/findings"
)

const (
	defaultTimeout = 10 * time.Second
	// defaultConcurrency caps the number of simultaneous TLS handshakes.
	// Empirical sslyze finding: >5 concurrent probes trigger server-side rate
	// limiting (connection resets, TCP RST floods) producing false negatives
	// where reachable servers appear unreachable. 5 is the safe upper bound.
	defaultConcurrency = 5
	maxTargets         = 100
)

// probeFn is the underlying single-endpoint probe function. It is a
// package-level variable so tests can inject an instrumented stub without
// making real network connections (comparable to Sprint 0's nowFn hook).
var probeFn = probe

// Engine is the TLS probe engine. Pure Go, always available.
type Engine struct{}

// New returns a new TLS probe Engine.
func New() *Engine { return &Engine{} }

// Name returns the engine identifier.
func (e *Engine) Name() string { return "tls-probe" }

// Tier returns Tier5Network.
func (e *Engine) Tier() engines.Tier { return engines.Tier5Network }

// SupportedLanguages returns nil because TLS probing is not file-based.
func (e *Engine) SupportedLanguages() []string { return nil }

// Available always returns true because this engine is pure Go.
func (e *Engine) Available() bool { return true }

// Version returns "embedded" because this engine has no external binary.
func (e *Engine) Version() string { return "embedded" }

// Scan probes each target in opts.TLSTargets and returns findings for
// quantum-vulnerable cryptography observed in TLS handshakes.
// If TLSTargets is empty or opts.NoNetwork is true, returns nil immediately.
func (e *Engine) Scan(ctx context.Context, opts engines.ScanOptions) ([]findings.UnifiedFinding, error) {
	if opts.NoNetwork {
		return nil, nil
	}
	if len(opts.TLSTargets) == 0 {
		return nil, nil
	}
	if len(opts.TLSTargets) > maxTargets {
		return nil, fmt.Errorf("tls-probe: too many targets (%d), maximum is %d", len(opts.TLSTargets), maxTargets)
	}

	timeout := defaultTimeout
	if opts.TLSTimeout > 0 {
		timeout = time.Duration(opts.TLSTimeout) * time.Second
	}

	probeOpts := ProbeOpts{
		Insecure:    opts.TLSInsecure,
		DenyPrivate: opts.TLSDenyPrivate,
		Timeout:     timeout,
		CACertPath:  opts.TLSCACert,
	}

	// Probe targets in parallel with bounded concurrency.
	sem := make(chan struct{}, defaultConcurrency)
	results := make([]ProbeResult, len(opts.TLSTargets))
	var wg sync.WaitGroup

	for i, target := range opts.TLSTargets {
		if ctx.Err() != nil {
			break
		}
		sem <- struct{}{} // acquire in parent; blocks here if concurrency cap is reached
		wg.Add(1)
		go func(idx int, t string) {
			defer wg.Done()
			defer func() { <-sem }() // release when probe finishes
			if ctx.Err() != nil {
				return
			}
			results[idx] = probeFn(ctx, t, probeOpts)
		}(i, target)
	}
	wg.Wait()

	// Deep-probe pass (--deep-probe, Sprint 7): for each reachable target, probe
	// each group in DefaultProbeGroups individually using hand-crafted ClientHellos.
	// Run sequentially per target to avoid rate-limiting (groups are already
	// sequential inside rawhello.DeepProbe; targets could be parallelised but
	// sequential is safe and keeps the code simple for MVP).
	if opts.DeepProbe {
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
				fmt.Fprintf(os.Stderr, "deep-probe: %s: %v\n", r.Target, deepErr)
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
			fmt.Fprintf(os.Stderr, "deep-probe: %s — %d/%d groups accepted, %d HRR\n",
				r.Target, len(r.DeepProbeAcceptedGroups), len(groupResults), len(r.DeepProbeHRRGroups))
		}
	}

	// Sprint 8 enumeration passes: run after deep-probe so addr is already resolved.
	// Passes run sequentially per target (same rate-limit rationale as deep-probe).
	// Total per-target budget: 60 s enforced by a child context.
	if opts.EnumerateGroups || opts.EnumerateSigAlgs || opts.DetectServerPreference {
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

			// 60-second budget for all enumeration passes on this target.
			enumCtx, enumCancel := context.WithTimeout(ctx, 60*time.Second)

			var modes []string

			if opts.EnumerateGroups {
				gr, gErr := enumerateGroups(enumCtx, addr, host, timeout)
				if gErr != nil && len(gr.AcceptedGroups) == 0 && len(gr.HRRGroups) == 0 {
					fmt.Fprintf(os.Stderr, "enumerate-groups: %s: %v\n", r.Target, gErr)
				} else {
					r.EnumAcceptedGroups = gr.AcceptedGroups
					r.EnumHRRGroups = gr.HRRGroups
					modes = append(modes, "groups")
					fmt.Fprintf(os.Stderr, "enumerate-groups: %s — %d accepted, %d HRR, %d rejected\n",
						r.Target, len(gr.AcceptedGroups), len(gr.HRRGroups), len(gr.RejectedGroups))
				}
			}

			if opts.EnumerateSigAlgs {
				sr, sErr := enumerateSigAlgs(enumCtx, addr, host, timeout)
				if sErr != nil && len(sr.AcceptedSigAlgs) == 0 {
					fmt.Fprintf(os.Stderr, "enumerate-sigalgs: %s: %v\n", r.Target, sErr)
				} else {
					r.EnumSupportedSigAlgs = sr.AcceptedSigAlgs
					modes = append(modes, "sigalgs")
					fmt.Fprintf(os.Stderr, "enumerate-sigalgs: %s — %d accepted\n",
						r.Target, len(sr.AcceptedSigAlgs))
				}
			}

			if opts.DetectServerPreference {
				// Use enum-accepted groups when available; fall back to deep-probe accepted.
				prefCandidates := r.EnumAcceptedGroups
				if len(prefCandidates) == 0 {
					prefCandidates = r.DeepProbeAcceptedGroups
				}
				if len(prefCandidates) >= 2 {
					prefResult, pErr := detectServerGroupPreference(enumCtx, addr, host, timeout, prefCandidates)
					if pErr != nil {
						fmt.Fprintf(os.Stderr, "detect-server-preference: %s: %v\n", r.Target, pErr)
					} else {
						r.EnumServerPrefGroup = prefResult.PreferredGroup
						r.EnumServerPrefMode = prefResult.Mode
						modes = append(modes, "preference")
						fmt.Fprintf(os.Stderr, "detect-server-preference: %s — group 0x%04x (%s)\n",
							r.Target, prefResult.PreferredGroup, prefResult.Mode)
					}
				}
			}

			if len(modes) > 0 {
				r.EnumerationMode = joinModes(modes)
			}

			enumCancel()
		}
	}

	// Collect findings and track errors.
	var allFindings []findings.UnifiedFinding
	var reachable, unreachable int

	for _, r := range results {
		if r.Error != nil {
			unreachable++
			fmt.Fprintf(os.Stderr, "WARNING: tls-probe: %s: %v\n", r.Target, r.Error)
			continue
		}
		reachable++

		// Emit cert verification warning if verification failed in default mode.
		if !opts.TLSInsecure && r.VerifyError != "" {
			fmt.Fprintf(os.Stderr, "WARNING: tls-probe: %s: certificate verification failed: %s\n", r.Target, r.VerifyError)
		}

		allFindings = append(allFindings, observationToFindings(r)...)
	}

	// Summary to stderr.
	fmt.Fprintf(os.Stderr, "TLS Probe: probed %d target(s) — %d reachable, %d unreachable\n",
		len(opts.TLSTargets), reachable, unreachable)

	// If ALL targets are unreachable and user explicitly provided targets, return error.
	if reachable == 0 && unreachable > 0 {
		return allFindings, fmt.Errorf("tls-probe: all %d target(s) unreachable", unreachable)
	}

	return allFindings, nil
}

// joinModes concatenates Sprint 8 enumeration mode names with "+".
// Example: joinModes([]string{"groups", "preference"}) → "groups+preference".
func joinModes(modes []string) string {
	return strings.Join(modes, "+")
}
