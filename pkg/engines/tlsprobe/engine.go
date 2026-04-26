// Package tlsprobe implements a Tier 5 (Network) engine that probes live TLS
// endpoints and detects quantum-vulnerable cryptography in their handshake
// parameters (cipher suites, certificate signing algorithms, key sizes).
// It is pure Go, always available, and requires no external binaries.
package tlsprobe

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/jimbo111/open-quantum-secure/pkg/engines"
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
//
// Scan is a phase coordinator. The actual probing logic lives in phases.go:
//
//  1. runInitialProbes  — parallel TLS handshakes (Sprint 1 baseline)
//  2. runDeepProbe      — per-group ClientHello probing (Sprint 7, optional)
//  3. runEnumeration    — group/sig-alg/preference enum (Sprint 8, optional)
//  4. runTLS12Fallback  — downgrade-vulnerability check (Sprint 9, default-on)
//  5. collectFindings   — aggregation + stderr summary
//
// Per-target probe budget (probesUsedPerTarget) is shared between phases 3
// and 4 so they can collectively respect maxProbes. Default 30 guards
// against the ~39-probe worst case (1 initial + 6 deep + 13 group-enum +
// 17 sigalg + 2 preference + 1 tls12).
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

	sem := make(chan struct{}, defaultConcurrency)

	results := runInitialProbes(ctx, opts.TLSTargets, probeOpts, sem)

	if opts.DeepProbe {
		runDeepProbe(ctx, results, timeout, opts.Verbose)
	}

	maxProbes := opts.MaxProbesPerTarget
	if maxProbes == 0 {
		maxProbes = 30
	}
	probesUsedPerTarget := initialProbeBudget(len(results), opts.DeepProbe)

	if opts.EnumerateGroups || opts.EnumerateSigAlgs || opts.DetectServerPreference {
		runEnumeration(ctx, results, opts, timeout, sem, probesUsedPerTarget, maxProbes)
	}

	if !opts.SkipTLS12Fallback {
		runTLS12Fallback(ctx, results, opts, timeout, sem, probesUsedPerTarget, maxProbes, probeOpts.DenyPrivate)
	}

	return collectFindings(results, opts, len(opts.TLSTargets))
}

// joinModes concatenates Sprint 8 enumeration mode names with "+".
// Example: joinModes([]string{"groups", "preference"}) → "groups+preference".
func joinModes(modes []string) string {
	return strings.Join(modes, "+")
}
