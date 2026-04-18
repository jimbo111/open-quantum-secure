package sshprobe

import (
	"context"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/jimbo111/open-quantum-secure/pkg/engines"
	"github.com/jimbo111/open-quantum-secure/pkg/findings"
)

const (
	// maxConcurrency caps simultaneous SSH probes. >5 concurrent probes risk
	// triggering server-side rate limiting or connection throttling — mirrors
	// the empirical bound from tls-probe (Sprint 2 M1).
	maxConcurrency = 5

	// maxTargets is a sanity cap to prevent accidental mass-scanning.
	maxTargets = 100
)

// Engine probes live SSH endpoints and detects quantum-vulnerable KEX methods
// in their SSH_MSG_KEXINIT advertisement. Pure Go, always available.
type Engine struct{}

// New returns a new SSH probe Engine.
func New() *Engine { return &Engine{} }

func (e *Engine) Name() string                 { return engineName }
func (e *Engine) Tier() engines.Tier           { return engines.Tier5Network }
func (e *Engine) SupportedLanguages() []string { return nil }
func (e *Engine) Available() bool              { return true }
func (e *Engine) Version() string              { return "embedded" }

// Scan probes each target in opts.SSHTargets and returns findings for
// quantum-vulnerable KEX methods observed in SSH_MSG_KEXINIT.
// Returns nil immediately when NoNetwork is true or SSHTargets is empty.
func (e *Engine) Scan(ctx context.Context, opts engines.ScanOptions) ([]findings.UnifiedFinding, error) {
	if opts.NoNetwork {
		return nil, nil
	}
	if len(opts.SSHTargets) == 0 {
		return nil, nil
	}
	if len(opts.SSHTargets) > maxTargets {
		return nil, fmt.Errorf("ssh-probe: too many targets (%d), maximum is %d", len(opts.SSHTargets), maxTargets)
	}

	timeout := defaultTimeout
	if opts.SSHTimeout > 0 {
		timeout = time.Duration(opts.SSHTimeout) * time.Second
	}

	results := make([]ProbeResult, len(opts.SSHTargets))
	var wg sync.WaitGroup
	sem := make(chan struct{}, maxConcurrency)

	// A5: Track how many goroutines were launched so the summary accurately
	// reflects probed targets when the context is cancelled mid-scan.
	var launched int

	// A4: labelled loop so the select's ctx.Done case can break out of the
	// for-range, not just out of the select statement.
outer:
	for i, target := range opts.SSHTargets {
		// Acquire semaphore in parent goroutine — prevents bursting beyond cap even
		// momentarily (mirrors tls-probe M1 pattern from Sprint 2).
		select {
		case sem <- struct{}{}:
		case <-ctx.Done():
			break outer // A4: exits the for-range, not just the select
		}
		launched++ // A5: count only goroutines that actually start
		wg.Add(1)
		go func(idx int, t string) {
			defer wg.Done()
			defer func() { <-sem }()
			results[idx] = probeFn(ctx, t, timeout, opts.SSHDenyPrivate)
		}(i, target)
	}
	wg.Wait()

	var allFindings []findings.UnifiedFinding
	var reachable, unreachable int

	// A5: Iterate only launched results — zero-value slots beyond launched are
	// targets that were never started due to context cancellation.
	for _, r := range results[:launched] {
		if r.Error != nil {
			unreachable++
			fmt.Fprintf(os.Stderr, "WARNING: ssh-probe: %s: %v\n", r.Target, r.Error)
			continue
		}
		reachable++
		allFindings = append(allFindings, kexInitToFindings(r)...)
	}

	fmt.Fprintf(os.Stderr, "SSH Probe: probed %d target(s) — %d reachable, %d unreachable\n",
		launched, reachable, unreachable)

	if reachable == 0 && unreachable > 0 {
		return nil, fmt.Errorf("ssh-probe: all %d target(s) unreachable", unreachable) // B5: return nil, not partial allFindings
	}

	return allFindings, nil
}
