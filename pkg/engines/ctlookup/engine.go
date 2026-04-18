package ctlookup

import (
	"context"
	"crypto/x509"
	"fmt"
	"os"
	"sync"

	"github.com/jimbo111/open-quantum-secure/pkg/engines"
	"github.com/jimbo111/open-quantum-secure/pkg/findings"
	"github.com/jimbo111/open-quantum-secure/pkg/quantum"
)

const (
	// maxConcurrency caps simultaneous crt.sh requests. crt.sh is soft-rate-limited
	// to ~1 req/sec; 3 concurrent callers share the token-bucket rate limiter to
	// stay within budget without starving each other.
	maxConcurrency = 3

	engineName = "ct-lookup"

	defaultRate  = 1.0
	defaultBurst = 3.0
)

// Engine queries Certificate Transparency logs (crt.sh) to recover certificate
// signing algorithms on TLS 1.3 hosts where ECH hides the Certificate message.
// It is pure Go with no external binary dependency.
type Engine struct {
	cache  *ctCache
	rl     *rateLimiter
	client *crtShClient
}

// New returns a new CT lookup Engine with default settings.
func New() *Engine {
	return &Engine{
		cache:  newCTCache(defaultCacheSize, defaultCacheTTL),
		rl:     newRateLimiter(defaultRate, defaultBurst),
		client: newCrtShClient(defaultHTTPTimeout, defaultBaseURL),
	}
}

// NewWithBaseURL returns a CT lookup Engine that targets baseURL instead of the
// production crt.sh endpoint. Intended for integration tests using httptest.Server.
func NewWithBaseURL(baseURL string) *Engine {
	return &Engine{
		cache:  newCTCache(defaultCacheSize, defaultCacheTTL),
		rl:     newRateLimiter(defaultRate, defaultBurst),
		client: newCrtShClient(defaultHTTPTimeout, baseURL),
	}
}

func (e *Engine) Name() string                { return engineName }
func (e *Engine) Tier() engines.Tier          { return engines.Tier5Network }
func (e *Engine) SupportedLanguages() []string { return nil }
func (e *Engine) Available() bool             { return true }
func (e *Engine) Version() string             { return "embedded" }

// Scan queries crt.sh for each hostname in opts.CTLookupTargets and returns a
// UnifiedFinding per unique certificate signature algorithm observed.
//
// Self-gating rules:
//   - Returns nil, nil immediately when opts.NoNetwork is true.
//   - Returns nil, nil when CTLookupTargets is empty (after deduplication).
//
// The orchestrator pre-populates CTLookupTargets from ECH findings (via
// ExtractECHHostnames) when CTLookupFromECH is true, so this engine does not
// need to inspect PriorFindings directly.
func (e *Engine) Scan(ctx context.Context, opts engines.ScanOptions) ([]findings.UnifiedFinding, error) {
	if opts.NoNetwork {
		return nil, nil
	}

	targets := deduplicateHostnames(opts.CTLookupTargets)
	if len(targets) == 0 {
		return nil, nil
	}

	// Filter invalid hostnames with a warning; valid ones proceed.
	valid := targets[:0]
	for _, h := range targets {
		if err := validateHostname(h); err != nil {
			fmt.Fprintf(os.Stderr, "WARNING: ct-lookup: skipping invalid hostname %q: %v\n", h, err)
			continue
		}
		valid = append(valid, h)
	}
	targets = valid
	if len(targets) == 0 {
		return nil, nil
	}

	type hostResult struct {
		hostname string
		records  []certRecord
		err      error
	}

	results := make([]hostResult, len(targets))
	var wg sync.WaitGroup
	sem := make(chan struct{}, maxConcurrency)

	for i, hostname := range targets {
		// Serve from cache without consuming a semaphore slot or rate-limit token.
		if recs, ok := e.cache.get(hostname); ok {
			results[i] = hostResult{hostname: hostname, records: recs}
			continue
		}
		if ctx.Err() != nil {
			break
		}
		// Acquire semaphore in parent goroutine — prevents bursting beyond cap even
		// momentarily (mirrors the tls-probe M1 pattern from Sprint 2).
		// Cancel-aware: if ctx is done while waiting for a slot, abort early.
		select {
		case sem <- struct{}{}:
		case <-ctx.Done():
			break
		}
		if ctx.Err() != nil {
			break
		}
		wg.Add(1)
		go func(idx int, host string) {
			defer wg.Done()
			defer func() { <-sem }()

			if ctx.Err() != nil {
				return
			}
			if err := e.rl.Wait(ctx); err != nil {
				results[idx] = hostResult{hostname: host, err: err}
				return
			}
			recs, err := e.queryHost(ctx, host)
			if err != nil {
				results[idx] = hostResult{hostname: host, err: err}
				return
			}
			if len(recs) == 0 {
				e.cache.putShort(host, recs)
			} else {
				e.cache.put(host, recs)
			}
			results[idx] = hostResult{hostname: host, records: recs}
		}(i, hostname)
	}
	wg.Wait()

	var allFindings []findings.UnifiedFinding
	var errCount, completed int
	for _, r := range results {
		if r.err != nil {
			errCount++
			fmt.Fprintf(os.Stderr, "WARNING: ct-lookup: %s: %v\n", r.hostname, r.err)
			continue
		}
		completed++
		for _, rec := range r.records {
			allFindings = append(allFindings, certRecordToFinding(r.hostname, rec))
		}
	}
	fmt.Fprintf(os.Stderr, "CT Lookup: queried %d hostname(s) — %d error(s)\n",
		completed, errCount)

	return allFindings, nil
}

// queryHost fetches CT entries for one hostname and returns cert records enriched
// with algorithm metadata from the DER-encoded certificate when available.
func (e *Engine) queryHost(ctx context.Context, hostname string) ([]certRecord, error) {
	entries, err := e.client.queryHostname(ctx, hostname)
	if err != nil {
		return nil, err
	}
	if len(entries) == 0 {
		return nil, nil
	}

	// Cap to maxCertsToFetch most-recent entries to bound the number of DER
	// fetches, each of which consumes a rate-limit token.
	if len(entries) > maxCertsToFetch {
		entries = entries[:maxCertsToFetch]
	}

	var records []certRecord
	for _, entry := range entries {
		if ctx.Err() != nil {
			break
		}
		// Rate-limit every DER fetch (separate from the outer host-level token).
		if err := e.rl.Wait(ctx); err != nil {
			break
		}
		der, fetchErr := e.client.fetchCertDER(ctx, entry.ID)
		if fetchErr != nil {
			fmt.Fprintf(os.Stderr, "WARNING: ct-lookup: DER fetch id=%d: %v\n", entry.ID, fetchErr)
			continue
		}
		cert, parseErr := x509.ParseCertificate(der)
		if parseErr != nil {
			fmt.Fprintf(os.Stderr, "WARNING: ct-lookup: DER parse id=%d: %v\n", entry.ID, parseErr)
			continue
		}
		rec := x509ToRecord(cert)
		rec.CertID = entry.ID
		records = append(records, rec)
	}
	return records, nil
}

// certRecordToFinding converts a certRecord into a UnifiedFinding.
// Confidence is Medium because CT logs provide indirect evidence (a cert was
// issued) rather than the live handshake observation that tls-probe provides.
func certRecordToFinding(hostname string, rec certRecord) findings.UnifiedFinding {
	algoName := rec.SigAlgorithm
	if algoName == "" {
		algoName = rec.PubKeyAlgorithm
	}

	c := quantum.ClassifyAlgorithm(algoName, "signature", rec.PubKeySize)

	// Serial prefix (8 hex chars) distinguishes multiple certs for the same host.
	serial := rec.Serial
	if len(serial) > 8 {
		serial = serial[:8]
	}

	return findings.UnifiedFinding{
		Location: findings.Location{
			File:         fmt.Sprintf("(ct-lookup)/%s#cert:%s", hostname, serial),
			Line:         0,
			ArtifactType: "ct-log",
		},
		Algorithm: &findings.Algorithm{
			Name:      algoName,
			Primitive: "signature",
			KeySize:   rec.PubKeySize,
			Curve:     rec.PubKeyCurve,
		},
		Confidence:    findings.ConfidenceMedium,
		SourceEngine:  engineName,
		Reachable:     findings.ReachableYes,
		RawIdentifier: fmt.Sprintf("ct-cert:%s|%s|%s", hostname, algoName, rec.Serial),
		QuantumRisk:   findings.QuantumRisk(c.Risk),
		Severity:      findings.Severity(c.Severity),
		// CT lookup resolves what ECH hid — this finding is complete inventory.
		PartialInventory: false,
	}
}
