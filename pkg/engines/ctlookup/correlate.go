package ctlookup

import (
	"net"
	"strings"

	"github.com/jimbo111/open-quantum-secure/pkg/findings"
)

const echPartialReason = "ECH_ENABLED"

// ExtractECHHostnames returns deduplicated bare hostnames from findings that are
// annotated as partial inventory due to ECH. It is exported so that the
// orchestrator can call it between the tls-probe and ct-lookup engine runs,
// pre-populating CTLookupTargets with ECH-obscured hosts before ct-lookup Scan().
//
// The reason string may be a composed value like "ECH_ENABLED+ENUMERATION_TRUNCATED"
// when S8 enumeration truncates an ECH target (see tlsprobe/classify.go). We match
// via strings.HasPrefix so the ECH signal survives composition.
func ExtractECHHostnames(ff []findings.UnifiedFinding) []string {
	seen := make(map[string]bool)
	var hosts []string
	for _, f := range ff {
		if !f.PartialInventory || !strings.HasPrefix(f.PartialInventoryReason, echPartialReason) {
			continue
		}
		h := hostnameFromFile(f.Location.File)
		if h == "" || seen[h] {
			continue
		}
		seen[h] = true
		hosts = append(hosts, h)
	}
	return hosts
}

// hostnameFromFile extracts the bare hostname (no port) from a tls-probe
// Location.File path with the form "(tls-probe)/host:port#suffix".
// It tolerates missing ports and non-tls-probe paths gracefully.
func hostnameFromFile(file string) string {
	// Strip engine prefix; e.g. "(tls-probe)/example.com:443#kex" → "example.com:443#kex".
	if idx := strings.Index(file, "/"); idx >= 0 {
		file = file[idx+1:]
	}
	// Strip fragment suffix; e.g. "example.com:443#kex" → "example.com:443".
	if idx := strings.LastIndex(file, "#"); idx >= 0 {
		file = file[:idx]
	}
	// Split host from port; bare hostnames without a port are returned as-is.
	host, _, err := net.SplitHostPort(file)
	if err != nil {
		return file
	}
	return host
}

// canonicalizeHostname returns a canonical form of h: lowercased, trailing dot
// stripped, and :port suffix removed. Applying this once at ingestion means
// cache keys, dedup maps, and rate-limiter counters all agree.
func canonicalizeHostname(h string) string {
	h = strings.ToLower(h)
	// Strip :port if present.
	if host, _, err := net.SplitHostPort(h); err == nil {
		h = host
	}
	// Strip trailing dot (root label).
	h = strings.TrimRight(h, ".")
	return h
}

// deduplicateHostnames returns a new slice with duplicate entries removed,
// preserving input order. Empty strings are dropped. Hostnames are
// canonicalized (lowercased, port-stripped, trailing-dot removed) before
// deduplication so "Example.Com:443" and "example.com" collapse to one entry.
func deduplicateHostnames(in []string) []string {
	seen := make(map[string]bool, len(in))
	out := make([]string, 0, len(in))
	for _, h := range in {
		c := canonicalizeHostname(h)
		if c == "" || seen[c] {
			continue
		}
		seen[c] = true
		out = append(out, c)
	}
	return out
}
