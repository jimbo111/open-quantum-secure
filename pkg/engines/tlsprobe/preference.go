package tlsprobe

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/jimbo111/open-quantum-secure/pkg/engines/tlsprobe/rawhello"
)

// detectServerGroupPreference sends a single ClientHello offering key shares for
// all groups in acceptedGroups and returns the IANA codepoint the server selected.
//
// The server's response — either ServerHello (SelectedGroup = chosen group) or HRR
// (SelectedGroup = demanded group) — identifies its top preference. When the server
// sends HRR it is demanding a retry with a specific group, which is the strongest
// possible preference signal.
//
// addr must be a pre-resolved "ip:port" string (SSRF guard applied by caller).
// Returns 0 when acceptedGroups has fewer than 2 entries, on Alert, or on error.
func detectServerGroupPreference(ctx context.Context, addr, sni string, timeout time.Duration, acceptedGroups []uint16) (uint16, error) {
	if len(acceptedGroups) < 2 {
		// With 0 or 1 accepted group there is no preference to detect.
		return 0, nil
	}
	if timeout == 0 {
		timeout = 10 * time.Second
	}
	// Defence-in-depth SSRF check.
	if h, _, err := net.SplitHostPort(addr); err != nil || net.ParseIP(h) == nil {
		return 0, fmt.Errorf("detectServerGroupPreference: addr %q must be a pre-resolved IP:port, not a hostname", addr)
	}

	// Build key shares for all accepted groups before dialing. Groups for which
	// ProbeKeyShare fails (unknown codepoint) are silently skipped — this guards
	// against future group additions that haven't been mapped yet. We filter
	// first to avoid a dial attempt when fewer than 2 valid groups remain.
	var keyShares []rawhello.KeyShareEntry
	var validGroups []uint16
	for _, g := range acceptedGroups {
		ks, ksErr := rawhello.ProbeKeyShare(g)
		if ksErr != nil {
			continue
		}
		keyShares = append(keyShares, ks)
		validGroups = append(validGroups, g)
	}
	if len(keyShares) < 2 {
		// Not enough valid groups after filtering — no preference to detect.
		return 0, nil
	}

	dialCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	conn, err := (&net.Dialer{}).DialContext(dialCtx, "tcp", addr)
	if err != nil {
		return 0, fmt.Errorf("detectServerGroupPreference: dial %s: %w", addr, err)
	}
	defer conn.Close()

	if dl, ok := dialCtx.Deadline(); ok {
		conn.SetDeadline(dl) //nolint:errcheck
	}

	ch, err := rawhello.BuildClientHello(rawhello.ClientHelloOpts{
		SNI:             sni,
		SupportedGroups: validGroups,
		KeyShares:       keyShares,
	})
	if err != nil {
		return 0, fmt.Errorf("detectServerGroupPreference: BuildClientHello: %w", err)
	}

	if _, err := conn.Write(ch); err != nil {
		return 0, fmt.Errorf("detectServerGroupPreference: write: %w", err)
	}

	parsed, err := rawhello.ParseServerResponse(dialCtx, conn)
	if err != nil {
		return 0, fmt.Errorf("detectServerGroupPreference: parse: %w", err)
	}
	if parsed.IsAlert {
		// Server rejected all offered groups — no preference to report.
		return 0, nil
	}

	// Both ServerHello and HRR carry SelectedGroup = the server's chosen group.
	// HRR is an even stronger signal: the server is demanding this group.
	return parsed.SelectedGroup, nil
}
