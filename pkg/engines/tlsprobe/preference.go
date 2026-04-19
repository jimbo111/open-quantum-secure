package tlsprobe

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/jimbo111/open-quantum-secure/pkg/engines/tlsprobe/rawhello"
)

// ServerPreferenceMode values returned by detectServerGroupPreference.
const (
	// PrefServerFixed means the server always selected the same group regardless
	// of the client's offered ordering — it has a fixed ranked preference list.
	PrefServerFixed = "server-fixed"
	// PrefClientOrder means the server selected whichever group appeared first
	// in the client's list — it honours client ordering.
	PrefClientOrder = "client-order"
	// PrefIndeterminate means the result could not be determined (fewer than 2
	// valid key-share groups, transport errors, or inconsistent data).
	PrefIndeterminate = "indeterminate"
)

// ServerPreferenceResult holds the outcome of a two-ordering preference probe.
type ServerPreferenceResult struct {
	// PreferredGroup is the group the server selected in the forward-order probe.
	// 0 when Mode is PrefIndeterminate.
	PreferredGroup uint16
	// Mode classifies the server's preference behaviour.
	Mode string
}

// classicalECDHGroups is the set of IANA SupportedGroup codepoints that use
// only classical ECDH key material. Used by detectServerGroupPreference to
// build a mixed key_share offering (1 classical + up to 2 hybrid/PQC).
var classicalECDHGroups = map[uint16]bool{
	0x001d: true, // x25519
	0x0017: true, // secp256r1
	0x0018: true, // secp384r1
	0x0019: true, // secp521r1
}

// maxPrefKeyShares caps the number of key_share entries in each preference
// probe ClientHello. ≥3 hybrid key shares push ClientHello past 7 KB,
// which trips some middlebox rate-limiters and inflates RTT on the probe
// connection. The cap preserves the preference signal while keeping the
// ClientHello within a safe size. Tradeoff: servers that only accept groups
// not in the capped subset may return Alert, causing PrefIndeterminate.
const maxPrefKeyShares = 3

// detectServerGroupPreference determines whether the server has a fixed group
// preference or respects the client's offered ordering.
//
// Algorithm: send two ClientHellos with the same groups in opposite orderings.
//   - Forward:  [A, B, C, ...]
//   - Reversed: [..., C, B, A]
//
// If both probes return the same selected group → PrefServerFixed.
// If they differ → PrefClientOrder.
// <2 valid groups or transport error → PrefIndeterminate.
//
// At most maxPrefKeyShares (3) groups are offered per probe, preferring a
// mix of 1 classical ECDH + 2 hybrid/PQC to keep ClientHello below 7 KB.
//
// addr must be a pre-resolved "ip:port" string (SSRF guard applied here).
// ctx bounds overall time; timeout bounds each individual TCP connection.
func detectServerGroupPreference(ctx context.Context, addr, sni string, timeout time.Duration, acceptedGroups []uint16) (ServerPreferenceResult, error) {
	indeterminate := ServerPreferenceResult{Mode: PrefIndeterminate}

	if len(acceptedGroups) < 2 {
		return indeterminate, nil
	}
	if timeout == 0 {
		timeout = 10 * time.Second
	}
	// Defence-in-depth SSRF check.
	if h, _, err := net.SplitHostPort(addr); err != nil || net.ParseIP(h) == nil {
		return indeterminate, fmt.Errorf("detectServerGroupPreference: addr %q must be a pre-resolved IP:port, not a hostname", addr)
	}

	// Pre-compute key shares for all accepted groups before dialing.
	// Unknown codepoints (no key share size) are silently skipped.
	var keySharesFwd []rawhello.KeyShareEntry
	var validGroupsFwd []uint16
	for _, g := range acceptedGroups {
		ks, err := rawhello.ProbeKeyShare(g)
		if err != nil {
			continue
		}
		keySharesFwd = append(keySharesFwd, ks)
		validGroupsFwd = append(validGroupsFwd, g)
	}
	if len(validGroupsFwd) < 2 {
		// Fewer than 2 valid groups after filtering — indeterminate.
		return indeterminate, nil
	}

	// Cap to maxPrefKeyShares (3) to keep ClientHello below 7 KB.
	// Prefer 1 classical + up to 2 hybrid/PQC for a representative mix.
	validGroupsFwd, keySharesFwd = selectPrefGroups(validGroupsFwd, keySharesFwd)
	if len(validGroupsFwd) < 2 {
		return indeterminate, nil
	}

	// Build reversed ordering.
	validGroupsRev := reverseGroups(validGroupsFwd)
	keySharesRev := reverseKeyShares(keySharesFwd)

	// Probe forward order [A, B, ...].
	fwdGroup, fwdErr := probeOrder(ctx, addr, sni, timeout, validGroupsFwd, keySharesFwd)
	if fwdErr != nil {
		return indeterminate, fmt.Errorf("detectServerGroupPreference: forward probe: %w", fwdErr)
	}
	if fwdGroup == 0 {
		// Server rejected or failed to respond.
		return indeterminate, nil
	}

	// Probe reversed order [..., B, A].
	revGroup, revErr := probeOrder(ctx, addr, sni, timeout, validGroupsRev, keySharesRev)
	if revErr != nil {
		return indeterminate, fmt.Errorf("detectServerGroupPreference: reverse probe: %w", revErr)
	}
	if revGroup == 0 {
		return indeterminate, nil
	}

	if fwdGroup == revGroup {
		// Same group selected regardless of client ordering → server-fixed preference.
		return ServerPreferenceResult{PreferredGroup: fwdGroup, Mode: PrefServerFixed}, nil
	}
	// Different selections → server respects client ordering.
	// Report the group selected in the forward (canonical) probe.
	return ServerPreferenceResult{PreferredGroup: fwdGroup, Mode: PrefClientOrder}, nil
}

// probeOrder sends a single ClientHello offering groups in the given order and
// returns the IANA codepoint selected by the server (from ServerHello or HRR).
// Returns 0 on Alert or error.
func probeOrder(ctx context.Context, addr, sni string, timeout time.Duration, groups []uint16, keyShares []rawhello.KeyShareEntry) (uint16, error) {
	dialCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	conn, err := (&net.Dialer{}).DialContext(dialCtx, "tcp", addr)
	if err != nil {
		return 0, fmt.Errorf("dial %s: %w", addr, err)
	}
	defer conn.Close()

	if dl, ok := dialCtx.Deadline(); ok {
		if err := conn.SetDeadline(dl); err != nil {
			return 0, fmt.Errorf("set deadline: %w", err)
		}
	}

	ch, err := rawhello.BuildClientHello(rawhello.ClientHelloOpts{
		SNI:             sni,
		SupportedGroups: groups,
		KeyShares:       keyShares,
	})
	if err != nil {
		return 0, fmt.Errorf("BuildClientHello: %w", err)
	}

	if _, err := conn.Write(ch); err != nil {
		return 0, fmt.Errorf("write: %w", err)
	}

	parsed, err := rawhello.ParseServerResponse(dialCtx, conn)
	if err != nil {
		return 0, fmt.Errorf("parse: %w", err)
	}
	if parsed.IsAlert {
		return 0, nil
	}
	// Both ServerHello and HRR carry SelectedGroup = the server's chosen group.
	return parsed.SelectedGroup, nil
}

// selectPrefGroups caps groups + keyShares to maxPrefKeyShares entries,
// preferring 1 classical ECDH + up to 2 hybrid/PQC for a representative mix.
// It preserves the input ordering within each tier.
func selectPrefGroups(groups []uint16, keyShares []rawhello.KeyShareEntry) ([]uint16, []rawhello.KeyShareEntry) {
	if len(groups) <= maxPrefKeyShares {
		return groups, keyShares
	}

	var selGroups []uint16
	var selShares []rawhello.KeyShareEntry

	classicalQuota, hybridQuota := 1, maxPrefKeyShares-1

	// First pass: pick classical groups up to quota.
	for i, g := range groups {
		if classicalECDHGroups[g] && classicalQuota > 0 {
			selGroups = append(selGroups, g)
			selShares = append(selShares, keyShares[i])
			classicalQuota--
		}
	}
	// Second pass: fill remaining slots with hybrid/PQC groups.
	for i, g := range groups {
		if len(selGroups) >= maxPrefKeyShares {
			break
		}
		if !classicalECDHGroups[g] && hybridQuota > 0 {
			selGroups = append(selGroups, g)
			selShares = append(selShares, keyShares[i])
			hybridQuota--
		}
	}
	// If still under cap (e.g. no classical groups), fill from any remaining.
	for i, g := range groups {
		if len(selGroups) >= maxPrefKeyShares {
			break
		}
		alreadySelected := false
		for _, sg := range selGroups {
			if sg == g {
				alreadySelected = true
				break
			}
		}
		if !alreadySelected {
			selGroups = append(selGroups, g)
			selShares = append(selShares, keyShares[i])
		}
	}
	return selGroups, selShares
}

// reverseGroups returns a new slice with the elements of s in reverse order.
func reverseGroups(s []uint16) []uint16 {
	out := make([]uint16, len(s))
	for i, v := range s {
		out[len(s)-1-i] = v
	}
	return out
}

// reverseKeyShares returns a new slice with the elements of s in reverse order.
func reverseKeyShares(s []rawhello.KeyShareEntry) []rawhello.KeyShareEntry {
	out := make([]rawhello.KeyShareEntry, len(s))
	for i, v := range s {
		out[len(s)-1-i] = v
	}
	return out
}
