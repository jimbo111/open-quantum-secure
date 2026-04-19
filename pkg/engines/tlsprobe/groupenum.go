package tlsprobe

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/jimbo111/open-quantum-secure/pkg/engines/tlsprobe/rawhello"
)

// fullEnumGroups is the comprehensive list of TLS SupportedGroup codepoints probed
// during --enumerate-groups. Broader than defaultProbeGroups (Sprint 7's fast-path
// 6-group set). Only groups with key share sizes in rawhello.ProbeKeyShare are
// included; FFDH groups (ffdhe*) and X448 are excluded — they require DH parameters
// that raw probes cannot generate.
var fullEnumGroups = []uint16{
	// Classical ECDH (quantum-vulnerable, broken by Shor's algorithm)
	0x001d, // X25519
	0x0017, // secp256r1
	0x0018, // secp384r1
	0x0019, // secp521r1
	// Hybrid KEM: classical ECDH + ML-KEM (FIPS 203 final, PQC-safe)
	0x11ec, // X25519MLKEM768
	0x11eb, // SecP256r1MLKEM768
	0x11ed, // SecP384r1MLKEM1024
	0x11ee, // curveSM2MLKEM768
	// Pure ML-KEM (FIPS 203 final, PQC-safe)
	0x0200, // MLKEM512
	0x0201, // MLKEM768
	0x0202, // MLKEM1024
	// Deprecated draft Kyber (pre-FIPS 203; positive signal for old deployments)
	0x6399, // X25519Kyber768Draft00 (IETF hybrid draft, deprecated)
	0x636D, // X25519Kyber768Draft00 (alternate codepoint, deprecated)
}

// GroupEnumResult holds the classification of every group codepoint probed for
// one target during --enumerate-groups.
type GroupEnumResult struct {
	// AcceptedGroups are codepoints for which the server responded with a
	// ServerHello (group accepted for key exchange). Populated with the server's
	// SelectedGroup from the ServerHello key_share (which for Accepted is
	// always equal to the probed group).
	AcceptedGroups []uint16
	// HRRGroups are codepoints NAMED BY THE SERVER via HelloRetryRequest.
	// HRR means "supported but not my first choice — please retry with this
	// group instead". HRR is positive PQC evidence when the named group is a
	// PQC codepoint. Populated with parsed.SelectedGroup, NOT the probed group
	// (the probed group is what we OFFERED; the named group is what the server
	// WILL ACCEPT on retry). Zero-valued selections are dropped.
	HRRGroups []uint16
	// RejectedGroups are codepoints for which the server sent a TLS Alert,
	// indicating the group is not supported. Populated with the probed group
	// since no server-chosen value is available on alert.
	RejectedGroups []uint16
}

// enumerateGroups probes addr for every group in fullEnumGroups and classifies
// each as accepted, HRR, or rejected. addr must be a pre-resolved "ip:port"
// string; the SSRF guard must be applied by the caller before invoking this.
//
// Groups are probed sequentially to avoid triggering server-side rate limiting
// (same rationale as the per-target concurrency cap in engine.go).
// ctx bounds total time; timeout bounds each individual probe.
func enumerateGroups(ctx context.Context, addr, sni string, timeout time.Duration) (GroupEnumResult, error) {
	if timeout == 0 {
		timeout = 10 * time.Second
	}
	// Defence-in-depth SSRF check: addr must be a pre-resolved IP literal.
	if h, _, err := net.SplitHostPort(addr); err != nil || net.ParseIP(h) == nil {
		return GroupEnumResult{}, fmt.Errorf("enumerateGroups: addr %q must be a pre-resolved IP:port, not a hostname", addr)
	}

	rawResults, err := rawhello.DeepProbe(ctx, addr, sni, timeout, fullEnumGroups)

	var result GroupEnumResult
	for _, r := range rawResults {
		switch r.Outcome {
		case rawhello.OutcomeAccepted:
			// On Accepted, SelectedGroup == probed GroupID (server echoes the
			// key_share we offered). Either works; use SelectedGroup for
			// consistency with OutcomeHRR.
			if r.SelectedGroup != 0 {
				result.AcceptedGroups = append(result.AcceptedGroups, r.SelectedGroup)
			} else {
				// Defensive fallback if parser didn't populate SelectedGroup.
				result.AcceptedGroups = append(result.AcceptedGroups, r.GroupID)
			}
		case rawhello.OutcomeHRR:
			// CRITICAL: use SelectedGroup (what the SERVER named in HRR),
			// NOT GroupID (what we offered). A server rejecting X25519 in favor
			// of X25519MLKEM768 should record X25519MLKEM768 as a supported
			// group, not X25519. Matches the S7 DeepProbe pattern at
			// engine.go:137. Zero SelectedGroup means the HRR lacked a
			// key_share hint — drop rather than record a false positive.
			if r.SelectedGroup != 0 {
				result.HRRGroups = append(result.HRRGroups, r.SelectedGroup)
			}
		case rawhello.OutcomeAlert:
			result.RejectedGroups = append(result.RejectedGroups, r.GroupID)
		// OutcomeError: transport/protocol failure — omitted from classification.
		}
	}
	return result, err
}
