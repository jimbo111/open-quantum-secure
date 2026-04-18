package rawhello

import (
	"context"
	"fmt"
	"net"
	"time"
)

// GroupOutcome classifies the server's response to a single-group probe.
type GroupOutcome uint8

const (
	OutcomeAccepted GroupOutcome = iota // ServerHello — server accepted the group
	OutcomeHRR                          // HelloRetryRequest — server wants a different group
	OutcomeAlert                        // TLS alert — server rejected entirely
	OutcomeError                        // Transport/protocol error
)

func (o GroupOutcome) String() string {
	switch o {
	case OutcomeAccepted:
		return "accepted"
	case OutcomeHRR:
		return "hrr"
	case OutcomeAlert:
		return "alert"
	default:
		return "error"
	}
}

// DeepProbeGroupResult describes the server's response to probing one group.
type DeepProbeGroupResult struct {
	GroupID       uint16
	// SelectedGroup is the IANA codepoint the server named in its key_share response.
	// Set for both OutcomeAccepted (SH key_share group) and OutcomeHRR (HRR selected_group).
	// HRR means "server will accept this group on retry" — positive PQC evidence per RFC 8446 §4.1.4.
	SelectedGroup uint16
	Outcome       GroupOutcome
	AlertDesc     uint8 // set when Outcome == OutcomeAlert
	Err           error // set when Outcome == OutcomeError
}

// DeepProbe tests a pre-resolved addr for each group in groups. For each group
// it opens a fresh TCP connection, sends a minimal TLS 1.3 ClientHello advertising
// only that group's key_share, reads the first server response, and classifies it.
//
// addr must be a pre-resolved "ip:port" string — SSRF protection must be applied
// by the caller before invoking DeepProbe. sni is used for the SNI extension.
//
// Groups are probed sequentially to avoid rate-limiting a single server
// (mirrors the per-target concurrency cap rationale in tlsprobe/engine.go).
func DeepProbe(ctx context.Context, addr, sni string, timeout time.Duration, groups []uint16) []DeepProbeGroupResult {
	results := make([]DeepProbeGroupResult, 0, len(groups))
	for _, groupID := range groups {
		if ctx.Err() != nil {
			break
		}
		r := probeGroup(ctx, addr, sni, timeout, groupID)
		results = append(results, r)
	}
	return results
}

// probeGroup opens a TCP connection to addr and probes a single group codepoint.
func probeGroup(ctx context.Context, addr, sni string, timeout time.Duration, groupID uint16) DeepProbeGroupResult {
	if timeout == 0 {
		timeout = 10 * time.Second
	}

	dialCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	conn, err := (&net.Dialer{}).DialContext(dialCtx, "tcp", addr)
	if err != nil {
		return DeepProbeGroupResult{
			GroupID: groupID,
			Outcome: OutcomeError,
			Err:     fmt.Errorf("dial %s: %w", addr, err),
		}
	}
	defer conn.Close()

	ks, err := ProbeKeyShare(groupID)
	if err != nil {
		return DeepProbeGroupResult{
			GroupID: groupID,
			Outcome: OutcomeError,
			Err:     err,
		}
	}

	ch, err := BuildClientHello(ClientHelloOpts{
		SNI:             sni,
		SupportedGroups: []uint16{groupID},
		KeyShares:       []KeyShareEntry{ks},
	})
	if err != nil {
		return DeepProbeGroupResult{
			GroupID: groupID,
			Outcome: OutcomeError,
			Err:     fmt.Errorf("BuildClientHello group 0x%04x: %w", groupID, err),
		}
	}

	// Write the raw record directly — it already includes the TLS record header.
	conn.SetWriteDeadline(effectiveDeadline(dialCtx))
	if _, err := conn.Write(ch); err != nil {
		return DeepProbeGroupResult{
			GroupID: groupID,
			Outcome: OutcomeError,
			Err:     fmt.Errorf("write ClientHello group 0x%04x: %w", groupID, err),
		}
	}

	parsed, err := ParseServerResponse(dialCtx, conn)
	if err != nil {
		return DeepProbeGroupResult{
			GroupID: groupID,
			Outcome: OutcomeError,
			Err:     fmt.Errorf("parse response group 0x%04x: %w", groupID, err),
		}
	}

	if parsed.IsAlert {
		return DeepProbeGroupResult{
			GroupID:   groupID,
			Outcome:   OutcomeAlert,
			AlertDesc: parsed.AlertDesc,
		}
	}
	if parsed.IsHRR {
		// HRR names the group the server WILL accept on retry — positive PQC evidence.
		return DeepProbeGroupResult{GroupID: groupID, Outcome: OutcomeHRR, SelectedGroup: parsed.SelectedGroup}
	}
	return DeepProbeGroupResult{GroupID: groupID, Outcome: OutcomeAccepted, SelectedGroup: parsed.SelectedGroup}
}
