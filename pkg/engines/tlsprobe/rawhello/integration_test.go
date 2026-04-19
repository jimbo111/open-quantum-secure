//go:build integration

package rawhello

import (
	"context"
	"testing"
	"time"
)

// TestDeepProbe_Cloudflare exercises the full stack against a real TLS 1.3
// endpoint. Requires network access and --tags=integration to run.
//
//	go test -tags=integration -run TestDeepProbe_Cloudflare ./pkg/engines/tlsprobe/rawhello/
func TestDeepProbe_Cloudflare(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	// cloudflare.com supports X25519MLKEM768 (0x11ec) as of 2024.
	results, _ := DeepProbe(ctx, "1.1.1.1:443", "cloudflare.com", 10*time.Second, []uint16{
		0x001d, // X25519 — classical baseline, must be accepted
		0x11ec, // X25519MLKEM768 — PQC hybrid, should be accepted by Cloudflare
	})

	if len(results) == 0 {
		t.Fatal("DeepProbe returned no results")
	}

	byGroup := make(map[uint16]DeepProbeGroupResult, len(results))
	for _, r := range results {
		byGroup[r.GroupID] = r
		if r.Err != nil {
			t.Logf("group 0x%04x: error: %v", r.GroupID, r.Err)
			continue
		}
		t.Logf("group 0x%04x: outcome=%s selectedGroup=0x%04x alertDesc=%d", r.GroupID, r.Outcome, r.SelectedGroup, r.AlertDesc)
	}

	// X25519 must be accepted by any modern TLS 1.3 server.
	if r, ok := byGroup[0x001d]; ok && r.Err == nil && r.Outcome != OutcomeAccepted {
		t.Errorf("X25519 (0x001d): expected Accepted, got %s", r.Outcome)
	}

	// X25519MLKEM768 must be accepted or HRR-proposed by Cloudflare (PQC assertion).
	// Cloudflare has supported X25519MLKEM768 since 2024; OutcomeAlert or OutcomeError here
	// indicates a server-side regression or network issue worth investigating.
	if r, ok := byGroup[0x11ec]; ok && r.Err == nil {
		if r.Outcome != OutcomeAccepted && r.Outcome != OutcomeHRR {
			t.Errorf("X25519MLKEM768 (0x11ec): expected Accepted or HRR from Cloudflare, got %s", r.Outcome)
		}
	}
}

// TestBuildAndSendClientHello_Cloudflare verifies the full record framing and
// parse pipeline against a live TLS endpoint.
func TestBuildAndSendClientHello_Cloudflare(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	r := probeGroup(ctx, "1.1.1.1:443", "cloudflare.com", 10*time.Second, 0x001d)
	if r.Err != nil {
		t.Fatalf("probeGroup X25519: %v", r.Err)
	}
	if r.Outcome == OutcomeError {
		t.Fatalf("unexpected error outcome")
	}
	t.Logf("X25519 result: outcome=%s", r.Outcome)
}
