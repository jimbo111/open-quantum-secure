//go:build integration

package tlsprobe

import (
	"context"
	"testing"
	"time"
)

// TestEnumerateGroups_Cloudflare_S8 verifies the Sprint 8 group enumeration
// pipeline against a live TLS endpoint. Requires network: --tags=integration.
//
//	go test -tags=integration -run TestEnumerateGroups_Cloudflare_S8 ./pkg/engines/tlsprobe/
func TestEnumerateGroups_Cloudflare_S8(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()

	// 1.1.1.1 = Cloudflare's anycast IP; pre-resolved to satisfy the SSRF guard.
	result, err := enumerateGroups(ctx, "1.1.1.1:443", "cloudflare.com", 10*time.Second)
	if err != nil {
		t.Logf("enumerateGroups warning (partial result expected for unsupported groups): %v", err)
	}

	total := len(result.AcceptedGroups) + len(result.HRRGroups)
	if total < 2 {
		t.Errorf("expected ≥2 supported groups from Cloudflare, got %d (accepted=%v hrr=%v)",
			total, result.AcceptedGroups, result.HRRGroups)
	}

	// X25519MLKEM768 (0x11ec) must appear in AcceptedGroups or HRRGroups.
	x25519mlkem768Found := false
	for _, g := range result.AcceptedGroups {
		if g == 0x11ec {
			x25519mlkem768Found = true
		}
	}
	for _, g := range result.HRRGroups {
		if g == 0x11ec {
			x25519mlkem768Found = true
		}
	}
	if !x25519mlkem768Found {
		t.Errorf("X25519MLKEM768 (0x11ec) not found in AcceptedGroups=%v or HRRGroups=%v",
			result.AcceptedGroups, result.HRRGroups)
	}

	t.Logf("S8 Cloudflare group enum: accepted=%v hrr=%v rejected=%v",
		result.AcceptedGroups, result.HRRGroups, result.RejectedGroups)
}
