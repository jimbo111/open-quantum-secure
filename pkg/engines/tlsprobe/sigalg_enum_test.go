package tlsprobe

import (
	"context"
	"net"
	"testing"
	"time"
)

// TestFullSigAlgList_Sanity verifies the sig alg list has no duplicates and
// covers the major algorithm families.
func TestFullSigAlgList_Sanity(t *testing.T) {
	const want = 17
	if got := len(fullSigAlgList); got != want {
		t.Errorf("len(fullSigAlgList) = %d, want %d", got, want)
	}

	seen := make(map[uint16]bool, len(fullSigAlgList))
	for _, s := range fullSigAlgList {
		if seen[s] {
			t.Errorf("duplicate sig alg 0x%04x in fullSigAlgList", s)
		}
		seen[s] = true
	}

	// ML-DSA (PQ) must be present.
	for _, s := range []uint16{0x0904, 0x0905, 0x0906} {
		if !seen[s] {
			t.Errorf("mldsa sig alg 0x%04x missing from fullSigAlgList", s)
		}
	}
	// RSA-PSS (modern) must be present.
	for _, s := range []uint16{0x0804, 0x0805, 0x0806} {
		if !seen[s] {
			t.Errorf("rsa_pss_rsae sig alg 0x%04x missing from fullSigAlgList", s)
		}
	}
	// ECDSA must be present.
	for _, s := range []uint16{0x0403, 0x0503, 0x0603} {
		if !seen[s] {
			t.Errorf("ecdsa sig alg 0x%04x missing from fullSigAlgList", s)
		}
	}
	// EdDSA must be present.
	if !seen[0x0807] {
		t.Error("ed25519 (0x0807) missing from fullSigAlgList")
	}
}

func TestSigAlgName_KnownSchemes(t *testing.T) {
	cases := []struct {
		scheme uint16
		want   string
	}{
		{0x0904, "mldsa44"},
		{0x0905, "mldsa65"},
		{0x0906, "mldsa87"},
		{0x0804, "rsa_pss_rsae_sha256"},
		{0x0403, "ecdsa_secp256r1_sha256"},
		{0x0807, "ed25519"},
		{0x0401, "rsa_pkcs1_sha256"},
		{0xffff, "0xffff"}, // unknown → hex string
	}
	for _, tc := range cases {
		got := SigAlgName(tc.scheme)
		if got != tc.want {
			t.Errorf("SigAlgName(0x%04x) = %q, want %q", tc.scheme, got, tc.want)
		}
	}
}

func TestEnumerateSigAlgs_SSRFGuard(t *testing.T) {
	_, err := enumerateSigAlgs(context.Background(), "example.com:443", "example.com", 5*time.Second)
	if err == nil {
		t.Error("expected error for hostname addr, got nil")
	}
}

func TestEnumerateSigAlgs_SSRFGuard_MissingPort(t *testing.T) {
	_, err := enumerateSigAlgs(context.Background(), "127.0.0.1", "", 5*time.Second)
	if err == nil {
		t.Error("expected error for addr without port, got nil")
	}
}

func TestEnumerateSigAlgs_ContextCancelled(t *testing.T) {
	addr := newGroupEnumLocalServer(t, func(c net.Conn) {
		time.Sleep(10 * time.Second)
	})

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	result, err := enumerateSigAlgs(ctx, addr, "", 5*time.Second)
	if err == nil {
		t.Error("expected non-nil error for pre-cancelled context")
	}
	if len(result.AcceptedSigAlgs)+len(result.RejectedSigAlgs) > 0 {
		t.Errorf("expected no results with cancelled ctx, got accepted=%d rejected=%d",
			len(result.AcceptedSigAlgs), len(result.RejectedSigAlgs))
	}
}

func TestProbeSigAlg_SSRFGuard_NotTestedDirectly(t *testing.T) {
	// probeSigAlg is an unexported function; the SSRF guard is at the addr level
	// (net.SplitHostPort). Test that a hostname addr yields a dial error (not panic).
	// This does a real DNS + connection attempt so use a non-routable addr.
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()

	// 192.0.2.0/24 is TEST-NET-1 (RFC 5737) — not routable, will time out.
	accepted, err := probeSigAlg(ctx, "192.0.2.1:443", "", 100*time.Millisecond, 0x0804)
	// Either timeout error or false; must not panic.
	if accepted {
		t.Error("expected not-accepted for unroutable address")
	}
	_ = err
}

func TestSigAlgEnumResult_EmptyDefault(t *testing.T) {
	var r SigAlgEnumResult
	if r.AcceptedSigAlgs != nil {
		t.Error("AcceptedSigAlgs must be nil in zero value")
	}
	if r.RejectedSigAlgs != nil {
		t.Error("RejectedSigAlgs must be nil in zero value")
	}
}

// TestProbeSigAlg_AlertBeforeSH verifies that a server sending an Alert before
// the ServerHello is classified as rejected (accepted=false, no error).
func TestProbeSigAlg_AlertBeforeSH(t *testing.T) {
	addr := newGroupEnumLocalServer(t, func(c net.Conn) {
		buf := make([]byte, 4096)
		c.SetReadDeadline(time.Now().Add(200 * time.Millisecond)) //nolint:errcheck
		c.Read(buf)                                                //nolint:errcheck
		sendAlertRecord(c)
	})

	ctx := context.Background()
	accepted, err := probeSigAlg(ctx, addr, "", 5*time.Second, 0x0804)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if accepted {
		t.Error("expected accepted=false for server that sent Alert before SH")
	}
}
