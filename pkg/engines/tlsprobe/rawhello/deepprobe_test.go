package rawhello

import (
	"context"
	"net"
	"testing"
	"time"
)

func TestGroupOutcome_String(t *testing.T) {
	cases := []struct {
		o    GroupOutcome
		want string
	}{
		{OutcomeAccepted, "accepted"},
		{OutcomeHRR, "hrr"},
		{OutcomeAlert, "alert"},
		{OutcomeError, "error"},
		{GroupOutcome(99), "error"}, // unknown falls through to default
	}
	for _, tc := range cases {
		got := tc.o.String()
		if got != tc.want {
			t.Errorf("GroupOutcome(%d).String(): got %q want %q", tc.o, got, tc.want)
		}
	}
}

// newLocalServer creates a local TCP listener; handler is called per accepted
// connection. t.Cleanup closes the listener.
func newLocalServer(t *testing.T, handler func(net.Conn)) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("newLocalServer: listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				handler(c)
			}()
		}
	}()
	return ln.Addr().String()
}

// drainAndSend discards incoming bytes then calls write.
func drainAndSend(c net.Conn, write func(net.Conn)) {
	buf := make([]byte, 4096)
	c.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
	c.Read(buf) //nolint:errcheck
	write(c)
}

func TestDeepProbe_Accepted(t *testing.T) {
	ctx := context.Background()
	var zero [32]byte
	zero[0] = 0x42 // not HRR magic

	addr := newLocalServer(t, func(c net.Conn) {
		drainAndSend(c, func(c net.Conn) {
			sendServerHello(c, ctx, zero, 0x1301, 0x001d, false)
		})
	})

	results := DeepProbe(ctx, addr, "", 5*time.Second, []uint16{0x001d})
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	r := results[0]
	if r.Err != nil {
		t.Fatalf("unexpected error: %v", r.Err)
	}
	if r.Outcome != OutcomeAccepted {
		t.Errorf("outcome: got %s want accepted", r.Outcome)
	}
	if r.GroupID != 0x001d {
		t.Errorf("GroupID: got 0x%04x want 0x001d", r.GroupID)
	}
	if r.SelectedGroup != 0x001d {
		t.Errorf("SelectedGroup: got 0x%04x want 0x001d (server key_share group)", r.SelectedGroup)
	}
}

func TestDeepProbe_HRR(t *testing.T) {
	ctx := context.Background()

	addr := newLocalServer(t, func(c net.Conn) {
		drainAndSend(c, func(c net.Conn) {
			sendServerHello(c, ctx, HRRMagic, 0x1302, 0x11ec, true)
		})
	})

	results := DeepProbe(ctx, addr, "", 5*time.Second, []uint16{0x11ec})
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	r := results[0]
	if r.Err != nil {
		t.Fatalf("unexpected error: %v", r.Err)
	}
	if r.Outcome != OutcomeHRR {
		t.Errorf("outcome: got %s want hrr", r.Outcome)
	}
	// F1: HRR selected_group must be carried back so callers know which PQC group
	// the server is willing to accept on retry.
	if r.SelectedGroup != 0x11ec {
		t.Errorf("SelectedGroup: got 0x%04x want 0x11ec (X25519MLKEM768)", r.SelectedGroup)
	}
}

func TestDeepProbe_Alert(t *testing.T) {
	ctx := context.Background()

	addr := newLocalServer(t, func(c net.Conn) {
		drainAndSend(c, func(c net.Conn) {
			WriteRecord(ctx, c, Record{ //nolint:errcheck
				Type:    RecordTypeAlert,
				Version: LegacyRecordVersion,
				Payload: []byte{0x02, 0x28}, // fatal handshake_failure
			})
		})
	})

	results := DeepProbe(ctx, addr, "", 5*time.Second, []uint16{0x001d})
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	r := results[0]
	if r.Err != nil {
		t.Fatalf("unexpected error: %v", r.Err)
	}
	if r.Outcome != OutcomeAlert {
		t.Errorf("outcome: got %s want alert", r.Outcome)
	}
	if r.AlertDesc != 0x28 {
		t.Errorf("AlertDesc: got 0x%02x want 0x28", r.AlertDesc)
	}
}

func TestDeepProbe_ConnRefused(t *testing.T) {
	// Use a port that is not listening.
	ctx := context.Background()
	results := DeepProbe(ctx, "127.0.0.1:1", "", 500*time.Millisecond, []uint16{0x001d})
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	if results[0].Outcome != OutcomeError {
		t.Errorf("outcome: got %s want error", results[0].Outcome)
	}
	if results[0].Err == nil {
		t.Error("expected non-nil Err for refused connection")
	}
}

func TestDeepProbe_UnknownGroup(t *testing.T) {
	// Group 0xDEAD has no key share size mapping → OutcomeError.
	ctx := context.Background()
	addr := newLocalServer(t, func(c net.Conn) {})

	results := DeepProbe(ctx, addr, "", 5*time.Second, []uint16{0xDEAD})
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	if results[0].Outcome != OutcomeError {
		t.Errorf("outcome: got %s want error", results[0].Outcome)
	}
}

func TestDeepProbe_ContextAlreadyCancelled(t *testing.T) {
	addr := newLocalServer(t, func(c net.Conn) {})
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel before calling

	results := DeepProbe(ctx, addr, "", 5*time.Second, []uint16{0x001d, 0x11ec})
	// All groups should be skipped due to cancelled context.
	if len(results) != 0 {
		t.Errorf("expected 0 results with cancelled ctx, got %d", len(results))
	}
}

func TestDeepProbe_MultipleGroups(t *testing.T) {
	// Two groups — verify sequential probing and independent results.
	ctx := context.Background()
	var zero [32]byte
	zero[0] = 0x42

	addr := newLocalServer(t, func(c net.Conn) {
		drainAndSend(c, func(c net.Conn) {
			sendServerHello(c, ctx, zero, 0x1301, 0x001d, false)
		})
	})

	groups := []uint16{0x001d, 0x11ec}
	results := DeepProbe(ctx, addr, "", 5*time.Second, groups)
	if len(results) != 2 {
		t.Fatalf("expected 2 results, got %d", len(results))
	}
	for i, r := range results {
		if r.GroupID != groups[i] {
			t.Errorf("result[%d].GroupID: got 0x%04x want 0x%04x", i, r.GroupID, groups[i])
		}
	}
}

func TestDeepProbe_EmptyGroupList(t *testing.T) {
	ctx := context.Background()
	results := DeepProbe(ctx, "127.0.0.1:1", "", 5*time.Second, []uint16{})
	if len(results) != 0 {
		t.Errorf("expected 0 results for empty group list, got %d", len(results))
	}
}

func TestProbeGroup_SSRFGuard(t *testing.T) {
	// addr is a hostname, not an IP literal — must return OutcomeError without dialing.
	ctx := context.Background()
	r := probeGroup(ctx, "example.com:443", "", 5*time.Second, 0x001d)
	if r.Outcome != OutcomeError {
		t.Errorf("outcome: got %s want error for hostname addr", r.Outcome)
	}
	if r.Err == nil {
		t.Error("expected non-nil Err for hostname addr")
	}
}

func TestProbeGroup_SSRFGuard_IPv6(t *testing.T) {
	// Valid IPv6 literal — SSRF guard should pass (dial will fail with connect
	// error, but not the SSRF guard error).
	ctx := context.Background()
	r := probeGroup(ctx, "[::1]:1", "", 200*time.Millisecond, 0xDEAD) // unknown group → ProbeKeyShare error
	// The SSRF guard must not fire; failure mode will be ProbeKeyShare/dial.
	if r.Outcome == OutcomeError && r.Err != nil {
		if r.Err.Error() == "probeGroup: addr \"[::1]:1\" must be a pre-resolved IP:port, not a hostname" {
			t.Error("SSRF guard incorrectly rejected valid IPv6 literal")
		}
	}
}

func TestProbeGroup_ServerClosesImmediately(t *testing.T) {
	// Server closes without sending anything → transport error (OutcomeError).
	addr := newLocalServer(t, func(c net.Conn) {
		// Close immediately, no response.
	})
	ctx := context.Background()
	r := probeGroup(ctx, addr, "", 5*time.Second, 0x001d)
	if r.Outcome != OutcomeError {
		t.Errorf("outcome: got %s want error", r.Outcome)
	}
}
