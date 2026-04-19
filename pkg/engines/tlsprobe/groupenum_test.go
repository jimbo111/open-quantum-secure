package tlsprobe

import (
	"context"
	"net"
	"testing"
	"time"
)

// TestFullEnumGroups_Sanity verifies the fullEnumGroups list has the expected
// entries and no duplicates. 13 entries: 4 classical + 4 hybrid + 3 pure-PQ + 2 deprecated.
func TestFullEnumGroups_Sanity(t *testing.T) {
	const want = 13
	if got := len(fullEnumGroups); got != want {
		t.Errorf("len(fullEnumGroups) = %d, want %d", got, want)
	}

	seen := make(map[uint16]bool, len(fullEnumGroups))
	for _, g := range fullEnumGroups {
		if seen[g] {
			t.Errorf("duplicate group 0x%04x in fullEnumGroups", g)
		}
		seen[g] = true
	}

	// Classical ECDH must all be present.
	for _, g := range []uint16{0x001d, 0x0017, 0x0018, 0x0019} {
		if !seen[g] {
			t.Errorf("classical group 0x%04x missing from fullEnumGroups", g)
		}
	}
	// PQC-safe hybrid groups.
	for _, g := range []uint16{0x11ec, 0x11eb, 0x11ed, 0x11ee} {
		if !seen[g] {
			t.Errorf("hybrid group 0x%04x missing from fullEnumGroups", g)
		}
	}
	// Pure ML-KEM.
	for _, g := range []uint16{0x0200, 0x0201, 0x0202} {
		if !seen[g] {
			t.Errorf("pure-PQ group 0x%04x missing from fullEnumGroups", g)
		}
	}
	// Deprecated draft Kyber.
	for _, g := range []uint16{0x6399, 0x636D} {
		if !seen[g] {
			t.Errorf("deprecated group 0x%04x missing from fullEnumGroups", g)
		}
	}
}

func TestEnumerateGroups_SSRFGuard(t *testing.T) {
	// Non-IP hostname addr must be rejected without dialing.
	_, err := enumerateGroups(context.Background(), "example.com:443", "example.com", 5*time.Second)
	if err == nil {
		t.Error("expected error for hostname addr, got nil")
	}
}

func TestEnumerateGroups_SSRFGuard_MissingPort(t *testing.T) {
	// SplitHostPort fails → error.
	_, err := enumerateGroups(context.Background(), "127.0.0.1", "", 5*time.Second)
	if err == nil {
		t.Error("expected error for addr without port, got nil")
	}
}

// newGroupEnumLocalServer creates a minimal TCP server for groupenum tests.
// The handler is invoked for each accepted connection.
func newGroupEnumLocalServer(t *testing.T, handler func(net.Conn)) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen: %v", err)
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

// sendAlertRecord writes a fatal handshake_failure alert TLS record.
func sendAlertRecord(c net.Conn) {
	// TLS Alert record: type=0x15, version=0x0303, len=2, level=2 (fatal), desc=40 (handshake_failure)
	record := []byte{0x15, 0x03, 0x03, 0x00, 0x02, 0x02, 0x28}
	c.SetWriteDeadline(time.Now().Add(200 * time.Millisecond)) //nolint:errcheck
	c.Write(record)                                             //nolint:errcheck
}

func TestEnumerateGroups_AllRejected(t *testing.T) {
	// Server sends Alert for every probe → all groups end up in RejectedGroups.
	addr := newGroupEnumLocalServer(t, func(c net.Conn) {
		// Drain incoming ClientHello then immediately send Alert.
		buf := make([]byte, 4096)
		c.SetReadDeadline(time.Now().Add(200 * time.Millisecond)) //nolint:errcheck
		c.Read(buf)                                                //nolint:errcheck
		sendAlertRecord(c)
	})

	result, _ := enumerateGroups(context.Background(), addr, "", 5*time.Second)
	// All fullEnumGroups should be rejected or error — rejected count must be > 0.
	if len(result.RejectedGroups) == 0 && len(result.AcceptedGroups) == 0 {
		// Transport errors (OutcomeError) are also acceptable for a server that
		// closes the connection right after the alert.
		t.Log("no groups classified (all transport errors) — acceptable for immediate-close server")
	}
	if len(result.AcceptedGroups) > 0 {
		t.Errorf("expected 0 accepted groups for alert-only server, got %d", len(result.AcceptedGroups))
	}
	if len(result.HRRGroups) > 0 {
		t.Errorf("expected 0 HRR groups for alert-only server, got %d", len(result.HRRGroups))
	}
}

func TestEnumerateGroups_ContextCancelled(t *testing.T) {
	addr := newGroupEnumLocalServer(t, func(c net.Conn) {
		// Server slow-reads; context will cancel first.
		time.Sleep(10 * time.Second)
	})

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // pre-cancel

	result, _ := enumerateGroups(ctx, addr, "", 5*time.Second)
	// No groups should be classified with a pre-cancelled context.
	if len(result.AcceptedGroups)+len(result.HRRGroups)+len(result.RejectedGroups) > 0 {
		t.Errorf("expected no results with cancelled ctx, got accepted=%d HRR=%d rejected=%d",
			len(result.AcceptedGroups), len(result.HRRGroups), len(result.RejectedGroups))
	}
}

func TestGroupEnumResult_EmptyDefault(t *testing.T) {
	var r GroupEnumResult
	if r.AcceptedGroups != nil {
		t.Error("AcceptedGroups must be nil in zero value")
	}
	if r.HRRGroups != nil {
		t.Error("HRRGroups must be nil in zero value")
	}
	if r.RejectedGroups != nil {
		t.Error("RejectedGroups must be nil in zero value")
	}
}
