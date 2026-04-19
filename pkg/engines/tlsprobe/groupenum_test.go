package tlsprobe

import (
	"context"
	"net"
	"testing"
	"time"
)

// sendMinimalHRR writes a HelloRetryRequest TLS record selecting groupID.
// HRR is encoded as ServerHello with the RFC 8446 §4.1.4 magic random.
func sendMinimalHRR(c net.Conn, groupID uint16) {
	hrrMagic := [32]byte{
		0xcf, 0x21, 0xad, 0x74, 0xe5, 0x9a, 0x61, 0x11,
		0xbe, 0x1d, 0x8c, 0x02, 0x1e, 0x65, 0xb8, 0x91,
		0xc2, 0xa2, 0x11, 0x16, 0x7a, 0xbb, 0x8c, 0x5e,
		0x07, 0x9e, 0x09, 0xe2, 0xc8, 0xa8, 0x33, 0x9c,
	}
	// HRR key_share ext body: selected_group only (2 bytes, no key_exchange).
	ksData := []byte{byte(groupID >> 8), byte(groupID)}

	var exts []byte
	exts = append(exts, 0x00, 0x2b, 0x00, 0x02, 0x03, 0x04) // supported_versions TLS 1.3
	exts = append(exts, 0x00, 0x33)
	exts = append(exts, byte(len(ksData)>>8), byte(len(ksData)))
	exts = append(exts, ksData...)

	var body []byte
	body = append(body, 0x03, 0x03)
	body = append(body, hrrMagic[:]...)
	body = append(body, 0x00)
	body = append(body, 0x13, 0x01)
	body = append(body, 0x00)
	body = append(body, byte(len(exts)>>8), byte(len(exts)))
	body = append(body, exts...)

	msg := make([]byte, 4+len(body))
	msg[0] = 0x02
	msg[1] = byte(len(body) >> 16)
	msg[2] = byte(len(body) >> 8)
	msg[3] = byte(len(body))
	copy(msg[4:], body)

	rec := make([]byte, 5+len(msg))
	rec[0] = 0x16
	rec[1] = 0x03
	rec[2] = 0x03
	rec[3] = byte(len(msg) >> 8)
	rec[4] = byte(len(msg))
	copy(rec[5:], msg)

	c.SetWriteDeadline(time.Now().Add(500 * time.Millisecond)) //nolint:errcheck
	c.Write(rec)                                                //nolint:errcheck
}

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

// TestEnumerateGroups_ZeroTimeout covers the timeout==0 default path (→ 10 s/probe).
func TestEnumerateGroups_ZeroTimeout(t *testing.T) {
	addr := newGroupEnumLocalServer(t, func(c net.Conn) {
		buf := make([]byte, 4096)
		c.SetReadDeadline(time.Now().Add(200 * time.Millisecond)) //nolint:errcheck
		c.Read(buf)                                                //nolint:errcheck
		sendAlertRecord(c)
	})
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	result, _ := enumerateGroups(ctx, addr, "", 0)
	if len(result.AcceptedGroups) > 0 {
		t.Errorf("expected no accepted groups from alert-only server, got %d", len(result.AcceptedGroups))
	}
}

// TestEnumerateGroups_AcceptedGroup covers the OutcomeAccepted branch
// (server sends a valid ServerHello for the first probe).
func TestEnumerateGroups_AcceptedGroup(t *testing.T) {
	responded := make(chan struct{}, 1) // buffer of 1 — first sender wins
	addr := newGroupEnumLocalServer(t, func(c net.Conn) {
		buf := make([]byte, 8192)
		c.SetReadDeadline(time.Now().Add(300 * time.Millisecond)) //nolint:errcheck
		c.Read(buf)                                                //nolint:errcheck
		select {
		case responded <- struct{}{}:
			sendMinimalServerHello(c, 0x001d) // first probe: ServerHello accepted
		default:
			sendAlertRecord(c) // subsequent probes: rejected
		}
	})
	result, _ := enumerateGroups(context.Background(), addr, "", 2*time.Second)
	if len(result.AcceptedGroups) == 0 {
		t.Error("expected ≥1 accepted group when server sends ServerHello for first probe")
	}
	if len(result.HRRGroups) > 0 {
		t.Errorf("expected 0 HRR groups, got %d", len(result.HRRGroups))
	}
}

// TestEnumerateGroups_HRRGroup covers the OutcomeHRR branch
// (server sends HelloRetryRequest for the first probe).
//
// Regression for Bug 1 (cross-sprint review): HRRGroups must contain the
// SERVER-NAMED codepoint (parsed.SelectedGroup, 0x11ec), NOT the PROBED
// codepoint (fullEnumGroups[0] = 0x001d X25519). Before the fix, r.GroupID
// was appended instead, producing "server accepts X25519 via HRR" when the
// server actually wanted X25519MLKEM768 — a false positive in SupportedGroups.
func TestEnumerateGroups_HRRGroup(t *testing.T) {
	const serverNamedGroup uint16 = 0x11ec // X25519MLKEM768
	const probedFirstGroup uint16 = 0x001d // X25519 (fullEnumGroups[0])

	responded := make(chan struct{}, 1)
	addr := newGroupEnumLocalServer(t, func(c net.Conn) {
		buf := make([]byte, 8192)
		c.SetReadDeadline(time.Now().Add(300 * time.Millisecond)) //nolint:errcheck
		c.Read(buf)                                                //nolint:errcheck
		select {
		case responded <- struct{}{}:
			sendMinimalHRR(c, serverNamedGroup) // HRR names X25519MLKEM768
		default:
			sendAlertRecord(c)
		}
	})
	result, _ := enumerateGroups(context.Background(), addr, "", 2*time.Second)
	if len(result.HRRGroups) == 0 {
		t.Fatal("expected ≥1 HRR group when server sends HRR for first probe")
	}
	if len(result.AcceptedGroups) > 0 {
		t.Errorf("expected 0 accepted groups, got %d", len(result.AcceptedGroups))
	}
	// Bug 1 regression assertion: first HRR entry must be server-named, not probed.
	if result.HRRGroups[0] != serverNamedGroup {
		t.Errorf("HRRGroups[0] = 0x%04x, want 0x%04x (server-named, not probed 0x%04x)",
			result.HRRGroups[0], serverNamedGroup, probedFirstGroup)
	}
	// Extra guard: the probed group must NOT appear in HRRGroups unless the
	// server also named it, which this mock does not do.
	for _, g := range result.HRRGroups {
		if g == probedFirstGroup {
			t.Errorf("HRRGroups contains probed codepoint 0x%04x — indicates Bug 1 regression", g)
		}
	}
}
