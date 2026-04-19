package tlsprobe

import (
	"context"
	"net"
	"sync/atomic"
	"testing"
	"time"
)

// sendMinimalServerHello writes a minimal TLS 1.3 ServerHello record selecting groupID.
func sendMinimalServerHello(c net.Conn, groupID uint16) {
	var random [32]byte
	random[0] = 0x42 // not HRRMagic — real ServerHello

	// key_share extension: group(2) + kex_len(2) + dummy kex(1)
	ksData := []byte{
		byte(groupID >> 8), byte(groupID),
		0x00, 0x01,
		0x42,
	}

	var exts []byte
	// supported_versions (0x002b): len=2, TLS 1.3 (0x0304)
	exts = append(exts, 0x00, 0x2b, 0x00, 0x02, 0x03, 0x04)
	// key_share (0x0033)
	exts = append(exts, 0x00, 0x33)
	exts = append(exts, byte(len(ksData)>>8), byte(len(ksData)))
	exts = append(exts, ksData...)

	var body []byte
	body = append(body, 0x03, 0x03)  // legacy_version
	body = append(body, random[:]...) // random
	body = append(body, 0x00)         // session_id_len=0
	body = append(body, 0x13, 0x01)  // TLS_AES_128_GCM_SHA256
	body = append(body, 0x00)         // compression=0
	body = append(body, byte(len(exts)>>8), byte(len(exts)))
	body = append(body, exts...)

	msg := make([]byte, 4+len(body))
	msg[0] = 0x02 // ServerHello
	msg[1] = byte(len(body) >> 16)
	msg[2] = byte(len(body) >> 8)
	msg[3] = byte(len(body))
	copy(msg[4:], body)

	rec := make([]byte, 5+len(msg))
	rec[0] = 0x16 // Handshake
	rec[1] = 0x03
	rec[2] = 0x03
	rec[3] = byte(len(msg) >> 8)
	rec[4] = byte(len(msg))
	copy(rec[5:], msg)

	c.SetWriteDeadline(time.Now().Add(500 * time.Millisecond)) //nolint:errcheck
	c.Write(rec)                                                //nolint:errcheck
}

func TestDetectServerGroupPreference_TooFewGroups(t *testing.T) {
	// Fewer than 2 accepted groups → indeterminate, no error, no dial attempt.
	cases := []struct {
		name   string
		groups []uint16
	}{
		{"nil", nil},
		{"empty", []uint16{}},
		{"single", []uint16{0x001d}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res, err := detectServerGroupPreference(context.Background(), "127.0.0.1:1", "", 5*time.Second, tc.groups)
			if err != nil {
				t.Errorf("unexpected error for %q: %v", tc.name, err)
			}
			if res.Mode != PrefIndeterminate {
				t.Errorf("expected mode=%q for %q, got %q", PrefIndeterminate, tc.name, res.Mode)
			}
			if res.PreferredGroup != 0 {
				t.Errorf("expected PreferredGroup=0 for %q, got 0x%04x", tc.name, res.PreferredGroup)
			}
		})
	}
}

func TestDetectServerGroupPreference_SSRFGuard(t *testing.T) {
	_, err := detectServerGroupPreference(context.Background(), "example.com:443", "example.com", 5*time.Second,
		[]uint16{0x001d, 0x11ec})
	if err == nil {
		t.Error("expected error for hostname addr, got nil")
	}
}

func TestDetectServerGroupPreference_SSRFGuard_MissingPort(t *testing.T) {
	_, err := detectServerGroupPreference(context.Background(), "127.0.0.1", "", 5*time.Second,
		[]uint16{0x001d, 0x11ec})
	if err == nil {
		t.Error("expected error for addr without port, got nil")
	}
}

func TestDetectServerGroupPreference_ServerFixed(t *testing.T) {
	// Server always selects 0x11ec regardless of the client ordering.
	// Both probes (forward [X25519, X25519MLKEM768] and reverse [X25519MLKEM768, X25519])
	// receive 0x11ec → mode=server-fixed.
	addr := newGroupEnumLocalServer(t, func(c net.Conn) {
		buf := make([]byte, 8192)
		c.SetReadDeadline(time.Now().Add(500 * time.Millisecond)) //nolint:errcheck
		c.Read(buf)                                                //nolint:errcheck
		sendMinimalServerHello(c, 0x11ec)
	})

	res, err := detectServerGroupPreference(
		context.Background(), addr, "",
		5*time.Second,
		[]uint16{0x001d, 0x11ec},
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.Mode != PrefServerFixed {
		t.Errorf("expected mode=%q, got %q", PrefServerFixed, res.Mode)
	}
	if res.PreferredGroup != 0x11ec {
		t.Errorf("expected PreferredGroup=0x11ec, got 0x%04x", res.PreferredGroup)
	}
}

func TestDetectServerGroupPreference_ClientOrder(t *testing.T) {
	// Server echoes the first group offered by the client.
	// Forward probe offers [0x001d, 0x11ec] → server selects 0x001d.
	// Reverse probe offers [0x11ec, 0x001d] → server selects 0x11ec.
	// They differ → mode=client-order.
	//
	// We simulate this by returning different groups on successive connections.
	var connCount atomic.Int32
	addr := newGroupEnumLocalServer(t, func(c net.Conn) {
		buf := make([]byte, 8192)
		c.SetReadDeadline(time.Now().Add(500 * time.Millisecond)) //nolint:errcheck
		c.Read(buf)                                                //nolint:errcheck
		n := connCount.Add(1)
		if n == 1 {
			// Forward probe response: first offered group = 0x001d.
			sendMinimalServerHello(c, 0x001d)
		} else {
			// Reverse probe response: first offered group = 0x11ec.
			sendMinimalServerHello(c, 0x11ec)
		}
	})

	res, err := detectServerGroupPreference(
		context.Background(), addr, "",
		5*time.Second,
		[]uint16{0x001d, 0x11ec},
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.Mode != PrefClientOrder {
		t.Errorf("expected mode=%q, got %q", PrefClientOrder, res.Mode)
	}
	// PreferredGroup = group from forward probe = 0x001d.
	if res.PreferredGroup != 0x001d {
		t.Errorf("expected PreferredGroup=0x001d, got 0x%04x", res.PreferredGroup)
	}
}

func TestDetectServerGroupPreference_AlertResponse(t *testing.T) {
	// Server sends Alert to both probes → indeterminate (PreferredGroup=0), no error.
	addr := newGroupEnumLocalServer(t, func(c net.Conn) {
		buf := make([]byte, 8192)
		c.SetReadDeadline(time.Now().Add(500 * time.Millisecond)) //nolint:errcheck
		c.Read(buf)                                                //nolint:errcheck
		sendAlertRecord(c)
	})

	res, err := detectServerGroupPreference(
		context.Background(), addr, "",
		5*time.Second,
		[]uint16{0x001d, 0x11ec},
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.Mode != PrefIndeterminate {
		t.Errorf("expected mode=%q for alert-only server, got %q", PrefIndeterminate, res.Mode)
	}
	if res.PreferredGroup != 0 {
		t.Errorf("expected PreferredGroup=0 for alert-only server, got 0x%04x", res.PreferredGroup)
	}
}

func TestDetectServerGroupPreference_UnknownGroupsFiltered(t *testing.T) {
	// acceptedGroups contains 0xDEAD which has no key share size.
	// After filtering, only 1 valid group remains → indeterminate without dialing.
	res, err := detectServerGroupPreference(
		context.Background(), "127.0.0.1:1", "",
		100*time.Millisecond,
		[]uint16{0x001d, 0xDEAD},
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.Mode != PrefIndeterminate {
		t.Errorf("expected mode=%q when only 1 valid group survives filter, got %q", PrefIndeterminate, res.Mode)
	}
}
