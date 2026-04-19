package tlsprobe

import (
	"context"
	"net"
	"testing"
	"time"
)

func TestDetectServerGroupPreference_TooFewGroups(t *testing.T) {
	// Fewer than 2 accepted groups → no preference to detect; returns 0, nil.
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
			pref, err := detectServerGroupPreference(context.Background(), "127.0.0.1:1", "", 5*time.Second, tc.groups)
			if err != nil {
				t.Errorf("unexpected error for %q: %v", tc.name, err)
			}
			if pref != 0 {
				t.Errorf("expected pref=0 for %q, got 0x%04x", tc.name, pref)
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

// sendMinimalServerHello writes a minimal ServerHello TLS record selecting groupID.
func sendMinimalServerHello(c net.Conn, groupID uint16) {
	// Use the same encoding as the rawhello test helpers, inlined here to avoid
	// importing the test-only helpers from the rawhello package.
	var random [32]byte
	random[0] = 0x42 // not HRRMagic — this is a real ServerHello

	// Build key_share extension data for ServerHello:
	//   group(2) + kex_len(2) + kex(1 dummy byte)
	ksData := []byte{
		byte(groupID >> 8), byte(groupID),
		0x00, 0x01, // kex_len = 1
		0x42, // dummy key material
	}

	// Extensions: supported_versions + key_share
	var exts []byte
	// supported_versions (0x002b): len=2, TLS 1.3
	exts = append(exts, 0x00, 0x2b, 0x00, 0x02, 0x03, 0x04)
	// key_share (0x0033)
	exts = append(exts, 0x00, 0x33)
	exts = append(exts, byte(len(ksData)>>8), byte(len(ksData)))
	exts = append(exts, ksData...)

	// ServerHello body:
	//   legacy_version(2) + random(32) + session_id_len(1) + cipher_suite(2) +
	//   compression(1) + extensions_len(2) + exts
	var body []byte
	body = append(body, 0x03, 0x03)   // legacy_version
	body = append(body, random[:]...)  // random
	body = append(body, 0x00)          // session_id_len = 0
	body = append(body, 0x13, 0x01)   // cipher suite TLS_AES_128_GCM_SHA256
	body = append(body, 0x00)          // compression = 0
	body = append(body, byte(len(exts)>>8), byte(len(exts)))
	body = append(body, exts...)

	// Handshake message: type(1) + length(3) + body
	msg := make([]byte, 4+len(body))
	msg[0] = 0x02 // ServerHello
	msg[1] = byte(len(body) >> 16)
	msg[2] = byte(len(body) >> 8)
	msg[3] = byte(len(body))
	copy(msg[4:], body)

	// TLS record header: type(1) + version(2) + len(2) + payload
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

func TestDetectServerGroupPreference_ServerChoosesGroup(t *testing.T) {
	// Server responds with ServerHello selecting X25519MLKEM768 (0x11ec).
	// detectServerGroupPreference should return 0x11ec.
	addr := newGroupEnumLocalServer(t, func(c net.Conn) {
		buf := make([]byte, 8192)
		c.SetReadDeadline(time.Now().Add(500 * time.Millisecond)) //nolint:errcheck
		c.Read(buf)                                                //nolint:errcheck
		sendMinimalServerHello(c, 0x11ec)
	})

	pref, err := detectServerGroupPreference(
		context.Background(), addr, "",
		5*time.Second,
		[]uint16{0x001d, 0x11ec}, // offer both classical and hybrid
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if pref != 0x11ec {
		t.Errorf("expected pref=0x11ec (X25519MLKEM768), got 0x%04x", pref)
	}
}

func TestDetectServerGroupPreference_AlertResponse(t *testing.T) {
	// Server sends Alert → returns pref=0 (no preference detected), no error.
	addr := newGroupEnumLocalServer(t, func(c net.Conn) {
		buf := make([]byte, 8192)
		c.SetReadDeadline(time.Now().Add(500 * time.Millisecond)) //nolint:errcheck
		c.Read(buf)                                                //nolint:errcheck
		sendAlertRecord(c)
	})

	pref, err := detectServerGroupPreference(
		context.Background(), addr, "",
		5*time.Second,
		[]uint16{0x001d, 0x11ec},
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if pref != 0 {
		t.Errorf("expected pref=0 for alert-only server, got 0x%04x", pref)
	}
}

func TestDetectServerGroupPreference_UnknownGroupsFiltered(t *testing.T) {
	// acceptedGroups includes an unknown codepoint (0xDEAD) that has no key share
	// size. It should be skipped; only the remaining groups are offered.
	// With only 1 valid group remaining the function returns 0.
	pref, err := detectServerGroupPreference(
		context.Background(), "127.0.0.1:1", "",
		100*time.Millisecond,
		[]uint16{0x001d, 0xDEAD}, // 0xDEAD has no key share size
	)
	// 0xDEAD is filtered out → only 1 valid group → return 0 early.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if pref != 0 {
		t.Errorf("expected pref=0 when only 1 valid group survives filter, got 0x%04x", pref)
	}
}
