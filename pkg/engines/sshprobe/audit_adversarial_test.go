package sshprobe

// audit_adversarial_test.go — T5-network audit (2026-04-20).
//
// Supplements adversarial_server_test.go with scenarios not covered there:
// SSH-1.x rejection, control chars in banner, empty payload, zero padding-length.
// All scenarios use a loopback TCP listener with an ephemeral port.

import (
	"bytes"
	"encoding/binary"
	"net"
	"testing"
	"time"
)

// newAuditListener is a small helper that mirrors serveOnce() from the
// adversarial_server_test.go file to keep this test file independent.
func newAuditListener(t *testing.T, handler func(net.Conn)) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
			go func(c net.Conn) {
				defer c.Close()
				handler(c)
			}(conn)
		}
	}()
	return ln.Addr().String()
}

// TestAuditSSH_SSH1xBannerRejected verifies that an SSH-1.5 banner is rejected
// (only SSH-2.0 and SSH-1.99 are acceptable per probe.go:93).
func TestAuditSSH_SSH1xBannerRejected(t *testing.T) {
	t.Parallel()

	addr := newAuditListener(t, func(conn net.Conn) {
		_, _ = conn.Write([]byte("SSH-1.5-LegacyDropbear\r\n"))
		// Keep the connection open long enough for the probe to reject.
		time.Sleep(1 * time.Second)
	})

	result := probeSSH(t.Context(), addr, 2*time.Second, false)
	if result.Error == nil {
		t.Error("expected error for SSH-1.5 banner")
	}
}

// TestAuditSSH_BannerWithControlCharsRejected verifies that a banner
// containing a bare \x00 byte (non-printable US-ASCII) is rejected by the
// B1 validation in readBannerWithPreamble.
func TestAuditSSH_BannerWithControlCharsRejected(t *testing.T) {
	t.Parallel()

	addr := newAuditListener(t, func(conn net.Conn) {
		// Valid-looking banner containing a NUL byte in the middle.
		_, _ = conn.Write([]byte("SSH-2.0-OpenSSH\x009.0\r\n"))
		time.Sleep(1 * time.Second)
	})

	result := probeSSH(t.Context(), addr, 2*time.Second, false)
	if result.Error == nil {
		t.Error("expected error for banner with NUL byte")
	}
}

// TestAuditSSH_ZeroPaddingLengthPacket sends a KEXINIT packet with
// padding_length = 0 (minimum possible). payloadLen = pkt_len - 1 - 0 must be
// non-negative. The parser must either accept and decode, or return a clean
// error — no panic.
func TestAuditSSH_ZeroPaddingLengthPacket(t *testing.T) {
	t.Parallel()

	// Build a minimal payload (KEXINIT type byte + 16-byte cookie + 10 empty
	// name-lists + boolean + reserved uint32).
	payload := make([]byte, 0, 64)
	payload = append(payload, 20) // SSH_MSG_KEXINIT
	payload = append(payload, bytes.Repeat([]byte{0}, 16)...)
	for i := 0; i < 10; i++ {
		payload = append(payload, 0, 0, 0, 0) // empty name-list (length 0)
	}
	payload = append(payload, 0)             // first_kex_packet_follows
	payload = append(payload, 0, 0, 0, 0)    // reserved

	// Packet: packet_length(4) + padding_length(1) + payload + padding.
	// padding_length = 0 so pktLen = 1 + len(payload).
	pktLen := uint32(1 + len(payload))
	hdr := make([]byte, 4)
	binary.BigEndian.PutUint32(hdr, pktLen)
	body := []byte{0}              // padding_length = 0
	body = append(body, payload...) // no padding bytes after

	full := append(hdr, body...)

	addr := newAuditListener(t, func(conn net.Conn) {
		_, _ = conn.Write([]byte("SSH-2.0-AuditZeroPad_1.0\r\n"))
		buf := make([]byte, 512)
		_, _ = conn.Read(buf)
		_, _ = conn.Write(full)
	})

	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("probe panicked on zero-padding packet: %v", r)
		}
	}()
	_ = probeSSH(t.Context(), addr, 3*time.Second, false)
}

// TestAuditSSH_MaxPaddingLengthPacket sends a KEXINIT packet with
// padding_length greater than packet_length - 1, which should be rejected by
// the bounds check in readPacket.
func TestAuditSSH_MaxPaddingLengthPacket(t *testing.T) {
	t.Parallel()

	// pktLen = 10, padding_length = 255 → payloadLen = 10 - 1 - 255 = -246 (rejected).
	hdr := make([]byte, 4)
	binary.BigEndian.PutUint32(hdr, 10)
	body := make([]byte, 10)
	body[0] = 255 // padding_length
	full := append(hdr, body...)

	addr := newAuditListener(t, func(conn net.Conn) {
		_, _ = conn.Write([]byte("SSH-2.0-AuditMaxPad_1.0\r\n"))
		buf := make([]byte, 512)
		_, _ = conn.Read(buf)
		_, _ = conn.Write(full)
	})

	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("probe panicked on max-padding packet: %v", r)
		}
	}()
	result := probeSSH(t.Context(), addr, 3*time.Second, false)
	if result.Error == nil {
		t.Error("expected error for padding_length=255 when pkt_len=10")
	}
}

// TestAuditSSH_EmptyPayloadPacket sends packet_length=2 with padding_length=1
// (empty payload, 1 pad byte). The probe should read it as an empty payload
// and skip it (continue looking for KEXINIT).
func TestAuditSSH_EmptyPayloadPacket(t *testing.T) {
	t.Parallel()

	hdr := make([]byte, 4)
	binary.BigEndian.PutUint32(hdr, 2) // packet_length
	body := []byte{1, 0xAA}            // padding_length=1, 1 pad byte
	full := append(hdr, body...)

	addr := newAuditListener(t, func(conn net.Conn) {
		_, _ = conn.Write([]byte("SSH-2.0-AuditEmptyPayload_1.0\r\n"))
		buf := make([]byte, 512)
		_, _ = conn.Read(buf)
		// Send 3 empty packets to exhaust the 2-packet skip budget.
		for i := 0; i < 3; i++ {
			_, _ = conn.Write(full)
		}
	})

	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("probe panicked on empty payload: %v", r)
		}
	}()
	result := probeSSH(t.Context(), addr, 3*time.Second, false)
	if result.Error == nil {
		t.Error("expected error when KEXINIT never arrives — only empty packets")
	}
}
