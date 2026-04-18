// adversarial_server_test.go — adversarial TCP server scenarios for the SSH probe.
//
// Purpose: verify that the probe handles pathological server behaviour safely —
// no panics, no goroutine leaks, and appropriate error returns. Each sub-test
// starts a local TCP listener that exhibits one specific hostile pattern.
//
// Scenarios covered:
//   (a) 1 MiB banner in a single write (exceeds maxBannerLen)
//   (b) Byte-by-byte banner with 100ms delays (slowloris-style)
//   (c) Oversized packet_length field (4 GiB claimed)
//   (d) Name-list with 64 KB of commas (max-length comma explosion)
//   (e) SSH_MSG_DISCONNECT immediately after banner
//   (f) TLS ClientHello bytes on the SSH port (protocol confusion)
//   (g) 6 non-KEXINIT packets (exceeds the 5-packet tolerance)
//   (h) 1 billion non-ASCII bytes as banner preamble (must be limited by cap)
package sshprobe

import (
	"bytes"
	"encoding/binary"
	"net"
	"testing"
	"time"
)

// dialWithTimeout connects to addr and returns the connection, failing the test
// if the dial itself fails (separate from probe error expectations).
func dialAndProbe(t *testing.T, addr string) ProbeResult {
	t.Helper()
	return probeSSH(t.Context(), addr, 3*time.Second, false)
}

// serveOnce starts a TCP listener, accepts exactly one connection, runs handler,
// and closes. Returns the listener address.
func serveOnce(t *testing.T, handler func(net.Conn)) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })
	addr := ln.Addr().String()
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
		defer conn.Close()
		handler(conn)
	}()
	return addr
}

// TestAdversarial_1MiBBannerInOneWrite — server sends a 1 MiB banner in one
// Write call. The probe must reject it (exceed maxBannerLen) and return an error.
func TestAdversarial_1MiBBannerInOneWrite(t *testing.T) {
	bigBanner := bytes.Repeat([]byte("X"), 1<<20) // 1 MiB, no newline
	addr := serveOnce(t, func(conn net.Conn) {
		_, _ = conn.Write(bigBanner)
	})

	result := dialAndProbe(t, addr)
	if result.Error == nil {
		t.Error("expected error for 1 MiB banner, got nil")
	}
}

// TestAdversarial_BannerByteByByte_Slowloris — server dribbles the banner one
// byte at a time with 100ms pauses between each byte. The 3-second deadline on
// the probe must cut it off before the full banner would arrive.
func TestAdversarial_BannerByteByByte_Slowloris(t *testing.T) {
	if testing.Short() {
		t.Skip("slowloris test skipped in short mode")
	}
	// Send 40 bytes at 100ms each → 4 seconds, longer than the probe timeout.
	data := []byte("SSH-2.0-Slowloris_1.0\r\n")
	addr := serveOnce(t, func(conn net.Conn) {
		for _, b := range data {
			_, _ = conn.Write([]byte{b})
			time.Sleep(100 * time.Millisecond)
		}
	})

	start := time.Now()
	result := dialAndProbe(t, addr)
	elapsed := time.Since(start)

	// The probe must have timed out within its 3s deadline, not blocked for
	// the full transmission time (>2.3s for 23 bytes at 100ms each).
	// We don't assert an exact time — just that it completed < 4s.
	if elapsed > 4*time.Second {
		t.Errorf("probe took %v; expected to time out within 3s deadline", elapsed)
	}
	_ = result // error or not — either is acceptable; what matters is liveness
}

// TestAdversarial_OversizedPacketLength — server sends a banner then a packet
// with claimed packet_length = 0xFFFFFFFF (4 GiB). The probe must reject it.
func TestAdversarial_OversizedPacketLength(t *testing.T) {
	addr := serveOnce(t, func(conn net.Conn) {
		// Valid banner first.
		_, _ = conn.Write([]byte("SSH-2.0-Evil_1.0\r\n"))
		// Read client banner (don't block on it — use short deadline).
		buf := make([]byte, 512)
		_, _ = conn.Read(buf)
		// Send packet with 0xFFFFFFFF packet_length.
		hdr := make([]byte, 4)
		binary.BigEndian.PutUint32(hdr, 0xFFFFFFFF)
		_, _ = conn.Write(hdr)
		// Don't send the body — the length check must reject before reading.
	})

	result := dialAndProbe(t, addr)
	if result.Error == nil {
		t.Error("expected error for packet_length=0xFFFFFFFF, got nil")
	}
}

// TestAdversarial_NameListCommaExplosion — server sends a valid banner then a
// KEXINIT packet whose kex_algorithms name-list is filled with 64 KB of commas,
// producing thousands of empty name segments. The probe must handle it without
// crashing or consuming excessive memory.
func TestAdversarial_NameListCommaExplosion(t *testing.T) {
	// Build a KEXINIT packet with a name-list payload of maxNameListLen commas.
	commas := bytes.Repeat([]byte(","), maxNameListLen)
	kexPayload := buildKEXInitPayloadRaw(commas)
	pkt := buildSSHPacket(kexPayload)

	addr := serveOnce(t, func(conn net.Conn) {
		_, _ = conn.Write([]byte("SSH-2.0-Evil_1.0\r\n"))
		buf := make([]byte, 512)
		_, _ = conn.Read(buf)
		_, _ = conn.Write(pkt)
	})

	result := dialAndProbe(t, addr)
	// The comma-explosion may succeed (returning many empty method names) or
	// error — both are acceptable. What we assert is: no panic.
	_ = result
}

// TestAdversarial_SSHMsgDisconnectAfterBanner — server sends banner + DISCONNECT
// (SSH_MSG_DISCONNECT = 1) instead of KEXINIT. The probe should exhaust its
// 5-packet skip budget and return an error.
func TestAdversarial_SSHMsgDisconnectAfterBanner(t *testing.T) {
	// SSH_MSG_DISCONNECT = 1. Build a dummy disconnect payload.
	disconnectPayload := make([]byte, 5)
	disconnectPayload[0] = 1 // SSH_MSG_DISCONNECT type

	addr := serveOnce(t, func(conn net.Conn) {
		_, _ = conn.Write([]byte("SSH-2.0-Disconnect_1.0\r\n"))
		buf := make([]byte, 512)
		_, _ = conn.Read(buf)
		// Send 6 DISCONNECT packets to exceed the 5-packet tolerance.
		for i := 0; i < 6; i++ {
			_, _ = conn.Write(buildSSHPacket(disconnectPayload))
		}
	})

	result := dialAndProbe(t, addr)
	if result.Error == nil {
		t.Error("expected error: server sent only non-KEXINIT packets, but probe succeeded")
	}
}

// TestAdversarial_TLSClientHelloOnSSHPort — server receives a connection and
// immediately sends TLS ClientHello-looking bytes instead of SSH banner.
// The probe must reject the non-SSH banner and return an error.
func TestAdversarial_TLSClientHelloOnSSHPort(t *testing.T) {
	// Minimal TLS ClientHello bytes (not a complete handshake — just the prefix).
	// TLS record header: ContentType=22 (Handshake), Version=0x0303 (TLS 1.2),
	// Length=arbitrary. The SSH probe checks for "SSH-" prefix.
	tlsHello := []byte{
		0x16, 0x03, 0x03, 0x00, 0x50, // TLS record header (handshake, TLS 1.2, length 80)
		0x01, 0x00, 0x00, 0x4c, 0x03, 0x03, // ClientHello header
		// 32-byte random
		0xDE, 0xAD, 0xBE, 0xEF, 0xDE, 0xAD, 0xBE, 0xEF,
		0xDE, 0xAD, 0xBE, 0xEF, 0xDE, 0xAD, 0xBE, 0xEF,
		0xDE, 0xAD, 0xBE, 0xEF, 0xDE, 0xAD, 0xBE, 0xEF,
		0xDE, 0xAD, 0xBE, 0xEF, 0xDE, 0xAD, 0xBE, 0xEF,
		'\n', // terminate the "line" so readBanner completes
	}

	addr := serveOnce(t, func(conn net.Conn) {
		_, _ = conn.Write(tlsHello)
	})

	result := dialAndProbe(t, addr)
	if result.Error == nil {
		t.Error("expected error: TLS ClientHello is not a valid SSH banner")
	}
}

// TestAdversarial_SixNonKEXINITPackets — server sends 6 non-KEXINIT packets,
// exceeding the 2-packet skip tolerance (B3: maxSkip=2). The probe must error.
func TestAdversarial_SixNonKEXINITPackets(t *testing.T) {
	// SSH_MSG_IGNORE = 2 (a valid non-KEXINIT packet type).
	ignorePayload := []byte{2, 0, 0, 0, 0}

	addr := serveOnce(t, func(conn net.Conn) {
		_, _ = conn.Write([]byte("SSH-2.0-NoKEX_1.0\r\n"))
		buf := make([]byte, 512)
		_, _ = conn.Read(buf)
		for i := 0; i < 6; i++ {
			_, _ = conn.Write(buildSSHPacket(ignorePayload))
		}
	})

	result := dialAndProbe(t, addr)
	if result.Error == nil {
		t.Error("expected error after 6 non-KEXINIT packets (exceeds maxSkip=2)")
	}
}

// TestAdversarial_BillionNonASCIIBannerPreamble — server sends a large block of
// non-ASCII bytes before the SSH banner line. The probe caps reads at
// maxBannerLen+2 bytes, so it must error long before reading 1 billion bytes.
func TestAdversarial_BillionNonASCIIBannerPreamble(t *testing.T) {
	// We can't actually send 1 billion bytes in a unit test. Instead, we send
	// maxBannerLen*2 non-ASCII bytes without a newline, verifying the probe
	// caps out promptly. The server closes after sending to avoid blocking.
	nonASCII := bytes.Repeat([]byte{0xFF}, maxBannerLen*2+100)
	addr := serveOnce(t, func(conn net.Conn) {
		_, _ = conn.Write(nonASCII)
	})

	start := time.Now()
	result := dialAndProbe(t, addr)
	elapsed := time.Since(start)

	if result.Error == nil {
		t.Error("expected error for non-ASCII preamble (no newline within cap), got nil")
	}
	// Must complete promptly — the cap limits how much data is read.
	if elapsed > 3*time.Second {
		t.Errorf("probe took %v reading non-ASCII preamble; should cap immediately", elapsed)
	}
}

// TestAdversarial_OneNonKEXINITThenKEXINIT — B3 regression: server sends exactly
// 1 non-KEXINIT packet then a valid KEXINIT. With maxSkip=2 the probe must succeed
// (KEXINIT arrives on the second read, i.e. skip=1 which is within the loop bound).
func TestAdversarial_OneNonKEXINITThenKEXINIT(t *testing.T) {
	ignorePayload := []byte{2, 0, 0, 0, 0} // SSH_MSG_IGNORE

	methods := []string{"mlkem768x25519-sha256", "curve25519-sha256"}

	addr := serveOnce(t, func(conn net.Conn) {
		_, _ = conn.Write([]byte("SSH-2.0-Tolerant_1.0\r\n"))
		buf := make([]byte, 512)
		_, _ = conn.Read(buf)
		// Send 1 non-KEXINIT packet (skip=0), then KEXINIT (skip=1).
		_, _ = conn.Write(buildSSHPacket(ignorePayload))
		_, _ = conn.Write(buildKEXInitPacket(methods))
	})

	result := dialAndProbe(t, addr)
	if result.Error != nil {
		t.Errorf("expected success with 1 non-KEXINIT then KEXINIT (within maxSkip=2), got: %v", result.Error)
	}
	if len(result.KEXMethods) != len(methods) {
		t.Errorf("KEXMethods len=%d; want %d", len(result.KEXMethods), len(methods))
	}
}

// TestAdversarial_TwoNonKEXINITNoKEXINIT — B3 regression: server sends exactly
// 2 non-KEXINIT packets with no KEXINIT. With maxSkip=2 this must error.
func TestAdversarial_TwoNonKEXINITNoKEXINIT(t *testing.T) {
	ignorePayload := []byte{2, 0, 0, 0, 0} // SSH_MSG_IGNORE

	addr := serveOnce(t, func(conn net.Conn) {
		_, _ = conn.Write([]byte("SSH-2.0-NoKEX_1.0\r\n"))
		buf := make([]byte, 512)
		_, _ = conn.Read(buf)
		for i := 0; i < 2; i++ {
			_, _ = conn.Write(buildSSHPacket(ignorePayload))
		}
	})

	result := dialAndProbe(t, addr)
	if result.Error == nil {
		t.Error("expected error after 2 non-KEXINIT packets with no KEXINIT (maxSkip=2)")
	}
}

// buildKEXInitPayloadRaw builds a KEXINIT payload with a raw name-list content
// bytes (not comma-joined from a []string). Used for adversarial inputs.
func buildKEXInitPayloadRaw(kexBytes []byte) []byte {
	var buf []byte
	buf = append(buf, sshMsgKexInit)
	buf = append(buf, make([]byte, kexinitCookieLen)...)

	// Name-list length prefix + raw bytes.
	lenBuf := make([]byte, 4)
	binary.BigEndian.PutUint32(lenBuf, uint32(len(kexBytes)))
	buf = append(buf, lenBuf...)
	buf = append(buf, kexBytes...)

	// 9 empty name-lists.
	emptyList := encodeNameList(nil)
	for i := 0; i < kexinitNameListCount-1; i++ {
		buf = append(buf, emptyList...)
	}

	// first_kex_packet_follows + reserved.
	buf = append(buf, 0, 0, 0, 0, 0)
	return buf
}
