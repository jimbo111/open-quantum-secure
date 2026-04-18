package sshprobe

import (
	"encoding/binary"
	"net"
	"strings"
	"testing"
	"time"
)

// buildKEXInitPacket creates a minimal SSH_MSG_KEXINIT binary packet with the
// given kex_algorithms list. All other name-list fields are empty.
func buildKEXInitPacket(kexMethods []string) []byte {
	payload := buildKEXInitPayload(kexMethods)
	return buildSSHPacket(payload)
}

// buildKEXInitPayload creates the raw KEXINIT payload (without binary packet framing).
func buildKEXInitPayload(kexMethods []string) []byte {
	var buf []byte

	// Type byte
	buf = append(buf, sshMsgKexInit)

	// 16-byte cookie (zeros for tests)
	buf = append(buf, make([]byte, kexinitCookieLen)...)

	// kex_algorithms name-list
	buf = append(buf, encodeNameList(kexMethods)...)

	// 9 remaining name-lists (all empty)
	emptyList := encodeNameList(nil)
	for i := 0; i < kexinitNameListCount-1; i++ {
		buf = append(buf, emptyList...)
	}

	// first_kex_packet_follows boolean
	buf = append(buf, 0)

	// reserved uint32
	buf = append(buf, 0, 0, 0, 0)

	return buf
}

// serveFakeSSH serves a minimal SSH handshake: sends banner + KEXINIT,
// reads client banner, then closes. Implemented as a test helper using
// net.Pipe so no real network port is used.
func serveFakeSSH(t *testing.T, serverID string, kexMethods []string) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	addr := ln.Addr().String()

	go func() {
		defer ln.Close()
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(5 * time.Second))

		// Send server banner.
		_, _ = conn.Write([]byte(serverID + "\r\n"))

		// Read client banner (ignore it).
		buf := make([]byte, 512)
		for {
			n, err := conn.Read(buf)
			if err != nil || n == 0 {
				break
			}
			s := string(buf[:n])
			if strings.Contains(s, "\n") {
				break
			}
		}

		// Send KEXINIT.
		pkt := buildKEXInitPacket(kexMethods)
		_, _ = conn.Write(pkt)
	}()

	return addr
}

func TestProbe_ClassicalOnly(t *testing.T) {
	methods := []string{
		"curve25519-sha256",
		"diffie-hellman-group14-sha256",
		"ecdh-sha2-nistp256",
	}
	addr := serveFakeSSH(t, "SSH-2.0-OpenSSH_7.4", methods)

	result := probeSSH(t.Context(), addr, 5*time.Second)

	if result.Error != nil {
		t.Fatalf("probeSSH error: %v", result.Error)
	}
	if result.ServerID != "SSH-2.0-OpenSSH_7.4" {
		t.Errorf("ServerID = %q; want SSH-2.0-OpenSSH_7.4", result.ServerID)
	}
	if len(result.KEXMethods) != len(methods) {
		t.Fatalf("KEXMethods len = %d; want %d", len(result.KEXMethods), len(methods))
	}
	for i, m := range methods {
		if result.KEXMethods[i] != m {
			t.Errorf("KEXMethods[%d] = %q; want %q", i, result.KEXMethods[i], m)
		}
	}
}

func TestProbe_MLKEMEnabled(t *testing.T) {
	methods := []string{
		"mlkem768x25519-sha256",
		"curve25519-sha256",
		"ecdh-sha2-nistp256",
	}
	addr := serveFakeSSH(t, "SSH-2.0-OpenSSH_10.0", methods)

	result := probeSSH(t.Context(), addr, 5*time.Second)

	if result.Error != nil {
		t.Fatalf("probeSSH error: %v", result.Error)
	}
	if len(result.KEXMethods) == 0 {
		t.Fatal("no KEX methods returned")
	}
	found := false
	for _, m := range result.KEXMethods {
		if m == "mlkem768x25519-sha256" {
			found = true
		}
	}
	if !found {
		t.Errorf("mlkem768x25519-sha256 not in KEX methods: %v", result.KEXMethods)
	}
}

func TestProbe_SntrupEnabled(t *testing.T) {
	methods := []string{
		"sntrup761x25519-sha512@openssh.com",
		"curve25519-sha256",
		"ecdh-sha2-nistp256",
	}
	addr := serveFakeSSH(t, "SSH-2.0-OpenSSH_9.0", methods)

	result := probeSSH(t.Context(), addr, 5*time.Second)

	if result.Error != nil {
		t.Fatalf("probeSSH error: %v", result.Error)
	}
	found := false
	for _, m := range result.KEXMethods {
		if m == "sntrup761x25519-sha512@openssh.com" {
			found = true
		}
	}
	if !found {
		t.Errorf("sntrup not in KEX methods: %v", result.KEXMethods)
	}
}

func TestProbe_MixedPQC(t *testing.T) {
	methods := []string{
		"mlkem768x25519-sha256",
		"sntrup761x25519-sha512@openssh.com",
		"curve25519-sha256",
		"diffie-hellman-group14-sha256",
	}
	addr := serveFakeSSH(t, "SSH-2.0-OpenSSH_10.0p1", methods)

	result := probeSSH(t.Context(), addr, 5*time.Second)

	if result.Error != nil {
		t.Fatalf("probeSSH error: %v", result.Error)
	}
	if len(result.KEXMethods) != len(methods) {
		t.Errorf("KEXMethods len = %d; want %d", len(result.KEXMethods), len(methods))
	}
}

func TestProbe_Unreachable(t *testing.T) {
	// Use a port that is not listening.
	result := probeSSH(t.Context(), "127.0.0.1:1", 1*time.Second)
	if result.Error == nil {
		t.Fatal("expected error for unreachable target, got nil")
	}
}

func TestProbe_NotSSH(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	addr := ln.Addr().String()
	go func() {
		conn, _ := ln.Accept()
		defer conn.Close()
		_, _ = conn.Write([]byte("HTTP/1.0 200 OK\r\n\r\n"))
	}()
	defer ln.Close()

	result := probeSSH(t.Context(), addr, 2*time.Second)
	if result.Error == nil {
		t.Fatal("expected error for non-SSH server, got nil")
	}
}

// TestParseKEXInitPayload_Roundtrip verifies that a payload built by
// buildKEXInitPayload is correctly parsed by parseKEXInitPayload.
func TestParseKEXInitPayload_Roundtrip(t *testing.T) {
	methods := []string{"mlkem768x25519-sha256", "curve25519-sha256"}
	payload := buildKEXInitPayload(methods)
	got, err := parseKEXInitPayload(payload)
	if err != nil {
		t.Fatalf("parseKEXInitPayload: %v", err)
	}
	if len(got) != len(methods) {
		t.Fatalf("got %d methods; want %d", len(got), len(methods))
	}
	for i, m := range methods {
		if got[i] != m {
			t.Errorf("method[%d] = %q; want %q", i, got[i], m)
		}
	}
}

func TestParseKEXInitPayload_TooShort(t *testing.T) {
	_, err := parseKEXInitPayload([]byte{sshMsgKexInit})
	if err == nil {
		t.Fatal("expected error for truncated KEXINIT, got nil")
	}
}

// encodeNameList is duplicated from wire_test.go to keep probe_test self-contained.
// Go test files in the same package share helpers, but we keep it explicit for clarity.
func mustEncodeUint32(v uint32) []byte {
	b := make([]byte, 4)
	binary.BigEndian.PutUint32(b, v)
	return b
}
