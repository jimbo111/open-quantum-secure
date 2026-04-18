package sshprobe

import (
	"bytes"
	"encoding/binary"
	"net"
	"strings"
	"testing"
	"time"
)

// connFromBytes wraps a byte slice in a net.Conn-shaped reader using net.Pipe.
func connFromBytes(t *testing.T, data []byte) net.Conn {
	t.Helper()
	client, server := net.Pipe()
	go func() {
		_, _ = server.Write(data)
		server.Close()
	}()
	t.Cleanup(func() { client.Close() })
	return client
}

func TestReadBanner(t *testing.T) {
	cases := []struct {
		name    string
		input   string
		want    string
		wantErr bool
	}{
		{"unix newline", "SSH-2.0-OpenSSH_9.0\n", "SSH-2.0-OpenSSH_9.0", false},
		{"crlf newline", "SSH-2.0-OpenSSH_9.0\r\n", "SSH-2.0-OpenSSH_9.0", false},
		{"dropbear", "SSH-2.0-dropbear_2022.83\r\n", "SSH-2.0-dropbear_2022.83", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			conn := connFromBytes(t, []byte(tc.input))
			got, err := readBanner(conn)
			if tc.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tc.want {
				t.Errorf("readBanner = %q; want %q", got, tc.want)
			}
		})
	}
}

func TestReadBannerTooLong(t *testing.T) {
	// 300 bytes without newline should error.
	data := bytes.Repeat([]byte("A"), 300)
	conn := connFromBytes(t, data)
	_, err := readBanner(conn)
	if err == nil {
		t.Fatal("expected error for oversized banner, got nil")
	}
}

// buildSSHPacket encodes payload as an SSH binary packet (RFC 4253 §6).
func buildSSHPacket(payload []byte) []byte {
	padding := 8 - (len(payload)+5)%8
	if padding < 4 {
		padding += 8
	}
	pktLen := uint32(1 + len(payload) + padding)
	buf := make([]byte, 4+1+len(payload)+padding)
	binary.BigEndian.PutUint32(buf[0:4], pktLen)
	buf[4] = byte(padding)
	copy(buf[5:], payload)
	return buf
}

func TestReadPacket(t *testing.T) {
	payload := []byte{sshMsgKexInit, 1, 2, 3, 4}
	raw := buildSSHPacket(payload)
	conn := connFromBytes(t, raw)
	got, err := readPacket(conn)
	if err != nil {
		t.Fatalf("readPacket: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Errorf("readPacket = %v; want %v", got, payload)
	}
}

func TestReadPacketInvalidLength(t *testing.T) {
	// packet_length = 0 is invalid (must be >= 2).
	raw := make([]byte, 4)
	binary.BigEndian.PutUint32(raw, 0)
	conn := connFromBytes(t, raw)
	_, err := readPacket(conn)
	if err == nil {
		t.Fatal("expected error for packet_length=0, got nil")
	}
}

func TestParseNameList(t *testing.T) {
	cases := []struct {
		name    string
		names   []string
		wantErr bool
	}{
		{"empty list", nil, false},
		{"single", []string{"curve25519-sha256"}, false},
		{"multiple", []string{"mlkem768x25519-sha256", "curve25519-sha256", "diffie-hellman-group14-sha256"}, false},
		{"1000 entries", makeEntries(1000, "alg"), false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			payload := encodeNameList(tc.names)
			got, newOff, err := parseNameList(payload, 0)
			if tc.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("parseNameList: %v", err)
			}
			if newOff != len(payload) {
				t.Errorf("newOffset = %d; want %d", newOff, len(payload))
			}
			if len(tc.names) == 0 {
				if len(got) != 0 {
					t.Errorf("expected empty list, got %v", got)
				}
				return
			}
			if strings.Join(got, ",") != strings.Join(tc.names, ",") {
				t.Errorf("got %v; want %v", got, tc.names)
			}
		})
	}
}

func TestParseNameListTruncated(t *testing.T) {
	// length field says 100 but payload only has 10 bytes.
	payload := make([]byte, 4+10)
	binary.BigEndian.PutUint32(payload, 100)
	_, _, err := parseNameList(payload, 0)
	if err == nil {
		t.Fatal("expected error for truncated name-list, got nil")
	}
}

func TestParseNameListTooShort(t *testing.T) {
	// Only 3 bytes — not enough for the uint32 length prefix.
	_, _, err := parseNameList([]byte{0, 0, 0}, 0)
	if err == nil {
		t.Fatal("expected error for payload too short for length, got nil")
	}
}

func TestParseNameListMaxSize(t *testing.T) {
	// Exactly at the 64 KB limit should succeed.
	big := make([]byte, maxNameListLen)
	for i := range big {
		if i == 0 {
			big[i] = 'a'
		} else {
			big[i] = 'b'
		}
	}
	payload := encodeNameList([]string{string(big)})
	_, _, err := parseNameList(payload, 0)
	if err != nil {
		t.Fatalf("unexpected error at max name-list size: %v", err)
	}
}

func TestParseNameListExceedsMax(t *testing.T) {
	// Claim a length one byte over the 64 KB cap.
	payload := make([]byte, 4)
	binary.BigEndian.PutUint32(payload, uint32(maxNameListLen+1))
	_, _, err := parseNameList(payload, 0)
	if err == nil {
		t.Fatal("expected error for name-list exceeding max size, got nil")
	}
}

// encodeNameList builds the wire-format byte slice for a name-list.
func encodeNameList(names []string) []byte {
	joined := strings.Join(names, ",")
	buf := make([]byte, 4+len(joined))
	binary.BigEndian.PutUint32(buf, uint32(len(joined)))
	copy(buf[4:], joined)
	return buf
}

func makeEntries(n int, prefix string) []string {
	out := make([]string, n)
	for i := range out {
		out[i] = prefix + string(rune('0'+i%10))
	}
	return out
}

// connFromReader wraps a reader in a net.Conn using net.Pipe with a deadline.
func connFromReader(t *testing.T, data []byte) net.Conn {
	t.Helper()
	c, s := net.Pipe()
	_ = s.SetDeadline(time.Now().Add(5 * time.Second))
	go func() {
		_, _ = s.Write(data)
		s.Close()
	}()
	t.Cleanup(func() { c.Close() })
	return c
}
