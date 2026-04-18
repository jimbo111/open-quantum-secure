// wire_boundary_test.go — boundary-value tests for SSH wire-format parsing.
//
// Purpose: exhaustively verify that readPacket, parseNameList, and readBanner
// enforce documented limits at exact boundary values. Tests are grouped by
// function and cover zero, just-below-minimum, exactly-at-maximum, and
// just-over-maximum inputs. All "must error" cases assert a non-nil error.
package sshprobe

import (
	"bytes"
	"encoding/binary"
	"strings"
	"testing"
)

// ─── readPacket packet_length boundaries ────────────────────────────────────

// TestReadPacket_Boundary_PacketLength verifies every defined boundary for
// the packet_length field. packet_length must be in [2, maxPacketLen].
func TestReadPacket_Boundary_PacketLength(t *testing.T) {
	cases := []struct {
		name      string
		pktLen    uint32
		wantError bool
		note      string
	}{
		{
			name: "length_0_must_error",
			// packet_length=0 fails: min is 2 (1 byte padding_length + ≥1 byte payload)
			pktLen: 0, wantError: true, note: "below minimum (< 2)",
		},
		{
			name: "length_1_must_error",
			// packet_length=1 fails: still below minimum of 2
			pktLen: 1, wantError: true, note: "at minimum-1 (still < 2)",
		},
		{
			name: "length_2_minimum_valid",
			// packet_length=2: padding_length(1)+payload(1). Body read will succeed
			// only if we actually send the 2-byte body. Build via helper.
			pktLen:    0, // not used when building via helper
			wantError: false,
		},
		{
			name: "length_35000_valid",
			// 35000 bytes is well within the 256 KB (262144) cap.
			pktLen:    0,
			wantError: false,
		},
		{
			name: "length_maxPacketLen_valid",
			// Exactly at the cap must succeed.
			pktLen:    0,
			wantError: false,
		},
		{
			name:      "length_maxPacketLen_plus1_must_error",
			pktLen:    uint32(maxPacketLen) + 1,
			wantError: true,
			note:      "one over cap",
		},
		{
			name:      "length_0xFFFFFFFF_must_error",
			pktLen:    0xFFFFFFFF,
			wantError: true,
			note:      "max uint32",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var raw []byte
			switch tc.name {
			case "length_2_minimum_valid":
				// Build a real packet with 1-byte payload (0x00)
				raw = buildSSHPacket([]byte{0x00})
			case "length_35000_valid":
				raw = buildSSHPacket(bytes.Repeat([]byte{0x42}, 35000))
			case "length_maxPacketLen_valid":
				// maxPacketLen bytes payload is too large to build directly in memory
				// (it would be 256 KB). Instead, send the 4-byte header + minimal body
				// indicating padding_length=0 and fill payload so total body = maxPacketLen.
				body := make([]byte, maxPacketLen)
				body[0] = 0 // padding_length = 0
				fill := make([]byte, 4)
				binary.BigEndian.PutUint32(fill, uint32(maxPacketLen))
				raw = append(fill, body...)
			default:
				// For error cases, only send the 4-byte length header (no body).
				raw = make([]byte, 4)
				binary.BigEndian.PutUint32(raw, tc.pktLen)
			}

			conn := connFromBytes(t, raw)
			_, err := readPacket(conn)
			if tc.wantError {
				if err == nil {
					t.Errorf("[%s] expected error (note: %s), got nil", tc.name, tc.note)
				}
			} else {
				if err != nil {
					t.Errorf("[%s] unexpected error: %v", tc.name, err)
				}
			}
		})
	}
}

// ─── parseNameList name-list length boundaries ───────────────────────────────

// TestParseNameList_Boundary_Length verifies name-list length field boundaries.
func TestParseNameList_Boundary_Length(t *testing.T) {
	t.Run("length_0_empty_list", func(t *testing.T) {
		// length=0 → empty name-list, no error.
		payload := encodeNameList(nil)
		got, off, err := parseNameList(payload, 0)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(got) != 0 {
			t.Errorf("expected empty list, got %v", got)
		}
		if off != len(payload) {
			t.Errorf("offset=%d, want %d", off, len(payload))
		}
	})

	t.Run("length_4_single_name", func(t *testing.T) {
		// length=4 bytes, content="curl" → single name "curl"
		payload := encodeNameList([]string{"curl"})
		got, _, err := parseNameList(payload, 0)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(got) != 1 || got[0] != "curl" {
			t.Errorf("expected [curl], got %v", got)
		}
	})

	t.Run("length_exactly_maxNameListLen_valid", func(t *testing.T) {
		// A single name of exactly maxNameListLen bytes should succeed.
		name := strings.Repeat("x", maxNameListLen)
		payload := encodeNameList([]string{name})
		_, _, err := parseNameList(payload, 0)
		if err != nil {
			t.Errorf("unexpected error at exact maxNameListLen: %v", err)
		}
	})

	t.Run("length_1MiB_must_error", func(t *testing.T) {
		// 1 MiB > maxNameListLen (64 KB) — must be rejected immediately.
		const oneMiB = 1 << 20
		payload := make([]byte, 4)
		binary.BigEndian.PutUint32(payload, oneMiB)
		_, _, err := parseNameList(payload, 0)
		if err == nil {
			t.Error("expected error for 1 MiB name-list length, got nil")
		}
	})

	t.Run("length_maxNameListLen_plus1_must_error", func(t *testing.T) {
		payload := make([]byte, 4)
		binary.BigEndian.PutUint32(payload, uint32(maxNameListLen+1))
		_, _, err := parseNameList(payload, 0)
		if err == nil {
			t.Error("expected error for maxNameListLen+1, got nil")
		}
	})

	t.Run("length_0xFFFFFFFF_must_error", func(t *testing.T) {
		payload := make([]byte, 4)
		binary.BigEndian.PutUint32(payload, 0xFFFFFFFF)
		_, _, err := parseNameList(payload, 0)
		if err == nil {
			t.Error("expected error for 0xFFFFFFFF, got nil")
		}
	})

	t.Run("claimed_length_exceeds_payload_must_error", func(t *testing.T) {
		// Claim 1000 bytes but only provide 4 (just the length header).
		payload := make([]byte, 4)
		binary.BigEndian.PutUint32(payload, 1000)
		_, _, err := parseNameList(payload, 0)
		if err == nil {
			t.Error("expected error for truncated payload, got nil")
		}
	})

	t.Run("payload_too_short_for_length_field", func(t *testing.T) {
		// Only 3 bytes — cannot read the 4-byte length prefix.
		_, _, err := parseNameList([]byte{0, 0, 0}, 0)
		if err == nil {
			t.Error("expected error for 3-byte payload, got nil")
		}
	})

	t.Run("offset_at_end_must_error", func(t *testing.T) {
		payload := []byte{1, 2, 3, 4}
		_, _, err := parseNameList(payload, 4) // offset == len(payload)
		if err == nil {
			t.Error("expected error when offset == len(payload), got nil")
		}
	})

	t.Run("offset_beyond_payload_must_error", func(t *testing.T) {
		payload := []byte{1, 2, 3, 4}
		_, _, err := parseNameList(payload, 10) // offset > len(payload)
		if err == nil {
			t.Error("expected error when offset > len(payload), got nil")
		}
	})
}

// ─── readBanner banner length boundaries ─────────────────────────────────────

// TestReadBanner_Boundary_Length verifies readBanner at critical byte counts.
func TestReadBanner_Boundary_Length(t *testing.T) {
	t.Run("zero_bytes_must_error", func(t *testing.T) {
		conn := connFromBytes(t, []byte{})
		_, err := readBanner(conn)
		if err == nil {
			t.Error("expected error for 0-byte input, got nil")
		}
	})

	t.Run("newline_only", func(t *testing.T) {
		// Single '\n' → valid banner, returns empty string.
		conn := connFromBytes(t, []byte{'\n'})
		got, err := readBanner(conn)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got != "" {
			t.Errorf("expected empty string, got %q", got)
		}
	})

	t.Run("crlf_only", func(t *testing.T) {
		conn := connFromBytes(t, []byte{'\r', '\n'})
		got, err := readBanner(conn)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got != "" {
			t.Errorf("expected empty string after stripping CRLF, got %q", got)
		}
	})

	t.Run("254_bytes_with_crlf_valid", func(t *testing.T) {
		// 254 content bytes + "\r\n" = 256 total.
		// readBanner loops up to maxBannerLen+2 = 257 iterations.
		// '\n' is at position 255, within the loop range — must succeed.
		content := bytes.Repeat([]byte("X"), 254)
		data := append(content, '\r', '\n')
		conn := connFromBytes(t, data)
		got, err := readBanner(conn)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(got) != 254 {
			t.Errorf("got banner len=%d, want 254", len(got))
		}
	})

	t.Run("255_bytes_no_newline_must_error", func(t *testing.T) {
		// 255 bytes with no newline: loop exhausts buffer (maxBannerLen+2=257),
		// then EOF — must error.
		data := bytes.Repeat([]byte("A"), 255)
		conn := connFromBytes(t, data)
		_, err := readBanner(conn)
		if err == nil {
			t.Error("expected error for 255-byte banner with no newline, got nil")
		}
	})

	t.Run("banner_at_max_content_plus_newline", func(t *testing.T) {
		// maxBannerLen content bytes + '\n': '\n' is at position maxBannerLen (255),
		// which is index 255 in the buf of size 257. Within loop bounds — should succeed.
		data := append(bytes.Repeat([]byte("B"), maxBannerLen), '\n')
		conn := connFromBytes(t, data)
		got, err := readBanner(conn)
		if err != nil {
			t.Fatalf("unexpected error at maxBannerLen content + newline: %v", err)
		}
		if len(got) != maxBannerLen {
			t.Errorf("banner len=%d, want %d", len(got), maxBannerLen)
		}
	})

	t.Run("over_max_banner_no_newline_must_error", func(t *testing.T) {
		// maxBannerLen+1 bytes with no newline exhausts the loop.
		data := bytes.Repeat([]byte("C"), maxBannerLen+10)
		conn := connFromBytes(t, data)
		_, err := readBanner(conn)
		if err == nil {
			t.Error("expected error for banner exceeding maxBannerLen+2 without newline, got nil")
		}
	})
}
