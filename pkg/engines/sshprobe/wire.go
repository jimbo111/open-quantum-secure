// Package sshprobe implements a Tier 5 (Network) engine that probes live SSH
// endpoints and detects quantum-vulnerable key exchange methods advertised in
// SSH_MSG_KEXINIT. It is pure Go, requires no external binaries, and only
// reads the server's KEXINIT advertisement — it never completes an SSH session.
package sshprobe

import (
	"encoding/binary"
	"fmt"
	"io"
	"strings"
)

const (
	sshMsgKexInit  = 20
	maxBannerLen   = 255
	maxPacketLen   = 256 * 1024 // 256 KB defensive cap; RFC 4253 §6.1 requires ≥35000 bytes support, we accept larger with OOM protection
	maxNameListLen = 64 * 1024  // 64 KB per name-list field
)

// readBanner reads the SSH identification string line (e.g. "SSH-2.0-OpenSSH_9.0").
// It reads byte-by-byte until \n (with optional preceding \r), up to maxBannerLen.
// Ref: RFC 4253 §4.2.
func readBanner(r io.Reader) (string, error) {
	buf := make([]byte, maxBannerLen+2)
	for i := range buf {
		if _, err := io.ReadFull(r, buf[i:i+1]); err != nil {
			return "", fmt.Errorf("read banner: %w", err)
		}
		if buf[i] == '\n' {
			line := string(buf[:i])
			return strings.TrimSuffix(line, "\r"), nil
		}
	}
	return "", fmt.Errorf("ssh banner too long (exceeded %d bytes without newline)", maxBannerLen)
}

// readPacket reads one binary SSH packet and returns the payload (without padding).
// Ref: RFC 4253 §6 — uint32 packet_length, byte padding_length, payload, padding.
func readPacket(r io.Reader) ([]byte, error) {
	var lenBuf [4]byte
	if _, err := io.ReadFull(r, lenBuf[:]); err != nil {
		return nil, fmt.Errorf("read packet length: %w", err)
	}
	pktLen := binary.BigEndian.Uint32(lenBuf[:])
	if pktLen < 2 || pktLen > maxPacketLen {
		return nil, fmt.Errorf("invalid packet_length %d (must be 2..%d)", pktLen, maxPacketLen)
	}

	body := make([]byte, pktLen)
	if _, err := io.ReadFull(r, body); err != nil {
		return nil, fmt.Errorf("read packet body: %w", err)
	}

	// body[0] = padding_length; payload = body[1 : pktLen-padding_length]
	paddingLen := int(body[0])
	payloadLen := int(pktLen) - 1 - paddingLen
	if payloadLen < 0 || payloadLen > int(pktLen)-1 {
		return nil, fmt.Errorf("invalid padding_length %d for packet_length %d", paddingLen, pktLen)
	}
	return body[1 : 1+payloadLen], nil
}

// parseNameList reads a comma-separated SSH name-list from payload starting at
// offset. Returns the names, the new offset after the list, and any error.
// Ref: RFC 4253 §5 — name-list = uint32 length + bytes (comma-separated).
// A6: Each name is validated for printable US-ASCII per RFC 4253 §5 (bytes
// 0x21–0x2B, 0x2D–0x7E; excludes space 0x20 and comma 0x2C).
func parseNameList(payload []byte, offset int) ([]string, int, error) {
	if offset+4 > len(payload) {
		return nil, offset, fmt.Errorf("parseNameList: need 4 bytes for length at offset %d, have %d", offset, len(payload)-offset)
	}
	length := int(binary.BigEndian.Uint32(payload[offset : offset+4]))
	offset += 4
	if length > maxNameListLen {
		return nil, offset, fmt.Errorf("parseNameList: length %d exceeds max %d", length, maxNameListLen)
	}
	if offset+length > len(payload) {
		return nil, offset, fmt.Errorf("parseNameList: truncated: need %d bytes at offset %d, have %d", length, offset, len(payload)-offset)
	}
	raw := string(payload[offset : offset+length])
	offset += length
	if raw == "" {
		return nil, offset, nil
	}
	names := strings.Split(raw, ",")
	for _, name := range names {
		if !isValidNameASCII(name) {
			return nil, offset, fmt.Errorf("parseNameList: algorithm name contains invalid byte: %q", name)
		}
	}
	return names, offset, nil
}

// isValidNameASCII reports whether every byte in s is within the printable
// US-ASCII range permitted for SSH algorithm names per RFC 4253 §5:
// 0x21–0x2B and 0x2D–0x7E (printable ASCII excluding space 0x20 and comma 0x2C).
// An empty name is rejected (commas create empty fields → malformed name-list).
func isValidNameASCII(s string) bool {
	if len(s) == 0 {
		return false
	}
	for i := 0; i < len(s); i++ {
		b := s[i]
		if (b >= 0x21 && b <= 0x2B) || (b >= 0x2D && b <= 0x7E) {
			continue
		}
		return false
	}
	return true
}
