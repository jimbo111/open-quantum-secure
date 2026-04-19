package rawhello

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
)

// HRRMagic is the SHA-256 hash of "HelloRetryRequest" per RFC 8446 §4.1.4.
// A ServerHello whose random field equals this value is a HelloRetryRequest.
var HRRMagic = [32]byte{
	0xcf, 0x21, 0xad, 0x74, 0xe5, 0x9a, 0x61, 0x11,
	0xbe, 0x1d, 0x8c, 0x02, 0x1e, 0x65, 0xb8, 0x91,
	0xc2, 0xa2, 0x11, 0x16, 0x7a, 0xbb, 0x8c, 0x5e,
	0x07, 0x9e, 0x09, 0xe2, 0xc8, 0xa8, 0x33, 0x9c,
}

// HandshakeTypeServerHello is the TLS handshake message type for ServerHello (RFC 8446 §4).
const HandshakeTypeServerHello uint8 = 0x02

// ParseResult holds the parsed response to a probe ClientHello.
type ParseResult struct {
	IsHRR          bool   // true if server sent HelloRetryRequest
	IsAlert        bool   // true if server sent an alert
	SelectedGroup  uint16 // IANA codepoint from key_share (0 = not present)
	SelectedCipher uint16 // cipher_suite from ServerHello
	AlertLevel     uint8
	AlertDesc      uint8
	Raw            []byte // raw handshake message body (nil for alert)
}

// ParseServerResponse reads the server's first response after a ClientHello and
// classifies it as a ServerHello, HelloRetryRequest, or Alert.
//
// Alert records are translated into ParseResult{IsAlert: true, ...} — they are
// NOT returned as errors, because handshake_failure(40) is a valid and expected
// server response when an offered group is unsupported.
//
// Transport errors (e.g. connection reset, timeout, context cancellation) are
// returned as errors.
func ParseServerResponse(ctx context.Context, conn net.Conn) (ParseResult, error) {
	msgType, body, err := ReadHandshakeMsg(ctx, conn)
	if err != nil {
		var ae *AlertError
		if errors.As(err, &ae) {
			return ParseResult{
				IsAlert:   true,
				AlertLevel: ae.Level,
				AlertDesc:  ae.Description,
			}, nil
		}
		return ParseResult{}, err
	}

	if msgType != HandshakeTypeServerHello {
		return ParseResult{}, fmt.Errorf("rawhello: expected ServerHello (0x02), got 0x%02x", msgType)
	}

	return parseServerHelloBody(body)
}

// parseServerHelloBody parses the body of a ServerHello or HelloRetryRequest.
// No panics on malformed input — all reads are bounds-checked.
func parseServerHelloBody(body []byte) (ParseResult, error) {
	// Minimum: legacy_version(2) + random(32) + session_id_len(1)
	if len(body) < 35 {
		return ParseResult{}, fmt.Errorf("rawhello: ServerHello body too short (%d bytes, need ≥35)", len(body))
	}
	off := 0

	// legacy_version: 2 bytes (informational, not enforced here)
	off += 2

	// random: 32 bytes — used to detect HRR
	var random [32]byte
	copy(random[:], body[off:off+32])
	off += 32

	// legacy_session_id_echo: 1-byte length + N bytes
	sidLen := int(body[off])
	off++
	if sidLen > 32 {
		return ParseResult{}, fmt.Errorf("rawhello: ServerHello session_id length %d out of range [0,32]", sidLen)
	}
	if len(body) < off+sidLen {
		return ParseResult{}, fmt.Errorf("rawhello: ServerHello session_id truncated (need %d, have %d)", off+sidLen, len(body))
	}
	off += sidLen

	// cipher_suite: 2 bytes
	if len(body) < off+2 {
		return ParseResult{}, fmt.Errorf("rawhello: ServerHello cipher_suite truncated")
	}
	cipherSuite := binary.BigEndian.Uint16(body[off : off+2])
	off += 2

	// legacy_compression_method: 1 byte (informational)
	if len(body) < off+1 {
		return ParseResult{}, fmt.Errorf("rawhello: ServerHello compression_method missing")
	}
	off++

	isHRR := random == HRRMagic
	result := ParseResult{
		IsHRR:          isHRR,
		SelectedCipher: cipherSuite,
		Raw:            body,
	}

	// extensions: optional (absent = no extension negotiated)
	if len(body) < off+2 {
		return result, nil
	}
	extsLen := int(binary.BigEndian.Uint16(body[off : off+2]))
	off += 2
	if len(body) < off+extsLen {
		return ParseResult{}, fmt.Errorf("rawhello: ServerHello extensions truncated (declared %d, have %d)", extsLen, len(body)-off)
	}
	extsData := body[off : off+extsLen]

	group, err := extractKeyShareGroup(extsData, isHRR)
	if err != nil {
		return ParseResult{}, err
	}
	result.SelectedGroup = group
	return result, nil
}

// extractKeyShareGroup scans extension data for the key_share extension (0x0033)
// and returns the selected group codepoint (0 if not present).
func extractKeyShareGroup(data []byte, isHRR bool) (uint16, error) {
	for off := 0; off+4 <= len(data); {
		extType := binary.BigEndian.Uint16(data[off : off+2])
		extLen := int(binary.BigEndian.Uint16(data[off+2 : off+4]))
		off += 4
		if len(data) < off+extLen {
			return 0, fmt.Errorf("rawhello: extension 0x%04x: declared length %d exceeds remaining data %d",
				extType, extLen, len(data)-off)
		}
		extData := data[off : off+extLen]
		off += extLen

		if extType == 0x0033 { // key_share
			return parseKeyShareExtGroup(extData, isHRR)
		}
	}
	return 0, nil
}

// parseKeyShareExtGroup extracts the group codepoint from a ServerHello or HRR
// key_share extension body.
//
//   - HRR (RFC 8446 §4.2.8): body = selected_group (uint16); no key_exchange.
//   - ServerHello: body = group(uint16) + key_exchange_len(uint16) + key_exchange.
func parseKeyShareExtGroup(data []byte, isHRR bool) (uint16, error) {
	if isHRR {
		if len(data) < 2 {
			return 0, fmt.Errorf("rawhello: HRR key_share ext too short (%d bytes, need 2)", len(data))
		}
		return binary.BigEndian.Uint16(data[0:2]), nil
	}
	// ServerHello key_share: group + kex_len + kex
	if len(data) < 4 {
		return 0, fmt.Errorf("rawhello: SH key_share ext too short (%d bytes, need ≥4)", len(data))
	}
	group := binary.BigEndian.Uint16(data[0:2])
	kexLen := int(binary.BigEndian.Uint16(data[2:4]))
	if len(data) < 4+kexLen {
		return 0, fmt.Errorf("rawhello: SH key_share kex_len %d exceeds ext data %d bytes", kexLen, len(data)-4)
	}
	return group, nil
}
