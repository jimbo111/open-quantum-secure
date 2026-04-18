package tlsprobe

import (
	"encoding/binary"
	"fmt"
)

// KeyShareInfo describes one key_share entry parsed from a TLS 1.3 ClientHello
// or ServerHello extension (RFC 8446 §4.2.8).
type KeyShareInfo struct {
	// GroupID is the IANA TLS SupportedGroup codepoint.
	GroupID uint16
	// KeyExchangeLen is the length in bytes of the key_exchange field.
	KeyExchangeLen int
	// Primitive categorises the algorithm family: "classical", "hybrid-kem", or "pure-pq".
	Primitive string
}

// expectedKeyShareLengths maps IANA SupportedGroup codepoints to their expected
// key_exchange byte lengths as defined in RFC 8446, RFC 8422, FIPS 203, and
// draft-ietf-tls-hybrid-design-16.
//
// Hybrid KEM entries carry two sub-entries (client, server) because the
// ML-KEM component has different sizes in each direction:
//   - Client sends the ML-KEM public key
//   - Server sends the ML-KEM ciphertext (encapsulated key)
//
// Map value: [clientLen, serverLen]. When both are equal only one is stored
// but indexed as [len, len] to make callers uniform.
var expectedKeyShareLengths = map[uint16][2]int{
	// Classical ECDH (client and server lengths are identical for ECDH).
	0x001d: {32, 32},   // X25519
	0x0017: {65, 65},   // secp256r1 (uncompressed point)
	0x0018: {97, 97},   // secp384r1
	0x0019: {133, 133}, // secp521r1

	// Pure ML-KEM (FIPS 203). Client sends encapsulation key; server sends ciphertext.
	0x0200: {800, 768},   // MLKEM512
	0x0201: {1184, 1088}, // MLKEM768
	0x0202: {1568, 1568}, // MLKEM1024

	// Hybrid KEMs (draft-ietf-tls-hybrid-design-16).
	// Client key_exchange = classical_pubkey || mlkem_pubkey.
	// Server key_exchange = classical_contribution || mlkem_ciphertext.
	0x11eb: {65 + 1184, 65 + 1088},   // SecP256r1MLKEM768  (1249 / 1153)
	0x11ec: {32 + 1184, 32 + 1088},   // X25519MLKEM768     (1216 / 1120)
	0x11ed: {97 + 1568, 97 + 1568},   // SecP384r1MLKEM1024 (1665 / 1665)
	0x11ee: {65 + 1184, 65 + 1088},   // curveSM2MLKEM768   (1249 / 1153)
}

// hybridGroups is the set of codepoints that represent hybrid KEMs.
var hybridGroups = map[uint16]bool{
	0x11eb: true,
	0x11ec: true,
	0x11ed: true,
	0x11ee: true,
}

// purePQGroups is the set of codepoints that represent pure ML-KEM.
var purePQGroups = map[uint16]bool{
	0x0200: true,
	0x0201: true,
	0x0202: true,
}

// inferPrimitive classifies a SupportedGroup codepoint as "classical",
// "hybrid-kem", or "pure-pq".
func inferPrimitive(groupID uint16) string {
	if hybridGroups[groupID] {
		return "hybrid-kem"
	}
	if purePQGroups[groupID] {
		return "pure-pq"
	}
	return "classical"
}

// TODO(sprint7): wire via rawhello.ClientHelloCapture — Sprint 7 raw CH builder
// will call ParseKeyShareExtension directly from captured outgoing ClientHellos.

// ParseKeyShareExtension parses the body of a key_share extension from a
// TLS 1.3 ClientHello or ServerHello and returns all key share entries found.
//
// Wire format (RFC 8446 §4.2.8):
//
//	ClientHello: KeyShareClientHello  { client_shares: KeyShareEntry list<2> }
//	ServerHello: KeyShareServerHello  { server_share:  KeyShareEntry }
//
//	KeyShareEntry { group: uint16; key_exchange: opaque<0..2^16-1> }
//
// isClient must be true when parsing a ClientHello extension (the payload
// starts with a 2-byte total list length). For ServerHello (isClient=false),
// the payload is a bare KeyShareEntry with no leading list-length prefix.
//
// Returns an error on any truncated or malformed input.
func ParseKeyShareExtension(ext []byte, isClient bool) ([]KeyShareInfo, error) {
	if isClient {
		return parseClientKeyShares(ext)
	}
	return parseServerKeyShare(ext)
}

// parseClientKeyShares parses the ClientHello key_share payload:
//
//	struct { KeyShareEntry client_shares<0..2^16-1>; } KeyShareClientHello;
func parseClientKeyShares(data []byte) ([]KeyShareInfo, error) {
	if len(data) < 2 {
		return nil, fmt.Errorf("key_share client: payload too short (%d bytes), need at least 2", len(data))
	}
	listLen := int(binary.BigEndian.Uint16(data[0:2]))
	data = data[2:]
	if len(data) < listLen {
		return nil, fmt.Errorf("key_share client: declared list length %d exceeds remaining payload %d", listLen, len(data))
	}
	return parseKeyShareEntries(data[:listLen], true)
}

// parseServerKeyShare parses the ServerHello key_share payload:
//
//	struct { KeyShareEntry server_share; } KeyShareServerHello;
func parseServerKeyShare(data []byte) ([]KeyShareInfo, error) {
	return parseKeyShareEntries(data, false)
}

// parseKeyShareEntries walks a sequence of KeyShareEntry structs.
// isClient controls which expected length (client vs server) is used for
// validation.
func parseKeyShareEntries(data []byte, isClient bool) ([]KeyShareInfo, error) {
	var infos []KeyShareInfo
	for len(data) > 0 {
		if len(data) < 4 {
			return nil, fmt.Errorf("key_share entry: truncated header (%d bytes, need 4)", len(data))
		}
		groupID := binary.BigEndian.Uint16(data[0:2])
		kexLen := int(binary.BigEndian.Uint16(data[2:4]))
		data = data[4:]

		if len(data) < kexLen {
			return nil, fmt.Errorf("key_share entry: group 0x%04x: declared kex_len %d exceeds remaining payload %d",
				groupID, kexLen, len(data))
		}

		info := KeyShareInfo{
			GroupID:        groupID,
			KeyExchangeLen: kexLen,
			Primitive:      inferPrimitive(groupID),
		}
		infos = append(infos, info)
		data = data[kexLen:]
	}
	return infos, nil
}
