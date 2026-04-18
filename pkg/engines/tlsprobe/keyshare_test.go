package tlsprobe

import (
	"encoding/binary"
	"encoding/hex"
	"testing"
)

// buildKeyShareEntry constructs a raw KeyShareEntry: 2-byte group + 2-byte len + kex bytes.
func buildKeyShareEntry(groupID uint16, kexBytes []byte) []byte {
	entry := make([]byte, 4+len(kexBytes))
	binary.BigEndian.PutUint16(entry[0:2], groupID)
	binary.BigEndian.PutUint16(entry[2:4], uint16(len(kexBytes)))
	copy(entry[4:], kexBytes)
	return entry
}

// buildClientPayload wraps one or more entries in the ClientHello list-length prefix.
func buildClientPayload(entries ...[]byte) []byte {
	var body []byte
	for _, e := range entries {
		body = append(body, e...)
	}
	out := make([]byte, 2+len(body))
	binary.BigEndian.PutUint16(out[0:2], uint16(len(body)))
	copy(out[2:], body)
	return out
}

// ── inferPrimitive ────────────────────────────────────────────────────────────

func TestInferPrimitive(t *testing.T) {
	t.Parallel()
	tests := []struct {
		groupID   uint16
		wantPrim  string
	}{
		{0x001D, "classical"},  // X25519
		{0x0017, "classical"},  // secp256r1
		{0x001E, "classical"},  // X448
		{0x11EB, "hybrid-kem"}, // SecP256r1MLKEM768
		{0x11EC, "hybrid-kem"}, // X25519MLKEM768
		{0x11ED, "hybrid-kem"}, // SecP384r1MLKEM1024
		{0x11EE, "hybrid-kem"}, // curveSM2MLKEM768
		{0x0200, "pure-pq"},    // MLKEM512
		{0x0201, "pure-pq"},    // MLKEM768
		{0x0202, "pure-pq"},    // MLKEM1024
		{0xFFFF, "classical"},  // unknown → classical fallback
	}
	for _, tt := range tests {
		t.Run("", func(t *testing.T) {
			t.Parallel()
			got := inferPrimitive(tt.groupID)
			if got != tt.wantPrim {
				t.Errorf("inferPrimitive(0x%04x) = %q, want %q", tt.groupID, got, tt.wantPrim)
			}
		})
	}
}

// ── expectedKeyShareLengths table ────────────────────────────────────────────

func TestExpectedKeyShareLengths_Table(t *testing.T) {
	t.Parallel()
	tests := []struct {
		groupID     uint16
		wantClient  int
		wantServer  int
	}{
		// Classical
		{0x001D, 32, 32},
		{0x0017, 65, 65},
		{0x0018, 97, 97},
		{0x0019, 133, 133},
		// Pure ML-KEM
		{0x0200, 800, 768},
		{0x0201, 1184, 1088},
		{0x0202, 1568, 1568},
		// Hybrid
		{0x11EB, 1249, 1153},
		{0x11EC, 1216, 1120},
		{0x11ED, 1665, 1665},
		{0x11EE, 1249, 1153},
	}
	for _, tt := range tests {
		t.Run("", func(t *testing.T) {
			t.Parallel()
			lens, ok := expectedKeyShareLengths[tt.groupID]
			if !ok {
				t.Fatalf("0x%04x not in expectedKeyShareLengths table", tt.groupID)
			}
			if lens[0] != tt.wantClient {
				t.Errorf("0x%04x client len=%d, want %d", tt.groupID, lens[0], tt.wantClient)
			}
			if lens[1] != tt.wantServer {
				t.Errorf("0x%04x server len=%d, want %d", tt.groupID, lens[1], tt.wantServer)
			}
		})
	}
}

// ── ParseKeyShareExtension — golden byte tests ───────────────────────────────

// TestParseKeyShareExtension_X25519_Client parses a ClientHello key_share
// containing a single X25519 entry with a 32-byte key exchange.
//
// Hex encoding:
//   0024        = list length = 36 bytes
//   001d        = X25519 group ID
//   0020        = kex length = 32 bytes
//   <32 bytes>  = fake X25519 public key (all 0xAA)
func TestParseKeyShareExtension_X25519_Client(t *testing.T) {
	t.Parallel()
	kex := make([]byte, 32) // 32 × 0x00
	for i := range kex {
		kex[i] = 0xAA
	}
	entry := buildKeyShareEntry(0x001D, kex)
	payload := buildClientPayload(entry)

	infos, err := ParseKeyShareExtension(payload, true)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(infos) != 1 {
		t.Fatalf("got %d infos, want 1", len(infos))
	}
	if infos[0].GroupID != 0x001D {
		t.Errorf("GroupID=0x%04x, want 0x001D", infos[0].GroupID)
	}
	if infos[0].KeyExchangeLen != 32 {
		t.Errorf("KeyExchangeLen=%d, want 32", infos[0].KeyExchangeLen)
	}
	if infos[0].Primitive != "classical" {
		t.Errorf("Primitive=%q, want classical", infos[0].Primitive)
	}
}

// TestParseKeyShareExtension_X25519MLKEM768_Client uses a literal hex encoding
// of a minimal ClientHello key_share for group 0x11EC (X25519MLKEM768) with
// a 1216-byte key exchange (32 B X25519 || 1184 B ML-KEM-768 encapsulation key).
//
// The hex string encodes:
//   04C4          = list length = 1220 bytes (4 header + 1216 kex)
//   11EC          = X25519MLKEM768 group ID
//   04C0          = kex length = 1216 bytes
//   <1216 bytes>  = zeroed key material (not cryptographically valid)
func TestParseKeyShareExtension_X25519MLKEM768_Client_Golden(t *testing.T) {
	t.Parallel()
	// Build the expected hex manually to verify the parser handles full 1216-byte kex.
	kex := make([]byte, 1216) // 32+1184 zeroed
	entry := buildKeyShareEntry(0x11EC, kex)
	payload := buildClientPayload(entry)

	// Verify our constructed payload matches the expected structure.
	// list_len = 4 (header) + 1216 (kex) = 1220 = 0x04C4
	if len(payload) != 1222 { // 2 list-len + 4 entry-hdr + 1216 kex
		t.Fatalf("payload length=%d, want 1222", len(payload))
	}
	wantHexPrefix := "04c4" + "11ec" + "04c0"
	gotHex := hex.EncodeToString(payload[:6])
	if gotHex != wantHexPrefix {
		t.Errorf("payload[0:6] hex=%q, want %q", gotHex, wantHexPrefix)
	}

	infos, err := ParseKeyShareExtension(payload, true)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(infos) != 1 {
		t.Fatalf("got %d infos, want 1", len(infos))
	}
	info := infos[0]
	if info.GroupID != 0x11EC {
		t.Errorf("GroupID=0x%04x, want 0x11EC", info.GroupID)
	}
	if info.KeyExchangeLen != 1216 {
		t.Errorf("KeyExchangeLen=%d, want 1216", info.KeyExchangeLen)
	}
	if info.Primitive != "hybrid-kem" {
		t.Errorf("Primitive=%q, want hybrid-kem", info.Primitive)
	}
}

// TestParseKeyShareExtension_MultiEntry_Client parses a ClientHello with two
// entries: X25519 (32 B) and X25519MLKEM768 (1216 B), as a typical Go 1.25
// ClientHello would advertise.
func TestParseKeyShareExtension_MultiEntry_Client(t *testing.T) {
	t.Parallel()
	e1 := buildKeyShareEntry(0x001D, make([]byte, 32))   // X25519
	e2 := buildKeyShareEntry(0x11EC, make([]byte, 1216)) // X25519MLKEM768
	payload := buildClientPayload(e1, e2)

	infos, err := ParseKeyShareExtension(payload, true)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(infos) != 2 {
		t.Fatalf("got %d infos, want 2", len(infos))
	}
	if infos[0].GroupID != 0x001D || infos[0].Primitive != "classical" {
		t.Errorf("entry[0]: got group=0x%04x prim=%q", infos[0].GroupID, infos[0].Primitive)
	}
	if infos[1].GroupID != 0x11EC || infos[1].Primitive != "hybrid-kem" {
		t.Errorf("entry[1]: got group=0x%04x prim=%q", infos[1].GroupID, infos[1].Primitive)
	}
}

// TestParseKeyShareExtension_Server_X25519 parses a ServerHello key_share
// (no list-length prefix) with X25519.
func TestParseKeyShareExtension_Server_X25519(t *testing.T) {
	t.Parallel()
	kex := make([]byte, 32)
	entry := buildKeyShareEntry(0x001D, kex)

	infos, err := ParseKeyShareExtension(entry, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(infos) != 1 {
		t.Fatalf("got %d infos, want 1", len(infos))
	}
	if infos[0].KeyExchangeLen != 32 {
		t.Errorf("KeyExchangeLen=%d, want 32", infos[0].KeyExchangeLen)
	}
}

// TestParseKeyShareExtension_MLKEM768_PureServer parses a ServerHello
// key_share for MLKEM768 (ciphertext: 1088 B).
func TestParseKeyShareExtension_MLKEM768_PureServer(t *testing.T) {
	t.Parallel()
	kex := make([]byte, 1088)
	entry := buildKeyShareEntry(0x0201, kex)

	infos, err := ParseKeyShareExtension(entry, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(infos) != 1 {
		t.Fatalf("got %d infos, want 1", len(infos))
	}
	if infos[0].Primitive != "pure-pq" {
		t.Errorf("Primitive=%q, want pure-pq", infos[0].Primitive)
	}
	if infos[0].KeyExchangeLen != 1088 {
		t.Errorf("KeyExchangeLen=%d, want 1088", infos[0].KeyExchangeLen)
	}
}

// ── Error cases ───────────────────────────────────────────────────────────────

func TestParseKeyShareExtension_TruncatedPayload(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		data    []byte
		isClient bool
	}{
		{"client_empty", []byte{}, true},
		{"client_one_byte", []byte{0x00}, true},
		{"client_list_len_exceeds_data", []byte{0x00, 0x10, 0x01, 0x02}, true},
		{"server_truncated_header", []byte{0x00, 0x01, 0x00}, false},
		// buildKeyShareEntry(X25519, 10B kex) = 14 bytes; slice to 13 so kex is 1 byte short.
		{"server_kex_too_short", buildKeyShareEntry(0x001D, make([]byte, 10))[:13], false},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			_, err := ParseKeyShareExtension(tt.data, tt.isClient)
			if err == nil {
				t.Errorf("expected error for truncated input %q, got nil", tt.name)
			}
		})
	}
}

func TestParseKeyShareExtension_EmptyClientList(t *testing.T) {
	t.Parallel()
	// Valid ClientHello with empty list: list_len=0.
	payload := []byte{0x00, 0x00}
	infos, err := ParseKeyShareExtension(payload, true)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(infos) != 0 {
		t.Errorf("expected 0 infos for empty list, got %d", len(infos))
	}
}
