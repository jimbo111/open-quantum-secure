package rawhello

import (
	"bytes"
	"encoding/binary"
	"testing"
)

// parseClientHelloFields parses a raw TLS record produced by BuildClientHello
// and returns the legacy_version, random, session_id, and the raw extensions
// block. Fails the test on any malformation.
func parseClientHelloFields(t *testing.T, raw []byte) (legacyVersion uint16, random []byte, sessionID []byte, exts []byte) {
	t.Helper()

	// TLS record header: type(1) + version(2) + length(2)
	if len(raw) < 5 {
		t.Fatalf("raw too short for record header: %d bytes", len(raw))
	}
	if raw[0] != RecordTypeHandshake {
		t.Fatalf("record type: got 0x%02x want 0x%02x", raw[0], RecordTypeHandshake)
	}
	recPayloadLen := int(binary.BigEndian.Uint16(raw[3:5]))
	if len(raw) < 5+recPayloadLen {
		t.Fatalf("truncated: declared payload %d, have %d after header", recPayloadLen, len(raw)-5)
	}
	hs := raw[5 : 5+recPayloadLen]

	// Handshake header: type(1) + length(3)
	if len(hs) < 4 {
		t.Fatalf("handshake header too short: %d bytes", len(hs))
	}
	if hs[0] != 0x01 {
		t.Fatalf("handshake type: got 0x%02x want 0x01", hs[0])
	}
	bodyLen := int(uint32(hs[1])<<16 | uint32(hs[2])<<8 | uint32(hs[3]))
	if len(hs) < 4+bodyLen {
		t.Fatalf("handshake body truncated: declared %d, have %d", bodyLen, len(hs)-4)
	}
	body := hs[4 : 4+bodyLen]

	off := 0
	// legacy_version
	if len(body) < off+2 {
		t.Fatalf("body too short for legacy_version")
	}
	legacyVersion = binary.BigEndian.Uint16(body[off : off+2])
	off += 2
	// random
	if len(body) < off+32 {
		t.Fatalf("body too short for random")
	}
	random = body[off : off+32]
	off += 32
	// legacy_session_id
	if len(body) < off+1 {
		t.Fatalf("body too short for session_id_len")
	}
	sidLen := int(body[off])
	off++
	if len(body) < off+sidLen {
		t.Fatalf("body too short for session_id")
	}
	sessionID = body[off : off+sidLen]
	off += sidLen
	// cipher_suites: skip
	if len(body) < off+2 {
		t.Fatalf("body too short for cipher_suites_len")
	}
	csLen := int(binary.BigEndian.Uint16(body[off : off+2]))
	off += 2 + csLen
	// compression: skip 2 bytes
	if len(body) < off+2 {
		t.Fatalf("body too short for compression")
	}
	off += 2
	// extensions
	if len(body) < off+2 {
		exts = nil
		return
	}
	extsLen := int(binary.BigEndian.Uint16(body[off : off+2]))
	off += 2
	if len(body) < off+extsLen {
		t.Fatalf("extensions truncated: declared %d, have %d", extsLen, len(body)-off)
	}
	exts = body[off : off+extsLen]
	return
}

func TestBuildClientHello_RFCCompliance(t *testing.T) {
	raw, err := BuildClientHello(ClientHelloOpts{
		SNI:             "example.com",
		SupportedGroups: []uint16{0x001d, 0x11ec},
	})
	if err != nil {
		t.Fatalf("BuildClientHello: %v", err)
	}

	lv, _, sid, _ := parseClientHelloFields(t, raw)

	// RFC 8446 §4.1.2: legacy_version MUST be 0x0303
	if lv != 0x0303 {
		t.Errorf("legacy_version: got 0x%04x want 0x0303", lv)
	}
	// RFC 8446 appendix D.4: legacy_session_id must be 32 bytes for middlebox compat.
	if len(sid) != 32 {
		t.Errorf("legacy_session_id: got %d bytes want 32", len(sid))
	}
}

func TestBuildClientHello_CompressionMethods(t *testing.T) {
	// The 2 bytes before extensions should be 0x01 0x00 (length=1, null compression).
	raw, err := BuildClientHello(ClientHelloOpts{SNI: "test.example"})
	if err != nil {
		t.Fatalf("BuildClientHello: %v", err)
	}
	// Walk the record to find compression methods bytes.
	hs := raw[5:]
	body := hs[4:]
	off := 2 + 32 + 1 + 32 // legacy_version + random + session_id_len + session_id
	csLen := int(binary.BigEndian.Uint16(body[off : off+2]))
	off += 2 + csLen
	// Now at legacy_compression_methods
	if len(body) < off+2 {
		t.Fatalf("body too short for compression")
	}
	if body[off] != 0x01 || body[off+1] != 0x00 {
		t.Errorf("compression methods: got [%02x %02x] want [01 00]", body[off], body[off+1])
	}
}

func TestBuildClientHello_SupportedVersionsPresent(t *testing.T) {
	raw, err := BuildClientHello(ClientHelloOpts{SNI: "test.example"})
	if err != nil {
		t.Fatalf("BuildClientHello: %v", err)
	}
	_, _, _, exts := parseClientHelloFields(t, raw)
	if exts == nil {
		t.Fatal("no extensions found")
	}

	found := false
	for off := 0; off+4 <= len(exts); {
		extType := binary.BigEndian.Uint16(exts[off : off+2])
		extLen := int(binary.BigEndian.Uint16(exts[off+2 : off+4]))
		off += 4
		if extType == 0x002b {
			found = true
			// Data: 1-byte list length + 0x0304
			if extLen < 3 {
				t.Errorf("supported_versions ext too short: %d bytes", extLen)
			} else {
				data := exts[off : off+extLen]
				if data[0] != 0x02 || data[1] != 0x03 || data[2] != 0x04 {
					t.Errorf("supported_versions: got [%02x %02x %02x] want [02 03 04]", data[0], data[1], data[2])
				}
			}
		}
		off += extLen
	}
	if !found {
		t.Error("supported_versions extension not found")
	}
}

func TestBuildClientHello_SNIExtension(t *testing.T) {
	sni := "probe.example.com"
	raw, err := BuildClientHello(ClientHelloOpts{SNI: sni})
	if err != nil {
		t.Fatalf("BuildClientHello: %v", err)
	}
	_, _, _, exts := parseClientHelloFields(t, raw)

	found := false
	for off := 0; off+4 <= len(exts); {
		extType := binary.BigEndian.Uint16(exts[off : off+2])
		extLen := int(binary.BigEndian.Uint16(exts[off+2 : off+4]))
		off += 4
		if extType == 0x0000 {
			found = true
			data := exts[off : off+extLen]
			// data: listLen(2) + nameType(1) + nameLen(2) + name
			if !bytes.Contains(data, []byte(sni)) {
				t.Errorf("SNI not found in extension data")
			}
		}
		off += extLen
	}
	if !found {
		t.Error("server_name extension not found")
	}
}

func TestBuildClientHello_NoSNI(t *testing.T) {
	raw, err := BuildClientHello(ClientHelloOpts{})
	if err != nil {
		t.Fatalf("BuildClientHello: %v", err)
	}
	_, _, _, exts := parseClientHelloFields(t, raw)
	for off := 0; off+4 <= len(exts); {
		extType := binary.BigEndian.Uint16(exts[off : off+2])
		extLen := int(binary.BigEndian.Uint16(exts[off+2 : off+4]))
		off += 4
		if extType == 0x0000 {
			t.Error("server_name extension present despite empty SNI")
		}
		off += extLen
	}
}

func TestBuildClientHello_DefaultCiphers(t *testing.T) {
	raw, err := BuildClientHello(ClientHelloOpts{SNI: "x.example"})
	if err != nil {
		t.Fatalf("BuildClientHello: %v", err)
	}
	hs := raw[5:]
	body := hs[4:]
	off := 2 + 32 + 1 + 32
	csLen := int(binary.BigEndian.Uint16(body[off : off+2]))
	off += 2
	cipherBytes := body[off : off+csLen]

	wantCiphers := DefaultCipherSuites
	if csLen != len(wantCiphers)*2 {
		t.Errorf("cipher suite list length: got %d want %d", csLen, len(wantCiphers)*2)
	}
	for i, cs := range wantCiphers {
		got := binary.BigEndian.Uint16(cipherBytes[i*2 : i*2+2])
		if got != cs {
			t.Errorf("cipher[%d]: got 0x%04x want 0x%04x", i, got, cs)
		}
	}
}

func TestBuildClientHello_RandomUnique(t *testing.T) {
	// Two builds must produce different randoms.
	r1, err := BuildClientHello(ClientHelloOpts{SNI: "x.example"})
	if err != nil {
		t.Fatal(err)
	}
	r2, err := BuildClientHello(ClientHelloOpts{SNI: "x.example"})
	if err != nil {
		t.Fatal(err)
	}
	_, rand1, _, _ := parseClientHelloFields(t, r1)
	_, rand2, _, _ := parseClientHelloFields(t, r2)
	if bytes.Equal(rand1, rand2) {
		t.Error("two ClientHellos produced identical randoms — crypto/rand not used")
	}
}

func TestProbeKeyShare_KnownGroups(t *testing.T) {
	for _, tc := range []struct {
		groupID uint16
		wantLen int
	}{
		{0x001d, 32},
		{0x0201, 1184},
		{0x0202, 1568},
		{0x0200, 800},
		{0x11ec, 32 + 1184},
		{0x11eb, 65 + 1184},
	} {
		ks, err := ProbeKeyShare(tc.groupID)
		if err != nil {
			t.Errorf("group 0x%04x: %v", tc.groupID, err)
			continue
		}
		if ks.GroupID != tc.groupID {
			t.Errorf("group 0x%04x: GroupID mismatch %04x", tc.groupID, ks.GroupID)
		}
		if len(ks.PublicKey) != tc.wantLen {
			t.Errorf("group 0x%04x: len %d want %d", tc.groupID, len(ks.PublicKey), tc.wantLen)
		}
	}
}

func TestProbeKeyShare_UnknownGroup(t *testing.T) {
	_, err := ProbeKeyShare(0xDEAD)
	if err == nil {
		t.Fatal("expected error for unknown group, got nil")
	}
}

func TestBuildClientHello_WithKeyShare(t *testing.T) {
	ks, err := ProbeKeyShare(0x001d) // X25519
	if err != nil {
		t.Fatal(err)
	}
	raw, err := BuildClientHello(ClientHelloOpts{
		SNI:             "example.com",
		SupportedGroups: []uint16{0x001d},
		KeyShares:       []KeyShareEntry{ks},
	})
	if err != nil {
		t.Fatalf("BuildClientHello: %v", err)
	}
	if len(raw) == 0 {
		t.Fatal("empty output")
	}
	// Verify the record type byte.
	if raw[0] != RecordTypeHandshake {
		t.Errorf("record type: 0x%02x", raw[0])
	}
}
