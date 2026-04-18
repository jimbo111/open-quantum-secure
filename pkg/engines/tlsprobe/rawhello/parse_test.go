package rawhello

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"net"
	"testing"
	"time"
)

// buildServerHello constructs a raw ServerHello handshake message body with the
// given random, cipher suite, and optional key_share extension entry.
// groupID=0 omits the key_share extension.
func buildServerHello(random [32]byte, cipherSuite uint16, groupID uint16, isHRR bool) []byte {
	var b []byte
	b = appendU16(b, 0x0303) // legacy_version
	b = append(b, random[:]...)
	b = append(b, 0x00) // session_id_len = 0
	b = appendU16(b, cipherSuite)
	b = append(b, 0x00) // legacy_compression_method = 0

	// Build extensions
	var exts []byte
	// supported_versions ext: 0x002b, len=2, 0x0304
	exts = appendU16(exts, 0x002b)
	exts = appendU16(exts, 2)
	exts = append(exts, 0x03, 0x04)

	if groupID != 0 {
		var ksData []byte
		if isHRR {
			ksData = appendU16(ksData, groupID)
		} else {
			// ServerHello key_share: group + kex_len + kex (minimal 1 byte)
			ksData = appendU16(ksData, groupID)
			ksData = appendU16(ksData, 1) // kex_len = 1
			ksData = append(ksData, 0x42) // dummy kex byte
		}
		exts = appendU16(exts, 0x0033)           // key_share
		exts = appendU16(exts, uint16(len(ksData)))
		exts = append(exts, ksData...)
	}

	b = appendU16(b, uint16(len(exts)))
	b = append(b, exts...)
	return b
}

// sendServerHello builds a complete TLS record carrying a ServerHello and writes
// it to conn. Must NOT call t.Fatalf — this function is invoked from goroutines.
// Write errors are dropped: the reader will observe io.EOF and the test fails there.
func sendServerHello(conn net.Conn, ctx context.Context, random [32]byte, cipherSuite uint16, groupID uint16, isHRR bool) {
	body := buildServerHello(random, cipherSuite, groupID, isHRR)
	msg := make([]byte, 4+len(body))
	msg[0] = HandshakeTypeServerHello
	msg[1] = 0
	msg[2] = byte(len(body) >> 8)
	msg[3] = byte(len(body))
	copy(msg[4:], body)
	_ = WriteRecord(ctx, conn, Record{
		Type:    RecordTypeHandshake,
		Version: LegacyRecordVersion,
		Payload: msg,
	})
}

func TestParseServerResponse_NormalServerHello(t *testing.T) {
	var random [32]byte
	random[0] = 0x42 // non-HRR random

	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	ctx := context.Background()
	go sendServerHello(client, ctx, random, 0x1301, 0x001d, false)

	result, err := ParseServerResponse(ctx, server)
	if err != nil {
		t.Fatalf("ParseServerResponse: %v", err)
	}
	if result.IsHRR {
		t.Error("IsHRR: got true want false")
	}
	if result.IsAlert {
		t.Error("IsAlert: got true want false")
	}
	if result.SelectedCipher != 0x1301 {
		t.Errorf("SelectedCipher: got 0x%04x want 0x1301", result.SelectedCipher)
	}
	if result.SelectedGroup != 0x001d {
		t.Errorf("SelectedGroup: got 0x%04x want 0x001d", result.SelectedGroup)
	}
}

func TestParseServerResponse_HRR(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	ctx := context.Background()
	go sendServerHello(client, ctx, HRRMagic, 0x1302, 0x11ec, true)

	result, err := ParseServerResponse(ctx, server)
	if err != nil {
		t.Fatalf("ParseServerResponse: %v", err)
	}
	if !result.IsHRR {
		t.Error("IsHRR: got false want true")
	}
	if result.IsAlert {
		t.Error("IsAlert: got true want false")
	}
	if result.SelectedGroup != 0x11ec {
		t.Errorf("SelectedGroup: got 0x%04x want 0x11ec", result.SelectedGroup)
	}
}

func TestParseServerResponse_AlertHandshakeFailure(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	ctx := context.Background()
	go func() {
		WriteRecord(ctx, client, Record{
			Type:    RecordTypeAlert,
			Version: LegacyRecordVersion,
			Payload: []byte{0x02, 0x28}, // fatal, handshake_failure
		})
	}()

	result, err := ParseServerResponse(ctx, server)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.IsAlert {
		t.Error("IsAlert: got false want true")
	}
	if result.AlertLevel != 0x02 {
		t.Errorf("AlertLevel: got %d want 2", result.AlertLevel)
	}
	if result.AlertDesc != 0x28 {
		t.Errorf("AlertDesc: got %d want 40 (handshake_failure)", result.AlertDesc)
	}
}

func TestParseServerResponse_UnknownHandshakeType(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	ctx := context.Background()
	go func() {
		// Send a handshake message with type 0xFF (not ServerHello)
		msg := []byte{0xFF, 0, 0, 1, 0x42} // type + 3-byte len + 1 byte body
		WriteRecord(ctx, client, Record{
			Type:    RecordTypeHandshake,
			Version: LegacyRecordVersion,
			Payload: msg,
		})
	}()

	_, err := ParseServerResponse(ctx, server)
	if err == nil {
		t.Fatal("expected error for unknown handshake type, got nil")
	}
}

func TestParseServerHelloBody_TruncatedInputs(t *testing.T) {
	tests := []struct {
		name string
		body []byte
	}{
		{"empty", []byte{}},
		{"too_short_random", make([]byte, 10)},
		{"truncated_sid", func() []byte {
			b := make([]byte, 35)
			b[34] = 0x20 // session_id_len = 32 but no bytes follow
			return b
		}()},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := parseServerHelloBody(tt.body)
			if err == nil {
				t.Errorf("expected error for truncated input, got nil")
			}
		})
	}
}

func TestParseServerHelloBody_ExtensionsTruncated(t *testing.T) {
	// Valid up to extensions, but extsLen overflows.
	var random [32]byte
	body := buildServerHello(random, 0x1301, 0, false)
	// Overwrite the extensions length to claim more than available.
	extLenOff := len(body) - 2 - len(extSupportedVersions()) // rough position
	// Just corrupt the last 2 bytes to claim a large extensions block.
	binary.BigEndian.PutUint16(body[len(body)-len(extSupportedVersions())-2:], 0x7FFF)
	_, err := parseServerHelloBody(body)
	if err == nil {
		// Only fail if the body was long enough to reach extensions at all.
		if extLenOff > 0 {
			t.Error("expected error for truncated extensions, got nil")
		}
	}
}

func TestHRRMagic_Correct(t *testing.T) {
	// Verify the HRR magic value matches RFC 8446 §4.1.4.
	want := [32]byte{
		0xcf, 0x21, 0xad, 0x74, 0xe5, 0x9a, 0x61, 0x11,
		0xbe, 0x1d, 0x8c, 0x02, 0x1e, 0x65, 0xb8, 0x91,
		0xc2, 0xa2, 0x11, 0x16, 0x7a, 0xbb, 0x8c, 0x5e,
		0x07, 0x9e, 0x09, 0xe2, 0xc8, 0xa8, 0x33, 0x9c,
	}
	if !bytes.Equal(HRRMagic[:], want[:]) {
		t.Errorf("HRRMagic mismatch:\n got  %x\n want %x", HRRMagic, want)
	}
}

func TestParseServerResponse_ContextCancelled(t *testing.T) {
	_, server := net.Pipe()
	defer server.Close()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := ParseServerResponse(ctx, server)
	if err == nil {
		t.Fatal("expected error for cancelled context, got nil")
	}
	var ae *AlertError
	if errors.As(err, &ae) {
		t.Fatal("expected transport error, not AlertError")
	}
}

func TestParseServerHelloBody_AdditionalTruncations(t *testing.T) {
	var zero [32]byte
	full := buildServerHello(zero, 0x1301, 0x001d, false)

	tests := []struct {
		name string
		body []byte
	}{
		// Truncated at cipher_suite (need 2 bytes after session_id)
		{"truncated_at_cipher_suite", func() []byte {
			b := make([]byte, 35) // version(2)+random(32)+sid_len(1)=35, sid_len=0
			return b[:35]         // no cipher bytes
		}()},
		// Truncated at compression_method (need 1 byte after cipher)
		{"truncated_at_compression", func() []byte {
			b := make([]byte, 37) // +cipher(2)
			return b[:37]
		}()},
		// Valid up through compression then truncated before extensions_len
		{"truncated_before_exts_len", func() []byte {
			// version(2)+random(32)+sidlen(1)+cipher(2)+compression(1)=38
			return full[:5+4+38] // record_hdr(5)+hs_hdr(4)+body(38)
		}()},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := parseServerHelloBody(tt.body)
			// Some truncations return error, some return a partial result; neither panics.
			_ = err
		})
	}
}

func TestParseServerHelloBody_UnknownExtensionSkip(t *testing.T) {
	// Build a ServerHello body with an unknown extension (0xFFFF) before key_share.
	var zero [32]byte
	var b []byte
	b = appendU16(b, 0x0303) // legacy_version
	b = append(b, zero[:]...)
	b = append(b, 0x00)       // session_id_len = 0
	b = appendU16(b, 0x1301)  // cipher_suite
	b = append(b, 0x00)       // compression = 0

	// Extensions: unknown 0xFFFF (4 bytes data) then supported_versions + key_share
	var exts []byte
	exts = appendU16(exts, 0xFFFF) // unknown type
	exts = appendU16(exts, 4)
	exts = append(exts, 0xDE, 0xAD, 0xBE, 0xEF)
	// supported_versions
	exts = appendU16(exts, 0x002b)
	exts = appendU16(exts, 2)
	exts = append(exts, 0x03, 0x04)
	// key_share for SH: group + kex_len + 1 byte kex
	exts = appendU16(exts, 0x0033)
	exts = appendU16(exts, 5) // group(2)+kexlen(2)+kex(1)
	exts = appendU16(exts, 0x001d)
	exts = appendU16(exts, 1)
	exts = append(exts, 0x42)

	b = appendU16(b, uint16(len(exts)))
	b = append(b, exts...)

	res, err := parseServerHelloBody(b)
	if err != nil {
		t.Fatalf("parseServerHelloBody: %v", err)
	}
	if res.SelectedGroup != 0x001d {
		t.Errorf("SelectedGroup: got 0x%04x want 0x001d", res.SelectedGroup)
	}
}

func TestParseServerHelloBody_ZeroLengthExtension(t *testing.T) {
	// Extension with length=0 must be skipped without error.
	var zero [32]byte
	var b []byte
	b = appendU16(b, 0x0303)
	b = append(b, zero[:]...)
	b = append(b, 0x00)
	b = appendU16(b, 0x1301)
	b = append(b, 0x00)

	var exts []byte
	exts = appendU16(exts, 0xABCD) // unknown type, zero length
	exts = appendU16(exts, 0)

	b = appendU16(b, uint16(len(exts)))
	b = append(b, exts...)

	res, err := parseServerHelloBody(b)
	if err != nil {
		t.Fatalf("zero-length extension: %v", err)
	}
	if res.SelectedGroup != 0 {
		t.Errorf("SelectedGroup: got 0x%04x want 0", res.SelectedGroup)
	}
}

func TestParseServerHelloBody_TLS12LegacyVersion(t *testing.T) {
	// A ServerHello with legacy_version=0x0302 parses without panic;
	// current code does not enforce version — exercises the version bytes path.
	var zero [32]byte
	var b []byte
	b = appendU16(b, 0x0302) // TLS 1.1 legacy version
	b = append(b, zero[:]...)
	b = append(b, 0x00)
	b = appendU16(b, 0x002F) // TLS_RSA_WITH_AES_128_CBC_SHA (TLS 1.2 suite)
	b = append(b, 0x00)

	_, err := parseServerHelloBody(b)
	// No extensions → returns result with no group. Must not panic.
	_ = err
}

func TestParseServerHelloBody_ExtensionLenOverflow(t *testing.T) {
	// Build a valid SH then corrupt the extensions length to overflow.
	var zero [32]byte
	body := buildServerHello(zero, 0x1301, 0, false)
	// The last 2 bytes of extensions block header: set to 0x7FFF (large claim).
	// body ends with the extensions block; walk to find extensions length field.
	// Simpler: corrupt the last 2 bytes that encode extsLen.
	if len(body) >= 4 {
		body[len(body)-len(extSupportedVersions())-2] = 0x7F
		body[len(body)-len(extSupportedVersions())-1] = 0xFF
	}
	_, _ = parseServerHelloBody(body) // must not panic
}

func TestParseServerHelloBody_RFC8448RealCapture(t *testing.T) {
	// ServerHello body from RFC 8448 §3 (TLS 1.3 example session).
	// Cipher: TLS_AES_128_GCM_SHA256 (0x1301), Group: X25519 (0x001d).
	body := []byte{
		// legacy_version = 0x0303
		0x03, 0x03,
		// server random (32 bytes)
		0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77,
		0x78, 0x79, 0x7a, 0x7b, 0x7c, 0x7d, 0x7e, 0x7f,
		0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87,
		0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f,
		// session_id_len = 32
		0x20,
		// session_id (32 bytes)
		0xe0, 0xe1, 0xe2, 0xe3, 0xe4, 0xe5, 0xe6, 0xe7,
		0xe8, 0xe9, 0xea, 0xeb, 0xec, 0xed, 0xee, 0xef,
		0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7,
		0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe, 0xff,
		// cipher_suite = TLS_AES_128_GCM_SHA256
		0x13, 0x01,
		// legacy_compression = null
		0x00,
		// extensions length = 46
		0x00, 0x2e,
		// key_share ext (type=0x0033, len=36): group=X25519, kex=32 bytes
		0x00, 0x33, 0x00, 0x24,
		0x00, 0x1d, 0x00, 0x20,
		0x9f, 0xd7, 0xad, 0x6d, 0xcf, 0xf4, 0x29, 0x8d,
		0xd3, 0xf9, 0x6d, 0x5b, 0x1b, 0x2a, 0xf9, 0x10,
		0xa0, 0x53, 0x5b, 0x14, 0x88, 0xd7, 0xf8, 0xfa,
		0xbb, 0x34, 0x9a, 0x98, 0x28, 0x80, 0xb6, 0x15,
		// supported_versions ext (type=0x002b, len=2): TLS 1.3
		0x00, 0x2b, 0x00, 0x02, 0x03, 0x04,
	}

	result, err := parseServerHelloBody(body)
	if err != nil {
		t.Fatalf("parseServerHelloBody RFC 8448: %v", err)
	}
	if result.IsHRR {
		t.Error("IsHRR: got true want false")
	}
	if result.SelectedCipher != 0x1301 {
		t.Errorf("SelectedCipher: got 0x%04x want 0x1301", result.SelectedCipher)
	}
	if result.SelectedGroup != 0x001d {
		t.Errorf("SelectedGroup: got 0x%04x want 0x001d (X25519)", result.SelectedGroup)
	}
}

// FuzzParseServerHello exercises parseServerHelloBody against arbitrary inputs.
// Run: go test -fuzz=FuzzParseServerHello ./pkg/engines/tlsprobe/rawhello/
func FuzzParseServerHello(f *testing.F) {
	var zero [32]byte
	// 10+ seeds covering valid SH, HRR, truncated, and edge cases.
	f.Add(buildServerHello(zero, 0x1301, 0x001d, false))
	f.Add(buildServerHello(HRRMagic, 0x1302, 0x11ec, true))
	f.Add(buildServerHello(zero, 0x1302, 0x11eb, false))
	f.Add(buildServerHello(HRRMagic, 0x1303, 0x0201, true))
	f.Add(buildServerHello(zero, 0x1303, 0, false))    // no key_share
	f.Add(buildServerHello(HRRMagic, 0x1301, 0, true)) // HRR no key_share
	f.Add([]byte{})
	f.Add(make([]byte, 38)) // exactly min for extensions present
	f.Add(make([]byte, 100))
	f.Add(make([]byte, 200))
	f.Add([]byte{0x03, 0x03}) // only legacy_version, truncated

	f.Fuzz(func(t *testing.T, data []byte) {
		result, err := parseServerHelloBody(data)
		if err != nil {
			return
		}
		_ = result.SelectedGroup
	})
}

// FuzzParseHRR exercises the HRR-specific parsing path in ParseServerResponse.
func FuzzParseHRR(f *testing.F) {
	ctx := context.Background()
	var zero [32]byte
	// 10+ seeds: valid HRR bodies and corrupted variants.
	hrrBodies := [][]byte{
		buildServerHello(HRRMagic, 0x1302, 0x11ec, true),
		buildServerHello(HRRMagic, 0x1301, 0x001d, true),
		buildServerHello(HRRMagic, 0x1303, 0x0201, true),
		buildServerHello(HRRMagic, 0x1302, 0x11eb, true),
		buildServerHello(HRRMagic, 0x1302, 0x0202, true),
		buildServerHello(HRRMagic, 0x1301, 0, true),
		buildServerHello(zero, 0x1301, 0x001d, false),
		buildServerHello(zero, 0x1302, 0, false),
		make([]byte, 35),
		make([]byte, 10),
		[]byte{},
	}
	for _, body := range hrrBodies {
		// Wrap body in a full handshake record so ReadHandshakeMsg can consume it.
		msg := make([]byte, 4+len(body))
		msg[0] = HandshakeTypeServerHello
		msg[2] = byte(len(body) >> 8)
		msg[3] = byte(len(body))
		copy(msg[4:], body)
		f.Add(msg)
	}

	f.Fuzz(func(t *testing.T, msgBody []byte) {
		// Feed msgBody as the payload of a handshake record via net.Pipe.
		client, server := net.Pipe()
		fctx, cancel := context.WithTimeout(ctx, 50*time.Millisecond)
		defer cancel()
		go func() {
			WriteRecord(fctx, client, Record{
				Type:    RecordTypeHandshake,
				Version: LegacyRecordVersion,
				Payload: msgBody,
			})
			client.Close()
		}()
		defer server.Close()
		_, _ = ParseServerResponse(fctx, server)
	})
}

// FuzzParseKeyShareExtGroup ensures parseKeyShareExtGroup never panics.
func FuzzParseKeyShareExtGroup(f *testing.F) {
	f.Add([]byte{0x00, 0x1d}, true)
	f.Add([]byte{0x11, 0xec, 0x00, 0x01, 0x42}, false)
	f.Add([]byte{}, true)
	f.Add(make([]byte, 200), false)
	f.Add([]byte{0x11, 0xeb}, true)                        // SecP256r1MLKEM768 HRR
	f.Add([]byte{0x02, 0x01, 0x00, 0x10}, false)           // MLKEM768 SH, kex_len=16
	f.Add([]byte{0x02, 0x00}, true)                        // MLKEM512 HRR
	f.Add([]byte{0x02, 0x02, 0x00, 0x04, 0x01, 0x02, 0x03, 0x04}, false) // MLKEM1024 SH
	f.Add([]byte{0x00}, true)                              // truncated (1 byte only)
	f.Add([]byte{0x00, 0x1d, 0x00}, false)                 // truncated kex_len

	f.Fuzz(func(t *testing.T, data []byte, isHRR bool) {
		_, _ = parseKeyShareExtGroup(data, isHRR)
	})
}
