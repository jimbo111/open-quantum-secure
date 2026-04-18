package rawhello

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"net"
	"testing"
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
// it to conn. Used in tests to simulate a server response.
func sendServerHello(t *testing.T, conn net.Conn, ctx context.Context, random [32]byte, cipherSuite uint16, groupID uint16, isHRR bool) {
	t.Helper()
	body := buildServerHello(random, cipherSuite, groupID, isHRR)
	msg := make([]byte, 4+len(body))
	msg[0] = HandshakeTypeServerHello
	msg[1] = 0
	msg[2] = byte(len(body) >> 8)
	msg[3] = byte(len(body))
	copy(msg[4:], body)
	err := WriteRecord(ctx, conn, Record{
		Type:    RecordTypeHandshake,
		Version: LegacyRecordVersion,
		Payload: msg,
	})
	if err != nil {
		t.Fatalf("sendServerHello WriteRecord: %v", err)
	}
}

func TestParseServerResponse_NormalServerHello(t *testing.T) {
	var random [32]byte
	random[0] = 0x42 // non-HRR random

	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	ctx := context.Background()
	go sendServerHello(t, client, ctx, random, 0x1301, 0x001d, false)

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
	go sendServerHello(t, client, ctx, HRRMagic, 0x1302, 0x11ec, true)

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

// FuzzParseServerHello exercises parseServerHelloBody against arbitrary inputs.
// Run: go test -fuzz=FuzzParseServerHello ./pkg/engines/tlsprobe/rawhello/
func FuzzParseServerHello(f *testing.F) {
	// Seed with valid SH bodies.
	var random [32]byte
	f.Add(buildServerHello(random, 0x1301, 0x001d, false))
	f.Add(buildServerHello(HRRMagic, 0x1302, 0x11ec, true))
	f.Add([]byte{})
	f.Add(make([]byte, 100))

	f.Fuzz(func(t *testing.T, data []byte) {
		// Must not panic on any input.
		result, err := parseServerHelloBody(data)
		if err != nil {
			return
		}
		// If it succeeded, SelectedGroup must be a sane uint16.
		_ = result.SelectedGroup
	})
}

// FuzzParseKeyShareExtGroup ensures parseKeyShareExtGroup never panics.
func FuzzParseKeyShareExtGroup(f *testing.F) {
	f.Add([]byte{0x00, 0x1d}, true)
	f.Add([]byte{0x11, 0xec, 0x00, 0x01, 0x42}, false)
	f.Add([]byte{}, true)
	f.Add(make([]byte, 200), false)

	f.Fuzz(func(t *testing.T, data []byte, isHRR bool) {
		_, _ = parseKeyShareExtGroup(data, isHRR)
	})
}
