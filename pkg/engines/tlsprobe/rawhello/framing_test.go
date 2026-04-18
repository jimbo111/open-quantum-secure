package rawhello

import (
	"bytes"
	"context"
	"errors"
	"net"
	"strings"
	"testing"
	"time"
)

// mockReadConn wraps a bytes.Reader as a net.Conn for fast unit/fuzz tests
// without creating OS sockets.
type mockReadConn struct {
	r *bytes.Reader
}

func (m *mockReadConn) Read(b []byte) (int, error)         { return m.r.Read(b) }
func (m *mockReadConn) Write(b []byte) (int, error)        { return len(b), nil }
func (m *mockReadConn) Close() error                       { return nil }
func (m *mockReadConn) LocalAddr() net.Addr                { return &net.TCPAddr{} }
func (m *mockReadConn) RemoteAddr() net.Addr               { return &net.TCPAddr{} }
func (m *mockReadConn) SetDeadline(t time.Time) error      { return nil }
func (m *mockReadConn) SetReadDeadline(t time.Time) error  { return nil }
func (m *mockReadConn) SetWriteDeadline(t time.Time) error { return nil }

func TestWriteReadRecord_Roundtrip(t *testing.T) {
	tests := []struct {
		name    string
		recType uint8
		payload []byte
	}{
		{"handshake_small", RecordTypeHandshake, []byte{0x01, 0x02, 0x03}},
		{"alert_2bytes", RecordTypeAlert, []byte{0x02, 0x28}},
		{"empty_payload", RecordTypeHandshake, []byte{}},
		{"max_payload", RecordTypeHandshake, bytes.Repeat([]byte{0xAB}, MaxRecordLen)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client, server := net.Pipe()
			defer client.Close()
			defer server.Close()

			ctx := context.Background()
			errCh := make(chan error, 1)
			go func() {
				errCh <- WriteRecord(ctx, client, Record{
					Type:    tt.recType,
					Version: LegacyRecordVersion,
					Payload: tt.payload,
				})
			}()

			got, err := ReadRecord(ctx, server)
			if err != nil {
				t.Fatalf("ReadRecord: %v", err)
			}
			if werr := <-errCh; werr != nil {
				t.Fatalf("WriteRecord: %v", werr)
			}
			if got.Type != tt.recType {
				t.Errorf("type: got %d want %d", got.Type, tt.recType)
			}
			if !bytes.Equal(got.Payload, tt.payload) {
				t.Errorf("payload mismatch: got %d bytes want %d bytes", len(got.Payload), len(tt.payload))
			}
		})
	}
}

func TestWriteRecord_TooLong(t *testing.T) {
	_, server := net.Pipe()
	defer server.Close()

	ctx := context.Background()
	err := WriteRecord(ctx, server, Record{
		Type:    RecordTypeHandshake,
		Version: LegacyRecordVersion,
		Payload: bytes.Repeat([]byte{0x00}, MaxRecordLen+1),
	})
	if err == nil {
		t.Fatal("expected error for oversized record, got nil")
	}
}

func TestReadRecord_TooLong(t *testing.T) {
	// Craft a record header that declares length > MaxRecordLen.
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	ctx := context.Background()
	go func() {
		// Use variables to avoid constant-overflow vet errors when converting
		// multi-byte constants (LegacyRecordVersion, MaxRecordLen) to byte.
		ver := LegacyRecordVersion
		overSize := MaxRecordLen + 1
		hdr := [5]byte{
			RecordTypeHandshake,
			byte(ver >> 8),
			byte(ver),
			byte(overSize >> 8),
			byte(overSize),
		}
		client.Write(hdr[:])
	}()

	_, err := ReadRecord(ctx, server)
	if err == nil {
		t.Fatal("expected error for oversized length header, got nil")
	}
}

func TestReadRecord_ContextCancelled(t *testing.T) {
	_, server := net.Pipe()
	defer server.Close()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := ReadRecord(ctx, server)
	if err == nil {
		t.Fatal("expected error for cancelled context, got nil")
	}
}

func TestWriteRecord_ContextCancelled(t *testing.T) {
	_, server := net.Pipe()
	defer server.Close()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	err := WriteRecord(ctx, server, Record{
		Type:    RecordTypeHandshake,
		Version: LegacyRecordVersion,
		Payload: []byte{0x01},
	})
	if err == nil {
		t.Fatal("expected error for cancelled context, got nil")
	}
}

func TestReadHandshakeMsg_SingleRecord(t *testing.T) {
	// Build a minimal handshake message: type(1) + length(3) + body.
	body := []byte{0xAA, 0xBB, 0xCC}
	msg := make([]byte, 4+len(body))
	msg[0] = HandshakeTypeServerHello
	msg[1] = 0
	msg[2] = 0
	msg[3] = byte(len(body))
	copy(msg[4:], body)

	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	ctx := context.Background()
	go func() {
		WriteRecord(ctx, client, Record{
			Type:    RecordTypeHandshake,
			Version: LegacyRecordVersion,
			Payload: msg,
		})
	}()

	mType, mBody, err := ReadHandshakeMsg(ctx, server)
	if err != nil {
		t.Fatalf("ReadHandshakeMsg: %v", err)
	}
	if mType != HandshakeTypeServerHello {
		t.Errorf("type: got 0x%02x want 0x%02x", mType, HandshakeTypeServerHello)
	}
	if !bytes.Equal(mBody, body) {
		t.Errorf("body mismatch")
	}
}

func TestReadHandshakeMsg_FragmentedAcrossRecords(t *testing.T) {
	body := bytes.Repeat([]byte{0x42}, 100)
	msg := make([]byte, 4+len(body))
	msg[0] = HandshakeTypeServerHello
	msg[1] = 0
	msg[2] = 0
	msg[3] = byte(len(body))
	copy(msg[4:], body)

	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	ctx := context.Background()
	go func() {
		// Fragment: send first 20 bytes in record 1, rest in record 2.
		WriteRecord(ctx, client, Record{Type: RecordTypeHandshake, Version: LegacyRecordVersion, Payload: msg[:20]})
		WriteRecord(ctx, client, Record{Type: RecordTypeHandshake, Version: LegacyRecordVersion, Payload: msg[20:]})
	}()

	mType, mBody, err := ReadHandshakeMsg(ctx, server)
	if err != nil {
		t.Fatalf("ReadHandshakeMsg: %v", err)
	}
	if mType != HandshakeTypeServerHello {
		t.Errorf("type: got 0x%02x", mType)
	}
	if !bytes.Equal(mBody, body) {
		t.Errorf("body mismatch: got %d bytes want %d bytes", len(mBody), len(body))
	}
}

func TestReadHandshakeMsg_AlertRecord(t *testing.T) {
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

	_, _, err := ReadHandshakeMsg(ctx, server)
	if err == nil {
		t.Fatal("expected AlertError, got nil")
	}
	var ae *AlertError
	if !errors.As(err, &ae) {
		t.Fatalf("expected *AlertError, got %T: %v", err, err)
	}
	if ae.Level != 0x02 {
		t.Errorf("alert level: got %d want 2", ae.Level)
	}
	if ae.Description != 0x28 {
		t.Errorf("alert desc: got %d want 40", ae.Description)
	}
}

func TestReadHandshakeMsg_SkipsChangeCipherSpec(t *testing.T) {
	body := []byte{0x01, 0x02}
	msg := make([]byte, 4+len(body))
	msg[0] = HandshakeTypeServerHello
	msg[1] = 0
	msg[2] = 0
	msg[3] = byte(len(body))
	copy(msg[4:], body)

	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	ctx := context.Background()
	go func() {
		// Send a ChangeCipherSpec first, then the real handshake record.
		WriteRecord(ctx, client, Record{Type: RecordTypeChangeCipherSpec, Version: LegacyRecordVersion, Payload: []byte{0x01}})
		WriteRecord(ctx, client, Record{Type: RecordTypeHandshake, Version: LegacyRecordVersion, Payload: msg})
	}()

	mType, _, err := ReadHandshakeMsg(ctx, server)
	if err != nil {
		t.Fatalf("ReadHandshakeMsg: %v", err)
	}
	if mType != HandshakeTypeServerHello {
		t.Errorf("type: got 0x%02x want 0x%02x", mType, HandshakeTypeServerHello)
	}
}

func TestAlertError_Error(t *testing.T) {
	ae := &AlertError{Level: 2, Description: 40}
	msg := ae.Error()
	if !strings.Contains(msg, "handshake_failure") {
		t.Errorf("want 'handshake_failure' in error string, got %q", msg)
	}
	if !strings.Contains(msg, "2") {
		t.Errorf("want level '2' in error string, got %q", msg)
	}
	// Unknown description maps to "unknown".
	ae2 := &AlertError{Level: 1, Description: 99}
	msg2 := ae2.Error()
	if !strings.Contains(msg2, "unknown") {
		t.Errorf("want 'unknown' in error string for code 99, got %q", msg2)
	}
}

func TestAlertDescName_KnownCodes(t *testing.T) {
	known := map[uint8]string{
		0: "close_notify", 10: "unexpected_message", 20: "bad_record_mac",
		40: "handshake_failure", 47: "illegal_parameter", 80: "internal_error",
		90: "user_canceled", 110: "unsupported_extension", 120: "no_application_protocol",
	}
	for code, want := range known {
		got := alertDescName(code)
		if got != want {
			t.Errorf("alertDescName(%d): got %q want %q", code, got, want)
		}
	}
	if alertDescName(99) != "unknown" {
		t.Errorf("alertDescName(99): want 'unknown'")
	}
}

func TestEffectiveDeadline_WithContextDeadline(t *testing.T) {
	dl := time.Now().Add(5 * time.Second)
	ctx, cancel := context.WithDeadline(context.Background(), dl)
	defer cancel()
	got := effectiveDeadline(ctx)
	if !got.Equal(dl) {
		t.Errorf("effectiveDeadline with ctx deadline: got %v want %v", got, dl)
	}
}

func TestEffectiveDeadline_WithoutDeadline(t *testing.T) {
	before := time.Now()
	got := effectiveDeadline(context.Background())
	if got.Before(before.Add(ioTimeout - time.Second)) {
		t.Errorf("effectiveDeadline without deadline: got %v, want ~now+%v", got, ioTimeout)
	}
}

func TestReadFull_PartialThenEOF(t *testing.T) {
	client, server := net.Pipe()
	go func() {
		client.Write([]byte{0x01, 0x02, 0x03}) // only 3 of 5 needed bytes
		client.Close()
	}()
	defer server.Close()
	buf := make([]byte, 5)
	if err := readFull(server, buf); err == nil {
		t.Fatal("expected error for partial read before EOF, got nil")
	}
}

func TestReadHandshakeMsg_OversizeHandshakeMsgLen(t *testing.T) {
	// Handshake record with uint24 length = 65536 > MaxHandshakeMsgLen (65535).
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	ctx := context.Background()
	go func() {
		payload := []byte{0x02, 0x01, 0x00, 0x00} // type=SH, len=0x010000=65536
		WriteRecord(ctx, client, Record{Type: RecordTypeHandshake, Version: LegacyRecordVersion, Payload: payload})
	}()
	_, _, err := ReadHandshakeMsg(ctx, server)
	if err == nil {
		t.Fatal("expected error for oversize handshake msg length, got nil")
	}
}

func TestReadHandshakeMsg_MalformedAlertRecord(t *testing.T) {
	// Alert record with only 1 byte — needs ≥2 for level+description.
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	ctx := context.Background()
	go func() {
		WriteRecord(ctx, client, Record{Type: RecordTypeAlert, Version: LegacyRecordVersion, Payload: []byte{0x02}})
	}()
	_, _, err := ReadHandshakeMsg(ctx, server)
	if err == nil {
		t.Fatal("expected error for malformed alert (1 byte), got nil")
	}
}

func TestReadRecord_ZeroLengthPayloadViaMock(t *testing.T) {
	// Five-byte header declaring zero-length payload: record is valid per RFC.
	wire := []byte{RecordTypeHandshake, 0x03, 0x03, 0x00, 0x00}
	conn := &mockReadConn{r: bytes.NewReader(wire)}
	got, err := ReadRecord(context.Background(), conn)
	if err != nil {
		t.Fatalf("ReadRecord zero-length: %v", err)
	}
	if len(got.Payload) != 0 {
		t.Errorf("expected empty payload, got %d bytes", len(got.Payload))
	}
}

func TestReadRecord_MaxLengthViaMock(t *testing.T) {
	payload := bytes.Repeat([]byte{0xAB}, MaxRecordLen)
	maxLen := MaxRecordLen
	hdr := []byte{RecordTypeHandshake, 0x03, 0x03, byte(maxLen >> 8), byte(maxLen)}
	wire := append(hdr, payload...)
	conn := &mockReadConn{r: bytes.NewReader(wire)}
	got, err := ReadRecord(context.Background(), conn)
	if err != nil {
		t.Fatalf("ReadRecord max-length: %v", err)
	}
	if len(got.Payload) != MaxRecordLen {
		t.Errorf("payload length: got %d want %d", len(got.Payload), MaxRecordLen)
	}
}

func TestReadRecord_InvalidContentType_PassThrough(t *testing.T) {
	// RFC 8446 §5.1: content_type is informational at the record layer.
	// ReadRecord returns unknown types as-is; higher layers (ReadHandshakeMsg)
	// skip them via the default case.
	for _, ctype := range []uint8{0x00, 0x01, 0xFF} {
		wire := []byte{ctype, 0x03, 0x03, 0x00, 0x01, 0x42}
		conn := &mockReadConn{r: bytes.NewReader(wire)}
		rec, err := ReadRecord(context.Background(), conn)
		if err != nil {
			t.Errorf("content type 0x%02x: unexpected error %v", ctype, err)
			continue
		}
		if rec.Type != ctype {
			t.Errorf("content type 0x%02x: got 0x%02x", ctype, rec.Type)
		}
	}
}

func TestReadRecord_LegacyVersionValues(t *testing.T) {
	// RFC 8446 §5.1: legacy_record_version MUST be ignored; ReadRecord accepts
	// any version field without error.
	for _, ver := range []uint16{0x0000, 0x0301, 0x0302, 0x0304, 0xFFFF} {
		wire := []byte{RecordTypeHandshake, byte(ver >> 8), byte(ver), 0x00, 0x01, 0x42}
		conn := &mockReadConn{r: bytes.NewReader(wire)}
		rec, err := ReadRecord(context.Background(), conn)
		if err != nil {
			t.Errorf("version 0x%04x: unexpected error %v", ver, err)
			continue
		}
		if rec.Version != ver {
			t.Errorf("version 0x%04x: got 0x%04x", ver, rec.Version)
		}
	}
}

// FuzzParseRecord exercises ReadRecord against arbitrary wire bytes without
// spawning OS sockets — must not panic on any input.
func FuzzParseRecord(f *testing.F) {
	seeds := [][]byte{
		{0x16, 0x03, 0x03, 0x00, 0x00},                                 // empty handshake
		{0x15, 0x03, 0x03, 0x00, 0x02, 0x02, 0x28},                     // fatal handshake_failure alert
		{0x14, 0x03, 0x03, 0x00, 0x01, 0x01},                           // ChangeCipherSpec
		{0x17, 0x03, 0x03, 0x00, 0x03, 0xAA, 0xBB, 0xCC},              // ApplicationData
		{0x16, 0x03, 0x01, 0x00, 0x03, 0x01, 0x02, 0x03},              // TLS 1.0 version
		{0x16, 0x03, 0x03},                                              // truncated header
		{0x16},                                                           // 1 byte
		{},                                                              // empty
		{0x16, 0x03, 0x03, 0x41, 0x00},                                 // declares MaxRecordLen
		{0x16, 0x03, 0x03, 0x41, 0x01},                                 // declares MaxRecordLen+1
		{0xFF, 0x03, 0x03, 0x00, 0x01, 0x42},                           // unknown record type
	}
	for _, s := range seeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		conn := &mockReadConn{r: bytes.NewReader(data)}
		_, _ = ReadRecord(context.Background(), conn)
	})
}
