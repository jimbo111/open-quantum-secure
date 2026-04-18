package rawhello

import (
	"bytes"
	"context"
	"errors"
	"net"
	"testing"
)

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
		// Write a raw header with length = MaxRecordLen+1
		hdr := [5]byte{
			RecordTypeHandshake,
			byte(LegacyRecordVersion >> 8),
			byte(LegacyRecordVersion),
			byte((MaxRecordLen + 1) >> 8),
			byte(MaxRecordLen + 1),
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
