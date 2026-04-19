// Package rawhello provides a pure-Go raw TLS 1.3 ClientHello builder and
// response parser. It is used by the --deep-probe flag to test arbitrary PQC
// group codepoints that Go's stdlib crypto/tls does not expose as CurveIDs.
package rawhello

import (
	"context"
	"fmt"
	"net"
	"time"
)

// TLS record content types (RFC 5246 §6.2.1, RFC 8446 §5.1).
const (
	RecordTypeChangeCipherSpec uint8 = 0x14
	RecordTypeAlert            uint8 = 0x15
	RecordTypeHandshake        uint8 = 0x16
	RecordTypeApplicationData  uint8 = 0x17
)

// LegacyRecordVersion is placed in every TLS record header for middlebox compat.
// TLS 1.3 mandates 0x0303 for records carrying ClientHello (RFC 8446 §5.1).
const LegacyRecordVersion uint16 = 0x0303

// MaxRecordLen is the maximum TLS plaintext record payload length per RFC 5246 §6.2.1.
// 2^14 + 256 = 16640 bytes. Records exceeding this are rejected to prevent OOM.
const MaxRecordLen = 16640

// MaxHandshakeMsgLen caps handshake message bodies. RFC 8446 §4 allows a 3-byte
// (uint24) length field = 16MB, but we cap at 65535 to guard against OOM on
// malformed server responses.
const MaxHandshakeMsgLen = 65535

// maxRecordsPerMsg caps the number of TLS records reassembled into a single
// handshake message. A legitimate ServerHello fits in 1–3 records; 256 is a
// generous upper bound that prevents an adversarial server from keeping the
// read loop alive indefinitely.
const maxRecordsPerMsg = 256

// ioTimeout is the fallback per-operation deadline used when ctx carries no deadline.
const ioTimeout = 15 * time.Second

// Record is a single TLS record.
type Record struct {
	Type    uint8
	Version uint16
	Payload []byte
}

// WriteRecord serialises rec to conn as a 5-byte TLS record header followed by
// the payload. Enforces ctx.Done cancellation and MaxRecordLen.
func WriteRecord(ctx context.Context, conn net.Conn, rec Record) error {
	if len(rec.Payload) > MaxRecordLen {
		return fmt.Errorf("rawhello: WriteRecord: payload %d bytes exceeds MaxRecordLen %d",
			len(rec.Payload), MaxRecordLen)
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	conn.SetWriteDeadline(effectiveDeadline(ctx)) //nolint:errcheck

	buf := make([]byte, 5+len(rec.Payload))
	buf[0] = rec.Type
	buf[1] = byte(rec.Version >> 8)
	buf[2] = byte(rec.Version)
	buf[3] = byte(len(rec.Payload) >> 8)
	buf[4] = byte(len(rec.Payload))
	copy(buf[5:], rec.Payload)

	_, err := conn.Write(buf)
	return err
}

// ReadRecord reads exactly one TLS record from conn.
// Returns an error if the record payload length exceeds MaxRecordLen.
func ReadRecord(ctx context.Context, conn net.Conn) (Record, error) {
	if err := ctx.Err(); err != nil {
		return Record{}, err
	}
	conn.SetReadDeadline(effectiveDeadline(ctx)) //nolint:errcheck

	var hdr [5]byte
	if err := readFull(conn, hdr[:]); err != nil {
		return Record{}, fmt.Errorf("rawhello: ReadRecord header: %w", err)
	}

	recType := hdr[0]
	version := uint16(hdr[1])<<8 | uint16(hdr[2])
	length := int(hdr[3])<<8 | int(hdr[4])

	if length > MaxRecordLen {
		return Record{}, fmt.Errorf("rawhello: ReadRecord: length %d exceeds MaxRecordLen %d", length, MaxRecordLen)
	}

	payload := make([]byte, length)
	if length > 0 {
		if err := ctx.Err(); err != nil {
			return Record{}, err
		}
		conn.SetReadDeadline(effectiveDeadline(ctx)) //nolint:errcheck
		if err := readFull(conn, payload); err != nil {
			return Record{}, fmt.Errorf("rawhello: ReadRecord payload: %w", err)
		}
	}

	return Record{Type: recType, Version: version, Payload: payload}, nil
}

// ReadHandshakeMsg reads TLS records and reassembles exactly one complete
// handshake message. ServerHello can span multiple records per RFC 8446 §5.1,
// so this function buffers across records until a complete message is assembled.
//
// Alert records are detected immediately and returned as *AlertError — the
// caller should use errors.As to inspect the alert.
//
// Returns (msgType, msgBody, nil) on success where msgBody excludes the 4-byte
// handshake header (type + uint24 length).
func ReadHandshakeMsg(ctx context.Context, conn net.Conn) (msgType uint8, body []byte, err error) {
	var buf []byte
	for recordCount := 0; ; recordCount++ {
		if recordCount >= maxRecordsPerMsg {
			return 0, nil, fmt.Errorf("rawhello: ReadHandshakeMsg: exceeded %d-record cap without completing a message", maxRecordsPerMsg)
		}
		rec, err := ReadRecord(ctx, conn)
		if err != nil {
			return 0, nil, err
		}

		switch rec.Type {
		case RecordTypeAlert:
			if len(rec.Payload) < 2 {
				return 0, nil, fmt.Errorf("rawhello: malformed alert record (%d bytes)", len(rec.Payload))
			}
			return 0, nil, &AlertError{Level: rec.Payload[0], Description: rec.Payload[1]}

		case RecordTypeHandshake:
			buf = append(buf, rec.Payload...)

		default:
			// ChangeCipherSpec or ApplicationData during handshake: skip.
			continue
		}

		// Attempt to decode a complete handshake message from the buffer.
		// Handshake header: type(1) + length(3 bytes = uint24).
		for len(buf) >= 4 {
			mType := buf[0]
			mLen := int(uint32(buf[1])<<16 | uint32(buf[2])<<8 | uint32(buf[3]))
			if mLen > MaxHandshakeMsgLen {
				return 0, nil, fmt.Errorf("rawhello: handshake msg length %d exceeds cap %d", mLen, MaxHandshakeMsgLen)
			}
			if len(buf) < 4+mLen {
				break // need more records
			}
			msgBody := make([]byte, mLen)
			copy(msgBody, buf[4:4+mLen])
			return mType, msgBody, nil
		}
	}
}

// AlertError represents a TLS alert received from the server.
type AlertError struct {
	Level       uint8
	Description uint8
}

func (e *AlertError) Error() string {
	return fmt.Sprintf("rawhello: TLS alert level=%d desc=%d (%s)",
		e.Level, e.Description, alertDescName(e.Description))
}

// alertDescName maps alert description codes to human-readable names.
func alertDescName(d uint8) string {
	names := map[uint8]string{
		0:   "close_notify",
		10:  "unexpected_message",
		20:  "bad_record_mac",
		40:  "handshake_failure",
		42:  "bad_certificate",
		43:  "unsupported_certificate",
		44:  "certificate_revoked",
		45:  "certificate_expired",
		46:  "certificate_unknown",
		47:  "illegal_parameter",
		48:  "unknown_ca",
		49:  "access_denied",
		50:  "decode_error",
		51:  "decrypt_error",
		70:  "protocol_version",
		71:  "insufficient_security",
		80:  "internal_error",
		86:  "inappropriate_fallback",
		90:  "user_canceled",
		109: "missing_extension",
		110: "unsupported_extension",
		112: "unrecognized_name",
		116: "certificate_required",
		120: "no_application_protocol",
	}
	if name, ok := names[d]; ok {
		return name
	}
	return "unknown"
}

// effectiveDeadline returns the deadline to use for a socket operation.
// If ctx carries a deadline, that is used; otherwise the fallback ioTimeout
// is applied from now.
func effectiveDeadline(ctx context.Context) time.Time {
	if dl, ok := ctx.Deadline(); ok {
		return dl
	}
	return time.Now().Add(ioTimeout)
}

// readFull reads exactly len(buf) bytes from conn into buf.
// Returns an error if fewer bytes are available.
func readFull(conn net.Conn, buf []byte) error {
	total := 0
	for total < len(buf) {
		n, err := conn.Read(buf[total:])
		total += n
		if err != nil {
			if total == len(buf) {
				return nil
			}
			return err
		}
	}
	return nil
}
