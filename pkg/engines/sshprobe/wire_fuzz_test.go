// wire_fuzz_test.go — fuzz tests for the SSH wire-format parsing functions.
//
// Purpose: drive FuzzReadBanner, FuzzReadPacket, and FuzzParseNameList with
// structured seed corpus (valid SSH captures + malformed variants) and assert
// that no input causes a panic. Each fuzzer is seeded with real-world values
// synthesised from RFC 4253 §4, §6 and the OpenSSH 7.4/8.5/9.0/10.0 defaults.
//
// Run with:
//   go test -fuzz=FuzzReadBanner   -fuzztime=60s ./pkg/engines/sshprobe/
//   go test -fuzz=FuzzReadPacket   -fuzztime=60s ./pkg/engines/sshprobe/
//   go test -fuzz=FuzzParseNameList -fuzztime=60s ./pkg/engines/sshprobe/
package sshprobe

import (
	"bytes"
	"encoding/binary"
	"net"
	"strings"
	"testing"
	"time"
)

// fuzzConnFromBytes wraps data in a net.Conn-like pipe with a short deadline so
// fuzz iterations don't block indefinitely on partial reads.
func fuzzConnFromBytes(data []byte) net.Conn {
	client, server := net.Pipe()
	_ = client.SetDeadline(time.Now().Add(2 * time.Second))
	_ = server.SetDeadline(time.Now().Add(2 * time.Second))
	go func() {
		_, _ = server.Write(data)
		server.Close()
	}()
	return client
}

// FuzzReadBanner feeds arbitrary byte sequences to readBanner and asserts no panic.
// Seeds:
//   - valid OpenSSH banners (7.4, 8.5, 9.0, 10.0)
//   - truncated banner (no newline)
//   - zero-length input
//   - max-length content without newline
//   - embedded NUL bytes
//   - CRLF injection (\r\n in the middle of the string)
//   - invalid UTF-8 sequences
func FuzzReadBanner(f *testing.F) {
	// Valid seeds from OpenSSH history
	f.Add([]byte("SSH-2.0-OpenSSH_7.4\r\n"))
	f.Add([]byte("SSH-2.0-OpenSSH_8.5\r\n"))
	f.Add([]byte("SSH-2.0-OpenSSH_9.0\r\n"))
	f.Add([]byte("SSH-2.0-OpenSSH_10.0\r\n"))
	f.Add([]byte("SSH-2.0-dropbear_2022.83\r\n"))
	f.Add([]byte("SSH-1.99-OpenSSH_3.8p1\r\n"))

	// Malformed variants
	f.Add([]byte{}) // zero-length
	f.Add([]byte("SSH-2.0-OpenSSH_9.0")) // no newline — truncated
	f.Add(bytes.Repeat([]byte("A"), maxBannerLen+50)) // exceeds cap, no newline
	f.Add([]byte("SSH-2.0-\x00NUL\r\n")) // embedded NUL
	f.Add([]byte("SSH-2.0-test\r\nEXTRA")) // extra bytes after banner
	f.Add([]byte("\r\n")) // bare CRLF — empty banner
	f.Add([]byte{0xFF, 0xFE, 0xFD, '\n'}) // invalid UTF-8 before newline
	f.Add([]byte("SSH-2.0-\xc3\x28\r\n")) // invalid UTF-8 sequence mid-banner

	f.Fuzz(func(t *testing.T, data []byte) {
		conn := fuzzConnFromBytes(data)
		defer conn.Close()
		// Must not panic — error is expected for malformed input.
		_, _ = readBanner(conn)
	})
}

// FuzzReadPacket feeds arbitrary byte sequences to readPacket and asserts no panic.
// Seeds:
//   - valid SSH binary packets with KEXINIT payload
//   - truncated (only 4-byte length header)
//   - zero-length packet_length field bytes
//   - max packet_length (256 KB)
//   - oversized claimed length (0xFFFFFFFF)
//   - padding_length larger than body
//   - single-byte payload
func FuzzReadPacket(f *testing.F) {
	// Build valid seed packets using the helper from wire_test.go.
	validPayload := []byte{sshMsgKexInit, 1, 2, 3}
	f.Add(buildSSHPacket(validPayload))

	// Minimal valid packet (padding_length + 1 byte payload)
	f.Add(buildSSHPacket([]byte{42}))

	// Truncated: just the length field, no body
	f.Add([]byte{0, 0, 0, 10})

	// Zero-length packet_length
	hdr := make([]byte, 4)
	binary.BigEndian.PutUint32(hdr, 0)
	f.Add(hdr)

	// packet_length = 1 (below minimum of 2)
	hdr1 := make([]byte, 4)
	binary.BigEndian.PutUint32(hdr1, 1)
	f.Add(hdr1)

	// packet_length exactly at maxPacketLen
	hdrMax := make([]byte, 4)
	binary.BigEndian.PutUint32(hdrMax, uint32(maxPacketLen))
	f.Add(hdrMax) // no body — body read will fail, but no panic

	// packet_length > maxPacketLen (0xFFFFFFFF)
	hdrBig := make([]byte, 4)
	binary.BigEndian.PutUint32(hdrBig, 0xFFFFFFFF)
	f.Add(hdrBig)

	// padding_length == body length (payloadLen would be 0 or negative)
	// packet_length = 5: body[0]=padding_length=4, body[1..4]=payload, no room
	body5 := make([]byte, 9) // 4-byte hdr + 5-byte body
	binary.BigEndian.PutUint32(body5[:4], 5)
	body5[4] = 4 // padding = 4, payload = 0
	f.Add(body5)

	f.Fuzz(func(t *testing.T, data []byte) {
		conn := fuzzConnFromBytes(data)
		defer conn.Close()
		_, _ = readPacket(conn)
	})
}

// FuzzParseNameList feeds arbitrary byte payloads to parseNameList and asserts no panic.
// Property check: if parsing succeeds and the input was produced by encodeNameList,
// the round-trip must recover the original list.
// Seeds:
//   - real-world OpenSSH 7.4/8.5/9.0/10.0 kex name-list encodings
//   - zero-length list
//   - billion-comma injection (large name-list with many empty entries)
//   - embedded NUL bytes inside names
//   - invalid UTF-8 bytes within names
//   - claimed length exceeding actual payload
//   - claimed length 0xFFFFFFFF
func FuzzParseNameList(f *testing.F) {
	// Valid seeds: real OpenSSH kex advertisements
	openssh74 := []string{
		"curve25519-sha256", "curve25519-sha256@libssh.org",
		"ecdh-sha2-nistp256", "ecdh-sha2-nistp384", "ecdh-sha2-nistp521",
		"diffie-hellman-group-exchange-sha256", "diffie-hellman-group14-sha256",
		"diffie-hellman-group14-sha1",
	}
	f.Add(encodeNameList(openssh74))

	openssh85 := []string{
		"sntrup761x25519-sha512@openssh.com",
		"curve25519-sha256", "curve25519-sha256@libssh.org",
		"ecdh-sha2-nistp256", "ecdh-sha2-nistp384", "ecdh-sha2-nistp521",
		"diffie-hellman-group-exchange-sha256", "diffie-hellman-group16-sha512",
		"diffie-hellman-group18-sha512", "diffie-hellman-group14-sha256",
	}
	f.Add(encodeNameList(openssh85))

	openssh100 := []string{
		"mlkem768x25519-sha256",
		"curve25519-sha256", "curve25519-sha256@libssh.org",
		"ecdh-sha2-nistp256", "ecdh-sha2-nistp384", "ecdh-sha2-nistp521",
		"diffie-hellman-group-exchange-sha256", "diffie-hellman-group16-sha512",
		"diffie-hellman-group18-sha512", "diffie-hellman-group14-sha256",
	}
	f.Add(encodeNameList(openssh100))

	// Empty list
	f.Add(encodeNameList(nil))

	// Single name
	f.Add(encodeNameList([]string{"curve25519-sha256"}))

	// Billion-comma injection: a single 64-KB buffer of commas
	commas := bytes.Repeat([]byte(","), maxNameListLen)
	commaPayload := make([]byte, 4+len(commas))
	binary.BigEndian.PutUint32(commaPayload[:4], uint32(len(commas)))
	copy(commaPayload[4:], commas)
	f.Add(commaPayload)

	// Claimed length 0xFFFFFFFF (must reject immediately)
	bigLen := make([]byte, 4)
	binary.BigEndian.PutUint32(bigLen, 0xFFFFFFFF)
	f.Add(bigLen)

	// Payload shorter than claimed length
	shortPayload := make([]byte, 4+2)
	binary.BigEndian.PutUint32(shortPayload[:4], 100)
	f.Add(shortPayload)

	// Embedded NUL in name
	nullName := encodeNameList([]string{"curve25519\x00-sha256"})
	f.Add(nullName)

	// Invalid UTF-8 inside name
	invalidUTF8 := encodeNameList([]string{"mlkem768\xc3\x28-sha256"})
	f.Add(invalidUTF8)

	// CRLF injection inside name
	crlfName := encodeNameList([]string{"diffie-hellman\r\ninjection"})
	f.Add(crlfName)

	// Max-length single name (at the 64 KB cap)
	maxName := strings.Repeat("x", maxNameListLen)
	f.Add(encodeNameList([]string{maxName}))

	f.Fuzz(func(t *testing.T, data []byte) {
		// Must not panic regardless of input.
		names, _, _ := parseNameList(data, 0)

		// Property: if the data was produced by encodeNameList, parsed names must
		// be decodable back to the same content.
		// We can't verify round-trip in fuzz mode (input is mutated), but we CAN
		// verify internal consistency: re-encoding the parsed names and parsing again
		// must produce the same list.
		if len(names) > 0 {
			re := encodeNameList(names)
			names2, _, err2 := parseNameList(re, 0)
			if err2 != nil {
				t.Errorf("re-encoding parsed names failed: %v", err2)
				return
			}
			if strings.Join(names2, ",") != strings.Join(names, ",") {
				t.Errorf("round-trip mismatch: %v vs %v", names, names2)
			}
		}
	})
}
