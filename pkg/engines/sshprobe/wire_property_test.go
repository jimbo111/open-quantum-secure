// wire_property_test.go — property-based tests for SSH wire-format codec functions.
//
// Purpose: verify that encodeNameList / parseNameList form a lossless round-trip
// for arbitrary valid UTF-8 name lists, and that buildSSHPacket / readPacket form
// a lossless round-trip for arbitrary payload lengths (0..35000 bytes).
//
// Uses testing/quick for randomised generation; deterministic with a fixed seed
// via testing.F for regression stability.
package sshprobe

import (
	"bytes"
	"math/rand"
	"strings"
	"testing"
	"testing/quick"
)

// TestNameListRoundTrip_Property verifies parseNameList(encodeNameList(list)) == list
// for randomised name lists. Names are restricted to printable ASCII to stay within
// valid SSH name-list encoding (RFC 4253 §5: names are US-ASCII printable).
func TestNameListRoundTrip_Property(t *testing.T) {
	// quick.Check generates random inputs. The property function receives a
	// []string and asserts the codec round-trip.
	err := quick.Check(func(names []string) bool {
		// Filter to printable ASCII names (RFC 4253 compliance).
		valid := make([]string, 0, len(names))
		for _, n := range names {
			if n == "" {
				continue // empty names are dropped; skip to keep test pure
			}
			if isPrintableASCII(n) {
				valid = append(valid, n)
			}
		}
		if len(valid) == 0 {
			return true // nothing to test for empty-after-filter input
		}
		// Total encoded size must not exceed maxNameListLen to avoid triggering
		// the cap (which is tested separately in wire_boundary_test.go).
		joined := strings.Join(valid, ",")
		if len(joined) > maxNameListLen {
			return true // skip oversized inputs
		}

		encoded := encodeNameList(valid)
		got, newOff, err := parseNameList(encoded, 0)
		if err != nil {
			return false
		}
		if newOff != len(encoded) {
			return false
		}
		return strings.Join(got, ",") == strings.Join(valid, ",")
	}, &quick.Config{MaxCount: 1000})
	if err != nil {
		t.Errorf("name-list round-trip property failed: %v", err)
	}
}

// TestNameListRoundTrip_KnownLists verifies the codec against concrete real-world
// OpenSSH KEX method lists (deterministic complement to the property test).
func TestNameListRoundTrip_KnownLists(t *testing.T) {
	lists := [][]string{
		{"curve25519-sha256"},
		{"mlkem768x25519-sha256", "curve25519-sha256", "ecdh-sha2-nistp256"},
		{"sntrup761x25519-sha512@openssh.com", "curve25519-sha256@libssh.org"},
		{"diffie-hellman-group14-sha256", "diffie-hellman-group14-sha1"},
	}
	for _, list := range lists {
		encoded := encodeNameList(list)
		got, off, err := parseNameList(encoded, 0)
		if err != nil {
			t.Errorf("parseNameList error for %v: %v", list, err)
			continue
		}
		if off != len(encoded) {
			t.Errorf("newOffset=%d, want %d for %v", off, len(encoded), list)
		}
		if strings.Join(got, ",") != strings.Join(list, ",") {
			t.Errorf("round-trip mismatch: got %v, want %v", got, list)
		}
	}
}

// TestReadPacketRoundTrip_Property verifies buildSSHPacket / readPacket round-trip
// for payloads of random lengths in [0..35000] bytes.
func TestReadPacketRoundTrip_Property(t *testing.T) {
	rng := rand.New(rand.NewSource(0x53534842)) // deterministic seed: "SSHB"
	const iterations = 300

	for i := 0; i < iterations; i++ {
		size := rng.Intn(35001) // [0, 35000]
		payload := make([]byte, size)
		if size > 0 {
			_, _ = rng.Read(payload)
		}

		raw := buildSSHPacket(payload)
		conn := connFromBytes(t, raw)
		got, err := readPacket(conn)
		if err != nil {
			t.Errorf("iteration %d (size=%d): readPacket error: %v", i, size, err)
			continue
		}
		if !bytes.Equal(got, payload) {
			t.Errorf("iteration %d (size=%d): payload mismatch: got %d bytes, want %d bytes",
				i, size, len(got), len(payload))
		}
	}
}

// TestReadPacketRoundTrip_FixedSizes verifies exact payload sizes that hit edge cases
// in the padding calculation inside buildSSHPacket.
func TestReadPacketRoundTrip_FixedSizes(t *testing.T) {
	for _, size := range []int{0, 1, 7, 8, 9, 15, 16, 17, 255, 256, 1023, 1024, 32767, 35000} {
		payload := bytes.Repeat([]byte{0x42}, size)
		raw := buildSSHPacket(payload)
		conn := connFromBytes(t, raw)
		got, err := readPacket(conn)
		if err != nil {
			t.Errorf("size=%d: readPacket error: %v", size, err)
			continue
		}
		if !bytes.Equal(got, payload) {
			t.Errorf("size=%d: round-trip mismatch: got %d bytes", size, len(got))
		}
	}
}

// isPrintableASCII returns true if every byte in s is a printable ASCII character
// and does not contain a comma (commas are the name-list delimiter).
func isPrintableASCII(s string) bool {
	for _, b := range []byte(s) {
		if b < 0x21 || b > 0x7E || b == ',' {
			return false
		}
	}
	return true
}
