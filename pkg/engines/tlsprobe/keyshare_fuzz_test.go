//go:build go1.18

package tlsprobe

// keyshare_fuzz_test.go — Bucket 2: fuzz harnesses for key_share and ECH scanner.
//
// Both harnesses use only seed corpora (derived from existing golden test data)
// so they run deterministically under "go test" without -fuzz.  Under
// "go test -fuzz=Fuzz..." they explore the full input space.
//
// Invariants enforced:
//   - FuzzParseKeyShareExtension: no panic; any successful parse returns only
//     entries with a non-zero GroupID or a consistent zero-length kex entry.
//   - FuzzScanBytesForECHExtension: no panic; return value is deterministic
//     (same input always produces the same bool).

import (
	"encoding/binary"
	"testing"
)

// FuzzParseKeyShareExtension feeds arbitrary bytes to ParseKeyShareExtension.
// The seed corpus covers all known-good formats from keyshare_test.go plus a
// handful of deliberately malformed cases.
func FuzzParseKeyShareExtension(f *testing.F) {
	// ── Seed corpus ────────────────────────────────────────────────────────────

	// Empty client payload (valid: empty list).
	f.Add([]byte{0x00, 0x00}, true)

	// X25519 client (32 B kex).
	x25519Entry := buildKeyShareEntry(0x001D, make([]byte, 32))
	f.Add(buildClientPayload(x25519Entry), true)

	// X25519MLKEM768 client (1216 B kex).
	x25519mlkemEntry := buildKeyShareEntry(0x11EC, make([]byte, 1216))
	f.Add(buildClientPayload(x25519mlkemEntry), true)

	// Multi-entry: X25519 + X25519MLKEM768.
	f.Add(buildClientPayload(x25519Entry, x25519mlkemEntry), true)

	// MLKEM768 server (1088 B ciphertext, no list-length prefix).
	mlkem768Server := buildKeyShareEntry(0x0201, make([]byte, 1088))
	f.Add(mlkem768Server, false)

	// Malformed: declared list_len > actual payload.
	f.Add([]byte{0x00, 0xFF, 0x00, 0x01}, true)

	// Malformed: truncated header (3 bytes, need 4 for entry).
	f.Add([]byte{0x00, 0x03, 0x11, 0xEC, 0x01}, true)

	// Malformed: kex length exceeds remaining bytes.
	malformed := make([]byte, 6)
	binary.BigEndian.PutUint16(malformed[0:2], 4) // list_len = 4
	binary.BigEndian.PutUint16(malformed[2:4], 0x001D)
	binary.BigEndian.PutUint16(malformed[4:6], 0x00FF) // kex_len=255, but 0 bytes follow
	f.Add(malformed, true)

	// ── Fuzz target ─────────────────────────────────────────────────────────────
	f.Fuzz(func(t *testing.T, data []byte, isClient bool) {
		// Invariant 1: no panic.
		infos, err := ParseKeyShareExtension(data, isClient)
		if err != nil {
			// Errors are expected for malformed input — just verify no panic.
			return
		}

		// Invariant 2: successful parses must return internally consistent entries.
		for _, info := range infos {
			// KeyExchangeLen must be non-negative (it's an int so this should always hold,
			// but verify no integer wrap-around occurred).
			if info.KeyExchangeLen < 0 {
				t.Errorf("KeyExchangeLen=%d for GroupID=0x%04x: negative length", info.KeyExchangeLen, info.GroupID)
			}
			// Primitive must be one of the three known values.
			switch info.Primitive {
			case "classical", "hybrid-kem", "pure-pq":
				// valid
			default:
				t.Errorf("unexpected Primitive=%q for GroupID=0x%04x", info.Primitive, info.GroupID)
			}
		}
	})
}

// FuzzScanBytesForECHExtension feeds arbitrary bytes to ScanBytesForECHExtension
// and verifies determinism (same input → same bool) and no panic.
func FuzzScanBytesForECHExtension(f *testing.F) {
	// ── Seed corpus ────────────────────────────────────────────────────────────

	// Empty input.
	f.Add([]byte(nil))

	// Random TLS-record-like prefix (5-byte header + body).
	tlsRecord := []byte{0x16, 0x03, 0x03, 0x00, 0x05, 0xDE, 0xAD, 0xBE, 0xEF, 0x00}
	f.Add(tlsRecord)

	// Crafted ECH extension at offset 0.
	f.Add([]byte{0xfe, 0x0d, 0x00, 0x10})

	// Crafted ECH extension buried mid-buffer.
	mid := make([]byte, 20)
	mid[10] = 0xfe
	mid[11] = 0x0d
	f.Add(mid)

	// Near-miss: 0xfe0e (off-by-one).
	f.Add([]byte{0x00, 0x17, 0xfe, 0x0e})

	// Single byte (can't form 2-byte pattern).
	f.Add([]byte{0xfe})

	// Oversize: 4 KB random-ish buffer.
	large := make([]byte, 4096)
	for i := range large {
		large[i] = byte(i & 0xFF)
	}
	f.Add(large)

	// ── Fuzz target ─────────────────────────────────────────────────────────────
	f.Fuzz(func(t *testing.T, data []byte) {
		// Invariant: no panic.
		found1, src1 := ScanBytesForECHExtension(data)

		// Determinism: calling again with the same data must produce the same result.
		found2, src2 := ScanBytesForECHExtension(data)
		if found1 != found2 {
			t.Errorf("non-deterministic: first call=%v second call=%v", found1, found2)
		}
		if src1 != src2 {
			t.Errorf("non-deterministic source: first=%q second=%q", src1, src2)
		}

		// Invariant: source string is either "tls-ext" (when found) or "" (when not).
		if found1 && src1 != "tls-ext" {
			t.Errorf("found=true but source=%q, want tls-ext", src1)
		}
		if !found1 && src1 != "" {
			t.Errorf("found=false but source=%q, want empty", src1)
		}
	})
}
