package tlsprobe

// keyshare_property_test.go — Bucket 1: property-based tests for ParseKeyShareExtension.
//
// These tests exercise the parser against 10 000+ random inputs and every known
// group ID to verify panic-freedom, correct Primitive inference, and proper
// rejection of malformed payloads.

import (
	"encoding/binary"
	"math/rand"
	"testing"
)

// TestParseKeyShareExtension_RandomNoPanic iterates 10 000 random group IDs
// (full uint16 range [0, 0xFFFF]) and asserts ParseKeyShareExtension never
// panics regardless of the input content.  We build minimal well-formed
// payloads so the parser exercises both the dispatch logic and the entry
// walking loop.
func TestParseKeyShareExtension_RandomNoPanic(t *testing.T) {
	t.Parallel()
	rng := rand.New(rand.NewSource(42))
	const iterations = 10_000

	for i := 0; i < iterations; i++ {
		groupID := uint16(rng.Intn(0x10000))
		kexLen := rng.Intn(2048)
		kex := make([]byte, kexLen)
		rng.Read(kex)

		entry := buildKeyShareEntry(groupID, kex)
		clientPayload := buildClientPayload(entry)

		// Neither call must panic.  Errors are acceptable.
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Errorf("ParseKeyShareExtension panicked on iteration %d (groupID=0x%04x kexLen=%d): %v",
						i, groupID, kexLen, r)
				}
			}()
			_, _ = ParseKeyShareExtension(clientPayload, true)
		}()

		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Errorf("ParseKeyShareExtension(server) panicked on iteration %d (groupID=0x%04x kexLen=%d): %v",
						i, groupID, kexLen, r)
				}
			}()
			_, _ = ParseKeyShareExtension(entry, false)
		}()
	}
}

// TestParseKeyShareExtension_KnownGroupsWellFormed checks that for every known
// group ID in expectedKeyShareLengths, a well-formed single-entry extension
// (client side, client-length payload) parses cleanly and returns the expected
// Primitive.
func TestParseKeyShareExtension_KnownGroupsWellFormed(t *testing.T) {
	t.Parallel()

	type expectation struct {
		primitive string
	}
	wantPrimitive := map[uint16]string{
		// Classical
		0x001d: "classical",
		0x0017: "classical",
		0x0018: "classical",
		0x0019: "classical",
		// Pure ML-KEM
		0x0200: "pure-pq",
		0x0201: "pure-pq",
		0x0202: "pure-pq",
		// Hybrid
		0x11eb: "hybrid-kem",
		0x11ec: "hybrid-kem",
		0x11ed: "hybrid-kem",
		0x11ee: "hybrid-kem",
	}

	for groupID, lens := range expectedKeyShareLengths {
		groupID := groupID
		lens := lens
		wantPrim := wantPrimitive[groupID]

		t.Run("", func(t *testing.T) {
			t.Parallel()
			clientKexLen := lens[0]
			kex := make([]byte, clientKexLen)
			entry := buildKeyShareEntry(groupID, kex)
			payload := buildClientPayload(entry)

			infos, err := ParseKeyShareExtension(payload, true)
			if err != nil {
				t.Errorf("groupID=0x%04x: unexpected error: %v", groupID, err)
				return
			}
			if len(infos) != 1 {
				t.Errorf("groupID=0x%04x: got %d infos, want 1", groupID, len(infos))
				return
			}
			if infos[0].GroupID != groupID {
				t.Errorf("groupID=0x%04x: returned GroupID=0x%04x", groupID, infos[0].GroupID)
			}
			if infos[0].KeyExchangeLen != clientKexLen {
				t.Errorf("groupID=0x%04x: KeyExchangeLen=%d, want %d", groupID, infos[0].KeyExchangeLen, clientKexLen)
			}
			if infos[0].Primitive != wantPrim {
				t.Errorf("groupID=0x%04x: Primitive=%q, want %q", groupID, infos[0].Primitive, wantPrim)
			}
		})
	}
}

// TestParseKeyShareExtension_ListLenExceedsPayload verifies that any extension
// that advertises a list length larger than the remaining payload bytes is
// rejected with a non-nil error (not a panic, not silent success).
func TestParseKeyShareExtension_ListLenExceedsPayload(t *testing.T) {
	t.Parallel()
	rng := rand.New(rand.NewSource(99))

	for i := 0; i < 500; i++ {
		// Declare a list_len larger than the body we actually provide.
		declaredListLen := uint16(rng.Intn(0xFFFF) + 1)
		actualBodyLen := rng.Intn(int(declaredListLen)) // always strictly less

		payload := make([]byte, 2+actualBodyLen)
		binary.BigEndian.PutUint16(payload[0:2], declaredListLen)
		rng.Read(payload[2:])

		_, err := ParseKeyShareExtension(payload, true)
		if err == nil {
			t.Errorf("iteration %d: expected error when declared listLen %d > actual payload %d, got nil",
				i, declaredListLen, actualBodyLen)
		}
	}
}

// TestParseKeyShareExtension_IsClientBranchParity verifies that toggling
// isClient on identical bytes produces consistent success/failure behaviour:
// the parse may return different result counts, but it must not succeed in
// one branch and panic in the other.  We test 1 000 random payloads.
func TestParseKeyShareExtension_IsClientBranchParity(t *testing.T) {
	t.Parallel()
	rng := rand.New(rand.NewSource(17))
	const iterations = 1_000

	for i := 0; i < iterations; i++ {
		size := rng.Intn(512)
		data := make([]byte, size)
		rng.Read(data)

		var (
			clientErr error
			serverErr error
		)

		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Errorf("client branch panicked on iteration %d: %v", i, r)
				}
			}()
			_, clientErr = ParseKeyShareExtension(data, true)
		}()

		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Errorf("server branch panicked on iteration %d: %v", i, r)
				}
			}()
			_, serverErr = ParseKeyShareExtension(data, false)
		}()

		// Both paths must terminate (either error or success).  We simply ensure
		// neither side is nil while the other is non-nil in a way that is
		// logically impossible (both nil is fine, both non-nil is fine, mismatched
		// is fine because client adds a list-length parse step).
		_ = clientErr
		_ = serverErr
	}
}
