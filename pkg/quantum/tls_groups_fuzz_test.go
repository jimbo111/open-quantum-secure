package quantum

import "testing"

// tls_groups_fuzz_test.go — fuzz tests for ClassifyTLSGroup.
//
// FuzzClassifyTLSGroup exercises the function with arbitrary uint16 codepoints
// and verifies two invariants that must hold for all inputs:
//
//   1. The function never panics.
//   2. When ok=false, GroupInfo is the zero value (callers rely on PQCPresent=false
//      for unknown codepoints; a non-zero GroupInfo would be a latent bug).
//   3. When ok=true, Name is non-empty (a PQCPresent=true finding with an empty
//      Name would produce malformed algorithm classifications downstream).
//
// The seed corpus covers all 19 registered codepoints plus several unknowns.
// During normal `go test` runs, the fuzzer executes seed entries only (fast).
//
// To run an extended fuzz session:
//
//	go test -fuzz=FuzzClassifyTLSGroup ./pkg/quantum/ -fuzztime=30s
//
// To run the full corpus (seed + any saved inputs):
//
//	go test -fuzz=FuzzClassifyTLSGroup ./pkg/quantum/ -fuzztime=10s -test.v
func FuzzClassifyTLSGroup(f *testing.F) {
	// ── Seed corpus: all 19 registered codepoints ───────────────────────────
	// Hybrid KEMs (IETF draft-ietf-tls-hybrid-design)
	f.Add(uint16(0x11EB)) // SecP256r1MLKEM768
	f.Add(uint16(0x11EC)) // X25519MLKEM768
	f.Add(uint16(0x11ED)) // SecP384r1MLKEM1024
	f.Add(uint16(0x11EE)) // curveSM2MLKEM768
	// Pure ML-KEM (FIPS 203)
	f.Add(uint16(0x0200)) // MLKEM512
	f.Add(uint16(0x0201)) // MLKEM768
	f.Add(uint16(0x0202)) // MLKEM1024
	// Deprecated draft Kyber
	f.Add(uint16(0x6399)) // X25519Kyber768Draft00 (primary codepoint)
	f.Add(uint16(0x636D)) // X25519Kyber768Draft00 (alternate codepoint)
	// Classical ECDH
	f.Add(uint16(0x0017)) // secp256r1
	f.Add(uint16(0x0018)) // secp384r1
	f.Add(uint16(0x0019)) // secp521r1
	f.Add(uint16(0x001d)) // X25519
	f.Add(uint16(0x001e)) // X448
	// Classical FFDH
	f.Add(uint16(0x0100)) // ffdhe2048
	f.Add(uint16(0x0101)) // ffdhe3072
	f.Add(uint16(0x0102)) // ffdhe4096
	f.Add(uint16(0x0103)) // ffdhe6144
	f.Add(uint16(0x0104)) // ffdhe8192
	// ── Unknown codepoints ─────────────────────────────────────────────────
	f.Add(uint16(0x0000)) // zero — no named group
	f.Add(uint16(0xFFFF)) // max uint16
	f.Add(uint16(0x9999)) // arbitrary unknown
	f.Add(uint16(0x11EA)) // boundary: one below SecP256r1MLKEM768
	f.Add(uint16(0x11EF)) // boundary: one above curveSM2MLKEM768
	f.Add(uint16(0x0001)) // gap below registered range
	f.Add(uint16(0x0500)) // gap between FFDH and Pure ML-KEM
	f.Add(uint16(0x1234)) // arbitrary unregistered
	f.Add(uint16(0xABCD)) // arbitrary unregistered
	f.Add(uint16(0x7777)) // arbitrary unregistered

	f.Fuzz(func(t *testing.T, id uint16) {
		// Invariant 1: must never panic.
		// (defer/recover is implicit in the fuzzer harness, but explicit here
		// as documentation of the no-panic contract.)
		info, ok := ClassifyTLSGroup(id)

		if !ok {
			// Invariant 2: unknown codepoint → zero GroupInfo.
			if info != (GroupInfo{}) {
				t.Errorf("ClassifyTLSGroup(0x%04x): ok=false but GroupInfo is non-zero: %+v", id, info)
			}
			// Corollary: must not claim PQC presence.
			if info.PQCPresent {
				t.Errorf("ClassifyTLSGroup(0x%04x): ok=false but PQCPresent=true", id)
			}
			return
		}

		// Invariant 3: known codepoint → non-empty Name.
		if info.Name == "" {
			t.Errorf("ClassifyTLSGroup(0x%04x): ok=true but Name is empty", id)
		}

		// Corollary: Maturity is one of the three valid values.
		switch info.Maturity {
		case "", "final", "draft":
			// valid
		default:
			t.Errorf("ClassifyTLSGroup(0x%04x): unexpected Maturity=%q (want \"\", \"final\", or \"draft\")",
				id, info.Maturity)
		}
	})
}
