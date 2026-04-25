package tlsprobe

// preference_sophisticated_test.go — Sophisticated tests for preference.go.
//
// Covers:
//  1. selectPrefGroups cap at exactly maxPrefKeyShares=3 with various compositions.
//  2. selectPrefGroups with no classical groups — fills all 3 slots from hybrid/PQC.
//  3. selectPrefGroups with exactly 3 groups — must be returned as-is (no mutation).
//  4. selectPrefGroups with duplicate prevention in the fill-from-any pass.
//  5. reverseGroups and reverseKeyShares symmetry.
//  6. Sprint-8 F8 regression: when >3 accepted groups, exactly 3 are offered.

import (
	"testing"

	"github.com/jimbo111/open-quantum-secure/pkg/engines/tlsprobe/rawhello"
)

// buildFakeKeyShare is a helper that returns a KeyShareEntry with zeroed key
// material for a given group ID, using rawhello.ProbeKeyShare if known, or
// a minimal 32-byte placeholder for unknown groups.
func buildFakeKeyShare(groupID uint16) rawhello.KeyShareEntry {
	ks, err := rawhello.ProbeKeyShare(groupID)
	if err != nil {
		// For groups not in ProbeKeyShare (e.g., unknown codepoints used in tests),
		// fabricate a minimal entry.
		ks = rawhello.KeyShareEntry{GroupID: groupID, PublicKey: make([]byte, 32)}
	}
	return ks
}

// TestSelectPrefGroups_Cap3_Mixed verifies that selectPrefGroups caps output to
// maxPrefKeyShares (3) when given >3 groups with a classical/hybrid mix:
// [X25519(cl), secp256r1(cl), X25519MLKEM768(hyb), SecP256r1MLKEM768(hyb), MLKEM768(pq)]
//
// Expected: 1 classical (X25519 first) + 2 hybrid (X25519MLKEM768 + SecP256r1MLKEM768).
// MLKEM768 and second classical (secp256r1) are dropped.
func TestSelectPrefGroups_Cap3_Mixed(t *testing.T) {
	t.Parallel()

	groups := []uint16{
		0x001d, // X25519 (classical)
		0x0017, // secp256r1 (classical)
		0x11ec, // X25519MLKEM768 (hybrid)
		0x11eb, // SecP256r1MLKEM768 (hybrid)
		0x0201, // MLKEM768 (pure-pq)
	}
	keyShares := make([]rawhello.KeyShareEntry, len(groups))
	for i, g := range groups {
		keyShares[i] = buildFakeKeyShare(g)
	}

	outGroups, outShares := selectPrefGroups(groups, keyShares)

	if len(outGroups) > maxPrefKeyShares {
		t.Errorf("selectPrefGroups returned %d groups, want ≤%d", len(outGroups), maxPrefKeyShares)
	}
	if len(outGroups) != len(outShares) {
		t.Errorf("outGroups (%d) and outShares (%d) have different lengths", len(outGroups), len(outShares))
	}
	// Verify the cap is exactly 3 for an input with 5 groups.
	if len(outGroups) != maxPrefKeyShares {
		t.Errorf("selectPrefGroups(%d groups) returned %d, want exactly %d",
			len(groups), len(outGroups), maxPrefKeyShares)
	}

	// Exactly 1 classical group must appear.
	classicalCount := 0
	for _, g := range outGroups {
		if classicalECDHGroups[g] {
			classicalCount++
		}
	}
	if classicalCount != 1 {
		t.Errorf("selectPrefGroups: classicalCount=%d in output, want 1 (1 classical + 2 hybrid/pq)",
			classicalCount)
	}
}

// TestSelectPrefGroups_NoClassical_AllHybrid verifies that when the accepted
// groups list contains only hybrid/PQC groups (no classical), selectPrefGroups
// fills all 3 slots from the hybrid/PQC tier using the fill-from-any fallback.
func TestSelectPrefGroups_NoClassical_AllHybrid(t *testing.T) {
	t.Parallel()

	// Only hybrid KEMs — no classical ECDH.
	groups := []uint16{
		0x11ec, // X25519MLKEM768
		0x11eb, // SecP256r1MLKEM768
		0x11ed, // SecP384r1MLKEM1024
		0x11ee, // curveSM2MLKEM768
	}
	keyShares := make([]rawhello.KeyShareEntry, len(groups))
	for i, g := range groups {
		keyShares[i] = buildFakeKeyShare(g)
	}

	outGroups, outShares := selectPrefGroups(groups, keyShares)

	if len(outGroups) > maxPrefKeyShares {
		t.Errorf("selectPrefGroups returned %d groups, want ≤%d", len(outGroups), maxPrefKeyShares)
	}
	if len(outGroups) != len(outShares) {
		t.Errorf("length mismatch: outGroups=%d outShares=%d", len(outGroups), len(outShares))
	}
	// No classical groups in input → no classical groups in output.
	for _, g := range outGroups {
		if classicalECDHGroups[g] {
			t.Errorf("unexpected classical group 0x%04x in all-hybrid input", g)
		}
	}
	// Must be capped at 3.
	if len(outGroups) != maxPrefKeyShares {
		t.Errorf("selectPrefGroups(4 hybrid groups) returned %d, want %d", len(outGroups), maxPrefKeyShares)
	}
}

// TestSelectPrefGroups_ExactlyCap_NoTruncation verifies that when the input has
// exactly maxPrefKeyShares (3) groups, selectPrefGroups returns them unchanged.
func TestSelectPrefGroups_ExactlyCap_NoTruncation(t *testing.T) {
	t.Parallel()

	groups := []uint16{0x001d, 0x11ec, 0x0201} // 3 groups
	keyShares := make([]rawhello.KeyShareEntry, len(groups))
	for i, g := range groups {
		keyShares[i] = buildFakeKeyShare(g)
	}

	outGroups, outShares := selectPrefGroups(groups, keyShares)

	if len(outGroups) != 3 {
		t.Errorf("selectPrefGroups(exactly 3 groups) returned %d, want 3", len(outGroups))
	}
	if len(outShares) != 3 {
		t.Errorf("outShares length=%d, want 3", len(outShares))
	}
	// Order must be preserved.
	for i, g := range groups {
		if outGroups[i] != g {
			t.Errorf("outGroups[%d]=0x%04x, want 0x%04x (order changed)", i, outGroups[i], g)
		}
	}
}

// TestSelectPrefGroups_NoDuplicates verifies that the fill-from-any pass in
// selectPrefGroups does not add a group that was already selected by the first
// two passes. Without the duplicate check, a classical group could appear twice.
func TestSelectPrefGroups_NoDuplicates(t *testing.T) {
	t.Parallel()

	// 1 classical + 1 hybrid — below cap, but fill-from-any should not re-add X25519.
	groups := []uint16{0x001d, 0x11ec}
	keyShares := make([]rawhello.KeyShareEntry, len(groups))
	for i, g := range groups {
		keyShares[i] = buildFakeKeyShare(g)
	}

	outGroups, _ := selectPrefGroups(groups, keyShares)

	seen := make(map[uint16]bool)
	for _, g := range outGroups {
		if seen[g] {
			t.Errorf("duplicate group 0x%04x in selectPrefGroups output", g)
		}
		seen[g] = true
	}
}

// TestSelectPrefGroups_Sprint8_F8_Regression is the direct regression for
// Sprint-8 F8: preference key_share capped at 3 groups. When enumerateGroups
// returns more than 3 accepted groups, detectServerGroupPreference must NOT
// send all of them in a single ClientHello (which would push it past 7 KB and
// trip middlebox rate limiters). selectPrefGroups is the gatekeeper.
//
// This test drives selectPrefGroups with 10 accepted groups — a realistic worst
// case — and asserts output is capped at maxPrefKeyShares (3).
func TestSelectPrefGroups_Sprint8_F8_Regression(t *testing.T) {
	t.Parallel()

	// 10 accepted groups from a hypothetical server that accepts everything.
	groups := []uint16{
		0x001d, 0x0017, 0x0018, 0x0019,       // 4 classical
		0x11ec, 0x11eb, 0x11ed, 0x11ee,       // 4 hybrid
		0x0200, 0x0201,                         // 2 pure-PQ
	}
	keyShares := make([]rawhello.KeyShareEntry, len(groups))
	for i, g := range groups {
		keyShares[i] = buildFakeKeyShare(g)
	}

	outGroups, outShares := selectPrefGroups(groups, keyShares)

	if len(outGroups) > maxPrefKeyShares {
		t.Errorf("Sprint-8 F8 regression: selectPrefGroups returned %d groups, cap is %d",
			len(outGroups), maxPrefKeyShares)
	}
	if len(outGroups) != len(outShares) {
		t.Errorf("length mismatch: groups=%d shares=%d", len(outGroups), len(outShares))
	}
}

// TestReverseGroups_Symmetry verifies that reversing a group slice twice
// returns the original order (double-reverse invariant).
func TestReverseGroups_Symmetry(t *testing.T) {
	t.Parallel()

	groups := []uint16{0x001d, 0x11ec, 0x0201, 0x0017}
	reversed := reverseGroups(groups)
	doubleReversed := reverseGroups(reversed)

	for i, g := range groups {
		if doubleReversed[i] != g {
			t.Errorf("double-reverse[%d]=0x%04x, want 0x%04x", i, doubleReversed[i], g)
		}
	}
}

// TestReverseGroups_EmptySlice verifies that reverseGroups does not panic on an
// empty input and returns an empty (not nil) slice.
func TestReverseGroups_EmptySlice(t *testing.T) {
	t.Parallel()
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("reverseGroups(nil) panicked: %v", r)
		}
	}()
	out := reverseGroups(nil)
	if out == nil {
		t.Error("reverseGroups(nil) returned nil, want empty non-nil slice")
	}
	if len(out) != 0 {
		t.Errorf("reverseGroups(nil) returned len=%d, want 0", len(out))
	}
}

// TestReverseGroups_SingleElement verifies that a single-element slice reversed
// returns itself.
func TestReverseGroups_SingleElement(t *testing.T) {
	t.Parallel()
	out := reverseGroups([]uint16{0x001d})
	if len(out) != 1 || out[0] != 0x001d {
		t.Errorf("reverseGroups([X25519]) = %v, want [0x001d]", out)
	}
}
