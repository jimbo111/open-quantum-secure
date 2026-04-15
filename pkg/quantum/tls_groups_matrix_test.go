package quantum

import (
	"fmt"
	"testing"
)

// tls_groups_matrix_test.go — exhaustive codepoint × expected-tuple matrix for
// ClassifyTLSGroup.
//
// Coverage:
//   - All 19 known codepoints × (Name, PQCPresent, Maturity, RiskLevel) tuple
//   - 10 unknown codepoints → (GroupInfo{}, false)
//   - Boundary codepoints adjacent to the hybrid-KEM range → unknown
//   - Invariant: only 0x6399 and 0x636D may carry Maturity=="draft"

func TestTLSGroupMatrix_AllKnownCodepoints(t *testing.T) {
	type wantTuple struct {
		Name       string
		PQCPresent bool
		Maturity   string
		RiskLevel  Risk
	}
	tests := []struct {
		id   uint16
		want wantTuple
	}{
		// ── Hybrid KEMs: classical ECDH + ML-KEM (IETF draft-ietf-tls-hybrid-design)
		{0x11EB, wantTuple{"SecP256r1MLKEM768", true, "final", RiskSafe}},
		{0x11EC, wantTuple{"X25519MLKEM768", true, "final", RiskSafe}},
		{0x11ED, wantTuple{"SecP384r1MLKEM1024", true, "final", RiskSafe}},
		{0x11EE, wantTuple{"curveSM2MLKEM768", true, "final", RiskSafe}},
		// ── Pure ML-KEM (FIPS 203)
		{0x0200, wantTuple{"MLKEM512", true, "final", RiskSafe}},
		{0x0201, wantTuple{"MLKEM768", true, "final", RiskSafe}},
		{0x0202, wantTuple{"MLKEM1024", true, "final", RiskSafe}},
		// ── Deprecated draft Kyber (pre-FIPS 203)
		{0x6399, wantTuple{"X25519Kyber768Draft00", true, "draft", RiskDeprecated}},
		{0x636D, wantTuple{"X25519Kyber768Draft00", true, "draft", RiskDeprecated}},
		// ── Classical ECDH
		{0x0017, wantTuple{"secp256r1", false, "", RiskVulnerable}},
		{0x0018, wantTuple{"secp384r1", false, "", RiskVulnerable}},
		{0x0019, wantTuple{"secp521r1", false, "", RiskVulnerable}},
		{0x001d, wantTuple{"X25519", false, "", RiskVulnerable}},
		{0x001e, wantTuple{"X448", false, "", RiskVulnerable}},
		// ── Classical FFDH
		{0x0100, wantTuple{"ffdhe2048", false, "", RiskVulnerable}},
		{0x0101, wantTuple{"ffdhe3072", false, "", RiskVulnerable}},
		{0x0102, wantTuple{"ffdhe4096", false, "", RiskVulnerable}},
		{0x0103, wantTuple{"ffdhe6144", false, "", RiskVulnerable}},
		{0x0104, wantTuple{"ffdhe8192", false, "", RiskVulnerable}},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(fmt.Sprintf("0x%04x/%s", tc.id, tc.want.Name), func(t *testing.T) {
			info, ok := ClassifyTLSGroup(tc.id)
			if !ok {
				t.Fatalf("ClassifyTLSGroup(0x%04x): ok=false, want ok=true", tc.id)
			}
			if info.Name != tc.want.Name {
				t.Errorf("Name = %q, want %q", info.Name, tc.want.Name)
			}
			if info.PQCPresent != tc.want.PQCPresent {
				t.Errorf("PQCPresent = %v, want %v", info.PQCPresent, tc.want.PQCPresent)
			}
			if info.Maturity != tc.want.Maturity {
				t.Errorf("Maturity = %q, want %q", info.Maturity, tc.want.Maturity)
			}
			if info.RiskLevel != tc.want.RiskLevel {
				t.Errorf("RiskLevel = %q, want %q", info.RiskLevel, tc.want.RiskLevel)
			}
		})
	}
}

// TestTLSGroupMatrix_UnknownCodepoints verifies that 10 arbitrary unregistered
// codepoints return (GroupInfo{}, false) and do not claim PQC presence.
func TestTLSGroupMatrix_UnknownCodepoints(t *testing.T) {
	unknowns := []uint16{
		0x0000, // zero — no named group / RSA KEM session
		0x0001, // just above zero
		0x0003, // gap below ECDH range
		0x0500, // between FFDH and Pure ML-KEM ranges
		0x1000, // unregistered gap
		0x1234, // arbitrary unregistered
		0x7777, // arbitrary unregistered
		0x9999, // arbitrary unregistered
		0xABCD, // arbitrary unregistered
		0xFFFF, // maximum uint16 — must not panic
	}

	for _, id := range unknowns {
		id := id
		t.Run(fmt.Sprintf("unknown/0x%04x", id), func(t *testing.T) {
			info, ok := ClassifyTLSGroup(id)
			if ok {
				t.Errorf("ClassifyTLSGroup(0x%04x): ok=true, want ok=false (unknown codepoint, Name=%q)", id, info.Name)
			}
			// Unknown codepoints must return a zero GroupInfo.
			if info != (GroupInfo{}) {
				t.Errorf("ClassifyTLSGroup(0x%04x): expected zero GroupInfo{} for unknown, got %+v", id, info)
			}
			// Callers must treat unknown codepoints as PQCPresent=false.
			if info.PQCPresent {
				t.Errorf("ClassifyTLSGroup(0x%04x): PQCPresent=true for unknown codepoint", id)
			}
		})
	}
}

// TestTLSGroupMatrix_BoundaryCodepoints checks codepoints immediately outside the
// hybrid-KEM assignment range. Neither 0x11EA nor 0x11EF is registered; both
// must return ok=false so adjacent-integer probing cannot claim PQC presence.
func TestTLSGroupMatrix_BoundaryCodepoints(t *testing.T) {
	boundaries := []struct {
		id      uint16
		comment string
	}{
		{0x11EA, "one below SecP256r1MLKEM768 (0x11EB)"},
		{0x11EF, "one above curveSM2MLKEM768 (0x11EE)"},
	}

	for _, tc := range boundaries {
		tc := tc
		t.Run(fmt.Sprintf("boundary/0x%04x", tc.id), func(t *testing.T) {
			info, ok := ClassifyTLSGroup(tc.id)
			if ok {
				t.Errorf("ClassifyTLSGroup(0x%04x) (%s): ok=true, want ok=false", tc.id, tc.comment)
			}
			if info != (GroupInfo{}) {
				t.Errorf("ClassifyTLSGroup(0x%04x) (%s): non-zero GroupInfo for boundary unknown: %+v",
					tc.id, tc.comment, info)
			}
		})
	}
}

// TestTLSGroupMatrix_DraftExclusivelyFor6399And636D verifies that "draft" maturity
// is exclusive to the two deprecated Kyber codepoints. Any other known codepoint
// carrying Maturity=="draft" would silently misclassify a final group as deprecated.
func TestTLSGroupMatrix_DraftExclusivelyFor6399And636D(t *testing.T) {
	draftAllowed := map[uint16]bool{0x6399: true, 0x636D: true}

	knownIDs := []uint16{
		0x11EB, 0x11EC, 0x11ED, 0x11EE,
		0x0200, 0x0201, 0x0202,
		0x6399, 0x636D,
		0x0017, 0x0018, 0x0019, 0x001d, 0x001e,
		0x0100, 0x0101, 0x0102, 0x0103, 0x0104,
	}

	for _, id := range knownIDs {
		info, ok := ClassifyTLSGroup(id)
		if !ok {
			t.Errorf("0x%04x: expected known codepoint, got ok=false", id)
			continue
		}
		if info.Maturity == "draft" && !draftAllowed[id] {
			t.Errorf("0x%04x (%s): Maturity=%q — only 0x6399 and 0x636D may have draft maturity",
				id, info.Name, info.Maturity)
		}
		if draftAllowed[id] && info.Maturity != "draft" {
			t.Errorf("0x%04x (%s): Maturity=%q — draft codepoint must have Maturity==\"draft\"",
				id, info.Name, info.Maturity)
		}
	}
}

// TestTLSGroupMatrix_PQCPresentImpliesNonEmptyName asserts that every codepoint
// returning PQCPresent=true also carries a non-empty Name. Consumers that trust
// Name when PQCPresent=true must never observe an empty string.
func TestTLSGroupMatrix_PQCPresentImpliesNonEmptyName(t *testing.T) {
	pqcIDs := []uint16{
		// hybrid
		0x11EB, 0x11EC, 0x11ED, 0x11EE,
		// pure ML-KEM
		0x0200, 0x0201, 0x0202,
		// deprecated draft (PQCPresent=true, Maturity="draft")
		0x6399, 0x636D,
	}
	for _, id := range pqcIDs {
		info, ok := ClassifyTLSGroup(id)
		if !ok {
			t.Errorf("0x%04x: expected known PQC codepoint, got ok=false", id)
			continue
		}
		if !info.PQCPresent {
			t.Errorf("0x%04x (%s): PQCPresent=false for known PQC codepoint", id, info.Name)
		}
		if info.Name == "" {
			t.Errorf("0x%04x: PQCPresent=true but Name is empty", id)
		}
	}
}

// TestTLSGroupMatrix_ClassicalPQCPresentFalse verifies that no classical ECDH/FFDH
// group claims PQC presence — a false positive here would mask quantum risk.
func TestTLSGroupMatrix_ClassicalPQCPresentFalse(t *testing.T) {
	classicalIDs := []uint16{
		0x0017, 0x0018, 0x0019, 0x001d, 0x001e,
		0x0100, 0x0101, 0x0102, 0x0103, 0x0104,
	}
	for _, id := range classicalIDs {
		info, ok := ClassifyTLSGroup(id)
		if !ok {
			t.Errorf("0x%04x: expected known classical codepoint, got ok=false", id)
			continue
		}
		if info.PQCPresent {
			t.Errorf("0x%04x (%s): PQCPresent=true for classical group — would mask quantum risk", id, info.Name)
		}
		if info.Maturity != "" {
			t.Errorf("0x%04x (%s): Maturity=%q for classical group — should be empty", id, info.Name, info.Maturity)
		}
		if info.RiskLevel != RiskVulnerable {
			t.Errorf("0x%04x (%s): RiskLevel=%q, want RiskVulnerable", id, info.Name, info.RiskLevel)
		}
	}
}
