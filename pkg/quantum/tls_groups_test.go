package quantum

import "testing"

func TestClassifyTLSGroup(t *testing.T) {
	tests := []struct {
		name       string
		id         uint16
		wantOK     bool
		wantPQC    bool
		wantName   string
		wantMature string
	}{
		// Hybrid KEMs — all final, PQC present
		{"SecP256r1MLKEM768", 0x11EB, true, true, "SecP256r1MLKEM768", "final"},
		{"X25519MLKEM768", 0x11EC, true, true, "X25519MLKEM768", "final"},
		{"SecP384r1MLKEM1024", 0x11ED, true, true, "SecP384r1MLKEM1024", "final"},
		{"curveSM2MLKEM768", 0x11EE, true, true, "curveSM2MLKEM768", "final"},
		// Pure ML-KEM — final, PQC present
		{"MLKEM512", 0x0200, true, true, "MLKEM512", "final"},
		{"MLKEM768", 0x0201, true, true, "MLKEM768", "final"},
		{"MLKEM1024", 0x0202, true, true, "MLKEM1024", "final"},
		// Draft Kyber — deprecated, PQC present but maturity=draft
		{"X25519Kyber768Draft00 primary", 0x6399, true, true, "X25519Kyber768Draft00", "draft"},
		{"X25519Kyber768Draft00 alt", 0x636D, true, true, "X25519Kyber768Draft00", "draft"},
		// Classical ECDH — no PQC
		{"X25519", 0x001d, true, false, "X25519", ""},
		{"secp256r1", 0x0017, true, false, "secp256r1", ""},
		{"secp384r1", 0x0018, true, false, "secp384r1", ""},
		{"secp521r1", 0x0019, true, false, "secp521r1", ""},
		// Classical FFDH
		{"ffdhe2048", 0x0100, true, false, "ffdhe2048", ""},
		// Unknown codepoint
		{"unknown", 0xFFFF, false, false, "", ""},
		// Zero (no named group / RSA KEM / TLS 1.2 without ECDHE)
		{"zero", 0x0000, false, false, "", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			info, ok := ClassifyTLSGroup(tt.id)
			if ok != tt.wantOK {
				t.Errorf("ClassifyTLSGroup(0x%04x) ok=%v, want %v", tt.id, ok, tt.wantOK)
			}
			if !ok {
				return
			}
			if info.PQCPresent != tt.wantPQC {
				t.Errorf("ClassifyTLSGroup(0x%04x).PQCPresent=%v, want %v", tt.id, info.PQCPresent, tt.wantPQC)
			}
			if info.Name != tt.wantName {
				t.Errorf("ClassifyTLSGroup(0x%04x).Name=%q, want %q", tt.id, info.Name, tt.wantName)
			}
			if info.Maturity != tt.wantMature {
				t.Errorf("ClassifyTLSGroup(0x%04x).Maturity=%q, want %q", tt.id, info.Maturity, tt.wantMature)
			}
		})
	}
}

func TestClassifyTLSGroup_DraftRiskDeprecated(t *testing.T) {
	// Draft Kyber codepoints must carry RiskDeprecated despite PQCPresent=true.
	for _, id := range []uint16{0x6399, 0x636D} {
		info, ok := ClassifyTLSGroup(id)
		if !ok {
			t.Fatalf("expected known codepoint 0x%04x", id)
		}
		if info.RiskLevel != RiskDeprecated {
			t.Errorf("draft codepoint 0x%04x RiskLevel=%q, want %q", id, info.RiskLevel, RiskDeprecated)
		}
	}
}

func TestClassifyTLSGroup_PQCRiskSafe(t *testing.T) {
	// Final PQC codepoints must carry RiskSafe.
	pqcFinal := []uint16{0x11EB, 0x11EC, 0x11ED, 0x11EE, 0x0200, 0x0201, 0x0202}
	for _, id := range pqcFinal {
		info, ok := ClassifyTLSGroup(id)
		if !ok {
			t.Fatalf("expected known codepoint 0x%04x", id)
		}
		if info.RiskLevel != RiskSafe {
			t.Errorf("PQC codepoint 0x%04x RiskLevel=%q, want %q", id, info.RiskLevel, RiskSafe)
		}
	}
}

func TestClassifyTLSGroup_ClassicalRiskVulnerable(t *testing.T) {
	classical := []uint16{0x0017, 0x0018, 0x0019, 0x001d, 0x001e, 0x0100}
	for _, id := range classical {
		info, ok := ClassifyTLSGroup(id)
		if !ok {
			t.Fatalf("expected known classical codepoint 0x%04x", id)
		}
		if info.PQCPresent {
			t.Errorf("classical codepoint 0x%04x should not have PQCPresent=true", id)
		}
		if info.RiskLevel != RiskVulnerable {
			t.Errorf("classical codepoint 0x%04x RiskLevel=%q, want %q", id, info.RiskLevel, RiskVulnerable)
		}
	}
}
