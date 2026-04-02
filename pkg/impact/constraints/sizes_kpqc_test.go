package constraints

import "testing"

func TestLookup_KPQC_Exact(t *testing.T) {
	tests := []struct {
		name    string
		wantPK  int
		wantSig int
		wantCT  int
	}{
		// SMAUG-T (KEM)
		{"SMAUG-T-128", 672, 0, 768},
		{"SMAUG-T-192", 992, 0, 1120},
		{"SMAUG-T-256", 1312, 0, 1440},
		// HAETAE (Signature)
		{"HAETAE-2", 1312, 2512, 0},
		{"HAETAE-3", 1952, 3504, 0},
		{"HAETAE-5", 2592, 4128, 0},
		// AIMer (Signature) — both fast and short variants
		{"AIMer-128f", 32, 5472, 0},
		{"AIMer-128s", 32, 2816, 0},
		{"AIMer-192f", 48, 11456, 0},
		{"AIMer-192s", 48, 7424, 0},
		{"AIMer-256f", 64, 17312, 0},
		{"AIMer-256s", 64, 12288, 0},
		// NTRU+ (KEM) — all four parameter sets
		{"NTRU+-576", 864, 0, 864},
		{"NTRU+-768", 1152, 0, 1152},
		{"NTRU+-864", 1312, 0, 1312},
		{"NTRU+-1277", 1920, 0, 1920},
		// KCDSA (classical Korean DSA)
		{"KCDSA-2048", 256, 256, 0},
		{"KCDSA-3072", 384, 384, 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			profile, ok := Lookup(tt.name)
			if !ok {
				t.Fatalf("Lookup(%q) returned false — entry missing", tt.name)
			}
			if profile.PublicKeyBytes != tt.wantPK {
				t.Errorf("PublicKeyBytes = %d, want %d", profile.PublicKeyBytes, tt.wantPK)
			}
			if profile.SignatureBytes != tt.wantSig {
				t.Errorf("SignatureBytes = %d, want %d", profile.SignatureBytes, tt.wantSig)
			}
			if profile.CiphertextBytes != tt.wantCT {
				t.Errorf("CiphertextBytes = %d, want %d", profile.CiphertextBytes, tt.wantCT)
			}
		})
	}
}

func TestLookup_KPQC_PrefixMatch(t *testing.T) {
	// "SMAUG-T" should prefix-match to one of the SMAUG-T entries
	_, ok := Lookup("SMAUG-T")
	if !ok {
		t.Error("Lookup(SMAUG-T) should prefix-match a SMAUG-T entry")
	}

	// "HAETAE" should prefix-match
	_, ok = Lookup("HAETAE")
	if !ok {
		t.Error("Lookup(HAETAE) should prefix-match a HAETAE entry")
	}
}

func TestMigrationTargets_KCDSA(t *testing.T) {
	targets := MigrationTargets("KCDSA")
	if len(targets) == 0 {
		t.Fatal("KCDSA should have migration targets")
	}
	found := false
	for _, tgt := range targets {
		if tgt == "HAETAE-3" || tgt == "ML-DSA-65" {
			found = true
		}
	}
	if !found {
		t.Errorf("KCDSA migration targets should include HAETAE-3 or ML-DSA-65, got %v", targets)
	}
}

func TestLookup_AIMerFastVsShort_DifferentSizes(t *testing.T) {
	fast, okF := Lookup("AIMer-192f")
	slow, okS := Lookup("AIMer-192s")
	if !okF || !okS {
		t.Fatal("both AIMer-192f and AIMer-192s should exist")
	}
	if fast.SignatureBytes == slow.SignatureBytes {
		t.Errorf("AIMer-192f and AIMer-192s should have different signature sizes, both are %d", fast.SignatureBytes)
	}
	if fast.SignatureBytes <= slow.SignatureBytes {
		t.Errorf("AIMer-192f (fast=%d) should have LARGER signature than AIMer-192s (short=%d)", fast.SignatureBytes, slow.SignatureBytes)
	}
}
