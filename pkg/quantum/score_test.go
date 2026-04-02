package quantum

import (
	"testing"

	"github.com/jimbo111/open-quantum-secure/pkg/findings"
	"github.com/jimbo111/open-quantum-secure/pkg/impact"
)

func TestCalculateQRS_Empty(t *testing.T) {
	qrs := CalculateQRS(nil)
	if qrs.Score != 100 {
		t.Errorf("empty findings: score = %d, want 100", qrs.Score)
	}
	if qrs.Grade != "A+" {
		t.Errorf("empty findings: grade = %q, want %q", qrs.Grade, "A+")
	}
}

func TestCalculateQRS_AllPQCSafe(t *testing.T) {
	ff := make([]findings.UnifiedFinding, 5)
	for i := range ff {
		ff[i] = findings.UnifiedFinding{
			Algorithm:   &findings.Algorithm{Name: "ML-KEM-768"},
			QuantumRisk: findings.QRSafe,
			Severity:    findings.SevInfo,
		}
	}
	qrs := CalculateQRS(ff)
	if qrs.Score < 95 {
		t.Errorf("all PQC-safe: score = %d, want >= 95", qrs.Score)
	}
	if qrs.Grade != "A+" {
		t.Errorf("all PQC-safe: grade = %q, want %q", qrs.Grade, "A+")
	}
}

func TestCalculateQRS_AllVulnerable(t *testing.T) {
	// 20 critical vulnerable findings: penalty = 20 * 2.0 = 40, score = 60
	ff := make([]findings.UnifiedFinding, 20)
	for i := range ff {
		ff[i] = findings.UnifiedFinding{
			Algorithm:   &findings.Algorithm{Name: "RSA-2048"},
			QuantumRisk: findings.QRVulnerable,
			Severity:    findings.SevCritical,
		}
	}
	qrs := CalculateQRS(ff)
	if qrs.Score > 65 {
		t.Errorf("20 critical: score = %d, want <= 65", qrs.Score)
	}

	// 60 critical vulnerable findings → score 100 - 120 = 0 (clamped)
	ff2 := make([]findings.UnifiedFinding, 60)
	for i := range ff2 {
		ff2[i] = findings.UnifiedFinding{
			Algorithm:   &findings.Algorithm{Name: "RSA-2048"},
			QuantumRisk: findings.QRVulnerable,
			Severity:    findings.SevCritical,
		}
	}
	qrs2 := CalculateQRS(ff2)
	if qrs2.Score != 0 {
		t.Errorf("60 critical: score = %d, want 0", qrs2.Score)
	}
	if qrs2.Grade != "F" {
		t.Errorf("60 critical: grade = %q, want F", qrs2.Grade)
	}
}

func TestCalculateQRS_Mixed(t *testing.T) {
	ff := []findings.UnifiedFinding{
		{Algorithm: &findings.Algorithm{Name: "RSA-2048"}, QuantumRisk: findings.QRVulnerable, Severity: findings.SevHigh},
		{Algorithm: &findings.Algorithm{Name: "AES-128"}, QuantumRisk: findings.QRWeakened, Severity: findings.SevLow},
		{Algorithm: &findings.Algorithm{Name: "ML-KEM-768"}, QuantumRisk: findings.QRSafe, Severity: findings.SevInfo},
		{Algorithm: &findings.Algorithm{Name: "AES-256"}, QuantumRisk: findings.QRResistant, Severity: findings.SevInfo},
	}
	qrs := CalculateQRS(ff)
	// One vulnerable (-1.5), one weakened (-0.5), one safe (+0.5) = 100 - 1.5 = 98.5 → 98
	if qrs.Score < 50 || qrs.Score > 100 {
		t.Errorf("mixed: score = %d, want between 50 and 100", qrs.Score)
	}
}

func TestCalculateQRS_CorroboratedWeight(t *testing.T) {
	// Same findings — one corroborated, one not
	base := findings.UnifiedFinding{
		Algorithm:   &findings.Algorithm{Name: "RSA-2048"},
		QuantumRisk: findings.QRVulnerable,
		Severity:    findings.SevCritical,
	}
	corroborated := base
	corroborated.CorroboratedBy = []string{"cryptoscan"}

	qrsNormal := CalculateQRS([]findings.UnifiedFinding{base})
	qrsCorr := CalculateQRS([]findings.UnifiedFinding{corroborated})

	// Corroborated should have more penalty (lower score)
	if qrsCorr.Score >= qrsNormal.Score {
		t.Errorf("corroborated score (%d) should be lower than normal (%d)", qrsCorr.Score, qrsNormal.Score)
	}
}

func TestCalculateQRS_Deprecated(t *testing.T) {
	ff := []findings.UnifiedFinding{
		{Algorithm: &findings.Algorithm{Name: "MD5"}, QuantumRisk: findings.QRDeprecated, Severity: findings.SevCritical},
	}
	qrs := CalculateQRS(ff)
	// One deprecated: -1.5 → score 98
	if qrs.Score < 95 || qrs.Score > 100 {
		t.Errorf("one deprecated: score = %d, want ~98", qrs.Score)
	}
}

func TestCalculateQRS_ScoreClamped(t *testing.T) {
	// 100 critical vulnerable findings → score should floor at 0
	ff := make([]findings.UnifiedFinding, 100)
	for i := range ff {
		ff[i] = findings.UnifiedFinding{
			Algorithm:   &findings.Algorithm{Name: "RSA-2048"},
			QuantumRisk: findings.QRVulnerable,
			Severity:    findings.SevCritical,
		}
	}
	qrs := CalculateQRS(ff)
	if qrs.Score != 0 {
		t.Errorf("100 critical: score = %d, want 0", qrs.Score)
	}
	if qrs.Grade != "F" {
		t.Errorf("100 critical: grade = %q, want F", qrs.Grade)
	}
}

func TestCalculateQRSWithImpact_NilImpact(t *testing.T) {
	ff := []findings.UnifiedFinding{
		{Algorithm: &findings.Algorithm{Name: "RSA-2048"}, QuantumRisk: findings.QRVulnerable, Severity: findings.SevCritical},
	}
	want := CalculateQRS(ff)
	got := CalculateQRSWithImpact(ff, nil)
	if got != want {
		t.Errorf("nil impact: got %+v, want %+v", got, want)
	}
}

func TestCalculateQRSWithImpact_EmptyZones(t *testing.T) {
	ff := []findings.UnifiedFinding{
		{Algorithm: &findings.Algorithm{Name: "RSA-2048"}, QuantumRisk: findings.QRVulnerable, Severity: findings.SevCritical},
	}
	want := CalculateQRS(ff)
	got := CalculateQRSWithImpact(ff, &impact.Result{})
	if got != want {
		t.Errorf("empty zones: got %+v, want %+v", got, want)
	}
}

func TestCalculateQRSWithImpact_WithZones(t *testing.T) {
	// 10 critical vulnerable findings: score = 100 - 20*2.0 = 60
	ff := make([]findings.UnifiedFinding, 10)
	for i := range ff {
		ff[i] = findings.UnifiedFinding{
			Algorithm:   &findings.Algorithm{Name: "RSA-2048"},
			QuantumRisk: findings.QRVulnerable,
			Severity:    findings.SevCritical,
		}
	}
	base := CalculateQRS(ff) // expect 80

	// avgBlast = 100 → adjustment = 80 * (1 - 0.15) = 80 * 0.85 = 68
	impactResult := &impact.Result{
		ImpactZones: []impact.ImpactZone{
			{BlastRadiusScore: 100},
		},
	}
	got := CalculateQRSWithImpact(ff, impactResult)
	wantScore := int(float64(base.Score) * 0.85)
	// Allow ±1 for rounding differences
	if got.Score < wantScore-1 || got.Score > wantScore+1 {
		t.Errorf("with zones (blast=100): score = %d, want ~%d (base=%d)", got.Score, wantScore, base.Score)
	}
	if got.Score > base.Score {
		t.Errorf("adjusted score %d should not exceed base score %d", got.Score, base.Score)
	}
}

func TestCalculateQRSWithImpact_AvgBlast(t *testing.T) {
	// 5 critical vulnerable: score = 100 - 10 = 90
	ff := make([]findings.UnifiedFinding, 5)
	for i := range ff {
		ff[i] = findings.UnifiedFinding{
			Algorithm:   &findings.Algorithm{Name: "RSA-2048"},
			QuantumRisk: findings.QRVulnerable,
			Severity:    findings.SevCritical,
		}
	}
	base := CalculateQRS(ff) // 90

	// Two zones: blast scores 50 and 50 → avg=50
	// adjusted = 90 * (1 - 0.15*50/100) = 90 * 0.925 = 83.25 → 83
	impactResult := &impact.Result{
		ImpactZones: []impact.ImpactZone{
			{BlastRadiusScore: 50},
			{BlastRadiusScore: 50},
		},
	}
	got := CalculateQRSWithImpact(ff, impactResult)
	wantScore := 83
	if got.Score < wantScore-1 || got.Score > wantScore+1 {
		t.Errorf("avg blast=50: score = %d, want ~%d (base=%d)", got.Score, wantScore, base.Score)
	}
}

func TestCalculateQRSWithImpact_FloorAtZero(t *testing.T) {
	// Force base score to 0 then apply blast — result must stay 0
	ff := make([]findings.UnifiedFinding, 100)
	for i := range ff {
		ff[i] = findings.UnifiedFinding{
			Algorithm:   &findings.Algorithm{Name: "RSA-2048"},
			QuantumRisk: findings.QRVulnerable,
			Severity:    findings.SevCritical,
		}
	}
	impactResult := &impact.Result{
		ImpactZones: []impact.ImpactZone{
			{BlastRadiusScore: 100},
		},
	}
	got := CalculateQRSWithImpact(ff, impactResult)
	if got.Score != 0 {
		t.Errorf("floor: score = %d, want 0", got.Score)
	}
	if got.Grade != "F" {
		t.Errorf("floor: grade = %q, want F", got.Grade)
	}
}

// --- Protocol-weighted QRS tests ---

// tlsImpactFor builds an impact.Result with a single ImpactZone whose
// FindingKey matches f.DedupeKey() and whose ViolatedProtocols contains
// the given protocol name.
func tlsImpactFor(f findings.UnifiedFinding, protocol string) *impact.Result {
	return &impact.Result{
		ImpactZones: []impact.ImpactZone{
			{
				FindingKey:        f.DedupeKey(),
				BlastRadiusScore:  0, // zero — isolates the protocol effect
				ViolatedProtocols: []impact.ProtocolViolation{{Protocol: protocol}},
			},
		},
	}
}

func TestProtocolMultiplierMap_AllEightProtocols(t *testing.T) {
	// The impact registry defines exactly 8 protocols. Every one must have an
	// entry in protocolMultipliers (using the lowercase normalised key).
	required := []string{"tls", "dtls", "ssh", "x.509", "grpc", "jwt", "ocsp", "s/mime"}
	for _, proto := range required {
		if _, ok := protocolMultipliers[proto]; !ok {
			t.Errorf("protocolMultipliers missing entry for %q", proto)
		}
	}
	if len(protocolMultipliers) != len(required) {
		t.Errorf("protocolMultipliers has %d entries, want %d", len(protocolMultipliers), len(required))
	}
}

func TestCalculateQRSWithImpact_TLSProtocol_LowerScore(t *testing.T) {
	// Use 5 critical findings so the TLS multiplier (1.2) produces a visibly lower
	// score after rounding.
	//   No-protocol: 100 - 5×2.0      = 90
	//   TLS (×1.2):  100 - 5×2.0×1.2 = 88
	makeFF := func(file string, n int) []findings.UnifiedFinding {
		ff := make([]findings.UnifiedFinding, n)
		for i := range ff {
			ff[i] = findings.UnifiedFinding{
				Location:    findings.Location{File: file, Line: i + 1},
				Algorithm:   &findings.Algorithm{Name: "RSA-2048"},
				QuantumRisk: findings.QRVulnerable,
				Severity:    findings.SevCritical,
			}
		}
		return ff
	}

	ffNoProto := makeFF("crypto/tls.go", 5)
	ffTLS := makeFF("crypto/tls.go", 5)

	noProtoZones := make([]impact.ImpactZone, len(ffNoProto))
	for i, f := range ffNoProto {
		noProtoZones[i] = impact.ImpactZone{FindingKey: f.DedupeKey(), BlastRadiusScore: 0}
	}
	tlsZones := make([]impact.ImpactZone, len(ffTLS))
	for i, f := range ffTLS {
		tlsZones[i] = impact.ImpactZone{
			FindingKey:        f.DedupeKey(),
			BlastRadiusScore:  0,
			ViolatedProtocols: []impact.ProtocolViolation{{Protocol: "TLS"}},
		}
	}

	withoutProtocol := CalculateQRSWithImpact(ffNoProto, &impact.Result{ImpactZones: noProtoZones})
	withTLS := CalculateQRSWithImpact(ffTLS, &impact.Result{ImpactZones: tlsZones})

	if withTLS.Score >= withoutProtocol.Score {
		t.Errorf("TLS protocol score (%d) should be lower than no-protocol score (%d)",
			withTLS.Score, withoutProtocol.Score)
	}
}

func TestCalculateQRSWithImpact_SMIMEProtocol_HigherScoreThanTLS(t *testing.T) {
	// S/MIME multiplier (0.9) is less than TLS multiplier (1.2), so the same
	// findings in S/MIME context should produce a higher (better) score than TLS.
	// Use 10 findings to make the rounding difference visible:
	//   TLS (×1.2):   100 - 10×2.0×1.2 = 76
	//   S/MIME (×0.9):100 - 10×2.0×0.9 = 82
	makeZones := func(ff []findings.UnifiedFinding, protocol string) []impact.ImpactZone {
		zones := make([]impact.ImpactZone, len(ff))
		for i, f := range ff {
			zones[i] = impact.ImpactZone{
				FindingKey:        f.DedupeKey(),
				BlastRadiusScore:  0,
				ViolatedProtocols: []impact.ProtocolViolation{{Protocol: protocol}},
			}
		}
		return zones
	}

	makeFF := func(file string, n int) []findings.UnifiedFinding {
		ff := make([]findings.UnifiedFinding, n)
		for i := range ff {
			ff[i] = findings.UnifiedFinding{
				Location:    findings.Location{File: file, Line: i + 1},
				Algorithm:   &findings.Algorithm{Name: "RSA-2048"},
				QuantumRisk: findings.QRVulnerable,
				Severity:    findings.SevCritical,
			}
		}
		return ff
	}

	ffSMIME := makeFF("mail/sign.go", 10)
	ffTLS := makeFF("mail/sign.go", 10)

	scoreSMIME := CalculateQRSWithImpact(ffSMIME, &impact.Result{ImpactZones: makeZones(ffSMIME, "S/MIME")})
	scoreTLS := CalculateQRSWithImpact(ffTLS, &impact.Result{ImpactZones: makeZones(ffTLS, "TLS")})

	if scoreSMIME.Score <= scoreTLS.Score {
		t.Errorf("S/MIME score (%d) should be higher than TLS score (%d)",
			scoreSMIME.Score, scoreTLS.Score)
	}
}

func TestCalculateQRSWithImpact_NoProtocol_BackwardCompatible(t *testing.T) {
	// A finding matched to a zone with no ViolatedProtocols must produce the
	// same score as CalculateQRS (protocol multiplier defaults to 1.0).
	f := findings.UnifiedFinding{
		Location:    findings.Location{File: "lib/crypto.go", Line: 5},
		Algorithm:   &findings.Algorithm{Name: "ECDH"},
		QuantumRisk: findings.QRVulnerable,
		Severity:    findings.SevHigh,
	}

	base := CalculateQRS([]findings.UnifiedFinding{f})
	withImpact := CalculateQRSWithImpact([]findings.UnifiedFinding{f}, &impact.Result{
		ImpactZones: []impact.ImpactZone{
			{FindingKey: f.DedupeKey(), BlastRadiusScore: 0 /* no blast, no protocols */},
		},
	})

	if withImpact.Score != base.Score {
		t.Errorf("no-protocol impact: score = %d, want %d (same as base)", withImpact.Score, base.Score)
	}
}

func TestCalculateQRSWithImpact_ProtocolMultiplierNumerics(t *testing.T) {
	// Use 10 critical findings (blast=0) to make per-protocol multiplier differences
	// survive integer rounding. Expected scores:
	//   No protocol (×1.0): 100 - 10×2.0×1.0 = 80
	//   TLS/DTLS (×1.2):    100 - 10×2.0×1.2 = 76
	//   X.509 (×1.15):      100 - 10×2.0×1.15 = 77
	//   SSH/gRPC (×1.1):    100 - 10×2.0×1.1 = 78
	//   JWT/OCSP (×1.0):    100 - 10×2.0×1.0 = 80 (same as no-protocol)
	//   S/MIME (×0.9):      100 - 10×2.0×0.9 = 82 (better than no-protocol)
	makeFindings := func(file string, n int) []findings.UnifiedFinding {
		ff := make([]findings.UnifiedFinding, n)
		for i := range ff {
			ff[i] = findings.UnifiedFinding{
				Location:    findings.Location{File: file, Line: i + 1},
				Algorithm:   &findings.Algorithm{Name: "RSA-2048"},
				QuantumRisk: findings.QRVulnerable,
				Severity:    findings.SevCritical,
			}
		}
		return ff
	}

	// wantCmp: -1 = score should be lower than no-protocol (worse),
	//           0 = score should equal no-protocol,
	//          +1 = score should be higher than no-protocol (better).
	tests := []struct {
		protocol string
		wantCmp  int
	}{
		{"TLS", -1},
		{"DTLS", -1},
		{"SSH", -1},
		{"X.509", -1},
		{"gRPC", -1},
		{"JWT", 0},   // mult=1.0, equal to no-protocol
		{"OCSP", 0},  // mult=1.0, equal to no-protocol
		{"S/MIME", 1}, // mult=0.9, penalty reduced → better score
	}

	for _, tt := range tests {
		t.Run(tt.protocol, func(t *testing.T) {
			ff := makeFindings("src/crypto.go", 10)

			// Build impact with one zone per finding (all same protocol).
			zones := make([]impact.ImpactZone, len(ff))
			for i, f := range ff {
				zones[i] = impact.ImpactZone{
					FindingKey:        f.DedupeKey(),
					BlastRadiusScore:  0,
					ViolatedProtocols: []impact.ProtocolViolation{{Protocol: tt.protocol}},
				}
			}
			withProto := CalculateQRSWithImpact(ff, &impact.Result{ImpactZones: zones})

			// Build impact with same zones but no protocols (mult=1.0 baseline).
			noProtoZones := make([]impact.ImpactZone, len(ff))
			for i, f := range ff {
				noProtoZones[i] = impact.ImpactZone{
					FindingKey:       f.DedupeKey(),
					BlastRadiusScore: 0,
				}
			}
			withoutProto := CalculateQRSWithImpact(ff, &impact.Result{ImpactZones: noProtoZones})

			switch tt.wantCmp {
			case -1:
				if withProto.Score >= withoutProto.Score {
					t.Errorf("protocol %q: score %d should be < no-protocol score %d",
						tt.protocol, withProto.Score, withoutProto.Score)
				}
			case 0:
				if withProto.Score != withoutProto.Score {
					t.Errorf("protocol %q: score %d should equal no-protocol score %d",
						tt.protocol, withProto.Score, withoutProto.Score)
				}
			case 1:
				if withProto.Score <= withoutProto.Score {
					t.Errorf("protocol %q: score %d should be > no-protocol score %d",
						tt.protocol, withProto.Score, withoutProto.Score)
				}
			}
		})
	}
}

func TestCalculateQRSWithImpact_HighestMultiplierWins(t *testing.T) {
	// When multiple protocols are violated, the highest multiplier is applied.
	// TLS (1.2) > SSH (1.1) → TLS wins.
	// Use 10 findings so the difference between 1.2 and 1.1 survives rounding:
	//   TLS (×1.2):     100 - 10×2.0×1.2 = 76
	//   SSH (×1.1):     100 - 10×2.0×1.1 = 78
	//   TLS+SSH (max=1.2): same as TLS-only = 76
	makeFF := func(n int) []findings.UnifiedFinding {
		ff := make([]findings.UnifiedFinding, n)
		for i := range ff {
			ff[i] = findings.UnifiedFinding{
				Location:    findings.Location{File: "gateway/handler.go", Line: i + 1},
				Algorithm:   &findings.Algorithm{Name: "RSA-2048"},
				QuantumRisk: findings.QRVulnerable,
				Severity:    findings.SevCritical,
			}
		}
		return ff
	}

	makeImpact := func(ff []findings.UnifiedFinding, protocols ...string) *impact.Result {
		pvs := make([]impact.ProtocolViolation, len(protocols))
		for i, p := range protocols {
			pvs[i] = impact.ProtocolViolation{Protocol: p}
		}
		zones := make([]impact.ImpactZone, len(ff))
		for i, f := range ff {
			zones[i] = impact.ImpactZone{
				FindingKey:        f.DedupeKey(),
				BlastRadiusScore:  0,
				ViolatedProtocols: pvs,
			}
		}
		return &impact.Result{ImpactZones: zones}
	}

	ffTLS := makeFF(10)
	ffSSH := makeFF(10)
	ffBoth := makeFF(10)

	tlsOnly := CalculateQRSWithImpact(ffTLS, makeImpact(ffTLS, "TLS"))
	sshOnly := CalculateQRSWithImpact(ffSSH, makeImpact(ffSSH, "SSH"))
	tlsAndSSH := CalculateQRSWithImpact(ffBoth, makeImpact(ffBoth, "TLS", "SSH"))

	// TLS+SSH should equal TLS-only (TLS mult=1.2 wins over SSH mult=1.1).
	if tlsAndSSH.Score != tlsOnly.Score {
		t.Errorf("TLS+SSH score (%d) should equal TLS-only score (%d)", tlsAndSSH.Score, tlsOnly.Score)
	}
	// SSH-only should be better (higher) than TLS-only (smaller multiplier = less penalty).
	if sshOnly.Score <= tlsOnly.Score {
		t.Errorf("SSH-only score (%d) should be > TLS-only score (%d)", sshOnly.Score, tlsOnly.Score)
	}
}

func TestCalculateQRSWithImpact_UnmatchedFinding_UsesBaseMultiplier(t *testing.T) {
	// If a finding has no corresponding ImpactZone (FindingKey mismatch),
	// protocolMultiplierForFinding must return 1.0 — no change to the penalty.
	f := findings.UnifiedFinding{
		Location:    findings.Location{File: "pkg/foo.go", Line: 1},
		Algorithm:   &findings.Algorithm{Name: "RSA-2048"},
		QuantumRisk: findings.QRVulnerable,
		Severity:    findings.SevCritical,
	}

	// ImpactZone keyed to a completely different finding.
	differentKey := "different/file.go|99|alg|ECDH"
	withImpact := CalculateQRSWithImpact([]findings.UnifiedFinding{f}, &impact.Result{
		ImpactZones: []impact.ImpactZone{
			{
				FindingKey:        differentKey,
				BlastRadiusScore:  0,
				ViolatedProtocols: []impact.ProtocolViolation{{Protocol: "TLS"}},
			},
		},
	})

	base := CalculateQRS([]findings.UnifiedFinding{f})
	// blast=0 and no matching zone → result must equal base
	if withImpact.Score != base.Score {
		t.Errorf("unmatched zone: score = %d, want %d (base)", withImpact.Score, base.Score)
	}
}

func TestScoreToGrade(t *testing.T) {
	tests := []struct {
		score int
		grade string
	}{
		{100, "A+"}, {95, "A+"}, {94, "A"}, {85, "A"},
		{84, "B"}, {70, "B"}, {69, "C"}, {50, "C"},
		{49, "D"}, {30, "D"}, {29, "F"}, {0, "F"},
	}
	for _, tt := range tests {
		got := scoreToGrade(tt.score)
		if got != tt.grade {
			t.Errorf("scoreToGrade(%d) = %q, want %q", tt.score, got, tt.grade)
		}
	}
}

func TestDataLifetimeMultiplier(t *testing.T) {
	tests := []struct {
		years int
		want  float64
	}{
		{0, 1.0},   // disabled / unknown
		{3, 0.85},  // short-lived (1–4 years): reduces penalties
		{7, 1.0},   // standard range (5–10 years): no adjustment
		{15, 1.15}, // long-lived (> 10 years): amplifies penalties
		{30, 1.15}, // very long-lived: same cap
	}
	for _, tt := range tests {
		got := DataLifetimeMultiplier(tt.years)
		if got != tt.want {
			t.Errorf("DataLifetimeMultiplier(%d) = %v, want %v", tt.years, got, tt.want)
		}
	}
}

func TestCalculateQRSWithLifetime_LongLived_LowerScore(t *testing.T) {
	// 10 critical vulnerable findings: base = 100 - 20 = 80
	// With multiplier 1.15: 100 - 23 = 77
	ff := make([]findings.UnifiedFinding, 10)
	for i := range ff {
		ff[i] = findings.UnifiedFinding{
			Algorithm:   &findings.Algorithm{Name: "RSA-2048"},
			QuantumRisk: findings.QRVulnerable,
			Severity:    findings.SevCritical,
		}
	}
	base := CalculateQRS(ff)
	long := CalculateQRSWithLifetime(ff, DataLifetimeMultiplier(20))
	if long.Score >= base.Score {
		t.Errorf("long-lived score (%d) should be lower than base (%d)", long.Score, base.Score)
	}
}

func TestCalculateQRSWithLifetime_ShortLived_HigherScore(t *testing.T) {
	// 10 critical findings: base = 80
	// With multiplier 0.85: 100 - 17 = 83
	ff := make([]findings.UnifiedFinding, 10)
	for i := range ff {
		ff[i] = findings.UnifiedFinding{
			Algorithm:   &findings.Algorithm{Name: "RSA-2048"},
			QuantumRisk: findings.QRVulnerable,
			Severity:    findings.SevCritical,
		}
	}
	base := CalculateQRS(ff)
	short := CalculateQRSWithLifetime(ff, DataLifetimeMultiplier(3))
	if short.Score <= base.Score {
		t.Errorf("short-lived score (%d) should be higher than base (%d)", short.Score, base.Score)
	}
}

func TestCalculateQRSWithLifetime_Standard_SameAsBase(t *testing.T) {
	// Multiplier 1.0 (years=7) → identical to CalculateQRS.
	ff := []findings.UnifiedFinding{
		{Algorithm: &findings.Algorithm{Name: "RSA-2048"}, QuantumRisk: findings.QRVulnerable, Severity: findings.SevHigh},
	}
	base := CalculateQRS(ff)
	standard := CalculateQRSWithLifetime(ff, DataLifetimeMultiplier(7))
	if standard != base {
		t.Errorf("standard lifetime: got %+v, want %+v", standard, base)
	}
}

func TestCalculateQRSWithLifetime_Disabled_SameAsBase(t *testing.T) {
	// Multiplier 1.0 (years=0, disabled) → identical to CalculateQRS.
	ff := []findings.UnifiedFinding{
		{Algorithm: &findings.Algorithm{Name: "RSA-2048"}, QuantumRisk: findings.QRVulnerable, Severity: findings.SevHigh},
	}
	base := CalculateQRS(ff)
	disabled := CalculateQRSWithLifetime(ff, DataLifetimeMultiplier(0))
	if disabled != base {
		t.Errorf("disabled lifetime: got %+v, want %+v", disabled, base)
	}
}

func TestCalculateQRSWithLifetime_PQCSafeNotMultiplied(t *testing.T) {
	// PQC-safe adoption bonus (+0.5) must NOT be multiplied by the lifetime factor.
	// 5 safe findings → score clamped to 100 regardless of lifetime multiplier.
	ff := make([]findings.UnifiedFinding, 5)
	for i := range ff {
		ff[i] = findings.UnifiedFinding{
			Algorithm:   &findings.Algorithm{Name: "ML-KEM-768"},
			QuantumRisk: findings.QRSafe,
			Severity:    findings.SevInfo,
		}
	}
	for _, years := range []int{3, 7, 20} {
		got := CalculateQRSWithLifetime(ff, DataLifetimeMultiplier(years))
		if got.Score != 100 {
			t.Errorf("safe findings (years=%d): score = %d, want 100", years, got.Score)
		}
	}
}
