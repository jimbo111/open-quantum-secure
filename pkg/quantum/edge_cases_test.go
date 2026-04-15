package quantum

// edge_cases_test.go — New edge-case tests for pkg/quantum.
// Covers input parsing, key-size boundaries, K-PQC candidates,
// QRS formula math, grade thresholds, and HNDL classification.

import (
	"strings"
	"testing"

	"github.com/jimbo111/open-quantum-secure/pkg/findings"
)

// ---------------------------------------------------------------------------
// 1. Input parsing — curve aliases, hash aliases, case sensitivity, whitespace
// ---------------------------------------------------------------------------

// TestClassify_CurveAliasNormalization verifies that common alternative names
// for elliptic curves are all recognised as quantum-vulnerable.
// The NIST curve P-256 appears as secp256r1 and prime256v1 in real-world code.
func TestClassify_CurveAliasNormalization(t *testing.T) {
	tests := []struct {
		name      string
		algName   string
		primitive string
		wantRisk  Risk
		wantSev   Severity
	}{
		// Canonical name
		{"P-256 ecdsa", "ECDSA", "signature", RiskVulnerable, SeverityHigh},
		// Common OpenSSL alias — extractBaseName splits at '-', first segment is "secp256r1"
		// No map hit → falls through to primitive path → signature → RiskVulnerable/High
		{"secp256r1 signature", "secp256r1", "signature", RiskVulnerable, SeverityHigh},
		// Another OpenSSL alias
		{"prime256v1 signature", "prime256v1", "signature", RiskVulnerable, SeverityHigh},
		// P-384 canonical via ECDSA primitive
		{"P-384 ecdsa", "ECDSA", "signature", RiskVulnerable, SeverityHigh},
		// secp384r1 alias
		{"secp384r1 signature", "secp384r1", "signature", RiskVulnerable, SeverityHigh},
		// brainpoolP256r1 — unknown curve, signature primitive → deferred HNDL
		{"brainpoolP256r1 signature", "brainpoolP256r1", "signature", RiskVulnerable, SeverityHigh},
		// P-224 via ECDH — key-exchange primitive → immediate HNDL
		{"P-224 key-exchange", "secp224r1", "key-exchange", RiskVulnerable, SeverityCritical},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			got := ClassifyAlgorithm(tt.algName, tt.primitive, 0)
			if got.Risk != tt.wantRisk {
				t.Errorf("ClassifyAlgorithm(%q, %q, 0).Risk = %q, want %q",
					tt.algName, tt.primitive, got.Risk, tt.wantRisk)
			}
			if got.Severity != tt.wantSev {
				t.Errorf("ClassifyAlgorithm(%q, %q, 0).Severity = %q, want %q",
					tt.algName, tt.primitive, got.Severity, tt.wantSev)
			}
		})
	}
}

// TestClassify_HashAliasNormalization verifies that SHA-1 and its common aliases
// are all classified as deprecated (classically broken regardless of quantum).
func TestClassify_HashAliasNormalization(t *testing.T) {
	aliases := []struct {
		name    string
		algName string
	}{
		{"SHA-1 canonical", "SHA-1"},
		{"SHA1 no-hyphen", "SHA1"},
		// SHA-1 with extra casing
		{"sha-1 lowercase", "sha-1"},
		{"sha1 lowercase", "sha1"},
		{"Sha-1 mixed case", "Sha-1"},
		{"SHA1 all-caps", "SHA1"},
	}

	for _, tt := range aliases {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			got := ClassifyAlgorithm(tt.algName, "hash", 0)
			if got.Risk != RiskDeprecated {
				t.Errorf("ClassifyAlgorithm(%q).Risk = %q, want %q (SHA-1 is deprecated)",
					tt.algName, got.Risk, RiskDeprecated)
			}
			if got.Severity != SeverityCritical {
				t.Errorf("ClassifyAlgorithm(%q).Severity = %q, want %q",
					tt.algName, got.Severity, SeverityCritical)
			}
		})
	}
}

// TestClassify_CaseSensitivity checks that algorithm names are matched
// case-insensitively for all the major families.
func TestClassify_CaseSensitivity(t *testing.T) {
	tests := []struct {
		name      string
		algName   string
		primitive string
		wantRisk  Risk
	}{
		// RSA variants
		{"rsa lowercase", "rsa", "", RiskVulnerable},
		{"Rsa mixed", "Rsa", "", RiskVulnerable},
		{"RSA-2048 embedded size", "RSA-2048", "", RiskVulnerable},
		// AES variants
		{"aes-256-gcm lowercase", "aes-256-gcm", "ae", RiskResistant},
		{"AES-256-GCM uppercase", "AES-256-GCM", "ae", RiskResistant},
		// MD5 deprecated
		{"md5 lowercase", "md5", "hash", RiskDeprecated},
		{"Md5 mixed", "Md5", "hash", RiskDeprecated},
		// ML-KEM safe
		{"ml-kem-768 lowercase", "ml-kem-768", "kem", RiskSafe},
		{"ML-KEM-768 uppercase", "ML-KEM-768", "kem", RiskSafe},
		// ECDH
		{"ecdh lowercase", "ecdh", "key-agree", RiskVulnerable},
		{"ECDH uppercase", "ECDH", "key-agree", RiskVulnerable},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			got := ClassifyAlgorithm(tt.algName, tt.primitive, 0)
			if got.Risk != tt.wantRisk {
				t.Errorf("ClassifyAlgorithm(%q, %q, 0).Risk = %q, want %q",
					tt.algName, tt.primitive, got.Risk, tt.wantRisk)
			}
		})
	}
}

// TestClassify_EmptyAndWhitespaceName verifies graceful handling of empty
// or whitespace-only algorithm names.
func TestClassify_EmptyAndWhitespaceName(t *testing.T) {
	tests := []struct {
		name      string
		algName   string
		primitive string
		wantRisk  Risk
	}{
		// Empty name, no primitive → RiskUnknown
		{"empty name no primitive", "", "", RiskUnknown},
		// Empty name with kem primitive → unknown alg with kem → RiskVulnerable (HNDL immediate)
		{"empty name kem", "", "kem", RiskVulnerable},
		// Empty name with signature primitive → RiskVulnerable (HNDL deferred)
		{"empty name signature", "", "signature", RiskVulnerable},
		// Whitespace-padded names should be trimmed before lookup.
		{"padded RSA", "  RSA  ", "", RiskVulnerable},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("ClassifyAlgorithm panicked with name=%q: %v", tt.algName, r)
				}
			}()
			got := ClassifyAlgorithm(tt.algName, tt.primitive, 0)
			if got.Risk != tt.wantRisk {
				t.Errorf("ClassifyAlgorithm(%q, %q, 0).Risk = %q, want %q",
					tt.algName, tt.primitive, got.Risk, tt.wantRisk)
			}
		})
	}
}

// TestClassify_WhitespacePaddedName verifies that whitespace-padded names are
// trimmed before classification. AST and grep engines regularly surface
// algorithm tokens with surrounding whitespace; leaving them unclassified was
// a silent false-negative in production scans.
func TestClassify_WhitespacePaddedName(t *testing.T) {
	t.Run("leading_trailing_space_RSA", func(t *testing.T) {
		got := ClassifyAlgorithm(" RSA ", "", 0)
		if got.Risk != RiskVulnerable {
			t.Errorf("ClassifyAlgorithm(\" RSA \").Risk = %q, want %q", got.Risk, RiskVulnerable)
		}
	})

	t.Run("tab_padded_SHA1", func(t *testing.T) {
		got := ClassifyAlgorithm("\tSHA-1\t", "hash", 0)
		if got.Risk != RiskDeprecated {
			t.Errorf("ClassifyAlgorithm(\"\\tSHA-1\\t\").Risk = %q, want %q", got.Risk, RiskDeprecated)
		}
	})
}

// ---------------------------------------------------------------------------
// 2. Key-size boundaries — RSA, AES, unusual ECC curves
// ---------------------------------------------------------------------------

// TestClassify_RSAKeySizeLadder verifies that RSA classifications follow the
// CNSA 2.0 key-size thresholds and that unusual sizes (0, negative, 1023,
// 2049, 8192) are handled without panic.
func TestClassify_RSAKeySizeLadder(t *testing.T) {
	tests := []struct {
		name        string
		keySize     int
		wantRisk    Risk
		wantSev     Severity
		wantHNDL    string
		wantTarget  string
	}{
		// Standard NIST-recommended sizes
		{"RSA-1024 default prim", 1024, RiskVulnerable, SeverityHigh, HNDLImmediate, "ML-DSA-44"},
		{"RSA-2048 default prim", 2048, RiskVulnerable, SeverityHigh, HNDLImmediate, "ML-DSA-44"},
		{"RSA-3072 default prim", 3072, RiskVulnerable, SeverityHigh, HNDLImmediate, "ML-DSA-65"},
		{"RSA-4096 default prim", 4096, RiskVulnerable, SeverityHigh, HNDLImmediate, "ML-DSA-87"},
		{"RSA-8192 large key", 8192, RiskVulnerable, SeverityHigh, HNDLImmediate, "ML-DSA-87"},
		// Off-by-one boundaries
		{"RSA-1023 unusual", 1023, RiskVulnerable, SeverityHigh, HNDLImmediate, "ML-DSA-44"},
		{"RSA-2049 unusual", 2049, RiskVulnerable, SeverityHigh, HNDLImmediate, "ML-DSA-44"},
		// Edge: zero keySize → no key-size info, still vulnerable
		{"RSA-0 no size", 0, RiskVulnerable, SeverityHigh, HNDLImmediate, "ML-DSA-44"},
		// Edge: negative keySize — must not panic
		{"RSA negative size", -1, RiskVulnerable, SeverityHigh, HNDLImmediate, "ML-DSA-44"},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("ClassifyAlgorithm panicked with RSA keySize=%d: %v", tt.keySize, r)
				}
			}()
			// No explicit primitive so it hits the "unknown primitive → conservative" path
			got := ClassifyAlgorithm("RSA", "", tt.keySize)
			if got.Risk != tt.wantRisk {
				t.Errorf("RSA keySize=%d Risk = %q, want %q", tt.keySize, got.Risk, tt.wantRisk)
			}
			if got.Severity != tt.wantSev {
				t.Errorf("RSA keySize=%d Severity = %q, want %q", tt.keySize, got.Severity, tt.wantSev)
			}
			if got.HNDLRisk != tt.wantHNDL {
				t.Errorf("RSA keySize=%d HNDLRisk = %q, want %q", tt.keySize, got.HNDLRisk, tt.wantHNDL)
			}
			if got.TargetAlgorithm != tt.wantTarget {
				t.Errorf("RSA keySize=%d TargetAlgorithm = %q, want %q", tt.keySize, got.TargetAlgorithm, tt.wantTarget)
			}
		})
	}
}

// TestClassify_AESKeySizeBoundaries probes AES at every significant boundary.
func TestClassify_AESKeySizeBoundaries(t *testing.T) {
	tests := []struct {
		name      string
		algName   string
		keySize   int
		wantRisk  Risk
		wantSev   Severity
	}{
		// < 128 bits → RiskWeakened/Medium (key too small)
		{"AES key<128", "AES", 64, RiskWeakened, SeverityMedium},
		{"AES key=127", "AES", 127, RiskWeakened, SeverityMedium},
		// 128-bit → weakened by Grover
		{"AES-128", "AES-128", 128, RiskWeakened, SeverityLow},
		// 192-bit → still weakened
		{"AES-192", "AES-192", 192, RiskWeakened, SeverityLow},
		// 256-bit → resistant
		{"AES-256", "AES-256", 256, RiskResistant, SeverityInfo},
		// 512-bit (hypothetical) → resistant
		{"AES-512 hypothetical", "AES", 512, RiskResistant, SeverityInfo},
		// 0 keySize, no suffix → cannot infer → RiskUnknown
		{"AES bare no size", "AES", 0, RiskUnknown, SeverityLow},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			got := ClassifyAlgorithm(tt.algName, "symmetric", tt.keySize)
			if got.Risk != tt.wantRisk {
				t.Errorf("AES keySize=%d Risk = %q, want %q", tt.keySize, got.Risk, tt.wantRisk)
			}
			if got.Severity != tt.wantSev {
				t.Errorf("AES keySize=%d Severity = %q, want %q", tt.keySize, got.Severity, tt.wantSev)
			}
		})
	}
}

// TestClassify_UnusualECCCurves checks P-224 and brainpool curves which are
// not in the canonical NIST set but appear in real-world deployments.
func TestClassify_UnusualECCCurves(t *testing.T) {
	tests := []struct {
		name      string
		algName   string
		primitive string
		wantRisk  Risk
		wantSev   Severity
		wantHNDL  string
	}{
		// P-224 via explicit ECDSA
		{"ECDSA P-224 size", "ECDSA", "signature", RiskVulnerable, SeverityHigh, HNDLDeferred},
		// P-224 via explicit ECDH
		{"ECDH P-224 size", "ECDH", "key-agree", RiskVulnerable, SeverityCritical, HNDLImmediate},
		// brainpoolP256r1 — unrecognised name, signature primitive
		{"brainpoolP256r1", "brainpoolP256r1", "signature", RiskVulnerable, SeverityHigh, HNDLDeferred},
		// brainpoolP384r1 — unrecognised name, key-exchange primitive
		{"brainpoolP384r1 key-exchange", "brainpoolP384r1", "key-exchange", RiskVulnerable, SeverityCritical, HNDLImmediate},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			got := ClassifyAlgorithm(tt.algName, tt.primitive, 224)
			if got.Risk != tt.wantRisk {
				t.Errorf("ClassifyAlgorithm(%q, %q, 224).Risk = %q, want %q",
					tt.algName, tt.primitive, got.Risk, tt.wantRisk)
			}
			if got.Severity != tt.wantSev {
				t.Errorf("ClassifyAlgorithm(%q, %q, 224).Severity = %q, want %q",
					tt.algName, tt.primitive, got.Severity, tt.wantSev)
			}
			if got.HNDLRisk != tt.wantHNDL {
				t.Errorf("ClassifyAlgorithm(%q, %q, 224).HNDLRisk = %q, want %q",
					tt.algName, tt.primitive, got.HNDLRisk, tt.wantHNDL)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// 3. K-PQC candidates — safe finalists vs eliminated candidates
// ---------------------------------------------------------------------------

// TestClassify_KPQCFinalistsAreSafe verifies that every K-PQC Round 4 finalist
// is classified as RiskSafe regardless of primitive tag.
func TestClassify_KPQCFinalistsAreSafe(t *testing.T) {
	finalists := []struct {
		algName   string
		primitive string
	}{
		{"SMAUG-T", "kem"},
		{"SMAUG-T-128", "kem"},
		{"SMAUG-T-192", "kem"},
		{"SMAUG-T-256", "kem"},
		{"HAETAE", "signature"},
		{"HAETAE-2", "signature"},
		{"HAETAE-3", "signature"},
		{"HAETAE-5", "signature"},
		{"AIMer", "signature"},
		{"AIMer-128f", "signature"},
		{"AIMer-128s", "signature"},
		{"AIMer-256f", "signature"},
		{"NTRU+", "kem"},
		{"NTRU+-576", "kem"},
		{"NTRU+-768", "kem"},
		{"NTRU+-864", "kem"},
	}

	for _, alg := range finalists {
		alg := alg
		t.Run(alg.algName, func(t *testing.T) {
			got := ClassifyAlgorithm(alg.algName, alg.primitive, 0)
			if got.Risk != RiskSafe {
				t.Errorf("K-PQC finalist %q should be RiskSafe, got %q", alg.algName, got.Risk)
			}
			if got.Severity != SeverityInfo {
				t.Errorf("K-PQC finalist %q should be SeverityInfo, got %q", alg.algName, got.Severity)
			}
			// Safe finalists must have no HNDL tag
			if got.HNDLRisk != "" {
				t.Errorf("K-PQC finalist %q should have empty HNDLRisk, got %q", alg.algName, got.HNDLRisk)
			}
		})
	}
}

// TestClassify_KPQCEliminatedAreVulnerable verifies all eliminated K-PQC candidates
// return RiskVulnerable with SeverityMedium and a migration recommendation.
func TestClassify_KPQCEliminatedAreVulnerable(t *testing.T) {
	eliminated := []struct {
		algName   string
		primitive string
	}{
		{"GCKSign", "signature"},
		{"NCC-Sign", "signature"},
		{"SOLMAE", "kem"},
		{"TiGER", "kem"},
		{"PALOMA", "kem"},
		{"REDOG", "kem"},
	}

	for _, alg := range eliminated {
		alg := alg
		t.Run(alg.algName, func(t *testing.T) {
			got := ClassifyAlgorithm(alg.algName, alg.primitive, 0)
			if got.Risk != RiskVulnerable {
				t.Errorf("eliminated candidate %q should be RiskVulnerable, got %q", alg.algName, got.Risk)
			}
			if got.Severity != SeverityMedium {
				t.Errorf("eliminated candidate %q should be SeverityMedium, got %q", alg.algName, got.Severity)
			}
			if got.Recommendation == "" {
				t.Errorf("eliminated candidate %q should have a non-empty Recommendation", alg.algName)
			}
			upperRec := strings.ToUpper(got.Recommendation)
			if !strings.Contains(upperRec, "SMAUG-T") && !strings.Contains(upperRec, "HAETAE") {
				t.Errorf("eliminated candidate %q recommendation should mention SMAUG-T or HAETAE, got: %s",
					alg.algName, got.Recommendation)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// 4. QRS formula — exact arithmetic verification
// ---------------------------------------------------------------------------

// TestQRS_ZeroFindingsIs100 confirms the base case is exactly 100/A+.
func TestQRS_ZeroFindingsIs100(t *testing.T) {
	for _, ff := range [][]findings.UnifiedFinding{nil, {}} {
		qrs := CalculateQRS(ff)
		if qrs.Score != 100 {
			t.Errorf("zero findings: Score = %d, want 100", qrs.Score)
		}
		if qrs.Grade != "A+" {
			t.Errorf("zero findings: Grade = %q, want A+", qrs.Grade)
		}
	}
}

// TestQRS_AllPQCSafe_DoesNotExceed100 confirms PQC bonuses never push the score above 100.
func TestQRS_AllPQCSafe_DoesNotExceed100(t *testing.T) {
	for _, n := range []int{1, 10, 100, 1000} {
		ff := make([]findings.UnifiedFinding, n)
		for i := range ff {
			ff[i] = findings.UnifiedFinding{
				Algorithm:   &findings.Algorithm{Name: "ML-KEM-768"},
				QuantumRisk: findings.QRSafe,
				Severity:    findings.SevInfo,
			}
		}
		qrs := CalculateQRS(ff)
		if qrs.Score > 100 {
			t.Errorf("%d safe findings: Score = %d, exceeds cap of 100", n, qrs.Score)
		}
		if qrs.Score != 100 {
			t.Errorf("%d safe findings: Score = %d, want 100", n, qrs.Score)
		}
	}
}

// TestQRS_AllVulnerable_FloorIsZero confirms score floors at 0 regardless of count.
func TestQRS_AllVulnerable_FloorIsZero(t *testing.T) {
	// 51 critical findings: 100 - 51*2.0 = -2 → clamped to 0
	ff := make([]findings.UnifiedFinding, 51)
	for i := range ff {
		ff[i] = findings.UnifiedFinding{
			Algorithm:   &findings.Algorithm{Name: "RSA-2048"},
			QuantumRisk: findings.QRVulnerable,
			Severity:    findings.SevCritical,
		}
	}
	qrs := CalculateQRS(ff)
	if qrs.Score != 0 {
		t.Errorf("51 critical findings: Score = %d, want 0 (clamped)", qrs.Score)
	}
	if qrs.Grade != "F" {
		t.Errorf("51 critical findings: Grade = %q, want F", qrs.Grade)
	}
}

// TestQRS_Exact1Point5xCorroborationMath verifies the exact 1.5x multiplier
// arithmetic for each severity level.
func TestQRS_Exact1Point5xCorroborationMath(t *testing.T) {
	tests := []struct {
		name          string
		sev           findings.Severity
		basePenalty   float64
		plainScore    int // 100 - basePenalty
		corrScore     int // 100 - basePenalty*1.5 (rounded)
	}{
		// Critical: base penalty 2.0, corroborated 3.0
		{"critical", findings.SevCritical, 2.0, 98, 97},
		// High: base penalty 1.5, corroborated 2.25 → 100-2.25=97.75 → round=98
		{"high", findings.SevHigh, 1.5, 99, 98},
		// Medium: base penalty 1.0, corroborated 1.5 → 100-1.5=98.5 → round=99
		//   NOTE: math.Round(98.5) in Go rounds half away from zero = 99
		{"medium", findings.SevMedium, 1.0, 99, 99},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			plain := findings.UnifiedFinding{
				Algorithm:   &findings.Algorithm{Name: "RSA"},
				QuantumRisk: findings.QRVulnerable,
				Severity:    tt.sev,
			}
			corr := plain
			corr.CorroboratedBy = []string{"engine-b"}

			qrsPlain := CalculateQRS([]findings.UnifiedFinding{plain})
			qrsCorr := CalculateQRS([]findings.UnifiedFinding{corr})

			if qrsPlain.Score != tt.plainScore {
				t.Errorf("%s plain: Score = %d, want %d (100 - %.1f)",
					tt.name, qrsPlain.Score, tt.plainScore, tt.basePenalty)
			}
			if qrsCorr.Score != tt.corrScore {
				t.Errorf("%s corroborated: Score = %d, want %d (100 - %.1f*1.5)",
					tt.name, qrsCorr.Score, tt.corrScore, tt.basePenalty)
			}
			// Corroborated must be <= plain (larger penalty → lower or equal score)
			if qrsCorr.Score > qrsPlain.Score {
				t.Errorf("%s: corroborated score (%d) must not exceed plain score (%d)",
					tt.name, qrsCorr.Score, qrsPlain.Score)
			}
		})
	}
}

// TestQRS_HighSeverityPlainScore verifies the single-finding plain (non-corroborated)
// score for high severity: 100 - 1.5 = 98.5 → math.Round = 99.
func TestQRS_HighSeverityPlainScore(t *testing.T) {
	f := findings.UnifiedFinding{
		Algorithm:   &findings.Algorithm{Name: "ECDSA"},
		QuantumRisk: findings.QRVulnerable,
		Severity:    findings.SevHigh,
	}
	qrs := CalculateQRS([]findings.UnifiedFinding{f})
	if qrs.Score != 99 {
		t.Errorf("single high-severity finding: Score = %d, want 99 (100 - 1.5 rounded)", qrs.Score)
	}
}

// ---------------------------------------------------------------------------
// 5. Data lifetime multiplier boundary values
// ---------------------------------------------------------------------------

// TestDataLifetimeMultiplier_BoundaryValues probes the exact boundary values
// including 0, 1, 4, 5, 10, 11, 30, 100, and negative inputs.
func TestDataLifetimeMultiplier_BoundaryValues(t *testing.T) {
	tests := []struct {
		years int
		want  float64
	}{
		// Negative: treated as disabled → 1.0
		{-1, 1.0},
		// 0: disabled → 1.0
		{0, 1.0},
		// 1: short-lived (1–4) → 0.85
		{1, 0.85},
		// 4: still short-lived → 0.85
		{4, 0.85},
		// 5: standard range (5–10) → 1.0
		{5, 1.0},
		// 10: still standard → 1.0
		{10, 1.0},
		// 11: long-lived (> 10) → 1.15
		{11, 1.15},
		// 30: long-lived → 1.15
		{30, 1.15},
		// 100: long-lived → 1.15 (no upper cap beyond the 1.15 ceiling)
		{100, 1.15},
	}

	for _, tt := range tests {
		tt := tt
		t.Run("", func(t *testing.T) {
			got := DataLifetimeMultiplier(tt.years)
			if got != tt.want {
				t.Errorf("DataLifetimeMultiplier(%d) = %v, want %v", tt.years, got, tt.want)
			}
		})
	}
}

// TestQRS_LifetimeMultiplier_ZeroYearsIsNeutral ensures years=0 (unknown/disabled)
// produces exactly the same result as the plain CalculateQRS.
func TestQRS_LifetimeMultiplier_ZeroYearsIsNeutral(t *testing.T) {
	ff := []findings.UnifiedFinding{
		{Algorithm: &findings.Algorithm{Name: "RSA-2048"}, QuantumRisk: findings.QRVulnerable, Severity: findings.SevCritical},
		{Algorithm: &findings.Algorithm{Name: "AES-128"}, QuantumRisk: findings.QRWeakened, Severity: findings.SevLow},
	}
	base := CalculateQRS(ff)
	withZero := CalculateQRSWithLifetime(ff, DataLifetimeMultiplier(0))
	if base != withZero {
		t.Errorf("years=0 should be identical to base: base=%+v, withLifetime=%+v", base, withZero)
	}
}

// TestQRS_LifetimeMultiplier_OneYearIsShortLived verifies years=1 falls in the
// short-lived tier (0.85) and produces a higher score than the base.
func TestQRS_LifetimeMultiplier_OneYearIsShortLived(t *testing.T) {
	ff := make([]findings.UnifiedFinding, 10)
	for i := range ff {
		ff[i] = findings.UnifiedFinding{
			Algorithm:   &findings.Algorithm{Name: "RSA-2048"},
			QuantumRisk: findings.QRVulnerable,
			Severity:    findings.SevCritical,
		}
	}
	base := CalculateQRS(ff) // 100 - 20 = 80
	withOne := CalculateQRSWithLifetime(ff, DataLifetimeMultiplier(1))
	if withOne.Score <= base.Score {
		t.Errorf("years=1 (short-lived) score=%d should be > base score=%d", withOne.Score, base.Score)
	}
}

// TestQRS_LifetimeMultiplier_100Years verifies very long retention still caps at 1.15.
func TestQRS_LifetimeMultiplier_100Years(t *testing.T) {
	ff := make([]findings.UnifiedFinding, 5)
	for i := range ff {
		ff[i] = findings.UnifiedFinding{
			Algorithm:   &findings.Algorithm{Name: "RSA-2048"},
			QuantumRisk: findings.QRVulnerable,
			Severity:    findings.SevCritical,
		}
	}
	// 100-year data has same multiplier as 30-year: 1.15
	with100 := CalculateQRSWithLifetime(ff, DataLifetimeMultiplier(100))
	with30 := CalculateQRSWithLifetime(ff, DataLifetimeMultiplier(30))
	if with100 != with30 {
		t.Errorf("years=100 and years=30 should produce identical scores (both → 1.15), got %d vs %d",
			with100.Score, with30.Score)
	}
}

// ---------------------------------------------------------------------------
// 6. Grade thresholds — exact boundary values
// ---------------------------------------------------------------------------

// TestScoreToGrade_ExactBoundaries verifies the grade assigned at each boundary
// and at the value just below it (boundary-1).
func TestScoreToGrade_ExactBoundaries(t *testing.T) {
	tests := []struct {
		score int
		grade string
	}{
		// A+ boundary
		{95, "A+"},
		{94, "A"},  // one below A+ threshold
		// A boundary
		{85, "A"},
		{84, "B"},  // one below A threshold
		// B boundary
		{70, "B"},
		{69, "C"},  // one below B threshold
		// C boundary
		{50, "C"},
		{49, "D"},  // one below C threshold
		// D boundary
		{30, "D"},
		{29, "F"},  // one below D threshold
		// Extremes
		{100, "A+"},
		{0, "F"},
	}

	for _, tt := range tests {
		tt := tt
		t.Run("", func(t *testing.T) {
			got := scoreToGrade(tt.score)
			if got != tt.grade {
				t.Errorf("scoreToGrade(%d) = %q, want %q", tt.score, got, tt.grade)
			}
		})
	}
}

// TestQRS_GradeBoundaryViaFindings verifies grade transitions by constructing
// finding sets whose exact QRS score lands at the threshold values using
// non-corroborated medium-severity findings (penalty = 1.0 each).
//
//   n medium-vulnerable → score = 100 - n
//   n=5  → 95 → A+
//   n=6  → 94 → A   (crosses 95 boundary)
//   n=15 → 85 → A
//   n=16 → 84 → B   (crosses 85 boundary)
//   n=30 → 70 → B
//   n=31 → 69 → C   (crosses 70 boundary)
//   n=50 → 50 → C
//   n=51 → 49 → D   (crosses 50 boundary)
//   n=70 → 30 → D
//   n=71 → 29 → F   (crosses 30 boundary)
func TestQRS_GradeBoundaryViaFindings(t *testing.T) {
	tests := []struct {
		n         int
		wantScore int
		wantGrade string
	}{
		{5, 95, "A+"},
		{6, 94, "A"},
		{15, 85, "A"},
		{16, 84, "B"},
		{30, 70, "B"},
		{31, 69, "C"},
		{50, 50, "C"},
		{51, 49, "D"},
		{70, 30, "D"},
		{71, 29, "F"},
	}

	for _, tt := range tests {
		tt := tt
		t.Run("", func(t *testing.T) {
			ff := make([]findings.UnifiedFinding, tt.n)
			for i := range ff {
				ff[i] = findings.UnifiedFinding{
					Algorithm:   &findings.Algorithm{Name: "RSA-2048"},
					QuantumRisk: findings.QRVulnerable,
					Severity:    findings.SevMedium,
				}
			}
			qrs := CalculateQRS(ff)
			if qrs.Score != tt.wantScore {
				t.Errorf("n=%d: Score = %d, want %d", tt.n, qrs.Score, tt.wantScore)
			}
			if qrs.Grade != tt.wantGrade {
				t.Errorf("n=%d: Grade = %q, want %q (score=%d)", tt.n, qrs.Grade, tt.wantGrade, qrs.Score)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// 7. HNDL — key-exchange vs signature
// ---------------------------------------------------------------------------

// TestHNDL_KeyExchangeImmediate_AllKnownFamilies checks every known key-exchange
// family returns HNDLImmediate.
func TestHNDL_KeyExchangeImmediate_AllKnownFamilies(t *testing.T) {
	cases := []struct {
		algName   string
		primitive string
	}{
		{"ECDH", "key-agree"},
		{"ECDHE", "key-agree"},
		{"X25519", "key-exchange"},
		{"X448", "key-exchange"},
		{"DH", "key-agree"},
		{"FFDH", "key-agree"},
		{"RSA", "kem"},
		{"RSAES-OAEP", "pke"},
		{"RSAES-PKCS1", "pke"},
		{"MQV", "key-agree"},
		{"ECMQV", "key-agree"},
	}

	for _, c := range cases {
		c := c
		t.Run(c.algName, func(t *testing.T) {
			got := ClassifyAlgorithm(c.algName, c.primitive, 0)
			if got.HNDLRisk != HNDLImmediate {
				t.Errorf("%q/%q HNDLRisk = %q, want %q",
					c.algName, c.primitive, got.HNDLRisk, HNDLImmediate)
			}
		})
	}
}

// TestHNDL_SignatureDeferred_AllKnownFamilies checks every known signature family
// returns HNDLDeferred when given the "signature" primitive.
func TestHNDL_SignatureDeferred_AllKnownFamilies(t *testing.T) {
	cases := []struct {
		algName string
	}{
		{"ECDSA"}, {"EdDSA"}, {"Ed25519"}, {"Ed448"},
		{"RSA"}, {"DSA"}, {"KCDSA"}, {"EC-KCDSA"},
		{"RSASSA-PKCS1"}, {"RSASSA-PSS"},
	}

	for _, c := range cases {
		c := c
		t.Run(c.algName, func(t *testing.T) {
			got := ClassifyAlgorithm(c.algName, "signature", 0)
			if got.HNDLRisk != HNDLDeferred {
				t.Errorf("%q with 'signature' primitive HNDLRisk = %q, want %q",
					c.algName, got.HNDLRisk, HNDLDeferred)
			}
		})
	}
}

// TestHNDL_PQCSafeAlgorithmsHaveNoHNDL verifies all safe algorithms carry no HNDL tag.
func TestHNDL_PQCSafeAlgorithmsHaveNoHNDL(t *testing.T) {
	safeAlgs := []struct {
		algName   string
		primitive string
	}{
		{"ML-KEM-768", "kem"},
		{"ML-DSA-65", "signature"},
		{"SLH-DSA-SHA2-128f", "signature"},
		{"SMAUG-T-128", "kem"},
		{"HAETAE-3", "signature"},
		{"AIMer-128f", "signature"},
		{"NTRU+-576", "kem"},
		{"HQC-128", "kem"},
		{"XMSS", "signature"},
		{"LMS", "signature"},
	}

	for _, alg := range safeAlgs {
		alg := alg
		t.Run(alg.algName, func(t *testing.T) {
			got := ClassifyAlgorithm(alg.algName, alg.primitive, 0)
			if got.HNDLRisk != "" {
				t.Errorf("PQC-safe %q HNDLRisk = %q, want empty", alg.algName, got.HNDLRisk)
			}
			if got.Risk != RiskSafe {
				t.Errorf("PQC-safe %q Risk = %q, want RiskSafe", alg.algName, got.Risk)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// 8. LookupTargetForKeySize — unusual key sizes
// ---------------------------------------------------------------------------

// TestLookupTargetForKeySize_UnusualSizes checks that unusual RSA key sizes
// (0, negative, 1023, 2049) fall into the expected tier without panicking.
func TestLookupTargetForKeySize_UnusualSizes(t *testing.T) {
	tests := []struct {
		name    string
		keySize int
		wantAlg string
	}{
		// All below 3072 → ML-DSA-44
		{"keySize=0", 0, "ML-DSA-44"},
		{"keySize=-1", -1, "ML-DSA-44"},
		{"keySize=1023", 1023, "ML-DSA-44"},
		{"keySize=2049", 2049, "ML-DSA-44"},
		// At/above 3072 → ML-DSA-65
		{"keySize=3072", 3072, "ML-DSA-65"},
		// At/above 4096 → ML-DSA-87
		{"keySize=4096", 4096, "ML-DSA-87"},
		{"keySize=8192", 8192, "ML-DSA-87"},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("LookupTargetForKeySize panicked: keySize=%d: %v", tt.keySize, r)
				}
			}()
			got := LookupTargetForKeySize("RSA", tt.keySize)
			if got.Algorithm != tt.wantAlg {
				t.Errorf("LookupTargetForKeySize(RSA, %d).Algorithm = %q, want %q",
					tt.keySize, got.Algorithm, tt.wantAlg)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// 9. CalculateQRSFull — combined lifetime + protocol + blast-radius
// ---------------------------------------------------------------------------

// TestCalculateQRSFull_NilImpactEqualsWithLifetime verifies that when impactResult
// is nil, CalculateQRSFull produces the same result as CalculateQRSWithLifetime.
func TestCalculateQRSFull_NilImpactEqualsWithLifetime(t *testing.T) {
	ff := make([]findings.UnifiedFinding, 5)
	for i := range ff {
		ff[i] = findings.UnifiedFinding{
			Algorithm:   &findings.Algorithm{Name: "RSA-2048"},
			QuantumRisk: findings.QRVulnerable,
			Severity:    findings.SevCritical,
		}
	}
	mult := DataLifetimeMultiplier(20) // 1.15
	want := CalculateQRSWithLifetime(ff, mult)
	got := CalculateQRSFull(ff, nil, mult)
	if got != want {
		t.Errorf("nil impact: CalculateQRSFull=%+v, want=%+v (same as WithLifetime)", got, want)
	}
}

// TestCalculateQRSFull_EmptyFindings verifies the base case for CalculateQRSFull.
func TestCalculateQRSFull_EmptyFindings(t *testing.T) {
	qrs := CalculateQRSFull(nil, nil, 1.0)
	if qrs.Score != 100 {
		t.Errorf("empty findings: Score = %d, want 100", qrs.Score)
	}
	if qrs.Grade != "A+" {
		t.Errorf("empty findings: Grade = %q, want A+", qrs.Grade)
	}
}
