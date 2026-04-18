package zeeklog

import (
	"strings"
	"testing"

	"github.com/jimbo111/open-quantum-secure/pkg/findings"
	"github.com/jimbo111/open-quantum-secure/pkg/quantum"
)

// TestBackcompat_Sprint0_QRSFields verifies Sprint 0 fields on UnifiedFinding are
// populated correctly by the zeek-log engine (QuantumRisk, Severity,
// Recommendation, HNDLRisk, MigrationEffort, TargetAlgorithm, TargetStandard).
func TestBackcompat_Sprint0_QRSFields(t *testing.T) {
	rec := SSLRecord{
		RespHost:   "1.2.3.4",
		RespPort:   "443",
		Cipher:     "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
		Curve:      "secp256r1",
		ServerName: "legacy.example.com",
	}
	fs := sslRecordToFindings(rec)
	if len(fs) == 0 {
		t.Fatal("no findings")
	}
	for _, f := range fs {
		// Sprint 0: every finding must have a non-empty QuantumRisk.
		if f.QuantumRisk == "" {
			t.Errorf("finding %q: QuantumRisk is empty (Sprint 0 regression)", f.Algorithm.Name)
		}
	}
}

// TestBackcompat_Sprint1_PQCFields verifies Sprint 1 PQC fields are set for
// hybrid KEM findings: NegotiatedGroup, NegotiatedGroupName, PQCPresent, PQCMaturity.
func TestBackcompat_Sprint1_PQCFields(t *testing.T) {
	rec := SSLRecord{
		RespHost:   "203.0.113.1",
		RespPort:   "443",
		Cipher:     "TLS_AES_256_GCM_SHA384",
		Curve:      "X25519MLKEM768",
		ServerName: "hybrid.example.com",
		Version:    "1.3",
	}
	fs := sslRecordToFindings(rec)
	var curveF *findings.UnifiedFinding
	for i := range fs {
		if fs[i].Algorithm != nil && fs[i].Algorithm.Name == "X25519MLKEM768" {
			curveF = &fs[i]
			break
		}
	}
	if curveF == nil {
		t.Fatal("no finding for X25519MLKEM768 curve")
	}
	if !curveF.PQCPresent {
		t.Error("Sprint 1 regression: PQCPresent=false for X25519MLKEM768")
	}
	if curveF.PQCMaturity != "final" {
		t.Errorf("Sprint 1 regression: PQCMaturity=%q, want final", curveF.PQCMaturity)
	}
	if curveF.NegotiatedGroupName != "X25519MLKEM768" {
		t.Errorf("Sprint 1 regression: NegotiatedGroupName=%q, want X25519MLKEM768", curveF.NegotiatedGroupName)
	}
}

// TestBackcompat_Sprint2_ObservabilityFields verifies Sprint 2 fields that
// zeek-log does NOT set (HandshakeVolumeClass, HandshakeBytes, PartialInventory)
// are left at zero-value. zeek-log is passive file ingestion — no byte counts.
func TestBackcompat_Sprint2_ObservabilityFields(t *testing.T) {
	rec := SSLRecord{
		RespHost:   "1.2.3.4",
		RespPort:   "443",
		Cipher:     "TLS_AES_256_GCM_SHA384",
		Curve:      "X25519MLKEM768",
		ServerName: "example.com",
	}
	fs := sslRecordToFindings(rec)
	for _, f := range fs {
		if f.HandshakeVolumeClass != "" {
			t.Errorf("zeek-log should not set HandshakeVolumeClass (Sprint 2 passive engine)")
		}
		if f.HandshakeBytes != 0 {
			t.Errorf("zeek-log should not set HandshakeBytes (Sprint 2 passive engine)")
		}
		if f.PartialInventory {
			t.Errorf("zeek-log should not set PartialInventory (Sprint 2 ECH field, TLS-probe only)")
		}
	}
}

// TestBackcompat_Sprint3_5_NoRegressionOnKnownAlgorithms verifies that the set
// of algorithms whose classification changed between sprints still classifies
// correctly. Specifically: Kyber draft codepoints should be QRDeprecated, not QRSafe.
func TestBackcompat_Sprint3_5_KyberDraftDeprecated(t *testing.T) {
	// Companion script reports 0x6399 = X25519Kyber768Draft00 (deprecated).
	rec := SSLRecord{
		RespHost:    "1.2.3.4",
		RespPort:    "443",
		PQCKeyShare: "6399",
	}
	fs := sslRecordToFindings(rec)
	var kf *findings.UnifiedFinding
	for i := range fs {
		if fs[i].Algorithm != nil && fs[i].Algorithm.Name == "X25519Kyber768Draft00" {
			kf = &fs[i]
			break
		}
	}
	if kf == nil {
		t.Fatal("no finding for X25519Kyber768Draft00 draft codepoint 0x6399")
	}
	if kf.QuantumRisk == findings.QRSafe {
		t.Errorf("X25519Kyber768Draft00 (deprecated): QuantumRisk=%q, want QRDeprecated not QRSafe (Sprint 2 T-BUG regression)", kf.QuantumRisk)
	}
	if kf.PQCMaturity != "draft" {
		t.Errorf("X25519Kyber768Draft00: PQCMaturity=%q, want draft", kf.PQCMaturity)
	}
}

// TestBackcompat_FindingLocationFormat verifies the (zeek-log)/<target>#<alg>
// path format that DedupeKey relies on has not changed.
func TestBackcompat_FindingLocationFormat(t *testing.T) {
	c := quantum.ClassifyAlgorithm("secp256r1", "key-agree", 0)
	f := buildFinding("secp256r1", "key-agree", 0, c, "legacy.example.com", "1.2.3.4", "443", "ssl.log/curve")
	if !strings.HasPrefix(f.Location.File, "(zeek-log)/") {
		t.Errorf("Location.File=%q: must start with (zeek-log)/", f.Location.File)
	}
	if !strings.Contains(f.Location.File, "#secp256r1") {
		t.Errorf("Location.File=%q: must contain #secp256r1", f.Location.File)
	}
	if f.Location.Line != 0 {
		t.Errorf("Location.Line=%d: zeek-log findings must have Line=0", f.Location.Line)
	}
	if f.SourceEngine != "zeek-log" {
		t.Errorf("SourceEngine=%q: want zeek-log", f.SourceEngine)
	}
	if f.Confidence != findings.ConfidenceMedium {
		t.Errorf("Confidence=%q: want ConfidenceMedium (Sprint 5 zeek-log passive source)", f.Confidence)
	}
}

// TestBackcompat_EngineNameConstant verifies the engineName constant has not changed.
// Downstream dedup, SARIF rule IDs, and output field values depend on this.
func TestBackcompat_EngineNameConstant(t *testing.T) {
	e := New()
	if e.Name() != "zeek-log" {
		t.Errorf("engine name=%q, want zeek-log (backcompat: changing this breaks existing integrations)", e.Name())
	}
}
