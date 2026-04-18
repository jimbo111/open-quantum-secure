package zeeklog

import (
	"strings"
	"testing"

	"github.com/jimbo111/open-quantum-secure/pkg/findings"
	"github.com/jimbo111/open-quantum-secure/pkg/quantum"
)

func TestSSLRecordToFindings_HybridKEM(t *testing.T) {
	rec := SSLRecord{
		RespHost:   "1.2.3.4",
		RespPort:   "443",
		Cipher:     "TLS_AES_256_GCM_SHA384",
		Curve:      "X25519MLKEM768",
		ServerName: "example.com",
		Version:    "1.3",
	}
	fs := sslRecordToFindings(rec)
	if len(fs) == 0 {
		t.Fatal("expected findings, got 0")
	}
	var pqcFound bool
	for _, f := range fs {
		if f.Algorithm != nil && f.Algorithm.Name == "X25519MLKEM768" {
			pqcFound = true
			if !f.PQCPresent {
				t.Error("X25519MLKEM768 finding should have PQCPresent=true")
			}
			if f.PQCMaturity != "final" {
				t.Errorf("X25519MLKEM768 PQCMaturity = %q, want final", f.PQCMaturity)
			}
			if f.QuantumRisk != findings.QRSafe {
				t.Errorf("X25519MLKEM768 QuantumRisk = %q, want quantum-safe", f.QuantumRisk)
			}
		}
		if f.SourceEngine != engineName {
			t.Errorf("SourceEngine = %q, want %q", f.SourceEngine, engineName)
		}
		if !strings.HasPrefix(f.Location.File, "(zeek-log)/") {
			t.Errorf("Location.File = %q, should start with (zeek-log)/", f.Location.File)
		}
	}
	if !pqcFound {
		t.Error("no finding for X25519MLKEM768 curve")
	}
}

func TestSSLRecordToFindings_Classical(t *testing.T) {
	rec := SSLRecord{
		RespHost:   "5.6.7.8",
		RespPort:   "443",
		Cipher:     "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
		Curve:      "secp256r1",
		ServerName: "legacy.example.com",
	}
	fs := sslRecordToFindings(rec)
	if len(fs) == 0 {
		t.Fatal("expected findings for classical record")
	}
	var curveFound bool
	for _, f := range fs {
		if f.Algorithm != nil && f.Algorithm.Name == "secp256r1" {
			curveFound = true
			if f.PQCPresent {
				t.Error("secp256r1 should have PQCPresent=false")
			}
		}
	}
	if !curveFound {
		t.Error("no finding for secp256r1 curve")
	}
}

func TestSSLRecordToFindings_PQCKeyShare(t *testing.T) {
	// Companion script codepoint 0x11EC = X25519MLKEM768
	rec := SSLRecord{
		RespHost:    "7.8.9.10",
		RespPort:    "443",
		Cipher:      "TLS_AES_256_GCM_SHA384",
		PQCKeyShare: "11EC",
	}
	fs := sslRecordToFindings(rec)
	var ksFound bool
	for _, f := range fs {
		if f.NegotiatedGroup == 0x11EC {
			ksFound = true
			if !f.PQCPresent {
				t.Error("key_share codepoint 0x11EC should be PQCPresent=true")
			}
		}
	}
	if !ksFound {
		t.Error("no finding for key_share codepoint 11EC")
	}
}

func TestX509RecordToFindings_RSA(t *testing.T) {
	rec := X509Record{
		SigAlg:  "sha256WithRSAEncryption",
		KeyAlg:  "rsaEncryption",
		KeyType: "rsa",
		KeyLen:  2048,
		SANDNS:  "example.com",
	}
	fs := x509RecordToFindings(rec)
	if len(fs) == 0 {
		t.Fatal("expected findings for RSA x509 record")
	}
	for _, f := range fs {
		if f.QuantumRisk == findings.QRSafe {
			t.Errorf("RSA cert finding should not be quantum-safe: %s → %v", f.Algorithm.Name, f.QuantumRisk)
		}
	}
}

func TestX509RecordToFindings_MLDSA(t *testing.T) {
	rec := X509Record{
		SigAlg:  "ML-DSA-65",
		KeyAlg:  "ML-DSA-65",
		KeyType: "unknown",
		SANDNS:  "pqc.example.com",
	}
	fs := x509RecordToFindings(rec)
	if len(fs) == 0 {
		t.Fatal("expected findings for ML-DSA-65 x509 record")
	}
	for _, f := range fs {
		if f.Algorithm != nil && strings.HasPrefix(f.Algorithm.Name, "ML-DSA") {
			if f.QuantumRisk != findings.QRSafe {
				t.Errorf("ML-DSA-65 cert finding QuantumRisk = %q, want quantum-safe", f.QuantumRisk)
			}
		}
	}
}

func TestBuildFinding_FilePathFormat(t *testing.T) {
	c := quantum.ClassifyAlgorithm("RSA", "asymmetric", 2048)
	f := buildFinding("RSA", "asymmetric", 2048, c, "example.com", "1.1.1.1", "443", "ssl.log/cipher")
	if !strings.HasPrefix(f.Location.File, "(zeek-log)/") {
		t.Errorf("file path = %q, want (zeek-log)/ prefix", f.Location.File)
	}
	if !strings.Contains(f.Location.File, "#RSA") {
		t.Errorf("file path = %q, should contain #RSA", f.Location.File)
	}
	if f.SourceEngine != engineName {
		t.Errorf("SourceEngine = %q, want %q", f.SourceEngine, engineName)
	}
}
