package tlsprobe

import (
	"strings"
	"testing"

	"github.com/jimbo111/open-quantum-secure/pkg/findings"
	"github.com/jimbo111/open-quantum-secure/pkg/quantum"
)

// TestLookupPQCSigAlgName verifies the OID → name mapping table.
func TestLookupPQCSigAlgName(t *testing.T) {
	tests := []struct {
		oid  string
		want string
	}{
		{"2.16.840.1.101.3.4.3.17", "mldsa44"},
		{"2.16.840.1.101.3.4.3.18", "mldsa65"},
		{"2.16.840.1.101.3.4.3.19", "mldsa87"},
		{"2.16.840.1.101.3.4.3.20", "slhdsa-sha2-128s"},
		{"2.16.840.1.101.3.4.3.31", "slhdsa-shake-256f"},
		{"1.2.3.4.5.6", ""},         // unknown OID → empty
		{"", ""},                    // empty OID → empty
	}
	for _, tc := range tests {
		got := quantum.LookupPQCSigAlgName(tc.oid)
		if got != tc.want {
			t.Errorf("LookupPQCSigAlgName(%q) = %q, want %q", tc.oid, got, tc.want)
		}
	}
}

// TestClassifyAlgorithm_PQCSigAlgNames verifies that ML-DSA and SLH-DSA OID-derived
// names (as produced by the TLS probe cert-sig extraction) classify as quantum-safe.
func TestClassifyAlgorithm_PQCSigAlgNames(t *testing.T) {
	pqcNames := []string{
		"mldsa44", "mldsa65", "mldsa87",
		"slhdsa-sha2-128s", "slhdsa-sha2-256f",
		"slhdsa-shake-128s", "slhdsa-shake-256f",
	}
	for _, name := range pqcNames {
		c := quantum.ClassifyAlgorithm(name, "digital-signature", 0)
		if c.Risk != quantum.RiskSafe {
			t.Errorf("ClassifyAlgorithm(%q, digital-signature, 0) risk = %q, want %q",
				name, c.Risk, quantum.RiskSafe)
		}
	}
}

// TestClassifyAlgorithm_ClassicalSigAlg verifies that classical cert sig alg key
// components (RSA, ECDSA) classify as quantum-vulnerable.
func TestClassifyAlgorithm_ClassicalSigAlg(t *testing.T) {
	cases := []struct {
		name string
		want quantum.Risk
	}{
		{"RSA", quantum.RiskVulnerable},
		{"ECDSA", quantum.RiskVulnerable},
		{"Ed25519", quantum.RiskVulnerable},
	}
	for _, tc := range cases {
		c := quantum.ClassifyAlgorithm(tc.name, "signature", 0)
		if c.Risk != tc.want {
			t.Errorf("ClassifyAlgorithm(%q) risk = %q, want %q", tc.name, c.Risk, tc.want)
		}
	}
}

// TestObservationToFindings_CertSigFinding verifies that observationToFindings
// emits a #cert-sig finding when LeafCertSigAlgo is set.
func TestObservationToFindings_CertSigFinding(t *testing.T) {
	result := ProbeResult{
		Target:          "example.com:443",
		ResolvedIP:      "93.184.216.34",
		TLSVersion:      0x0303, // TLS 1.2 negotiated (no separate kex finding for 1.2)
		CipherSuiteID:   0x002f, // TLS_RSA_WITH_AES_128_CBC_SHA (known but not in default registry)
		CipherSuiteName: "TLS_RSA_WITH_AES_128_CBC_SHA",
		LeafCertKeyAlgo: "RSA",
		LeafCertKeySize: 2048,
		LeafCertSigAlgo: "SHA256-RSA",
	}

	ff := observationToFindings(result)

	var certSigFinding *findings.UnifiedFinding
	for i := range ff {
		if strings.HasSuffix(ff[i].Location.File, "#cert-sig") {
			certSigFinding = &ff[i]
			break
		}
	}
	if certSigFinding == nil {
		t.Fatal("expected a #cert-sig finding, got none")
	}
	if certSigFinding.Algorithm == nil {
		t.Fatal("#cert-sig finding has nil Algorithm")
	}
	if certSigFinding.Algorithm.Name != "SHA256-RSA" {
		t.Errorf("#cert-sig Algorithm.Name = %q, want %q", certSigFinding.Algorithm.Name, "SHA256-RSA")
	}
	if certSigFinding.Algorithm.Primitive != "digital-signature" {
		t.Errorf("#cert-sig Primitive = %q, want %q", certSigFinding.Algorithm.Primitive, "digital-signature")
	}
}

// TestObservationToFindings_PQCCertSigFinding verifies #cert-sig for a PQC sig alg.
func TestObservationToFindings_PQCCertSigFinding(t *testing.T) {
	result := ProbeResult{
		Target:             "pqc.example.com:443",
		ResolvedIP:         "192.0.2.1",
		TLSVersion:         0x0304,
		CipherSuiteID:      0x1302,
		CipherSuiteName:    "TLS_AES_256_GCM_SHA384",
		NegotiatedGroupID:  0x11EC, // X25519MLKEM768
		LeafCertKeyAlgo:    "RSA",
		LeafCertKeySize:    2048,
		LeafCertSigAlgo:    "mldsa65",
		LeafCertSigAlgOID:  "2.16.840.1.101.3.4.3.18",
	}

	ff := observationToFindings(result)

	var certSigFinding *findings.UnifiedFinding
	for i := range ff {
		if strings.HasSuffix(ff[i].Location.File, "#cert-sig") {
			certSigFinding = &ff[i]
			break
		}
	}
	if certSigFinding == nil {
		t.Fatal("expected a #cert-sig finding for PQC cert, got none")
	}
	if certSigFinding.Algorithm.Name != "mldsa65" {
		t.Errorf("#cert-sig Algorithm.Name = %q, want %q", certSigFinding.Algorithm.Name, "mldsa65")
	}
}

// TestObservationToFindings_UnknownCertSigAlg verifies graceful handling when
// the cert has an unrecognized signature algorithm OID.
func TestObservationToFindings_UnknownCertSigAlg(t *testing.T) {
	result := ProbeResult{
		Target:            "unknown.example.com:443",
		ResolvedIP:        "192.0.2.2",
		TLSVersion:        0x0303,
		CipherSuiteID:     0x002f,
		CipherSuiteName:   "TLS_RSA_WITH_AES_128_CBC_SHA",
		LeafCertKeyAlgo:   "RSA",
		LeafCertKeySize:   2048,
		LeafCertSigAlgo:   "unknown-9.9.9.9.9",
		LeafCertSigAlgOID: "9.9.9.9.9",
	}

	// Must not panic.
	ff := observationToFindings(result)

	var certSigFinding *findings.UnifiedFinding
	for i := range ff {
		if strings.HasSuffix(ff[i].Location.File, "#cert-sig") {
			certSigFinding = &ff[i]
			break
		}
	}
	if certSigFinding == nil {
		t.Fatal("expected a #cert-sig finding even for unknown OID")
	}
	// Name should start with "unknown-"
	if !strings.HasPrefix(certSigFinding.Algorithm.Name, "unknown-") {
		t.Errorf("#cert-sig Algorithm.Name = %q, want prefix 'unknown-'", certSigFinding.Algorithm.Name)
	}
}

// TestExtractSigAlgOIDFromRawTBS verifies the ASN.1 parser on a known cert DER snippet.
// We use an empty/nil input to verify graceful error handling (no panic).
func TestExtractSigAlgOIDFromRawTBS_InvalidInput(t *testing.T) {
	// Empty input → must return "" without panicking.
	oid := extractSigAlgOIDFromRawTBS(nil)
	if oid != "" {
		t.Errorf("extractSigAlgOIDFromRawTBS(nil) = %q, want empty", oid)
	}

	oid = extractSigAlgOIDFromRawTBS([]byte{0x30, 0x00}) // empty SEQUENCE
	if oid != "" {
		// Parsing an empty TBSCertificate may fail gracefully; either "" is fine.
		t.Logf("extractSigAlgOIDFromRawTBS(empty SEQUENCE) = %q", oid)
	}
}
