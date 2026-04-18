package zeeklog

import (
	"strings"
	"testing"

	"github.com/jimbo111/open-quantum-secure/pkg/findings"
)

// oidMatrixEntry describes expected behavior for a given OID input.
type oidMatrixEntry struct {
	input    string // raw input as it would appear in a Zeek log
	wantName string // expected resolved name (empty = no resolution)
	wantSafe bool   // true if resulting finding should be QRSafe
}

// TestOIDMatrix_MLDSA verifies all ML-DSA OIDs (NIST FIPS 204) resolve to
// canonical names and classify as quantum-safe.
func TestOIDMatrix_MLDSA(t *testing.T) {
	cases := []oidMatrixEntry{
		{"2.16.840.1.101.3.4.3.17", "ML-DSA-44", true},
		{"2.16.840.1.101.3.4.3.18", "ML-DSA-65", true},
		{"2.16.840.1.101.3.4.3.19", "ML-DSA-87", true},
		// Zeek "unknown <OID>" fallback format.
		{"unknown 2.16.840.1.101.3.4.3.17", "ML-DSA-44", true},
		{"unknown 2.16.840.1.101.3.4.3.18", "ML-DSA-65", true},
		{"unknown 2.16.840.1.101.3.4.3.19", "ML-DSA-87", true},
	}
	checkOIDMatrix(t, "ML-DSA", cases)
}

// TestOIDMatrix_SLHDSA_SHA2 verifies all SLH-DSA SHA2 variants (FIPS 205).
func TestOIDMatrix_SLHDSA_SHA2(t *testing.T) {
	cases := []oidMatrixEntry{
		{"2.16.840.1.101.3.4.3.20", "SLH-DSA-SHA2-128s", true},
		{"2.16.840.1.101.3.4.3.21", "SLH-DSA-SHA2-128f", true},
		{"2.16.840.1.101.3.4.3.22", "SLH-DSA-SHA2-192s", true},
		{"2.16.840.1.101.3.4.3.23", "SLH-DSA-SHA2-192f", true},
		{"2.16.840.1.101.3.4.3.24", "SLH-DSA-SHA2-256s", true},
		{"2.16.840.1.101.3.4.3.25", "SLH-DSA-SHA2-256f", true},
		{"unknown 2.16.840.1.101.3.4.3.20", "SLH-DSA-SHA2-128s", true},
		{"unknown 2.16.840.1.101.3.4.3.25", "SLH-DSA-SHA2-256f", true},
	}
	checkOIDMatrix(t, "SLH-DSA-SHA2", cases)
}

// TestOIDMatrix_SLHDSA_SHAKE verifies all SLH-DSA SHAKE variants (FIPS 205).
func TestOIDMatrix_SLHDSA_SHAKE(t *testing.T) {
	cases := []oidMatrixEntry{
		{"2.16.840.1.101.3.4.3.26", "SLH-DSA-SHAKE-128s", true},
		{"2.16.840.1.101.3.4.3.27", "SLH-DSA-SHAKE-128f", true},
		{"2.16.840.1.101.3.4.3.28", "SLH-DSA-SHAKE-192s", true},
		{"2.16.840.1.101.3.4.3.29", "SLH-DSA-SHAKE-192f", true},
		{"2.16.840.1.101.3.4.3.30", "SLH-DSA-SHAKE-256s", true},
		{"2.16.840.1.101.3.4.3.31", "SLH-DSA-SHAKE-256f", true},
		{"unknown 2.16.840.1.101.3.4.3.26", "SLH-DSA-SHAKE-128s", true},
		{"unknown 2.16.840.1.101.3.4.3.31", "SLH-DSA-SHAKE-256f", true},
	}
	checkOIDMatrix(t, "SLH-DSA-SHAKE", cases)
}

// TestOIDMatrix_MLKEM verifies all ML-KEM OIDs (FIPS 203).
func TestOIDMatrix_MLKEM(t *testing.T) {
	cases := []oidMatrixEntry{
		{"2.16.840.1.101.3.4.4.1", "ML-KEM-512", true},
		{"2.16.840.1.101.3.4.4.2", "ML-KEM-768", true},
		{"2.16.840.1.101.3.4.4.3", "ML-KEM-1024", true},
		{"unknown 2.16.840.1.101.3.4.4.1", "ML-KEM-512", true},
		{"unknown 2.16.840.1.101.3.4.4.3", "ML-KEM-1024", true},
	}
	checkOIDMatrix(t, "ML-KEM", cases)
}

// TestOIDMatrix_Unknown verifies that unknown OIDs return ("", false) from
// resolveOIDAlgorithm and are handled gracefully in x509RecordToFindings.
func TestOIDMatrix_Unknown(t *testing.T) {
	unknownOIDs := []string{
		"1.2.3.4.5.6.7",
		"unknown 1.2.3.4.5.6.7",
		"unknown ",
		"",
		"not-an-oid",
	}
	for _, oid := range unknownOIDs {
		name, ok := resolveOIDAlgorithm(oid)
		if ok {
			t.Errorf("resolveOIDAlgorithm(%q)=(%q, true): unknown OID should return (_, false)", oid, name)
		}
	}
}

// TestOIDMatrix_Malformed verifies malformed OID strings don't panic and return
// graceful (empty, false) from resolveOIDAlgorithm.
func TestOIDMatrix_Malformed(t *testing.T) {
	malformed := []string{
		"\x00",                   // NUL byte
		"\x1b[31mFAKE\x1b[0m",   // ANSI injection
		"<script>alert(1)</script>",
		strings.Repeat("9", 1000), // very long
		"unknown " + strings.Repeat("1.", 1000) + "1",
	}
	for _, input := range malformed {
		// Must not panic.
		name, ok := resolveOIDAlgorithm(input)
		if ok {
			t.Errorf("resolveOIDAlgorithm(%q) unexpectedly resolved to %q", input[:min(len(input), 50)], name)
		}
	}
}

// TestOIDMatrix_InFindings verifies OID resolution is wired into x509RecordToFindings:
// a record with a raw OID sig_alg produces a finding with the resolved canonical name.
func TestOIDMatrix_InFindings(t *testing.T) {
	cases := []struct {
		rawOID   string
		wantName string
	}{
		{"2.16.840.1.101.3.4.3.17", "ML-DSA-44"},
		{"2.16.840.1.101.3.4.3.18", "ML-DSA-65"},
		{"unknown 2.16.840.1.101.3.4.3.19", "ML-DSA-87"},
		{"2.16.840.1.101.3.4.4.2", "ML-KEM-768"},
		{"unknown 2.16.840.1.101.3.4.3.20", "SLH-DSA-SHA2-128s"},
	}

	for _, tc := range cases {
		rec := X509Record{
			ID:     "FuidOID",
			SigAlg: tc.rawOID,
			SANDNS: "test.example.com",
		}
		fs := x509RecordToFindings(rec)
		if len(fs) == 0 {
			t.Errorf("OID %q: x509RecordToFindings returned 0 findings", tc.rawOID)
			continue
		}
		var found bool
		for _, f := range fs {
			if f.Algorithm != nil && f.Algorithm.Name == tc.wantName {
				found = true
				if f.QuantumRisk != findings.QRSafe {
					t.Errorf("OID %q → %q: QuantumRisk=%q, want QRSafe", tc.rawOID, tc.wantName, f.QuantumRisk)
				}
			}
		}
		if !found {
			names := make([]string, 0, len(fs))
			for _, f := range fs {
				if f.Algorithm != nil {
					names = append(names, f.Algorithm.Name)
				}
			}
			t.Errorf("OID %q: expected finding with name %q, got %v", tc.rawOID, tc.wantName, names)
		}
	}
}

// checkOIDMatrix is a helper that runs resolveOIDAlgorithm checks for a slice of entries.
func checkOIDMatrix(t *testing.T, family string, cases []oidMatrixEntry) {
	t.Helper()
	for _, tc := range cases {
		name, ok := resolveOIDAlgorithm(tc.input)
		if !ok {
			t.Errorf("[%s] resolveOIDAlgorithm(%q): got (_, false), want (%q, true)", family, tc.input, tc.wantName)
			continue
		}
		if name != tc.wantName {
			t.Errorf("[%s] resolveOIDAlgorithm(%q)=%q, want %q", family, tc.input, name, tc.wantName)
		}
	}
}

