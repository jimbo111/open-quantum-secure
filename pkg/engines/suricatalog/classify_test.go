package suricatalog

import (
	"fmt"
	"strings"
	"testing"

	"github.com/jimbo111/open-quantum-secure/pkg/findings"
)

func TestTLSRecordToFindingsCipher(t *testing.T) {
	tests := []struct {
		name          string
		cipher        string
		wantRisk      findings.QuantumRisk
		wantPrimitive string
	}{
		{
			name:          "TLS1.3 AES-128 symmetric resistant",
			cipher:        "TLS_AES_128_GCM_SHA256",
			wantRisk:      findings.QRResistant,
			wantPrimitive: "symmetric",
		},
		{
			name:          "TLS1.2 ECDHE-RSA vulnerable",
			cipher:        "ECDHE-RSA-AES256-GCM-SHA384",
			wantRisk:      findings.QRVulnerable,
			wantPrimitive: "key-agree",
		},
		{
			name:          "AES256-SHA256 symmetric resistant",
			cipher:        "AES256-SHA256",
			wantRisk:      findings.QRResistant,
			wantPrimitive: "symmetric",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			rec := TLSRecord{
				DestIP:      "1.2.3.4",
				DestPort:    "443",
				CipherSuite: tc.cipher,
				SNI:         "test.example.com",
			}
			fs := tlsRecordToFindings(rec)
			if len(fs) == 0 {
				t.Fatal("expected at least one finding")
			}
			// First finding is the cipher finding.
			f := fs[0]
			if f.QuantumRisk != tc.wantRisk {
				t.Errorf("QuantumRisk = %q, want %q", f.QuantumRisk, tc.wantRisk)
			}
			if f.Algorithm == nil {
				t.Fatal("Algorithm is nil")
			}
			if f.Algorithm.Primitive != tc.wantPrimitive {
				t.Errorf("Primitive = %q, want %q", f.Algorithm.Primitive, tc.wantPrimitive)
			}
		})
	}
}

func TestBuildFindingFilePath(t *testing.T) {
	rec := TLSRecord{
		DestIP:      "192.0.2.1",
		DestPort:    "8443",
		CipherSuite: "TLS_AES_256_GCM_SHA384",
		SNI:         "sni.example.com",
	}
	fs := tlsRecordToFindings(rec)
	if len(fs) == 0 {
		t.Fatal("expected findings")
	}
	f := fs[0]
	if f.Location.File == "" {
		t.Fatal("Location.File is empty")
	}
	// File must contain the suricata-log marker.
	if !strings.HasPrefix(f.Location.File, "(suricata-log)/") {
		t.Errorf("Location.File does not start with (suricata-log)/: %q", f.Location.File)
	}
}

func TestFindingSourceEngine(t *testing.T) {
	rec := TLSRecord{
		DestIP:      "1.1.1.1",
		DestPort:    "443",
		CipherSuite: "TLS_AES_128_GCM_SHA256",
	}
	fs := tlsRecordToFindings(rec)
	if len(fs) == 0 {
		t.Fatal("expected findings")
	}
	for _, f := range fs {
		if f.SourceEngine != "suricata-log" {
			t.Errorf("SourceEngine = %q, want %q", f.SourceEngine, "suricata-log")
		}
	}
}

func TestCipherPrimitive(t *testing.T) {
	cases := []struct {
		cipher string
		want   string
	}{
		{"ECDHE-RSA-AES128-GCM-SHA256", "key-agree"},
		{"DHE-RSA-AES256-SHA", "key-agree"},
		{"TLS_AES_128_GCM_SHA256", "symmetric"},
		{"AES256-SHA", "symmetric"},
	}
	for _, c := range cases {
		got := cipherPrimitive(c.cipher)
		if got != c.want {
			t.Errorf("cipherPrimitive(%q) = %q, want %q", c.cipher, got, c.want)
		}
	}
}

func TestSplitCSV(t *testing.T) {
	cases := []struct {
		input string
		want  []string
	}{
		{"", nil},
		{"rsa_pkcs1_sha256", []string{"rsa_pkcs1_sha256"}},
		{"rsa_pkcs1_sha256,ecdsa_secp256r1_sha256", []string{"rsa_pkcs1_sha256", "ecdsa_secp256r1_sha256"}},
		{" a , b , c ", []string{"a", "b", "c"}},
	}
	for _, c := range cases {
		got := splitCSV(c.input)
		if len(got) != len(c.want) {
			t.Errorf("splitCSV(%q) = %v, want %v", c.input, got, c.want)
			continue
		}
		for i, v := range got {
			if v != c.want[i] {
				t.Errorf("splitCSV(%q)[%d] = %q, want %q", c.input, i, v, c.want[i])
			}
		}
	}
}

// TestSplitCSVCap verifies that splitCSV enforces maxCSVEntries even when the
// input contains far more comma-separated entries. Prevents CSV amplification
// attacks where an adversarially crafted 4 MB log line yields millions of findings.
func TestSplitCSVCap(t *testing.T) {
	// Build a 1000-entry CSV — all distinct so no early exit from dedup.
	entries := make([]string, 1000)
	for i := range entries {
		entries[i] = fmt.Sprintf("entry%d", i)
	}
	input := strings.Join(entries, ",")
	got := splitCSV(input)
	if len(got) != maxCSVEntries {
		t.Errorf("splitCSV(1000-entry input) = %d entries, want %d (maxCSVEntries cap)", len(got), maxCSVEntries)
	}
	// The first maxCSVEntries entries must be preserved in order.
	for i, v := range got {
		if v != entries[i] {
			t.Errorf("splitCSV[%d] = %q, want %q", i, v, entries[i])
			break
		}
	}
}

func TestTargetSNIPreference(t *testing.T) {
	// When SNI is set, it should be preferred over IP:port in the file path.
	rec := TLSRecord{
		DestIP:      "1.2.3.4",
		DestPort:    "443",
		CipherSuite: "TLS_AES_128_GCM_SHA256",
		SNI:         "api.example.com",
	}
	fs := tlsRecordToFindings(rec)
	if len(fs) == 0 {
		t.Fatal("expected findings")
	}
	// The file path should contain the SNI, not the IP.
	for _, f := range fs {
		if f.Location.File != "" && len(f.Location.File) > 15 {
			path := f.Location.File[15:] // strip "(suricata-log)/"
			// Should contain "api.example.com" not "1.2.3.4"
			if len(path) > 0 && path[:3] == "1.2" {
				t.Errorf("file path uses IP instead of SNI: %q", f.Location.File)
			}
		}
	}
}
