package output

import (
	"bytes"
	"strings"
	"testing"

	"github.com/jimbo111/open-quantum-secure/pkg/findings"
)

func TestWriteCSV_HeaderOnly(t *testing.T) {
	result := ScanResult{Findings: []findings.UnifiedFinding{}}
	var buf bytes.Buffer
	if err := WriteCSV(&buf, result); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	lines := strings.Split(strings.TrimRight(buf.String(), "\n"), "\n")
	if len(lines) != 1 {
		t.Fatalf("expected 1 line (header only), got %d", len(lines))
	}
	if !strings.HasPrefix(lines[0], "severity,confidence,algorithm") {
		t.Errorf("unexpected header: %s", lines[0])
	}
}

func TestWriteCSV_NilAlgorithm(t *testing.T) {
	result := ScanResult{
		Findings: []findings.UnifiedFinding{
			{
				Location:     findings.Location{File: "test.go", Line: 1},
				Algorithm:    nil,
				Confidence:   findings.ConfidenceHigh,
				SourceEngine: "test",
				Reachable:    findings.ReachableYes,
				QuantumRisk:  findings.QRUnknown,
			},
		},
	}
	var buf bytes.Buffer
	if err := WriteCSV(&buf, result); err != nil {
		t.Fatalf("unexpected error with nil Algorithm: %v", err)
	}
	lines := strings.Split(strings.TrimRight(buf.String(), "\n"), "\n")
	if len(lines) != 2 {
		t.Fatalf("expected 2 lines, got %d", len(lines))
	}
	// algorithm, primitive, keySize columns should all be empty
	fields := parseCSVLine(lines[1])
	if fields[2] != "" { // algorithm
		t.Errorf("algorithm field = %q, want empty", fields[2])
	}
}

func TestWriteCSV_FieldWithComma(t *testing.T) {
	result := ScanResult{
		Findings: []findings.UnifiedFinding{
			{
				Location:     findings.Location{File: "path/with,comma.go", Line: 10},
				Confidence:   findings.ConfidenceHigh,
				SourceEngine: "test",
				Reachable:    findings.ReachableYes,
				Algorithm: &findings.Algorithm{
					Name:      "RSA",
					Primitive: "signature",
				},
			},
		},
	}
	var buf bytes.Buffer
	if err := WriteCSV(&buf, result); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	lines := strings.Split(strings.TrimRight(buf.String(), "\n"), "\n")
	if len(lines) != 2 {
		t.Fatalf("expected 2 lines, got %d", len(lines))
	}
	fields := parseCSVLine(lines[1])
	if fields[11] != "path/with,comma.go" { // file column
		t.Errorf("file field = %q, want %q", fields[11], "path/with,comma.go")
	}
}

func TestWriteCSV_FieldWithNewline(t *testing.T) {
	result := ScanResult{
		Findings: []findings.UnifiedFinding{
			{
				Location:     findings.Location{File: "normal.go", Line: 1},
				Confidence:   findings.ConfidenceHigh,
				SourceEngine: "test",
				Reachable:    findings.ReachableYes,
				QuantumRisk:  findings.QRVulnerable,
				Algorithm: &findings.Algorithm{
					Name:      "RSA",
					Primitive: "signature\nwith newline",
				},
			},
		},
	}
	var buf bytes.Buffer
	if err := WriteCSV(&buf, result); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// The output should contain a quoted field with the embedded newline.
	out := buf.String()
	if !strings.Contains(out, "\"signature\nwith newline\"") {
		t.Errorf("expected quoted newline in output; got:\n%s", out)
	}
}

func TestWriteCSV_FieldWithQuote(t *testing.T) {
	result := ScanResult{
		Findings: []findings.UnifiedFinding{
			{
				Location:     findings.Location{File: `file"with"quotes.go`, Line: 5},
				Confidence:   findings.ConfidenceHigh,
				SourceEngine: "test",
				Reachable:    findings.ReachableYes,
				Algorithm: &findings.Algorithm{
					Name:      "RSA",
					Primitive: "signature",
				},
			},
		},
	}
	var buf bytes.Buffer
	if err := WriteCSV(&buf, result); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	out := buf.String()
	// Embedded quotes are doubled: "file""with""quotes.go"
	if !strings.Contains(out, `"file""with""quotes.go"`) {
		t.Errorf("expected doubled quotes in output; got:\n%s", out)
	}
}

func TestWriteCSV_ThreeFindings(t *testing.T) {
	result := ScanResult{
		Findings: []findings.UnifiedFinding{
			{
				Location:     findings.Location{File: "a.go", Line: 1},
				Confidence:   findings.ConfidenceHigh,
				SourceEngine: "cipherscope",
				Reachable:    findings.ReachableYes,
				QuantumRisk:  findings.QRVulnerable,
				Severity:     findings.SevCritical,
				Algorithm: &findings.Algorithm{
					Name:      "RSA",
					Primitive: "key-exchange",
					KeySize:   2048,
				},
			},
			{
				Location:     findings.Location{File: "(tls-probe)/example.com:443#kex", Line: 0},
				Confidence:   findings.ConfidenceHigh,
				SourceEngine: "tls-probe",
				Reachable:    findings.ReachableYes,
				QuantumRisk:  findings.QRSafe,
				PQCPresent:   true,
				PQCMaturity:  "final",
				NegotiatedGroupName: "X25519MLKEM768",
				HandshakeVolumeClass: "hybrid-kem",
				HandshakeBytes:       9500,
				Algorithm: &findings.Algorithm{
					Name:      "X25519MLKEM768",
					Primitive: "key-exchange",
				},
			},
			{
				Location:               findings.Location{File: "(tls-probe)/example.com:443#cert", Line: 0},
				Confidence:             findings.ConfidenceHigh,
				SourceEngine:           "tls-probe",
				Reachable:              findings.ReachableYes,
				QuantumRisk:            findings.QRVulnerable,
				PartialInventory:       true,
				PartialInventoryReason: "ECH_ENABLED",
				Algorithm: &findings.Algorithm{
					Name:      "ECDSA",
					Primitive: "signature",
					KeySize:   256,
				},
			},
		},
	}

	var buf bytes.Buffer
	if err := WriteCSV(&buf, result); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	lines := strings.Split(strings.TrimRight(buf.String(), "\n"), "\n")
	if len(lines) != 4 { // header + 3 findings
		t.Fatalf("expected 4 lines, got %d:\n%s", len(lines), buf.String())
	}

	// Check header columns
	header := parseCSVLine(lines[0])
	wantCols := []string{
		"severity", "confidence", "algorithm", "primitive", "keySize", "risk",
		"pqcPresent", "pqcMaturity", "negotiatedGroupName", "handshakeVolumeClass",
		"handshakeBytes", "file", "line", "sourceEngine", "reachable",
		"partialInventory", "partialInventoryReason", "dedupeKey",
	}
	if len(header) != len(wantCols) {
		t.Fatalf("header has %d columns, want %d", len(header), len(wantCols))
	}
	for i, col := range wantCols {
		if header[i] != col {
			t.Errorf("header[%d] = %q, want %q", i, header[i], col)
		}
	}

	// Spot-check second finding (PQC)
	row2 := parseCSVLine(lines[2])
	if row2[6] != "true" { // pqcPresent
		t.Errorf("pqcPresent = %q, want true", row2[6])
	}
	if row2[8] != "X25519MLKEM768" { // negotiatedGroupName
		t.Errorf("negotiatedGroupName = %q, want X25519MLKEM768", row2[8])
	}
	if row2[10] != "9500" { // handshakeBytes
		t.Errorf("handshakeBytes = %q, want 9500", row2[10])
	}

	// Spot-check third finding (partialInventory)
	row3 := parseCSVLine(lines[3])
	if row3[15] != "true" { // partialInventory
		t.Errorf("partialInventory = %q, want true", row3[15])
	}
	if row3[16] != "ECH_ENABLED" { // partialInventoryReason
		t.Errorf("partialInventoryReason = %q, want ECH_ENABLED", row3[16])
	}
}

// parseCSVLine splits a CSV line by commas, respecting quoted fields.
// This is a simplified parser for test verification only.
func parseCSVLine(line string) []string {
	var fields []string
	var current strings.Builder
	inQuote := false
	for i := 0; i < len(line); i++ {
		ch := line[i]
		switch {
		case inQuote && ch == '"' && i+1 < len(line) && line[i+1] == '"':
			// doubled quote → single quote
			current.WriteByte('"')
			i++
		case ch == '"':
			inQuote = !inQuote
		case ch == ',' && !inQuote:
			fields = append(fields, current.String())
			current.Reset()
		default:
			current.WriteByte(ch)
		}
	}
	fields = append(fields, current.String())
	return fields
}
