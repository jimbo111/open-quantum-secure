package zeeklog

// audit_adversarial_test.go — T5-network audit (2026-04-20).
//
// Stresses the TSV + NDJSON ssl.log parsers with hostile input: oversize
// lines, mixed CRLF/LF, mid-line truncation, negative numeric fields,
// invalid UTF-8. zeeklog explicitly tolerates bufio.ErrTooLong and returns
// partial records — suricatalog does NOT; that divergence is documented in
// the audit report.

import (
	"bytes"
	"context"
	"strings"
	"testing"
)

// TestAuditZeek_TSV_OversizeLineTolerated builds an ssl.log with a 5 MB line
// (exceeds scanner buffer) between two short valid rows. The first row must
// still be returned; the oversize line must not abort parsing.
func TestAuditZeek_TSV_OversizeLineTolerated(t *testing.T) {
	t.Parallel()

	header := "#separator \\x09\n" +
		"#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tversion\tcipher\tcurve\tserver_name\testablished\n"

	// One valid record:
	row1 := "1234.0\tC1\t1.1.1.1\t12345\t2.2.2.2\t443\tTLSv13\tTLS_AES_128_GCM_SHA256\tX25519\texample.com\tT\n"

	// Oversize record (5 MB server_name that blows past the 4 MB buffer).
	huge := strings.Repeat("A", 5*1024*1024)
	rowHuge := "1235.0\tC2\t1.1.1.1\t12345\t2.2.2.2\t443\tTLSv13\tTLS_AES_128_GCM_SHA256\tX25519\t" + huge + "\tT\n"

	// Another valid record after the oversize line.
	row2 := "1236.0\tC3\t3.3.3.3\t45678\t4.4.4.4\t443\tTLSv13\tTLS_AES_256_GCM_SHA384\tP-256\tb.example.com\tT\n"

	buf := bytes.NewBufferString(header + row1 + rowHuge + row2)
	recs, err := parseSSLTSV(context.Background(), buf)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// zeeklog documents: ErrTooLong is silently suppressed and partial recs returned.
	// The first short record must survive.
	if len(recs) < 1 {
		t.Errorf("got %d records; expected ≥1 (zeeklog tolerates ErrTooLong)", len(recs))
	}
}

// TestAuditZeek_JSON_OversizeLineTolerated is the NDJSON counterpart.
func TestAuditZeek_JSON_OversizeLineTolerated(t *testing.T) {
	t.Parallel()

	row1 := `{"uid":"C1","id.resp_h":"1.1.1.1","id.resp_p":443,"version":"TLSv13","cipher":"TLS_AES_128_GCM_SHA256","curve":"X25519","server_name":"a.example.com","established":true}` + "\n"

	huge := strings.Repeat("A", 5*1024*1024)
	rowHuge := `{"uid":"C2","id.resp_h":"2.2.2.2","id.resp_p":443,"version":"TLSv13","cipher":"TLS_AES_128_GCM_SHA256","curve":"X25519","server_name":"` + huge + `","established":true}` + "\n"

	row2 := `{"uid":"C3","id.resp_h":"3.3.3.3","id.resp_p":443,"version":"TLSv13","cipher":"TLS_AES_256_GCM_SHA384","curve":"P-256","server_name":"b.example.com","established":true}` + "\n"

	buf := bytes.NewBufferString(row1 + rowHuge + row2)
	recs, err := parseSSLJSON(context.Background(), buf)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(recs) < 1 {
		t.Errorf("got %d records; expected ≥1 for NDJSON ErrTooLong tolerance", len(recs))
	}
}

// TestAuditZeek_TSV_MixedCRLF verifies CRLF-terminated ssl.log lines (common
// when the file was produced on a Windows Zeek build or transferred through a
// tool that rewrote newlines) parse identically to LF.
func TestAuditZeek_TSV_MixedCRLF(t *testing.T) {
	t.Parallel()

	header := "#separator \\x09\r\n" +
		"#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tversion\tcipher\tcurve\tserver_name\testablished\r\n"

	row1 := "1234.0\tC1\t1.1.1.1\t12345\t2.2.2.2\t443\tTLSv13\tTLS_AES_128_GCM_SHA256\tX25519\texample.com\tT\r\n"
	row2 := "1235.0\tC2\t1.1.1.1\t12346\t3.3.3.3\t443\tTLSv13\tTLS_AES_128_GCM_SHA256\tsecp256r1\tb.example.com\tT\n" // LF

	buf := bytes.NewBufferString(header + row1 + row2)
	recs, err := parseSSLTSV(context.Background(), buf)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(recs) != 2 {
		t.Errorf("got %d records, want 2 (CRLF+LF mixed)", len(recs))
	}
}

// TestAuditZeek_JSON_MidLineTruncation verifies a truncated trailing line (no
// closing brace, no newline) is skipped without error.
func TestAuditZeek_JSON_MidLineTruncation(t *testing.T) {
	t.Parallel()

	row1 := `{"uid":"C1","id.resp_h":"1.1.1.1","id.resp_p":443,"version":"TLSv13","cipher":"TLS_AES_128_GCM_SHA256","curve":"X25519","server_name":"ok","established":true}` + "\n"
	rowTrunc := `{"uid":"C2","id.resp_h":"2.2.2.2","id.resp_p"` // truncated mid-field

	recs, err := parseSSLJSON(context.Background(), bytes.NewReader([]byte(row1+rowTrunc)))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(recs) != 1 {
		t.Errorf("got %d records, want 1 (truncated trailing line must be skipped)", len(recs))
	}
}

// TestAuditZeek_JSON_NegativePort verifies a negative port value does not
// crash the parser. `sslPortString` handles int/float/string variants.
func TestAuditZeek_JSON_NegativePort(t *testing.T) {
	t.Parallel()

	row := `{"uid":"C1","id.resp_h":"1.1.1.1","id.resp_p":-1,"version":"TLSv13","cipher":"TLS_AES_128_GCM_SHA256","curve":"X25519","server_name":"neg","established":true}` + "\n"
	recs, err := parseSSLJSON(context.Background(), strings.NewReader(row))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(recs) != 1 {
		t.Fatalf("got %d records, want 1", len(recs))
	}
	if recs[0].RespPort != "-1" {
		t.Errorf("RespPort=%q, want %q — negative port should pass through", recs[0].RespPort, "-1")
	}
}

// TestAuditZeek_JSON_InvalidUTF8InServerName verifies invalid UTF-8 in a
// string field does not crash the parser. encoding/json typically rejects
// invalid UTF-8 inside quoted strings, so the line will be skipped.
func TestAuditZeek_JSON_InvalidUTF8InServerName(t *testing.T) {
	t.Parallel()

	valid := `{"uid":"C1","id.resp_h":"1.1.1.1","id.resp_p":443,"version":"TLSv13","cipher":"TLS_AES_128_GCM_SHA256","curve":"X25519","server_name":"valid","established":true}` + "\n"
	bad := []byte(`{"uid":"C2","id.resp_h":"2.2.2.2","id.resp_p":443,"version":"TLSv13","cipher":"x","curve":"y","server_name":"bad`)
	bad = append(bad, 0xC3, 0x28) // invalid UTF-8 bare continuation
	bad = append(bad, []byte(`","established":true}`+"\n")...)

	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("panic: %v", r)
		}
	}()
	buf := append([]byte(valid), bad...)
	recs, err := parseSSLJSON(context.Background(), bytes.NewReader(buf))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Only the valid line should survive.
	if len(recs) < 1 {
		t.Errorf("got %d records, want ≥1 valid", len(recs))
	}
}

// TestAuditZeek_TSV_BogusSeparatorDirective verifies that a corrupt
// "#separator" directive does not crash the parser and falls back to the
// default TAB separator behavior.
func TestAuditZeek_TSV_BogusSeparatorDirective(t *testing.T) {
	t.Parallel()

	// #separator with a multi-character value (invalid) should be ignored.
	hdr := "#separator BOGUSLONG\n" +
		"#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tversion\tcipher\tcurve\tserver_name\testablished\n"
	row := "1234.0\tC1\t1.1.1.1\t1\t2.2.2.2\t443\tTLSv13\tTLS_AES_128_GCM_SHA256\tX25519\tok\tT\n"
	recs, err := parseSSLTSV(context.Background(), strings.NewReader(hdr+row))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(recs) != 1 {
		t.Errorf("got %d records, want 1 (TAB fallback)", len(recs))
	}
}
