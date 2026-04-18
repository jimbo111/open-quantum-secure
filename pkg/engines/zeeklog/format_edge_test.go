package zeeklog

import (
	"context"
	"bytes"
	"compress/gzip"
	"strings"
	"testing"
)

// TestFormatEdge_UTF8BOM verifies that a UTF-8 BOM (0xEF 0xBB 0xBF) before the
// log header does not cause a panic. The BOM causes the first byte to be 0xEF,
// which is neither '#' nor '{' → detectFormat returns formatUnknown.
// The parser attempts JSON first, then TSV; both may return empty results.
func TestFormatEdge_UTF8BOM(t *testing.T) {
	tsvWithBOM := append([]byte{0xEF, 0xBB, 0xBF}, []byte(sslTSVGolden)...)
	recs, err := parseSSLLog(context.Background(), bytes.NewReader(tsvWithBOM))
	if err != nil {
		t.Fatalf("UTF-8 BOM + TSV: unexpected error: %v", err)
	}
	// With BOM the format detector returns unknown → JSON tried first (fails), then TSV.
	// TSV parse skips the BOM-prefixed line as an unrecognized comment.
	// Result may be 0 records (BOM confused the header) or the expected 2 records.
	_ = recs
}

// TestFormatEdge_UTF16BOM_Reject verifies that UTF-16 LE BOM (0xFF 0xFE) input
// does not panic. detectFormat returns formatUnknown; JSON and TSV parsers
// skip or silently fail the non-UTF-8 data.
func TestFormatEdge_UTF16BOM_Reject(t *testing.T) {
	utf16LE := []byte{0xFF, 0xFE, 0x23, 0x00, 0x66, 0x00} // BOM + "#f" in UTF-16LE
	_, err := parseSSLLog(context.Background(), bytes.NewReader(utf16LE))
	// Should not panic; error or empty result is acceptable.
	_ = err
}

// TestFormatEdge_WeirdSeparator verifies that a log claiming a space separator
// (instead of tab) doesn't crash the parser. The TSV parser splits on \t, so
// space-separated values would end up as single-column rows that are skipped.
func TestFormatEdge_WeirdSeparator(t *testing.T) {
	spaceSep := "#separator \\x20\n" +
		"#fields uid id.resp_h id.resp_p cipher curve established\n" +
		"Cx 1.2.3.4 443 TLS_AES_256_GCM_SHA384 X25519MLKEM768 T\n"
	_, err := parseSSLLog(context.Background(), strings.NewReader(spaceSep))
	// No crash; records may be 0 (column parsing falls back gracefully).
	_ = err
}

// TestFormatEdge_InterleavedTSVAndJSON verifies that a file starting with '#'
// (TSV format) that contains JSON-formatted lines mid-stream doesn't panic.
// The TSV parser skips lines it can't parse as valid tab-delimited rows.
func TestFormatEdge_InterleavedTSVAndJSON(t *testing.T) {
	mixed := "#separator \\x09\n" +
		"#fields\tts\tuid\tid.resp_h\tid.resp_p\tcipher\tcurve\testablished\n" +
		"1704067200\tCx1\t1.2.3.4\t443\tTLS_AES_256_GCM_SHA384\tX25519MLKEM768\tT\n" +
		`{"ts":1704067201,"uid":"Cx2","id.resp_h":"5.6.7.8","id.resp_p":443,"established":true}` + "\n" +
		"1704067202\tCx3\t9.10.11.12\t443\tTLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384\tsecp256r1\tT\n"
	recs, err := parseSSLLog(context.Background(), strings.NewReader(mixed))
	if err != nil {
		t.Fatalf("interleaved TSV+JSON: unexpected error: %v", err)
	}
	// TSV parser includes all 3 non-comment lines as data rows.
	// The JSON line becomes an empty record (no tab separators → all columns map
	// to out-of-range indices → empty field values). All 3 records have distinct
	// dedup keys, so 3 unique records total.
	if len(recs) != 3 {
		t.Errorf("interleaved: got %d records, want 3", len(recs))
	}
}

// TestFormatEdge_GzipCompressedJSON verifies that a .gz file containing valid
// NDJSON (not TSV) is decompressed and parsed correctly.
func TestFormatEdge_GzipCompressedJSON(t *testing.T) {
	jsonContent := sslJSONGolden
	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	if _, err := gw.Write([]byte(jsonContent)); err != nil {
		t.Fatalf("gzip write: %v", err)
	}
	_ = gw.Close()

	rc := nopCloser{bytes.NewReader(buf.Bytes())}
	out, err := openMaybeGzip(rc, "ssl.log.gz")
	if err != nil {
		t.Fatalf("openMaybeGzip: %v", err)
	}
	defer out.Close()

	recs, err := parseSSLLog(context.Background(), out)
	if err != nil {
		t.Fatalf("parse compressed JSON: %v", err)
	}
	if len(recs) != 2 {
		t.Errorf("compressed JSON: got %d records, want 2", len(recs))
	}
}

// TestFormatEdge_GzipCompressedTSV verifies .gz containing TSV parses correctly.
func TestFormatEdge_GzipCompressedTSV(t *testing.T) {
	tsvContent := sslTSVGolden
	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	_, _ = gw.Write([]byte(tsvContent))
	_ = gw.Close()

	rc := nopCloser{bytes.NewReader(buf.Bytes())}
	out, err := openMaybeGzip(rc, "ssl.log.gz")
	if err != nil {
		t.Fatalf("openMaybeGzip: %v", err)
	}
	defer out.Close()

	recs, err := parseSSLLog(context.Background(), out)
	if err != nil {
		t.Fatalf("parse compressed TSV: %v", err)
	}
	if len(recs) != 2 {
		t.Errorf("compressed TSV: got %d records, want 2", len(recs))
	}
}

// TestFormatEdge_GzExtWithoutMagic verifies that a file named .gz but containing
// non-gzip bytes returns an error from gzip.NewReader, not a panic.
func TestFormatEdge_GzExtWithoutMagic(t *testing.T) {
	fakePlaintext := []byte("#fields\tts\tuid\n1704067200\tCx\n")
	rc := nopCloser{bytes.NewReader(fakePlaintext)}
	_, err := openMaybeGzip(rc, "ssl.log.gz")
	if err == nil {
		t.Error("expected gzip.NewReader error for non-gzip data with .gz extension, got nil")
	}
}

// TestFormatEdge_EmptyGzipBody verifies an empty gzip stream (valid header, no content)
// is handled gracefully, returning 0 records without panic.
func TestFormatEdge_EmptyGzipBody(t *testing.T) {
	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	_ = gw.Close()

	rc := nopCloser{bytes.NewReader(buf.Bytes())}
	out, err := openMaybeGzip(rc, "empty.log.gz")
	if err != nil {
		t.Fatalf("openMaybeGzip empty body: %v", err)
	}
	defer out.Close()

	recs, _ := parseSSLLog(context.Background(), out)
	if len(recs) != 0 {
		t.Errorf("empty gzip: got %d records, want 0", len(recs))
	}
}

// TestFormatDetect_AllPrefixes exercises detectFormat with every ASCII prefix byte.
func TestFormatDetect_AllPrefixes(t *testing.T) {
	for b := 0; b < 256; b++ {
		peek := []byte{byte(b)}
		f := detectFormat(peek)
		switch byte(b) {
		case '#':
			if f != formatTSV {
				t.Errorf("byte 0x%02X: detectFormat=%d, want formatTSV", b, f)
			}
		case '{':
			if f != formatJSON {
				t.Errorf("byte 0x%02X: detectFormat=%d, want formatJSON", b, f)
			}
		case ' ', '\t', '\r', '\n':
			// Whitespace is skipped; formatUnknown expected for single whitespace byte.
			if f != formatUnknown {
				t.Errorf("byte 0x%02X (whitespace): detectFormat=%d, want formatUnknown", b, f)
			}
		default:
			if f != formatUnknown {
				t.Errorf("byte 0x%02X: detectFormat=%d, want formatUnknown", b, f)
			}
		}
	}
}
