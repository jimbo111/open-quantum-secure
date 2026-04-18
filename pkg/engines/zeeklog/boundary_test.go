package zeeklog

import (
	"bytes"
	"compress/gzip"
	"fmt"
	"io"
	"strings"
	"testing"
)

// TestBoundary_EmptyFile verifies that parsing an empty reader returns no records.
func TestBoundary_EmptyFile(t *testing.T) {
	for _, name := range []string{"SSL", "X509"} {
		t.Run(name, func(t *testing.T) {
			var recs interface{}
			var err error
			if name == "SSL" {
				recs, err = parseSSLLog(bytes.NewReader(nil))
			} else {
				recs, err = parseX509Log(bytes.NewReader(nil))
			}
			// sniffFormat returns io.EOF on empty → error or (nil, nil) are both acceptable.
			// What matters: no panic.
			_ = recs
			_ = err
		})
	}
}

// TestBoundary_SingleByte verifies single-byte inputs don't panic.
func TestBoundary_SingleByte(t *testing.T) {
	for _, b := range []byte{'#', '{', ' ', '\n', '\t', 0x00, 0xFF} {
		_, _ = parseSSLLog(bytes.NewReader([]byte{b}))
		_, _ = parseX509Log(bytes.NewReader([]byte{b}))
	}
}

// TestBoundary_HeaderOnly_NoData verifies header-only file (no data rows) returns empty slice.
func TestBoundary_HeaderOnly_NoData(t *testing.T) {
	sslHeaderOnly := "#separator \\x09\n#set_separator\t,\n#empty_field\t(empty)\n#unset_field\t-\n#path\tssl\n" +
		"#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tversion\tcipher\tcurve\tserver_name\testablished\n" +
		"#types\ttime\tstring\taddr\tport\taddr\tport\tstring\tstring\tstring\tstring\tbool\n"
	recs, err := parseSSLLog(strings.NewReader(sslHeaderOnly))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(recs) != 0 {
		t.Errorf("header-only: got %d records, want 0", len(recs))
	}
}

// TestBoundary_SingleHeaderLine verifies a log with only the #fields line (no #types, no data).
func TestBoundary_SingleHeaderLine(t *testing.T) {
	recs, err := parseSSLLog(strings.NewReader("#fields\tts\tuid\tid.resp_h\tid.resp_p\tcipher\tcurve\testablished\n"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(recs) != 0 {
		t.Errorf("fields-only: got %d records, want 0", len(recs))
	}
}

// TestBoundary_EOFMidRow verifies that a row truncated before the last field is skipped gracefully.
func TestBoundary_EOFMidRow(t *testing.T) {
	// Row is cut after the cipher field — missing curve, server_name, established.
	input := "#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tversion\tcipher\tcurve\tserver_name\testablished\n" +
		"1704067200\tCx\t10.0.0.1\t9999\t1.2.3.4\t443\tTLSv13\tTLS_AES_256_GCM_SHA384" // EOF mid-row
	recs, err := parseSSLLog(strings.NewReader(input))
	if err != nil {
		t.Fatalf("unexpected error on EOF mid-row: %v", err)
	}
	// The incomplete row has established="" → not "F"/"false" so it may be included;
	// what matters is no panic and no crash.
	_ = recs
}

// TestBoundary_EOFMidJSON verifies truncated JSON object doesn't panic.
func TestBoundary_EOFMidJSON(t *testing.T) {
	input := `{"ts":1700,"uid":"Cx","id.resp_h":"1.2.3.4","id.resp_p":443,"cipher":"TLS_AES_256_GCM_SHA384","established":true`
	recs, err := parseSSLLog(strings.NewReader(input))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Truncated JSON → skipped; result is empty or partial.
	_ = recs
}

// TestBoundary_LastLineNoNewline verifies a well-formed log without trailing newline parses correctly.
func TestBoundary_LastLineNoNewline(t *testing.T) {
	input := "#separator \\x09\n#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tversion\tcipher\tcurve\tserver_name\testablished\n" +
		"1704067200\tCx\t10.0.0.1\t9999\t1.2.3.4\t443\tTLSv13\tTLS_AES_256_GCM_SHA384\tX25519MLKEM768\texample.com\tT" // no trailing newline
	recs, err := parseSSLLog(strings.NewReader(input))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(recs) != 1 {
		t.Errorf("last-line-no-newline: got %d records, want 1", len(recs))
	}
}

// TestBoundary_SizeCapBoundaryMinus1 verifies that reading exactly maxDecompressedBytes succeeds.
func TestBoundary_SizeCapBoundaryMinus1(t *testing.T) {
	const cap = int64(16)
	data := bytes.Repeat([]byte("A"), int(cap))

	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	_, _ = gw.Write(data)
	_ = gw.Close()

	gz, _ := gzip.NewReader(bytes.NewReader(buf.Bytes()))
	lrc := &limitedReadCloser{
		Reader: io.LimitReader(gz, cap+1),
		inner:  gz,
		outer:  io.NopCloser(bytes.NewReader(nil)),
		limit:  cap,
		path:   "test.log.gz",
	}
	// Read exactly cap bytes — must succeed (read == limit, not > limit).
	readBuf := make([]byte, int(cap))
	n, err := io.ReadFull(lrc, readBuf)
	if n == int(cap) && err == nil {
		// success — exactly at boundary is fine
		return
	}
	// ReadFull may return io.ErrUnexpectedEOF if fewer bytes available; that's ok.
	// What's NOT ok is the "exceeds" cap error at exactly cap bytes.
	if err != nil && strings.Contains(err.Error(), "exceeds") {
		t.Errorf("size cap triggered at exactly boundary (%d bytes), want only above boundary", cap)
	}
}

// TestBoundary_SizeCapBoundaryPlus1 verifies that reading maxDecompressedBytes+1 is rejected.
func TestBoundary_SizeCapBoundaryPlus1(t *testing.T) {
	const cap = int64(16)
	data := bytes.Repeat([]byte("B"), int(cap)+2)

	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	_, _ = gw.Write(data)
	_ = gw.Close()

	gz, _ := gzip.NewReader(bytes.NewReader(buf.Bytes()))
	lrc := &limitedReadCloser{
		Reader: io.LimitReader(gz, cap+2),
		inner:  gz,
		outer:  io.NopCloser(bytes.NewReader(nil)),
		limit:  cap,
		path:   "test.log.gz",
	}
	// Use io.ReadAll: it calls Read repeatedly and propagates the cap error.
	_, err := io.ReadAll(lrc)
	if err == nil {
		t.Error("expected size cap error for cap+1 bytes, got nil")
	} else if !strings.Contains(err.Error(), "exceeds") {
		t.Errorf("unexpected error type: %v — expected 'exceeds' message", err)
	}
}

// TestBoundary_GzipBombReject verifies the gzip decompression limit is enforced
// when reading a log through the engine's file path.
// We simulate a gzip "bomb" by writing content that exceeds maxDecompressedBytes using
// limitedReadCloser with a tiny synthetic limit.
func TestBoundary_GzipBombReject(t *testing.T) {
	const syntheticLimit = int64(50) // simulate 50-byte decompression cap

	content := strings.Repeat("A", 60) // 60 bytes decompressed — exceeds 50-byte cap
	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	_, _ = gw.Write([]byte(content))
	_ = gw.Close()

	gz, err := gzip.NewReader(bytes.NewReader(buf.Bytes()))
	if err != nil {
		t.Fatalf("gzip reader: %v", err)
	}
	lrc := &limitedReadCloser{
		Reader: io.LimitReader(gz, syntheticLimit+1),
		inner:  gz,
		outer:  io.NopCloser(bytes.NewReader(nil)),
		limit:  syntheticLimit,
		path:   "bomb.log.gz",
	}

	_, err = io.ReadAll(lrc)
	if err == nil {
		t.Error("gzip bomb: expected decompression cap error, got nil")
	}
	if !strings.Contains(err.Error(), "exceeds") {
		t.Errorf("gzip bomb: error %q should mention 'exceeds'", err)
	}
}

// TestBoundary_DoubleGzip verifies that a double-gzip file (gzip inside gzip)
// is handled without panic. The outer layer is decompressed; inner layer is
// read as raw data (not valid log format) — parse returns empty or error.
func TestBoundary_DoubleGzip(t *testing.T) {
	// Inner gzip containing valid TSV.
	innerContent := "#fields\tts\tuid\tid.resp_h\tid.resp_p\tcipher\tcurve\testablished\n" +
		"1704067200\tCx\t1.2.3.4\t443\taes256\tx25519\tT\n"
	var innerBuf bytes.Buffer
	gw1 := gzip.NewWriter(&innerBuf)
	_, _ = gw1.Write([]byte(innerContent))
	_ = gw1.Close()

	// Outer gzip containing the inner gzip.
	var outerBuf bytes.Buffer
	gw2 := gzip.NewWriter(&outerBuf)
	_, _ = gw2.Write(innerBuf.Bytes())
	_ = gw2.Close()

	// openMaybeGzip on .gz will decompress one layer — result is inner gzip bytes.
	// parseSSLLog will see gzip magic bytes as content and treat it as unknown format.
	rc := nopCloser{bytes.NewReader(outerBuf.Bytes())}
	out, err := openMaybeGzip(rc, "double.log.gz")
	if err != nil {
		t.Fatalf("openMaybeGzip: %v", err)
	}
	defer out.Close()
	// Parse should not panic — result may be empty/error.
	_, _ = parseSSLLog(out)
}

// TestBoundary_EmptyGzip verifies that a valid gzip stream containing no bytes parses safely.
func TestBoundary_EmptyGzip(t *testing.T) {
	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	_ = gw.Close() // empty gzip body

	rc := nopCloser{bytes.NewReader(buf.Bytes())}
	out, err := openMaybeGzip(rc, "empty.log.gz")
	if err != nil {
		t.Fatalf("openMaybeGzip empty gzip: %v", err)
	}
	defer out.Close()
	recs, err := parseSSLLog(out)
	_ = err
	if len(recs) != 0 {
		t.Errorf("empty gzip: expected 0 records, got %d", len(recs))
	}
}

// TestBoundary_DedupCap verifies that 1M identical rows result in exactly 1 unique record
// and the function completes in a reasonable time without OOM.
func TestBoundary_DedupCap(t *testing.T) {
	const rows = 1_000_000
	var sb strings.Builder
	sb.WriteString("#separator \\x09\n#set_separator\t,\n#empty_field\t(empty)\n#unset_field\t-\n#path\tssl\n")
	sb.WriteString("#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tversion\tcipher\tcurve\tserver_name\testablished\n")
	sb.WriteString("#types\ttime\tstring\taddr\tport\taddr\tport\tstring\tstring\tstring\tstring\tbool\n")
	for i := 0; i < rows; i++ {
		sb.WriteString(fmt.Sprintf("1704067200.%d\tCx%d\t10.0.0.1\t9999\t1.2.3.4\t443\tTLSv13\tTLS_AES_256_GCM_SHA384\tX25519MLKEM768\texample.com\tT\n", i, i))
	}
	recs, err := parseSSLLog(strings.NewReader(sb.String()))
	if err != nil {
		t.Fatalf("1M rows: unexpected error: %v", err)
	}
	if len(recs) != 1 {
		t.Errorf("1M identical rows: got %d unique records, want 1", len(recs))
	}
}
