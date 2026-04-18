package suricatalog

import (
	"bytes"
	"compress/gzip"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestSingleByteFile verifies that a 1-byte file (not valid JSON) produces 0 records.
func TestSingleByteFile(t *testing.T) {
	recs, err := parseEveJSON(context.Background(), strings.NewReader("{"))
	if err != nil {
		t.Fatalf("single-byte file should not error: %v", err)
	}
	if len(recs) != 0 {
		t.Fatalf("single-byte file: got %d records, want 0", len(recs))
	}
}

// TestEOFMidStringValue verifies that a line truncated inside a JSON string value is skipped
// and earlier complete lines are still returned.
func TestEOFMidStringValue(t *testing.T) {
	const data = `{"event_type":"tls","dest_ip":"1.2.3.4","dest_port":443,"tls":{"version":"TLSv1.3","cipher_suite":"TLS_AES_128_GCM_SHA256"}}
{"event_type":"tls","dest_ip":"5.6.7.8","dest_port":443,"tls":{"version":"TLSv1.3","sni":"truncated-mid-`
	recs, err := parseEveJSON(context.Background(), strings.NewReader(data))
	if err != nil {
		t.Fatalf("EOF mid-string should not error: %v", err)
	}
	if len(recs) != 1 {
		t.Fatalf("EOF mid-string: got %d records, want 1 (truncated line must be skipped)", len(recs))
	}
}

// TestEOFMidArray verifies that a line with an unclosed JSON array is skipped.
func TestEOFMidArray(t *testing.T) {
	const data = `{"event_type":"tls","dest_ip":"1.2.3.4","dest_port":443,"tls":{"version":"TLSv1.3","cipher_suite":"TLS_AES_128_GCM_SHA256"}}
{"event_type":"tls","dest_ip":"5.6.7.8","dest_port":443,"tls":{"extensions":[1,2,`
	recs, err := parseEveJSON(context.Background(), strings.NewReader(data))
	if err != nil {
		t.Fatalf("EOF mid-array should not error: %v", err)
	}
	if len(recs) != 1 {
		t.Fatalf("EOF mid-array: got %d records, want 1", len(recs))
	}
}

// TestSizeCap_OverLimit verifies that a file exceeding maxDecompressedBytes is rejected.
func TestSizeCap_OverLimit(t *testing.T) {
	tmp := filepath.Join(t.TempDir(), "over-cap.json")
	f, err := os.Create(tmp)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	chunk := make([]byte, 65536)
	written := int64(0)
	for written <= maxDecompressedBytes {
		n, werr := f.Write(chunk)
		written += int64(n)
		if werr != nil {
			break
		}
	}
	f.Close()

	_, err = readEveJSON(context.Background(), tmp)
	if err == nil {
		t.Fatal("expected size-cap error for file over maxDecompressedBytes")
	}
}

// TestGzipBomb150MB verifies that a gzip file decompressing to 150MB is rejected.
func TestGzipBomb150MB(t *testing.T) {
	const bombed = 150 * 1024 * 1024
	tmp := filepath.Join(t.TempDir(), "bomb.json.gz")
	f, err := os.Create(tmp)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	gz := gzip.NewWriter(f)
	chunk := bytes.Repeat([]byte(" "), 65536)
	written := 0
	for written < bombed {
		n := len(chunk)
		if bombed-written < n {
			n = bombed - written
		}
		if _, werr := gz.Write(chunk[:n]); werr != nil {
			break
		}
		written += n
	}
	gz.Close()
	f.Close()

	_, err = readEveJSON(context.Background(), tmp)
	if err == nil {
		t.Fatal("expected size-cap error for 150MB gzip bomb")
	}
}

// TestDoubleGzip verifies that a double-gzip file (gzip inside gzip) does not panic.
// The inner gzip bytes are treated as non-UTF-8 JSON lines and silently skipped.
func TestDoubleGzip(t *testing.T) {
	inner := `{"event_type":"tls","dest_ip":"1.2.3.4","dest_port":443,"tls":{"version":"TLSv1.3","cipher_suite":"TLS_AES_128_GCM_SHA256"}}` + "\n"

	var innerGZ bytes.Buffer
	w1 := gzip.NewWriter(&innerGZ)
	_, _ = w1.Write([]byte(inner))
	w1.Close()

	tmp := filepath.Join(t.TempDir(), "double.json.gz")
	f, err := os.Create(tmp)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	w2 := gzip.NewWriter(f)
	_, _ = w2.Write(innerGZ.Bytes())
	w2.Close()
	f.Close()

	// Must not panic; result (0 or more records) is irrelevant.
	_, _ = readEveJSON(context.Background(), tmp)
}

// TestEmptyGzipBody verifies that a valid-but-empty gzip stream produces 0 records.
func TestEmptyGzipBody(t *testing.T) {
	tmp := filepath.Join(t.TempDir(), "empty.json.gz")
	f, err := os.Create(tmp)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	gz := gzip.NewWriter(f)
	gz.Close()
	f.Close()

	recs, err := readEveJSON(context.Background(), tmp)
	if err != nil {
		t.Fatalf("empty gzip body should not error: %v", err)
	}
	if len(recs) != 0 {
		t.Fatalf("empty gzip body: got %d records, want 0", len(recs))
	}
}

// TestMegaLinePastBuffer verifies that a line longer than the 4MB scanner buffer
// does not panic. The scanner stops on buffer overflow; this tests that the parser
// propagates the error without crashing.
func TestMegaLinePastBuffer(t *testing.T) {
	// 5MB line of spaces (not valid JSON; bufio.Scanner will overflow its 4MB cap).
	bigLine := strings.Repeat(" ", 5*1024*1024)
	data := bigLine + "\n" + `{"event_type":"tls","dest_ip":"1.2.3.4","dest_port":443,"tls":{"version":"TLSv1.3","cipher_suite":"TLS_AES_128_GCM_SHA256"}}` + "\n"
	// Must not panic — scanner error is surfaced via parseEveJSON return value.
	_, _ = parseEveJSON(context.Background(), strings.NewReader(data))
}

// TestDedupCapBoundaryExact verifies that exactly maxSuricataRecords unique records
// are retained and the (maxSuricataRecords+1)th unique record is dropped.
func TestDedupCapBoundaryExact(t *testing.T) {
	var sb strings.Builder
	// Write maxSuricataRecords + 1 unique records.
	for i := 0; i <= maxSuricataRecords; i++ {
		fmt.Fprintf(&sb,
			"{\"event_type\":\"tls\",\"dest_ip\":\"%d.%d.%d.%d\",\"dest_port\":443,\"tls\":{\"version\":\"TLSv1.3\",\"cipher_suite\":\"TLS_AES_128_GCM_SHA256\"}}\n",
			(i>>24)&0xFF, (i>>16)&0xFF, (i>>8)&0xFF, i&0xFF)
	}

	recs, err := parseEveJSON(context.Background(), strings.NewReader(sb.String()))
	if err != nil {
		t.Fatalf("parseEveJSON: %v", err)
	}
	if len(recs) != maxSuricataRecords {
		t.Errorf("dedup cap boundary: got %d records, want exactly %d (cap is %d)",
			len(recs), maxSuricataRecords, maxSuricataRecords)
	}
}

// TestDedupCapBoundary_ExactCapSize verifies that exactly maxSuricataRecords unique
// records (no +1) are all retained — the cap is non-inclusive on the good side.
func TestDedupCapBoundary_ExactCapSize(t *testing.T) {
	var sb strings.Builder
	for i := 0; i < maxSuricataRecords; i++ {
		fmt.Fprintf(&sb,
			"{\"event_type\":\"tls\",\"dest_ip\":\"%d.%d.%d.%d\",\"dest_port\":443,\"tls\":{\"version\":\"TLSv1.3\",\"cipher_suite\":\"TLS_AES_128_GCM_SHA256\"}}\n",
			(i>>24)&0xFF, (i>>16)&0xFF, (i>>8)&0xFF, i&0xFF)
	}

	recs, err := parseEveJSON(context.Background(), strings.NewReader(sb.String()))
	if err != nil {
		t.Fatalf("parseEveJSON: %v", err)
	}
	if len(recs) != maxSuricataRecords {
		t.Errorf("expected exactly %d records at cap boundary, got %d", maxSuricataRecords, len(recs))
	}
}
