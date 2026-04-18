package zeeklog

import (
	"bytes"
	"testing"
)

// FuzzParseSSLTSV exercises parseSSLTSV with arbitrary byte sequences.
// Run with: go test -fuzz=FuzzParseSSLTSV -fuzztime=500000x ./pkg/engines/zeeklog/...
// Invariant: must not panic regardless of input.
func FuzzParseSSLTSV(f *testing.F) {
	// Seed: valid TSV log
	f.Add([]byte(sslTSVGolden))

	// Seed: missing #fields header
	f.Add([]byte("1704067200\tCx\t10.0.0.1\t9999\t1.2.3.4\t443\tTLSv13\tTLS_AES_256_GCM_SHA384\tX25519\texample.com\tT\n"))

	// Seed: wrong column count (fewer columns than header declares)
	f.Add([]byte("#fields\tts\tuid\tid.resp_h\tid.resp_p\tcipher\tcurve\testablished\n#types\ttime\tstring\taddr\tport\tstring\tstring\tbool\n1704067200\tCx\t1.2.3.4\n"))

	// Seed: embedded NUL bytes
	f.Add([]byte("#fields\tts\tuid\tid.resp_h\tid.resp_p\tcipher\tcurve\testablished\n1700\x00000\tCx\t1.2.3.4\t443\taes\tx25519\tT\n"))

	// Seed: CRLF line endings
	f.Add([]byte("#separator \\x09\r\n#fields\tts\tuid\tid.resp_h\tid.resp_p\tcipher\tcurve\testablished\r\n1704067200\tCx\t1.2.3.4\t443\taes\tx25519\tT\r\n"))

	// Seed: trailing whitespace
	f.Add([]byte("#fields\tts\tuid\tid.resp_h\tid.resp_p\tcipher\tcurve\testablished   \n1704067200\tCx\t1.2.3.4\t443\taes\tx25519\tT   \n"))

	// Seed: bytes before first # (non-comment prefix)
	f.Add([]byte("GARBAGE\n#fields\tts\tuid\tid.resp_h\tid.resp_p\tcipher\tcurve\testablished\n1704067200\tCx\t1.2.3.4\t443\taes\tx25519\tT\n"))

	// Seed: UTF-8 BOM
	f.Add(append([]byte{0xEF, 0xBB, 0xBF}, []byte("#fields\tts\tuid\tid.resp_h\tid.resp_p\tcipher\tcurve\testablished\n1704067200\tCx\t1.2.3.4\t443\taes\tx25519\tT\n")...))

	// Seed: invalid UTF-8 sequences in field values
	f.Add([]byte("#fields\tts\tuid\tid.resp_h\tid.resp_p\tcipher\tcurve\testablished\n1704067200\tCx\t\xff\xfe1.2.3.4\t443\taes\tx25519\tT\n"))

	// Seed: empty
	f.Add([]byte{})

	// Seed: single byte
	f.Add([]byte{'#'})

	// Seed: only headers, no data rows
	f.Add([]byte("#separator \\x09\n#fields\tts\tuid\tid.resp_h\tid.resp_p\tcipher\tcurve\testablished\n"))

	// Seed: very long line
	longLine := make([]byte, 65536)
	for i := range longLine {
		longLine[i] = 'A'
	}
	f.Add(append([]byte("#fields\tts\tuid\tid.resp_h\tid.resp_p\tcipher\tcurve\testablished\n"), longLine...))

	f.Fuzz(func(t *testing.T, data []byte) {
		// Must not panic.
		_, _ = parseSSLTSV(bytes.NewReader(data))
	})
}

// FuzzParseSSLJSON exercises parseSSLJSON with arbitrary byte sequences.
// Run with: go test -fuzz=FuzzParseSSLJSON -fuzztime=500000x ./pkg/engines/zeeklog/...
func FuzzParseSSLJSON(f *testing.F) {
	// Seed: valid JSON log
	f.Add([]byte(sslJSONGolden))

	// Seed: broken JSON object
	f.Add([]byte(`{"ts":1700,"uid":"Cx","id.resp_h":"1.2.3.4","id.resp_p":443,"cipher":"aes","established":true` + "\n"))

	// Seed: truncated mid-field
	f.Add([]byte(`{"ts":1700,"uid":"Cx","id.resp_h":"1.2.`))

	// Seed: array instead of object
	f.Add([]byte("[1,2,3]\n"))

	// Seed: null bytes inside JSON string
	f.Add([]byte("{\"uid\":\"C\x00x\",\"established\":true,\"cipher\":\"aes\",\"id.resp_h\":\"1.2.3.4\",\"id.resp_p\":443}\n"))

	// Seed: deeply nested JSON (not valid ssl.log but should not panic)
	f.Add([]byte(`{"a":{"b":{"c":{"d":{"e":"f"}}}},"established":true}` + "\n"))

	// Seed: extremely large number
	f.Add([]byte(`{"id.resp_p":999999999999999999999999,"established":true,"cipher":"aes","id.resp_h":"1.2.3.4"}` + "\n"))

	// Seed: UTF-8 BOM
	f.Add(append([]byte{0xEF, 0xBB, 0xBF}, []byte(`{"established":true,"cipher":"aes","id.resp_h":"1.2.3.4","id.resp_p":443}`+"\n")...))

	// Seed: invalid UTF-8 in values
	f.Add([]byte("{\"cipher\":\"\xff\xfe\",\"established\":true,\"id.resp_h\":\"1.2.3.4\",\"id.resp_p\":443}\n"))

	// Seed: multiple lines, some malformed
	f.Add([]byte(`{"established":true,"cipher":"aes","id.resp_h":"1.2.3.4","id.resp_p":443}` + "\n" +
		"NOT JSON\n" +
		`{"established":false,"cipher":"ecdhe","id.resp_h":"5.6.7.8","id.resp_p":443}` + "\n"))

	// Seed: empty
	f.Add([]byte{})

	// Seed: single newline
	f.Add([]byte("\n"))

	f.Fuzz(func(t *testing.T, data []byte) {
		// Must not panic.
		_, _ = parseSSLJSON(bytes.NewReader(data))
	})
}
