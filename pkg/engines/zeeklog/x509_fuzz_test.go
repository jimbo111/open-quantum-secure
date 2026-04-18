package zeeklog

import (
	"bytes"
	"testing"
)

// FuzzParseX509TSV exercises parseX509TSV with arbitrary byte sequences.
// Run with: go test -fuzz=FuzzParseX509TSV -fuzztime=500000x ./pkg/engines/zeeklog/...
func FuzzParseX509TSV(f *testing.F) {
	// Seed: valid x509 TSV
	f.Add([]byte(x509TSVGolden))

	// Seed: missing #fields header — data rows should be skipped
	f.Add([]byte("1704067200\tFuid01\t3\t01\tCN=ex\tCN=CA\t1700000000\t1800000000\trsaEncryption\tsha256WithRSAEncryption\trsa\t2048\t65537\t-\tex.com\t-\t-\t-\tF\n"))

	// Seed: wrong column count
	f.Add([]byte("#fields\tts\tid\tcertificate.sig_alg\tcertificate.key_alg\n1704067200\tFuid01\n"))

	// Seed: embedded NUL bytes
	f.Add([]byte("#fields\tts\tid\tcertificate.sig_alg\tcertificate.key_alg\tcertificate.key_type\tcertificate.key_length\tcertificate.curve\tsan.dns\n1704067200\tFuid01\tsha256\x00WithRSA\trsaEnc\trsa\t2048\t-\tex.com\n"))

	// Seed: CRLF line endings
	f.Add([]byte("#fields\tts\tid\tcertificate.sig_alg\tcertificate.key_alg\tcertificate.key_type\tcertificate.key_length\tcertificate.curve\tsan.dns\r\n1704067200\tFuid01\tsha256\trsaEnc\trsa\t2048\t-\tex.com\r\n"))

	// Seed: trailing whitespace in values
	f.Add([]byte("#fields\tts\tid\tcertificate.sig_alg\tcertificate.key_alg\tcertificate.key_type\tcertificate.key_length\tcertificate.curve\tsan.dns\n1704067200\tFuid01\tsha256WithRSAEncryption   \trsaEncryption   \trsa\t2048\t-\tex.com\n"))

	// Seed: non-numeric key_length
	f.Add([]byte("#fields\tts\tid\tcertificate.sig_alg\tcertificate.key_alg\tcertificate.key_type\tcertificate.key_length\tcertificate.curve\tsan.dns\n1704067200\tFuid01\tsha256WithRSAEncryption\trsaEncryption\trsa\tNOTANUM\t-\tex.com\n"))

	// Seed: bytes before first #
	f.Add([]byte("GARBAGE\n#fields\tts\tid\tcertificate.sig_alg\tcertificate.key_alg\n1704067200\tFuid01\tsha256\trsaEnc\n"))

	// Seed: UTF-8 BOM
	f.Add(append([]byte{0xEF, 0xBB, 0xBF}, []byte("#fields\tts\tid\tcertificate.sig_alg\tcertificate.key_alg\n1704067200\tFuid01\tsha256\trsaEnc\n")...))

	// Seed: invalid UTF-8 in OID field
	f.Add([]byte("#fields\tts\tid\tcertificate.sig_alg\tcertificate.key_alg\tcertificate.key_type\tcertificate.key_length\tcertificate.curve\tsan.dns\n1704067200\tFuid01\t\xff\xfe\trsaEnc\trsa\t2048\t-\tex.com\n"))

	// Seed: empty
	f.Add([]byte{})

	// Seed: only separator comment
	f.Add([]byte("#separator \\x09\n"))

	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = parseX509TSV(bytes.NewReader(data))
	})
}

// FuzzParseX509JSON exercises parseX509JSON with arbitrary byte sequences.
// Run with: go test -fuzz=FuzzParseX509JSON -fuzztime=500000x ./pkg/engines/zeeklog/...
func FuzzParseX509JSON(f *testing.F) {
	// Seed: valid nested JSON (contrived fixture — current code parses this)
	f.Add([]byte(x509JSONGolden))

	// Seed: real Zeek flat-dotted JSON (expected to yield 0 records against current code)
	flatJSON := `{"ts":1719792000.0,"id":"FrRSA1","certificate.version":3,"certificate.sig_alg":"sha256WithRSAEncryption","certificate.key_alg":"rsaEncryption","certificate.key_type":"rsa","certificate.key_length":2048,"san.dns":["rsa.example.com"]}` + "\n"
	f.Add([]byte(flatJSON))

	// Seed: truncated JSON object
	f.Add([]byte(`{"id":"Fuid01","certificate":{"sig_alg":"sha256`))

	// Seed: null values
	f.Add([]byte(`{"id":"Fuid01","certificate":{"sig_alg":null,"key_alg":null,"key_type":null,"key_length":null,"curve":null},"san":{"dns":null}}` + "\n"))

	// Seed: key_length as string
	f.Add([]byte(`{"id":"Fuid01","certificate":{"sig_alg":"sha256WithRSAEncryption","key_alg":"rsaEncryption","key_type":"rsa","key_length":"4096","curve":""},"san":{"dns":"example.com"}}` + "\n"))

	// Seed: key_length as negative float
	f.Add([]byte(`{"id":"Fuid01","certificate":{"sig_alg":"sha256WithRSAEncryption","key_alg":"rsaEncryption","key_type":"rsa","key_length":-1.5,"curve":""},"san":{"dns":"example.com"}}` + "\n"))

	// Seed: both sig_alg and key_alg empty → should be skipped
	f.Add([]byte(`{"id":"Fuid01","certificate":{"sig_alg":"","key_alg":"","key_type":"rsa","key_length":2048,"curve":""},"san":{"dns":"example.com"}}` + "\n"))

	// Seed: invalid UTF-8
	f.Add([]byte("{\"id\":\"Fuid\xff\",\"certificate\":{\"sig_alg\":\"sha256\",\"key_alg\":\"rsa\",\"key_type\":\"rsa\",\"key_length\":2048,\"curve\":\"\"},\"san\":{\"dns\":\"ex.com\"}}\n"))

	// Seed: array at top level
	f.Add([]byte("[{\"id\":\"Fuid01\"}]\n"))

	// Seed: empty input
	f.Add([]byte{})

	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = parseX509JSON(bytes.NewReader(data))
	})
}
