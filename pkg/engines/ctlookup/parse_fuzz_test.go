// parse_fuzz_test.go — Fuzz tests for the crt.sh JSON parser. Seed corpus
// covers the golden-path plus common malformed variants; the fuzzer explores
// the full space looking for panics or races.
//
// Run extended fuzzing with:
//
//	go test -fuzz=FuzzParseCrtShJSON -fuzztime=20s ./pkg/engines/ctlookup/
package ctlookup

import "testing"

// FuzzParseCrtShJSON exercises parseCrtShJSON with arbitrary byte sequences.
// The invariant under test: the function must never panic regardless of input,
// and a nil return value must be accompanied by a nil error for empty input.
func FuzzParseCrtShJSON(f *testing.F) {
	// ── Seed corpus ───────────────────────────────────────────────────────────
	// Empty / null
	f.Add([]byte(nil))
	f.Add([]byte{})
	f.Add([]byte("[]"))
	f.Add([]byte("null"))

	// Single valid entry (realistic crt.sh response shape)
	f.Add([]byte(`[{"issuer_ca_id":183267,"issuer_name":"C=US, O=Let's Encrypt, CN=R10","common_name":"example.com","name_value":"example.com","id":10000001,"entry_timestamp":"2024-01-15T12:00:00","not_before":"2024-01-15T00:00:00","not_after":"2024-04-15T00:00:00","serial_number":"04D2A1B3C4E5F601"}]`))

	// Multiple entries
	f.Add([]byte(`[{"id":1,"common_name":"a.com"},{"id":2,"common_name":"b.com"}]`))

	// Truncated variants (common real-world corruption patterns)
	f.Add([]byte(`[{"id":`))
	f.Add([]byte(`[{"id":1,"common_name":`))
	f.Add([]byte(`[{`))
	f.Add([]byte(`[`))

	// Malformed JSON
	f.Add([]byte(`{not valid json`))
	f.Add([]byte(`"just a string"`))
	f.Add([]byte(`42`))
	f.Add([]byte(`true`))

	// Large ID and serial values
	f.Add([]byte(`[{"id":9223372036854775807,"serial_number":"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"}]`))

	// Unicode in string fields
	f.Add([]byte(`[{"common_name":"日本語.example.jp","id":1}]`))

	// Binary garbage
	f.Add([]byte{0x00, 0x01, 0x02, 0xff, 0xfe})
	f.Add([]byte{'{', '"', 0x80, '"', ':'})

	// ── Fuzz target ───────────────────────────────────────────────────────────
	f.Fuzz(func(t *testing.T, data []byte) {
		// Invariant: must never panic.
		entries, err := parseCrtShJSON(data)

		// Additional invariant: nil/empty input returns nil without error.
		if len(data) == 0 {
			if err != nil {
				t.Errorf("empty input: unexpected error: %v", err)
			}
			if entries != nil {
				t.Errorf("empty input: expected nil entries, got %v", entries)
			}
		}
	})
}

// FuzzParseTime exercises parseTime with arbitrary timestamp strings.
// The invariant: must never panic and must return time.Time{} for unrecognised
// inputs (not an error — a zero value is the documented fallback).
func FuzzParseTime(f *testing.F) {
	f.Add("")
	f.Add("2024-01-15T12:00:00")
	f.Add("2024-01-15T12:00:00.999")
	f.Add("2024-01-15 12:00:00")
	f.Add("2024-01-15")
	f.Add("not-a-date")
	f.Add("9999-99-99T99:99:99")
	f.Add("\x00\xff")

	f.Fuzz(func(t *testing.T, s string) {
		// Must not panic.
		_ = parseTime(s)
	})
}
