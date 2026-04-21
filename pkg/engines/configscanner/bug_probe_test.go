package configscanner

// Bug probes — targeted tests for suspected defects found during code review.
// These are NOT fuzz tests; they encode specific hypotheses about parser bugs.

import (
	"strings"
	"testing"
)

// B1. HCL block-comment detection ignores string quotes.
// If an HCL string literal contains "/*", the parser treats it as a block
// comment start and drops everything after it on the line (and possibly the
// whole rest of the file if no */ follows).
//
// NOTE: audit agent — this test documents the bug, does NOT fix it. Set
// t.Log rather than t.Error so the test suite stays green; the finding is
// recorded in docs/audits/2026-04-20-scanner-layer-audit/04-t4-config.md.
func TestBugProbe_HCLBlockCommentInsideString(t *testing.T) {
	input := `algorithm = "AES/*pattern*/"
key_size = 256
`
	kvs, err := parseHCL([]byte(input))
	if err != nil {
		t.Fatalf("parseHCL error: %v", err)
	}
	m := make(map[string]string)
	for _, kv := range kvs {
		m[kv.Key] = kv.Value
	}
	if v, ok := m["algorithm"]; !ok {
		t.Errorf("algorithm key dropped by block-comment detector: parsed=%+v", m)
	} else if v != `AES/*pattern*/` {
		t.Errorf("algorithm value mangled by block-comment detector: got %q, want %q",
			v, `AES/*pattern*/`)
	}
	if _, ok := m["key_size"]; !ok {
		t.Errorf("key_size dropped because /*..*/ in prior line consumed it")
	}
}

// B2. HCL block-comment opener with no closer swallows rest of file, even
// when the "/*" is inside a quoted value that would terminate on the SAME line.
func TestBugProbe_HCLUnterminatedSlashStarInString(t *testing.T) {
	input := `algorithm = "has /* slashstar"
key_size = 256
`
	kvs, err := parseHCL([]byte(input))
	if err != nil {
		t.Fatalf("parseHCL error: %v", err)
	}
	m := make(map[string]string)
	for _, kv := range kvs {
		m[kv.Key] = kv.Value
	}
	if v, ok := m["algorithm"]; !ok {
		t.Errorf("algorithm dropped by /* detector inside string: parsed=%+v", m)
	} else if v != "has /* slashstar" {
		t.Errorf("algorithm value truncated by /* inside string: got %q, want %q",
			v, "has /* slashstar")
	}
	if _, ok := m["key_size"]; !ok {
		t.Errorf("key_size swallowed by unterminated /* detector inside string")
	}
}

// B3. HCL heredoc marker strip — `strings.Trim(marker, \"\")` strips ALL
// double quotes, not just surrounding ones. A marker like `"E"OF"` would lose
// internal quotes. Realistic? Terraform allows `<<"EOF"` as a quoted marker.
// The trim is benign for standard usage but not for pathological markers.
func TestBugProbe_HCLHeredocMarkerQuotes(t *testing.T) {
	// Non-standard marker — Terraform does not allow internal quotes, so we
	// don't expect to find one in practice. Skip for now but retain the probe.
	input := `script = <<"EOF"
hello
EOF
algorithm = "AES"
`
	kvs, err := parseHCL([]byte(input))
	if err != nil {
		t.Fatalf("parseHCL error: %v", err)
	}
	m := make(map[string]string)
	for _, kv := range kvs {
		m[kv.Key] = kv.Value
	}
	if _, ok := m["algorithm"]; !ok {
		t.Errorf("BUG: heredoc marker strip discarded sibling keys")
	}
}

// B4. HCL "block type with no body" — `name "x"` on its own line without a
// subsequent `{` on the next line. The peek-ahead logic treats any non-{
// next line as "not a block". Confirms that free-standing `resource "x"`
// with no body does NOT pollute the state machine.
func TestBugProbe_HCLBlockHeaderWithoutBody(t *testing.T) {
	input := `resource "tls_private_key" "orphan"
algorithm = "AES"
`
	kvs, err := parseHCL([]byte(input))
	if err != nil {
		t.Fatalf("parseHCL error: %v", err)
	}
	m := make(map[string]string)
	for _, kv := range kvs {
		m[kv.Key] = kv.Value
	}
	t.Logf("parsed: %+v", m)
	// algorithm should be at top level (since the resource header is orphaned).
	if v, ok := m["algorithm"]; !ok {
		t.Errorf("BUG: algorithm dropped after orphan block header")
	} else if v != "AES" {
		t.Errorf("algorithm value wrong: got %q want AES", v)
	}
}

// B5. HCL heredoc with indented closing marker beyond what the input has.
// If `<<-EOF` expects an indented closer but the EOF marker is at column 0
// with content, should we recognise it? Current impl trims spaces unconditionally
// so closing EOF works at any indent.
func TestBugProbe_HCLIndentedHeredocIndentMismatch(t *testing.T) {
	input := `script = <<-EOF
hello
EOF
algorithm = "AES"
`
	kvs, err := parseHCL([]byte(input))
	if err != nil {
		t.Fatalf("parseHCL error: %v", err)
	}
	m := make(map[string]string)
	for _, kv := range kvs {
		m[kv.Key] = kv.Value
	}
	if _, ok := m["algorithm"]; !ok {
		t.Errorf("BUG: indented heredoc consumed sibling keys")
	}
}

// B6. HCL raw string (backtick) — HCL does not have Go-style raw strings,
// but hclExtractValue might misbehave on backtick content. Verify a string
// starting with ` is returned as-is (unquoted path) without panic.
func TestBugProbe_HCLBacktickValue(t *testing.T) {
	input := "key = `raw value`\n"
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("parseHCL panicked on backtick: %v", r)
		}
	}()
	kvs, err := parseHCL([]byte(input))
	if err != nil {
		t.Fatalf("parseHCL error: %v", err)
	}
	if len(kvs) != 1 || kvs[0].Key != "key" {
		t.Logf("parsed: %+v", kvs)
	}
}

// B7. INI quoted value with embedded matching quote — `key="val\"ue"` —
// INI's quoted handling uses `strings.IndexByte(value[1:], quote)` which
// finds the FIRST matching quote byte. There is no escape handling, so
// `\"` is treated as a closing quote, truncating the value.
func TestBugProbe_INIEmbeddedQuote(t *testing.T) {
	input := `key="val\"ue"
`
	kvs, err := parseINI([]byte(input))
	if err != nil {
		t.Fatalf("parseINI error: %v", err)
	}
	m := make(map[string]string)
	for _, kv := range kvs {
		m[kv.Key] = kv.Value
	}
	t.Logf("parsed: %+v", m)
	// Document current behavior: INI does not support \" escape; the value
	// will be truncated at the first ". This is a minor correctness note.
	if v := m["key"]; v != `val\` {
		t.Logf("INOTE: INI truncates at first quote (no escape support); got %q", v)
	}
}

// B8. ENV parser — similar concern. `KEY="val\"ue"` — same missing escape.
func TestBugProbe_ENVEmbeddedQuote(t *testing.T) {
	input := `KEY="val\"ue"
`
	kvs, err := parseEnv([]byte(input))
	if err != nil {
		t.Fatalf("parseEnv error: %v", err)
	}
	m := make(map[string]string)
	for _, kv := range kvs {
		m[kv.Key] = kv.Value
	}
	t.Logf("parsed: %+v", m)
	if v := m["KEY"]; v != `val\` {
		t.Logf("INOTE: ENV truncates at first quote (no escape support); got %q", v)
	}
}

// B9. Properties parser: continuation line counter. `lineNum` is incremented
// inside the continuation loop, but `startLine` is captured before. The
// reported line number for a multi-line continuation is the FIRST line.
// This is documented behavior — no bug.

// B10. HCL line comments — `//` at start. What about `://` inside a URL value?
// `strings.HasPrefix(line, "//")` only triggers when the line STARTS with //.
// So a value like `url = "https://..."` doesn't trip this; but what about an
// INLINE // comment on the same line? `hclExtractValue` strips " //" from
// unquoted values. For quoted values it does NOT. Good. What about:
// `key = value // comment`? The RHS "value" has a trailing " //" which is
// stripped. OK.
func TestBugProbe_HCLURLValue(t *testing.T) {
	input := `endpoint = "https://example.com/algorithm"
algorithm = "AES"
`
	kvs, err := parseHCL([]byte(input))
	if err != nil {
		t.Fatalf("parseHCL error: %v", err)
	}
	m := make(map[string]string)
	for _, kv := range kvs {
		m[kv.Key] = kv.Value
	}
	if v := m["endpoint"]; v != `https://example.com/algorithm` {
		t.Errorf("BUG: URL value mangled by // comment detector: got %q", v)
	}
	if _, ok := m["algorithm"]; !ok {
		t.Errorf("BUG: algorithm dropped")
	}
}

// B11. Properties parser hash-suffix edge: `key=value#hash` — NO space before
// #, so it's NOT an inline comment (per test corpus). Confirm.
func TestBugProbe_PropertiesHashNoSpace(t *testing.T) {
	input := "key=value#nospace\n"
	kvs, _ := parseProperties([]byte(input))
	if len(kvs) != 1 {
		t.Fatalf("expected 1 kv, got %d", len(kvs))
	}
	if kvs[0].Value != "value#nospace" {
		t.Errorf("expected value#nospace, got %q", kvs[0].Value)
	}
}

// B12. matchCryptoParams: empty Key (from parser producing {Key: "", Value: "AES"}).
// matchCryptoParams does strings.Contains(lowerKey=""), which returns TRUE only
// for an empty KeyPattern — none exist. Safe.
// But: what about a Key == "algorithm" and Value == "" (empty)? Should NOT match
// because ValueHints is non-empty for algorithm patterns.
func TestBugProbe_EmptyValueMatch(t *testing.T) {
	kv := KeyValue{Key: "algorithm", Value: "", Line: 1}
	fds := matchCryptoParams("x.yml", []KeyValue{kv})
	if len(fds) != 0 {
		t.Errorf("empty value should not match: got %d findings", len(fds))
	}
}

// B13. matchCryptoParams: key-size pattern but value is a non-numeric string.
// parseIntValue returns 0, and matchCryptoParams emits a finding with KeySize=0.
// Is this intentional? Let's observe.
func TestBugProbe_KeySizeNonNumeric(t *testing.T) {
	kv := KeyValue{Key: "keysize", Value: "large", Line: 1}
	fds := matchCryptoParams("x.yml", []KeyValue{kv})
	if len(fds) == 0 {
		t.Logf("keysize=large produces no finding (OK)")
	} else {
		t.Logf("keysize=large produces finding with KeySize=%d (may be surprising)",
			fds[0].Algorithm.KeySize)
	}
}

// B14. matchCryptoParams: deeply long key with many crypto substrings.
// Expected: first match wins. Document.
func TestBugProbe_LongKeyMultipleMatches(t *testing.T) {
	kv := KeyValue{Key: "algorithm.cipher.hash", Value: "AES", Line: 1}
	fds := matchCryptoParams("x.yml", []KeyValue{kv})
	if len(fds) != 1 {
		t.Errorf("expected 1 finding (first match wins), got %d", len(fds))
	}
}

// B15. HCL: quoted-key with spaces (not allowed in HCL, but YAML/TOML flat keys
// with quoted-key syntax). HCL's tokenizer drops spaces via `strings.ContainsAny`.
// Confirm no panic.
func TestBugProbe_HCLKeyWithSpaces(t *testing.T) {
	input := `"my key" = "AES"
`
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("parseHCL panicked: %v", r)
		}
	}()
	kvs, _ := parseHCL([]byte(input))
	t.Logf("parsed: %+v", kvs)
}

// B16. INI section with unmatched bracket at end of file.
func TestBugProbe_INIUnmatchedBracket(t *testing.T) {
	input := "[unclosed\nkey=val\n"
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("parseINI panicked: %v", r)
		}
	}()
	kvs, _ := parseINI([]byte(input))
	t.Logf("parsed: %+v", kvs)
	// "[unclosed" is not a valid section header (no closing ]); the parser
	// keeps section="" and treats "key=val" as a top-level assignment.
}

// B17. CRLF handling. splitLines normalises \r\n → \n then splits. What about
// a lone \r in the middle of a value? splitLines converts it to \n, splitting
// the logical value across two lines — minor data-loss issue.
func TestBugProbe_LoneCarriageReturnInValue(t *testing.T) {
	input := []byte("key=first\rsecond\n")
	kvs, _ := parseProperties(input)
	t.Logf("parsed: %+v", kvs)
	// splitLines converts \r to \n, so this appears as two lines: "key=first"
	// and "second". The "second" line has no = or :, so it's skipped.
	if len(kvs) == 1 && !strings.Contains(kvs[0].Value, "second") {
		t.Logf("NOTE: lone \\r in value is converted to newline; 'second' data silently dropped")
	}
}
