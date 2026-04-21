package configscanner

// Extended bug probes found during audit.

import (
	"testing"
)

// F1 extension: verify /* in a value truly corrupts multi-line state.
// A string value containing /* with no */ in the file causes ALL subsequent
// key/value parsing to be swallowed into the "block comment" state.
func TestBugExtra_HCLCommentStateLeaksAcrossBlocks(t *testing.T) {
	input := `resource "a" "x" {
  description = "contains /* no closer"
}

resource "b" "y" {
  algorithm = "AES"
  key_size = 2048
}
`
	kvs, _ := parseHCL([]byte(input))
	m := make(map[string]string)
	for _, kv := range kvs {
		m[kv.Key] = kv.Value
	}
	if _, ok := m["resource.b.y.algorithm"]; !ok {
		t.Errorf("/* leak swallowed subsequent resource blocks; parsed=%v", keysOfMap(m))
	}
	if _, ok := m["resource.b.y.key_size"]; !ok {
		t.Errorf("/* leak swallowed subsequent resource blocks; parsed=%v", keysOfMap(m))
	}
}

// F3: heredoc detection runs on the whole value. If a value is `key = "<<foo"`,
// the check `strings.HasPrefix(val, "<<")` looks at val AFTER hclExtractValue,
// which returns the unquoted content. So a quoted string value `"<<foo"` would
// have val = `<<foo`, tripping the heredoc branch falsely.
func TestBugExtra_HCLQuotedStringLookingLikeHeredoc(t *testing.T) {
	input := `algorithm = "<<EOF unclosed"
key_size = 2048
`
	kvs, _ := parseHCL([]byte(input))
	m := make(map[string]string)
	for _, kv := range kvs {
		m[kv.Key] = kv.Value
	}
	if _, ok := m["key_size"]; !ok {
		t.Errorf("quoted value starting with `<<` misdetected as heredoc; key_size swallowed; parsed=%+v", m)
	}
	if v, ok := m["algorithm"]; !ok {
		t.Errorf("algorithm key dropped by heredoc misdetection")
	} else if v != "<<EOF unclosed" {
		t.Errorf("heredoc misdetection mangled algorithm value: got %q, want %q", v, "<<EOF unclosed")
	}
}

// F4: INI lines with only a section prefix and whitespace after close bracket.
// e.g. "[sec]  # trailing comment"
func TestBugExtra_INISectionWithTrailingComment(t *testing.T) {
	input := "[sec]  ; trailing\nkey=val\n"
	kvs, _ := parseINI([]byte(input))
	m := make(map[string]string)
	for _, kv := range kvs {
		m[kv.Key] = kv.Value
	}
	t.Logf("parsed: %+v", m)
	if _, ok := m["sec.key"]; !ok {
		t.Logf("NOTE: INI section header with trailing comment may not be handled")
	}
}

// F5: YAML parseYAML sets `err` inside the decode loop but returns (kvs, err)
// carrying the LAST error. When the FIRST document parses successfully but the
// SECOND is malformed, the error path return is: "if len(kvs) > 0 ... return kvs, err".
// scanConfigFile discards the error when len(kvs) > 0. Good behavior, but note:
// the YAML parser can leak partial state.
func TestBugExtra_YAMLPartialMultiDoc(t *testing.T) {
	input := `algorithm: AES
key_size: 256
---
malformed: : :
`
	kvs, err := parseYAML([]byte(input))
	t.Logf("err=%v, kvs=%+v", err, kvs)
	// Expect at least the first doc's keys.
	m := make(map[string]string)
	for _, kv := range kvs {
		m[kv.Key] = kv.Value
	}
	if _, ok := m["algorithm"]; !ok {
		t.Logf("NOTE: YAML partial parse does not preserve first document's keys")
	}
}

// F6: HCL depth-limit brace-counter logic — `strings.HasPrefix(l, "}")` vs
// `strings.HasSuffix(l, "{")`. A single line like `}{` would increment braceDepth
// AND decrement it on the same line. What if line is `}`, then followed by
// valid content? The depth-limiter scans until braceDepth == 0; it strips braces
// from bracket count, but doesn't handle `}` inside a string.
func TestBugExtra_HCLDepthLimitBraceInString(t *testing.T) {
	// Construct an HCL snippet with depth > maxHCLDepth and containing a string
	// with `{` or `}` embedded.
	// Skip if too tedious — just verify no panic.
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("panic in depth-limit case: %v", r)
		}
	}()
	input := `a {
  b = "string with { inside"
  c = "string with } inside"
  algorithm = "AES"
}
`
	kvs, _ := parseHCL([]byte(input))
	t.Logf("parsed: %+v", kvs)
}

func keysOfMap(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return keys
}
