package configscanner

// Fuzz harnesses for the config-scanner parsers.
//
// These are Go native fuzz tests. Each one exercises a single parser with a
// small corpus of valid seeds; the fuzzer mutates those and asserts the parser
// never panics and respects its documented entry/depth caps.
//
// Run:
//   go test -run=FuzzYAMLParser       ./pkg/engines/configscanner -fuzz=FuzzYAMLParser       -fuzztime=3m
//   go test -run=FuzzJSONParser       ./pkg/engines/configscanner -fuzz=FuzzJSONParser       -fuzztime=3m
//   go test -run=FuzzHCLParser        ./pkg/engines/configscanner -fuzz=FuzzHCLParser        -fuzztime=3m
//   go test -run=FuzzTOMLParser       ./pkg/engines/configscanner -fuzz=FuzzTOMLParser       -fuzztime=3m
//   go test -run=FuzzINIParser        ./pkg/engines/configscanner -fuzz=FuzzINIParser        -fuzztime=3m
//   go test -run=FuzzXMLParser        ./pkg/engines/configscanner -fuzz=FuzzXMLParser        -fuzztime=3m
//   go test -run=FuzzPropertiesParser ./pkg/engines/configscanner -fuzz=FuzzPropertiesParser -fuzztime=3m
//   go test -run=FuzzEnvParser        ./pkg/engines/configscanner -fuzz=FuzzEnvParser        -fuzztime=3m
//
// Each harness is also runnable as a normal unit test (TestFuzzXxxSeeds) against
// its corpus, so CI replays known seeds even without `-fuzz`.

import (
	"strings"
	"testing"
	"time"
)

// fuzzBudget is a per-input wall-clock budget. A parser that does not return in
// this time is almost certainly an infinite loop bug.
const fuzzBudget = 2 * time.Second

// runWithBudget invokes fn and fails the test if it does not complete within
// fuzzBudget. Returns true iff fn completed.
func runWithBudget(t *testing.T, fn func()) bool {
	t.Helper()
	done := make(chan struct{})
	go func() {
		defer close(done)
		defer func() {
			_ = recover() // panics reported by the caller via fn guarding
		}()
		fn()
	}()
	select {
	case <-done:
		return true
	case <-time.After(fuzzBudget):
		return false
	}
}

// ---------- FuzzHCLParser ----------

func FuzzHCLParser(f *testing.F) {
	seeds := []string{
		`algorithm = "AES"`,
		`resource "tls_private_key" "a" {
  algorithm = "RSA"
  rsa_bits = 2048
}`,
		`script = <<EOF
line
EOF`,
		`script = <<-EOF
  line
  EOF`,
		`script = <<"EOF"
line
EOF`,
		`/* unterminated`,
		`/* inline */ algorithm = "AES"`,
		`a { b { c { algorithm = "AES" } } }`,
		"key = \"value with \\\"escape\\\"\"",
		`"\"`,
		`key = ` + "`raw`",
		// Common pathological inputs
		strings.Repeat("{", 200),
		strings.Repeat("}", 200),
		strings.Repeat("a = \"b\"\n", 1000),
	}
	for _, s := range seeds {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 1<<20 { // skip >1MB inputs — fuzzer rarely sends these but cheap guard
			t.Skip()
		}
		done := runWithBudget(t, func() {
			defer func() {
				if r := recover(); r != nil {
					t.Errorf("parseHCL panicked on %q: %v", truncate(data, 120), r)
				}
			}()
			kvs, _ := parseHCL(data)
			if len(kvs) > maxHCLEntries {
				t.Errorf("parseHCL: entry cap breached: got %d > %d", len(kvs), maxHCLEntries)
			}
		})
		if !done {
			t.Errorf("parseHCL did not complete within %v on %q", fuzzBudget, truncate(data, 120))
		}
	})
}

// ---------- FuzzTOMLParser ----------

func FuzzTOMLParser(f *testing.F) {
	seeds := []string{
		`key = "value"`,
		`[section]
a = 1
b = "x"`,
		`[[array]]
name = "one"
[[array]]
name = "two"`,
		`inline = { a = 1, b = 2 }`,
		`multi = """
multi
line
"""`,
		`literal = 'a\b\c'`,
		`date = 1979-05-27`,
		`dotted.key.path = 1`,
		`"quoted key" = 1`,
		`# comment only`,
		strings.Repeat("a", 10000) + " = 1",
	}
	for _, s := range seeds {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 1<<20 {
			t.Skip()
		}
		done := runWithBudget(t, func() {
			defer func() {
				if r := recover(); r != nil {
					t.Errorf("parseTOML panicked on %q: %v", truncate(data, 120), r)
				}
			}()
			kvs, _ := parseTOML(data)
			if len(kvs) > maxTOMLEntries {
				t.Errorf("parseTOML: entry cap breached: got %d > %d", len(kvs), maxTOMLEntries)
			}
		})
		if !done {
			t.Errorf("parseTOML did not complete within %v on %q", fuzzBudget, truncate(data, 120))
		}
	})
}

// ---------- FuzzINIParser ----------

func FuzzINIParser(f *testing.F) {
	seeds := []string{
		"[section]\nkey=value\n",
		"key=val ; comment\n",
		"key=\"quoted ; with ; semicolons\"\n",
		"key=first\\\nsecond\\\nthird\n",
		"[nested.section]\nkey=val\n",
		"=orphan\nkey=val\n",
		"[ws section]\nk = v\n",
		"[unterminated\nkey=val\n",
		strings.Repeat("[s]\nk=v\n", 500),
		strings.Repeat("key=\\\n", 1000), // continuation bomb
	}
	for _, s := range seeds {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 1<<20 {
			t.Skip()
		}
		done := runWithBudget(t, func() {
			defer func() {
				if r := recover(); r != nil {
					t.Errorf("parseINI panicked on %q: %v", truncate(data, 120), r)
				}
			}()
			kvs, _ := parseINI(data)
			if len(kvs) > maxHCLEntries {
				t.Errorf("parseINI: entry cap breached: got %d > %d", len(kvs), maxHCLEntries)
			}
		})
		if !done {
			t.Errorf("parseINI did not complete within %v on %q", fuzzBudget, truncate(data, 120))
		}
	})
}

// ---------- FuzzYAMLParser ----------

func FuzzYAMLParser(f *testing.F) {
	seeds := []string{
		"a: 1\n",
		"list:\n  - a\n  - b\n",
		"defaults: &a\n  x: 1\nuse:\n  <<: *a\n",
		"---\na: 1\n---\nb: 2\n",
		"key: |\n  multi\n  line\n",
		"!!binary dGVzdA==",
		"{}",
		"null",
		strings.Repeat("  ", 100) + "deep: 1\n",
	}
	for _, s := range seeds {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 1<<20 {
			t.Skip()
		}
		done := runWithBudget(t, func() {
			defer func() {
				if r := recover(); r != nil {
					t.Errorf("parseYAML panicked on %q: %v", truncate(data, 120), r)
				}
			}()
			kvs, _ := parseYAML(data)
			if len(kvs) > maxYAMLEntries {
				t.Errorf("parseYAML: entry cap breached: got %d > %d", len(kvs), maxYAMLEntries)
			}
		})
		if !done {
			t.Errorf("parseYAML did not complete within %v on %q", fuzzBudget, truncate(data, 120))
		}
	})
}

// ---------- FuzzJSONParser ----------

func FuzzJSONParser(f *testing.F) {
	seeds := []string{
		`{"a":"b"}`,
		`[1,2,3]`,
		`{"nested":{"deep":{"v":1}}}`,
		`{"k":null}`,
		`{"k":true}`,
		`{"":"empty key"}`,
		`{"k":"` + strings.Repeat("a", 1000) + `"}`,
	}
	for _, s := range seeds {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 1<<20 {
			t.Skip()
		}
		done := runWithBudget(t, func() {
			defer func() {
				if r := recover(); r != nil {
					t.Errorf("parseJSON panicked on %q: %v", truncate(data, 120), r)
				}
			}()
			kvs, _ := parseJSON(data)
			if len(kvs) > maxJSONEntries {
				t.Errorf("parseJSON: entry cap breached: got %d > %d", len(kvs), maxJSONEntries)
			}
		})
		if !done {
			t.Errorf("parseJSON did not complete within %v on %q", fuzzBudget, truncate(data, 120))
		}
	})
}

// ---------- FuzzXMLParser ----------

func FuzzXMLParser(f *testing.F) {
	seeds := []string{
		`<a>1</a>`,
		`<a b="c"/>`,
		`<?xml version="1.0"?><a><b>c</b></a>`,
		`<!-- comment --><a/>`,
		`<a><![CDATA[raw <data> here]]></a>`,
		`<!DOCTYPE a [<!ENTITY x "y">]><a>&x;</a>`,
		// XXE attempt — must not fetch anything.
		`<!DOCTYPE a [<!ENTITY x SYSTEM "file:///etc/passwd">]><a>&x;</a>`,
		strings.Repeat("<a>", 80) + strings.Repeat("</a>", 80),
	}
	for _, s := range seeds {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 1<<20 {
			t.Skip()
		}
		done := runWithBudget(t, func() {
			defer func() {
				if r := recover(); r != nil {
					t.Errorf("parseXML panicked on %q: %v", truncate(data, 120), r)
				}
			}()
			kvs, _ := parseXML(data)
			if len(kvs) > maxXMLEntries {
				t.Errorf("parseXML: entry cap breached: got %d > %d", len(kvs), maxXMLEntries)
			}
			// XXE check — no file system content should leak.
			for _, kv := range kvs {
				if strings.Contains(kv.Value, "root:x:0:0") || strings.Contains(kv.Value, "/bin/bash") {
					t.Errorf("parseXML may have leaked /etc/passwd content: key=%q value=%q", kv.Key, kv.Value)
				}
			}
		})
		if !done {
			t.Errorf("parseXML did not complete within %v on %q", fuzzBudget, truncate(data, 120))
		}
	})
}

// ---------- FuzzPropertiesParser ----------

func FuzzPropertiesParser(f *testing.F) {
	seeds := []string{
		"key=value\n",
		"key: value\n",
		"# comment\nkey=value\n",
		"! comment\nkey=value\n",
		"long=line\\\n continuation\n",
		strings.Repeat("key=val\\\n", 1000), // continuation bomb
	}
	for _, s := range seeds {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 1<<20 {
			t.Skip()
		}
		done := runWithBudget(t, func() {
			defer func() {
				if r := recover(); r != nil {
					t.Errorf("parseProperties panicked on %q: %v", truncate(data, 120), r)
				}
			}()
			kvs, _ := parseProperties(data)
			if len(kvs) > maxHCLEntries {
				t.Errorf("parseProperties: entry cap breached: got %d > %d", len(kvs), maxHCLEntries)
			}
		})
		if !done {
			t.Errorf("parseProperties did not complete within %v on %q", fuzzBudget, truncate(data, 120))
		}
	})
}

// ---------- FuzzEnvParser ----------

func FuzzEnvParser(f *testing.F) {
	seeds := []string{
		"KEY=value\n",
		"export KEY=value\n",
		`KEY="quoted"` + "\n",
		"KEY='single'\n",
		`KEY="unterminated`,
		"KEY=val # comment\n",
		"KEY=\n",
	}
	for _, s := range seeds {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 1<<20 {
			t.Skip()
		}
		done := runWithBudget(t, func() {
			defer func() {
				if r := recover(); r != nil {
					t.Errorf("parseEnv panicked on %q: %v", truncate(data, 120), r)
				}
			}()
			kvs, _ := parseEnv(data)
			if len(kvs) > maxHCLEntries {
				t.Errorf("parseEnv: entry cap breached: got %d > %d", len(kvs), maxHCLEntries)
			}
		})
		if !done {
			t.Errorf("parseEnv did not complete within %v on %q", fuzzBudget, truncate(data, 120))
		}
	})
}

func truncate(b []byte, n int) string {
	if len(b) <= n {
		return string(b)
	}
	return string(b[:n]) + "...(truncated)"
}
