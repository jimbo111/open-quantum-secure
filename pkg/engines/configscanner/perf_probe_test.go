package configscanner

// Performance probes for crafted inputs that trip slow paths in parsers.
// Each test records wall clock; >1s is flagged as a concern.
//
// These are NOT fuzz tests — they run as normal unit tests and are cheap.

import (
	"strings"
	"testing"
	"time"
)

// TestPerf_YAMLLargeSequence parses a flat 10k-element sequence.
// yaml.v3's DocumentNode reuse of the Node tree is O(n) — this should be fast.
func TestPerf_YAMLLargeSequence(t *testing.T) {
	var b strings.Builder
	b.WriteString("items:\n")
	for i := 0; i < 10000; i++ {
		b.WriteString("  - item\n")
	}
	start := time.Now()
	kvs, _ := parseYAML([]byte(b.String()))
	d := time.Since(start)
	t.Logf("parsed %d entries in %v", len(kvs), d)
	if d > 2*time.Second {
		t.Errorf("YAML large sequence took %v (>2s)", d)
	}
}

// TestPerf_TOMLLargeTable parses a flat 10k-key table.
func TestPerf_TOMLLargeTable(t *testing.T) {
	var b strings.Builder
	for i := 0; i < 10000; i++ {
		if i < 26*26 {
			// Generate unique 2-char keys.
			k := string(rune('a'+i/26)) + string(rune('a'+i%26))
			b.WriteString(k)
		} else {
			b.WriteString("k")
			b.WriteString(strings.Repeat("a", i%10+1))
			b.WriteString(strings.Repeat("b", i/676))
		}
		b.WriteString(" = \"v\"\n")
	}
	start := time.Now()
	kvs, err := parseTOML([]byte(b.String()))
	d := time.Since(start)
	t.Logf("parsed %d entries in %v (err=%v)", len(kvs), d, err)
	if d > 2*time.Second {
		t.Errorf("TOML large table took %v (>2s)", d)
	}
}

// TestPerf_JSONLongString parses a JSON object with a single very long string.
func TestPerf_JSONLongString(t *testing.T) {
	v := strings.Repeat("x", 1_000_000)
	input := []byte(`{"k":"` + v + `"}`)
	start := time.Now()
	_, err := parseJSON(input)
	d := time.Since(start)
	t.Logf("parsed %d-byte JSON string in %v (err=%v)", len(input), d, err)
	if d > 2*time.Second {
		t.Errorf("JSON long string took %v (>2s)", d)
	}
}

// TestPerf_INIManyContinuations stresses the INI continuation consumption loop.
func TestPerf_INIManyContinuations(t *testing.T) {
	input := strings.Repeat("k=x\\\n", 10000) + "last\n"
	start := time.Now()
	_, _ = parseINI([]byte(input))
	d := time.Since(start)
	t.Logf("INI continuation bomb parsed in %v", d)
	if d > 2*time.Second {
		t.Errorf("INI continuation took %v (>2s)", d)
	}
}
