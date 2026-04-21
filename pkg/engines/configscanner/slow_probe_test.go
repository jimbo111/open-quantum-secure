package configscanner

// Diagnostic probes for parser performance on adversarial inputs.
// These are intentionally short, bounded tests — NOT part of the fuzz harness.
// They exist to verify that known-bad patterns (alias bombs, deep XML, etc.)
// complete within a reasonable wall clock, or reveal which parsers hang.

import (
	"strings"
	"testing"
	"time"
)

const slowThreshold = 3 * time.Second

func runOrFailSlow(t *testing.T, name string, fn func()) {
	t.Helper()
	done := make(chan struct{})
	start := time.Now()
	go func() {
		defer close(done)
		defer func() { _ = recover() }()
		fn()
	}()
	select {
	case <-done:
		if d := time.Since(start); d > slowThreshold {
			t.Errorf("%s: SLOW (%.2fs > %v threshold) — possible DoS vector",
				name, d.Seconds(), slowThreshold)
		}
	case <-time.After(slowThreshold):
		t.Errorf("%s: TIMEOUT — did not complete within %v (probable DoS)", name, slowThreshold)
	}
}

// TestSlowProbe_YAMLAliasBomb_Resolved verifies the alias-bomb guard in
// flattenYAMLNode prevents the classic billion-laughs style expansion.
func TestSlowProbe_YAMLAliasBomb_Resolved(t *testing.T) {
	payload := `a: &a ["lol","lol","lol","lol","lol","lol","lol","lol","lol"]
b: &b [*a,*a,*a,*a,*a,*a,*a,*a,*a]
c: &c [*b,*b,*b,*b,*b,*b,*b,*b,*b]
d: &d [*c,*c,*c,*c,*c,*c,*c,*c,*c]
e: &e [*d,*d,*d,*d,*d,*d,*d,*d,*d]
f: &f [*e,*e,*e,*e,*e,*e,*e,*e,*e]
g: &g [*f,*f,*f,*f,*f,*f,*f,*f,*f]
h: [*g,*g,*g,*g,*g,*g,*g,*g,*g]
`
	runOrFailSlow(t, "YAMLAliasBomb", func() {
		kvs, _ := parseYAML([]byte(payload))
		if len(kvs) > maxYAMLEntries {
			t.Errorf("entry cap breached: %d", len(kvs))
		}
	})
}

// TestSlowProbe_HCLDeeplyNestedBraces exercises the HCL recursion guard with
// 1000-level nesting.
func TestSlowProbe_HCLDeeplyNestedBraces(t *testing.T) {
	var b strings.Builder
	for i := 0; i < 1000; i++ {
		b.WriteString("a {\n")
	}
	for i := 0; i < 1000; i++ {
		b.WriteString("}\n")
	}
	runOrFailSlow(t, "HCLNested1000", func() {
		_, _ = parseHCL([]byte(b.String()))
	})
}

// TestSlowProbe_INIContinuationBomb stresses the INI continuation logic.
func TestSlowProbe_INIContinuationBomb(t *testing.T) {
	input := strings.Repeat("k=\\\n", 100_000) + "done\n"
	runOrFailSlow(t, "INIContinuationBomb", func() {
		_, _ = parseINI([]byte(input))
	})
}

// TestSlowProbe_PropertiesContinuationBomb stresses properties continuation.
func TestSlowProbe_PropertiesContinuationBomb(t *testing.T) {
	input := strings.Repeat("k=\\\n", 100_000) + "done\n"
	runOrFailSlow(t, "PropertiesContinuationBomb", func() {
		_, _ = parseProperties([]byte(input))
	})
}

// TestSlowProbe_XMLDeepNesting stresses the XML depth guard.
func TestSlowProbe_XMLDeepNesting(t *testing.T) {
	var b strings.Builder
	for i := 0; i < 1000; i++ {
		b.WriteString("<a>")
	}
	b.WriteString("x")
	for i := 0; i < 1000; i++ {
		b.WriteString("</a>")
	}
	runOrFailSlow(t, "XMLDeep1000", func() {
		_, _ = parseXML([]byte(b.String()))
	})
}

// TestSlowProbe_JSONDeepNesting stresses the JSON depth guard.
func TestSlowProbe_JSONDeepNesting(t *testing.T) {
	var b strings.Builder
	for i := 0; i < 1000; i++ {
		b.WriteString(`{"a":`)
	}
	b.WriteString("1")
	for i := 0; i < 1000; i++ {
		b.WriteString("}")
	}
	runOrFailSlow(t, "JSONDeep1000", func() {
		_, _ = parseJSON([]byte(b.String()))
	})
}
