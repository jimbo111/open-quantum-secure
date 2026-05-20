package astgrep

import (
	"bytes"
	"os"
	"strings"
	"testing"
)

// TestFlattenRulesArray covers the wrapper-format → multi-doc transform that
// makes embedded rules consumable by ast-grep's `-r` flag (which accepts a
// single rule per file or multi-doc YAML, but rejects directories with
// `Is a directory (os error 21)`).
func TestFlattenRulesArray_WrapperFormat(t *testing.T) {
	in := []byte(`rules:
  - id: rule-one
    language: go
    rule:
      pattern: foo($X)
    message: m1
    severity: warning

  - id: rule-two
    language: python
    rule:
      pattern: bar($Y)
    message: m2
    severity: error
`)
	docs, err := flattenRulesArray(in)
	if err != nil {
		t.Fatalf("flattenRulesArray: %v", err)
	}
	if len(docs) != 2 {
		t.Fatalf("expected 2 flattened docs, got %d", len(docs))
	}
	for i, want := range []string{"rule-one", "rule-two"} {
		if !strings.Contains(string(docs[i]), "id: "+want) {
			t.Errorf("doc[%d] missing 'id: %s'\n--- doc ---\n%s", i, want, docs[i])
		}
	}
}

// Bare single-rule files (the ast-grep-native format used in external rules
// dirs) must pass through unchanged so users keeping their own rule libraries
// don't lose any field that yaml round-trips might silently drop.
func TestFlattenRulesArray_PassThrough(t *testing.T) {
	in := []byte(`id: solo
language: go
rule:
  pattern: x
message: m
severity: info
`)
	docs, err := flattenRulesArray(in)
	if err != nil {
		t.Fatalf("flattenRulesArray: %v", err)
	}
	if len(docs) != 1 {
		t.Fatalf("expected 1 doc, got %d", len(docs))
	}
	if !bytes.Equal(docs[0], in) {
		t.Errorf("pass-through doc must be byte-identical\n--- got ---\n%s\n--- want ---\n%s", docs[0], in)
	}
}

// TestConcatEmbeddedRules ends in a real, parseable multi-doc file with one
// `id:` per embedded rule. This is the integration check that ast-grep would
// accept the output via `-r tmpfile`.
func TestConcatEmbeddedRules_ProducesMultiDocFile(t *testing.T) {
	path, cleanup, err := concatEmbeddedRules()
	if err != nil {
		t.Fatalf("concatEmbeddedRules: %v", err)
	}
	defer cleanup()

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read produced rules file: %v", err)
	}
	if len(data) == 0 {
		t.Fatal("produced rules file is empty")
	}
	// Multi-doc YAML separator must be present (>1 rule means >=1 separator).
	if !bytes.Contains(data, []byte("\n---\n")) {
		t.Error("expected `---` separator between flattened rule docs")
	}
	// Every flattened doc starts with `id:` at the document root.
	idCount := bytes.Count(data, []byte("id: "))
	if idCount < 4 {
		t.Errorf("expected at least 4 flattened rules across embedded files, got id-line count %d", idCount)
	}
}
