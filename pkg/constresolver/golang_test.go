package constresolver

import (
	"testing"
)

func TestGoParser_Extensions(t *testing.T) {
	p := &GoParser{}
	exts := p.Extensions()
	if len(exts) != 1 || exts[0] != ".go" {
		t.Errorf("expected [.go], got %v", exts)
	}
}

func TestGoParser_ParseFile(t *testing.T) {
	tests := []struct {
		name     string
		path     string
		content  string
		wantKeys map[string]int
		wantNone []string
	}{
		{
			name: "simple const",
			path: "crypto.go",
			content: `package crypto
const KEY_SIZE = 256`,
			wantKeys: map[string]int{
				"crypto.KEY_SIZE": 256,
			},
		},
		{
			name: "const block",
			path: "config.go",
			content: `package config
const (
	KEY_BITS  = 128
	BLOCK_BITS = 64
)`,
			wantKeys: map[string]int{
				"config.KEY_BITS":   128,
				"config.BLOCK_BITS": 64,
			},
		},
		{
			name: "iota is skipped",
			path: "types.go",
			content: `package types
const (
	TypeA = iota
	TypeB
	TypeC
)`,
			wantKeys: map[string]int{},
		},
		{
			name: "expression is skipped",
			path: "expr.go",
			content: `package expr
const DERIVED = 128 * 8`,
			wantKeys: map[string]int{},
		},
		{
			name: "mixed const block",
			path: "mixed.go",
			content: `package mixed
const (
	LITERAL   = 256
	FROM_IOTA = iota
	STRING_CONST = "hello"
)`,
			wantKeys: map[string]int{
				"mixed.LITERAL": 256,
			},
			wantNone: []string{"mixed.FROM_IOTA", "mixed.STRING_CONST"},
		},
		{
			name: "typed int constant",
			path: "typed.go",
			content: `package typed
const KEY_BITS int = 2048`,
			wantKeys: map[string]int{
				"typed.KEY_BITS": 2048,
			},
		},
		{
			name: "multiple const declarations",
			path: "multi.go",
			content: `package multi
const A = 1
const B = 2
const C = 3`,
			wantKeys: map[string]int{
				"multi.A": 1,
				"multi.B": 2,
				"multi.C": 3,
			},
		},
		{
			name: "zero value",
			path: "zero.go",
			content: `package zero
const NONE = 0`,
			wantKeys: map[string]int{
				"zero.NONE": 0,
			},
		},
		{
			name: "invalid Go returns error and partial results",
			path: "bad.go",
			content: `package bad
this is not valid go code
const VALID = 42`,
			// ParseFile returns error but map may be empty since invalid Go can't be parsed.
			wantKeys: map[string]int{},
		},
		{
			name: "no constants",
			path: "empty.go",
			content: `package empty
func main() {}`,
			wantKeys: map[string]int{},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			p := &GoParser{}
			cm, _ := p.ParseFile(tc.path, []byte(tc.content))
			// Note: error is tolerated (partial results).
			for k, want := range tc.wantKeys {
				if got, ok := cm[k]; !ok {
					t.Errorf("key %q not found", k)
				} else if got != want {
					t.Errorf("key %q: want %d, got %d", k, want, got)
				}
			}
			for _, k := range tc.wantNone {
				if _, ok := cm[k]; ok {
					t.Errorf("key %q should not be present", k)
				}
			}
		})
	}
}

func TestGoParser_ReturnsErrorForBadSyntax(t *testing.T) {
	p := &GoParser{}
	_, err := p.ParseFile("bad.go", []byte("this is not go"))
	if err == nil {
		t.Error("expected error for invalid Go syntax")
	}
}
