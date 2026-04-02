package constresolver

import (
	"testing"
)

func TestTypeScriptParser_Extensions(t *testing.T) {
	p := &TypeScriptParser{}
	exts := p.Extensions()
	if len(exts) != 2 {
		t.Fatalf("expected 2 extensions, got %v", exts)
	}
	found := map[string]bool{}
	for _, e := range exts {
		found[e] = true
	}
	if !found[".ts"] || !found[".tsx"] {
		t.Errorf("expected .ts and .tsx, got %v", exts)
	}
}

func TestTypeScriptParser_ParseFile(t *testing.T) {
	tests := []struct {
		name     string
		path     string
		content  string
		wantKeys map[string]int
		wantNone []string
	}{
		{
			name: "export const",
			path: "crypto.ts",
			content: `export const KEY_SIZE = 256;`,
			wantKeys: map[string]int{
				"crypto.KEY_SIZE": 256,
			},
		},
		{
			name: "bare const",
			path: "config.ts",
			content: `const BLOCK_SIZE = 128;`,
			wantKeys: map[string]int{
				"config.BLOCK_SIZE": 128,
			},
		},
		{
			name: "const with type annotation",
			path: "typed.ts",
			content: `export const KEY_LEN: number = 384;`,
			wantKeys: map[string]int{
				"typed.KEY_LEN": 384,
			},
		},
		{
			name: "multiple constants",
			path: "constants.ts",
			content: `export const AES_KEY_SIZE = 256;
export const RSA_KEY_SIZE = 2048;
const EC_KEY_SIZE = 384;`,
			wantKeys: map[string]int{
				"constants.AES_KEY_SIZE": 256,
				"constants.RSA_KEY_SIZE": 2048,
				"constants.EC_KEY_SIZE":  384,
			},
		},
		{
			name: "lowercase names are skipped (must be UPPER_SNAKE_CASE)",
			path: "lower.ts",
			content: `export const keySize = 256;
export const KEY_SIZE = 512;`,
			wantKeys: map[string]int{
				"lower.KEY_SIZE": 512,
			},
			wantNone: []string{"lower.keySize"},
		},
		{
			name: ".tsx extension",
			path: "component.tsx",
			content: `export const MAX_KEY_SIZE = 4096;`,
			wantKeys: map[string]int{
				"component.MAX_KEY_SIZE": 4096,
			},
		},
		{
			name: "string constants are skipped",
			path: "strings.ts",
			content: `export const ALG_NAME = "AES";
export const KEY_SIZE = 256;`,
			wantKeys: map[string]int{
				"strings.KEY_SIZE": 256,
			},
			wantNone: []string{"strings.ALG_NAME"},
		},
		{
			name: "zero value",
			path: "zero.ts",
			content: `export const NONE = 0;`,
			wantKeys: map[string]int{
				"zero.NONE": 0,
			},
		},
		{
			name: "no matches",
			path: "empty.ts",
			content: `// No constants here
function foo(): void {}`,
			wantKeys: map[string]int{},
		},
		{
			name: "module name from path",
			path: "/path/to/cryptoUtils.ts",
			content: `export const HASH_SIZE = 256;`,
			wantKeys: map[string]int{
				"cryptoUtils.HASH_SIZE": 256,
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			p := &TypeScriptParser{}
			cm, err := p.ParseFile(tc.path, []byte(tc.content))
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
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
