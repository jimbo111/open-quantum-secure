package constresolver

import (
	"testing"
)

func TestPythonParser_Extensions(t *testing.T) {
	p := &PythonParser{}
	exts := p.Extensions()
	if len(exts) != 1 || exts[0] != ".py" {
		t.Errorf("expected [.py], got %v", exts)
	}
}

func TestPythonParser_ParseFile(t *testing.T) {
	tests := []struct {
		name     string
		path     string
		content  string
		wantKeys map[string]int
		wantNone []string
	}{
		{
			name: "simple module-level constant",
			path: "crypto.py",
			content: `KEY_SIZE = 256`,
			wantKeys: map[string]int{
				"crypto.KEY_SIZE": 256,
			},
		},
		{
			name: "multiple constants",
			path: "constants.py",
			content: `KEY_SIZE = 256
BLOCK_SIZE = 128
MAX_ROUNDS = 10`,
			wantKeys: map[string]int{
				"constants.KEY_SIZE":   256,
				"constants.BLOCK_SIZE": 128,
				"constants.MAX_ROUNDS": 10,
			},
		},
		{
			name: "indented lines are skipped (inside function)",
			path: "funcs.py",
			content: `KEY_SIZE = 256
def my_func():
    INNER = 999
    key_size = 128`,
			wantKeys: map[string]int{
				"funcs.KEY_SIZE": 256,
			},
			wantNone: []string{"funcs.INNER", "funcs.key_size"},
		},
		{
			name: "indented with tab is skipped",
			path: "tabs.py",
			content: "KEY_BITS = 512\n\tTABBED = 999",
			wantKeys: map[string]int{
				"tabs.KEY_BITS": 512,
			},
			wantNone: []string{"tabs.TABBED"},
		},
		{
			name: "lowercase names are skipped",
			path: "lower.py",
			content: `key_size = 256
KEY_SIZE = 512`,
			wantKeys: map[string]int{
				"lower.KEY_SIZE": 512,
			},
			wantNone: []string{"lower.key_size"},
		},
		{
			name: "mixed case is skipped (must start uppercase)",
			path: "mixed.py",
			content: `KeySize = 256
KEY_SIZE = 512`,
			wantKeys: map[string]int{
				"mixed.KEY_SIZE": 512,
			},
			wantNone: []string{"mixed.KeySize"},
		},
		{
			name: "comments and blank lines are safe",
			path: "commented.py",
			content: `# This is a comment
KEY_SIZE = 256

# Another comment
BLOCK_SIZE = 128`,
			wantKeys: map[string]int{
				"commented.KEY_SIZE":   256,
				"commented.BLOCK_SIZE": 128,
			},
		},
		{
			name: "zero value constant",
			path: "zero.py",
			content: `NONE = 0`,
			wantKeys: map[string]int{
				"zero.NONE": 0,
			},
		},
		{
			name: "no matches",
			path: "empty.py",
			content: `# Just a comment
def foo():
    pass`,
			wantKeys: map[string]int{},
		},
		{
			name: "module name derived from path",
			path: "/some/long/path/my_module.py",
			content: `KEY_SIZE = 256`,
			wantKeys: map[string]int{
				"my_module.KEY_SIZE": 256,
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			p := &PythonParser{}
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
