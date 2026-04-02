package constresolver

import (
	"testing"
)

func TestJavaParser_Extensions(t *testing.T) {
	p := &JavaParser{}
	exts := p.Extensions()
	if len(exts) != 1 || exts[0] != ".java" {
		t.Errorf("expected [.java], got %v", exts)
	}
}

func TestJavaParser_ParseFile(t *testing.T) {
	tests := []struct {
		name     string
		path     string
		content  string
		wantKeys map[string]int
		wantNone []string
	}{
		{
			name: "public static final int",
			path: "Crypto.java",
			content: `public class Crypto {
    public static final int KEY_SIZE = 256;
    public static final int BLOCK_SIZE = 128;
}`,
			wantKeys: map[string]int{
				"Crypto.KEY_SIZE":   256,
				"Crypto.BLOCK_SIZE": 128,
			},
		},
		{
			name: "package-private static final int",
			path: "Constants.java",
			content: `class Constants {
    static final int MAX_BITS = 4096;
}`,
			wantKeys: map[string]int{
				"Constants.MAX_BITS": 4096,
			},
		},
		{
			name: "class name from declaration wins over filename",
			path: "WrongName.java",
			content: `public class RightName {
    public static final int VALUE = 42;
}`,
			wantKeys: map[string]int{
				"RightName.VALUE": 42,
			},
			wantNone: []string{"WrongName.VALUE"},
		},
		{
			name: "fallback to filename when no class declaration",
			path: "MyFile.java",
			content: `// Just a constants file
public static final int MAGIC = 99;`,
			wantKeys: map[string]int{
				"MyFile.MAGIC": 99,
			},
		},
		{
			name: "private and protected modifiers",
			path: "Access.java",
			content: `public class Access {
    private static final int PRIV = 1;
    protected static final int PROT = 2;
}`,
			wantKeys: map[string]int{
				"Access.PRIV": 1,
				"Access.PROT": 2,
			},
		},
		{
			name: "no matches",
			path: "Empty.java",
			content: `public class Empty {
    public String name = "hello";
}`,
			wantKeys: map[string]int{},
		},
		{
			name: "non-integer static finals are ignored",
			path: "Mixed.java",
			content: `public class Mixed {
    public static final String ALG = "AES";
    public static final int KEY_SIZE = 256;
    public static final boolean ENABLED = true;
}`,
			wantKeys: map[string]int{
				"Mixed.KEY_SIZE": 256,
			},
			wantNone: []string{"Mixed.ALG", "Mixed.ENABLED"},
		},
		{
			name: "zero value",
			path: "Zero.java",
			content: `public class Zero {
    public static final int NONE = 0;
}`,
			wantKeys: map[string]int{
				"Zero.NONE": 0,
			},
		},
		{
			name: "nested class uses simple outer class name",
			path: "Outer.java",
			content: `public class Outer {
    public static final int OUTER_KEY = 128;
    static class Inner {
        public static final int INNER_KEY = 256;
    }
}`,
			wantKeys: map[string]int{
				"Outer.OUTER_KEY": 128,
				"Outer.INNER_KEY": 256,
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			p := &JavaParser{}
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
