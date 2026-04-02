package constresolver

import (
	"testing"
)

func TestCppParser_Extensions(t *testing.T) {
	p := &CppParser{}
	exts := p.Extensions()
	want := []string{".c", ".cpp", ".cc", ".cxx", ".h", ".hpp", ".hxx"}
	if len(exts) != len(want) {
		t.Fatalf("Extensions() = %v, want %v", exts, want)
	}
	for i, e := range want {
		if exts[i] != e {
			t.Errorf("Extensions()[%d] = %q, want %q", i, exts[i], e)
		}
	}
}

func TestCppParser_ParseFile(t *testing.T) {
	tests := []struct {
		name     string
		path     string
		content  string
		wantKeys map[string]int
		wantNone []string
	}{
		// --- #define macros ---
		{
			name:    "define decimal",
			path:    "crypto.h",
			content: `#define KEY_SIZE 2048`,
			wantKeys: map[string]int{
				"KEY_SIZE": 2048,
			},
		},
		{
			name:    "define hex",
			path:    "crypto.h",
			content: `#define AES_BLOCK 0x10`,
			wantKeys: map[string]int{
				"AES_BLOCK": 16,
			},
		},
		{
			name:    "define octal",
			path:    "crypto.h",
			content: `#define OCTAL_VAL 0777`,
			wantKeys: map[string]int{
				"OCTAL_VAL": 511,
			},
		},
		{
			name:    "define binary",
			path:    "crypto.h",
			content: `#define BIN_VAL 0b10000000`,
			wantKeys: map[string]int{
				"BIN_VAL": 128,
			},
		},
		{
			name:    "define binary uppercase B",
			path:    "crypto.h",
			content: `#define BIN_VAL2 0B10000000`,
			wantKeys: map[string]int{
				"BIN_VAL2": 128,
			},
		},
		{
			name:    "define zero",
			path:    "crypto.h",
			content: `#define NONE 0`,
			wantKeys: map[string]int{
				"NONE": 0,
			},
		},
		{
			name: "multiple defines",
			path: "keys.h",
			content: `#define RSA_BITS 4096
#define AES_BITS 256
#define DES_BITS 56`,
			wantKeys: map[string]int{
				"RSA_BITS": 4096,
				"AES_BITS": 256,
				"DES_BITS": 56,
			},
		},
		// --- Skip cases for #define ---
		{
			name:     "skip function-like macro",
			path:     "macro.h",
			content:  `#define FOO(x) (x*2)`,
			wantKeys: map[string]int{},
			wantNone: []string{"FOO"},
		},
		{
			name: "skip multiline define",
			path: "macro.h",
			content: `#define MULTI_LINE \
    some_value`,
			wantKeys: map[string]int{},
			wantNone: []string{"MULTI_LINE"},
		},
		{
			name:     "skip computed expression",
			path:     "macro.h",
			content:  `#define COMPUTED (2*1024)`,
			wantKeys: map[string]int{},
			wantNone: []string{"COMPUTED"},
		},
		{
			name:     "skip string define",
			path:     "macro.h",
			content:  `#define STRING "hello"`,
			wantKeys: map[string]int{},
			wantNone: []string{"STRING"},
		},
		{
			name:     "skip define with expression (addition)",
			path:     "macro.h",
			content:  `#define EXPR 256 + 128`,
			wantKeys: map[string]int{},
			wantNone: []string{"EXPR"},
		},
		// --- const declarations ---
		{
			name:    "const int",
			path:    "crypto.cpp",
			content: `const int AES_KEY_LENGTH = 256;`,
			wantKeys: map[string]int{
				"AES_KEY_LENGTH": 256,
			},
		},
		{
			name:    "const unsigned int",
			path:    "crypto.cpp",
			content: `const unsigned int RSA_BITS = 4096;`,
			wantKeys: map[string]int{
				"RSA_BITS": 4096,
			},
		},
		{
			name:    "static const int",
			path:    "crypto.cpp",
			content: `static const int KEY_SIZE = 128;`,
			wantKeys: map[string]int{
				"KEY_SIZE": 128,
			},
		},
		{
			name:    "const size_t",
			path:    "crypto.cpp",
			content: `const size_t BLOCK_SIZE = 16;`,
			wantKeys: map[string]int{
				"BLOCK_SIZE": 16,
			},
		},
		{
			name:    "const long",
			path:    "crypto.cpp",
			content: `const long MAX_SIZE = 65536;`,
			wantKeys: map[string]int{
				"MAX_SIZE": 65536,
			},
		},
		// --- constexpr declarations ---
		{
			name:    "constexpr int",
			path:    "crypto.hpp",
			content: `constexpr int KEY_LEN = 256;`,
			wantKeys: map[string]int{
				"KEY_LEN": 256,
			},
		},
		{
			name:    "constexpr unsigned",
			path:    "crypto.hpp",
			content: `constexpr unsigned RSA_BITS = 4096;`,
			wantKeys: map[string]int{
				"RSA_BITS": 4096,
			},
		},
		{
			name:    "static constexpr size_t",
			path:    "crypto.hpp",
			content: `static constexpr size_t BLOCK = 0x10;`,
			wantKeys: map[string]int{
				"BLOCK": 16,
			},
		},
		{
			name:    "constexpr unsigned int",
			path:    "crypto.hpp",
			content: `constexpr unsigned int HASH_BITS = 512;`,
			wantKeys: map[string]int{
				"HASH_BITS": 512,
			},
		},
		// --- enum values ---
		{
			name: "anonymous enum with explicit values",
			path: "keys.h",
			content: `enum { KEY_128 = 128, KEY_256 = 256 };`,
			wantKeys: map[string]int{
				"KEY_128": 128,
				"KEY_256": 256,
			},
		},
		{
			name: "named enum with explicit values",
			path: "keys.h",
			content: `enum KeySize { SMALL = 128, LARGE = 256 };`,
			wantKeys: map[string]int{
				"SMALL": 128,
				"LARGE": 256,
			},
		},
		{
			name: "enum with mixed explicit and implicit values",
			path: "keys.h",
			content: `enum Mode { NONE, CBC = 1, GCM = 2 };`,
			wantKeys: map[string]int{
				"CBC": 1,
				"GCM": 2,
			},
			// NONE has no explicit assignment, so it is skipped.
			wantNone: []string{"NONE"},
		},
		{
			name: "enum with hex values",
			path: "keys.h",
			content: `enum Flags { FLAG_A = 0x01, FLAG_B = 0x02 };`,
			wantKeys: map[string]int{
				"FLAG_A": 1,
				"FLAG_B": 2,
			},
		},
		// --- C++ digit separators ---
		{
			name:    "define with digit separator",
			path:    "crypto.h",
			content: `#define KEY_BITS 2'048`,
			wantKeys: map[string]int{
				"KEY_BITS": 2048,
			},
		},
		{
			name:    "constexpr with digit separator",
			path:    "crypto.hpp",
			content: `constexpr int LARGE = 1'000'000;`,
			wantKeys: map[string]int{
				"LARGE": 1000000,
			},
		},
		// --- Mixed file ---
		{
			name: "mixed file with all patterns",
			path: "all_patterns.hpp",
			content: `#pragma once

// Key sizes for cryptographic algorithms
#define RSA_KEY_BITS 2048
#define AES_KEY_BITS 0x100
#define DH_PARAM 0777

static const int HASH_SIZE = 256;
constexpr int SIGN_BITS = 512;

enum KeyStrength {
    WEAK   = 64,
    MEDIUM = 128,
    STRONG = 256,
};

// Function-like macros are skipped
#define ALIGN(x) ((x + 3) & ~3)

// Multiline macros are skipped
#define MULTI \
    123
`,
			wantKeys: map[string]int{
				"RSA_KEY_BITS": 2048,
				"AES_KEY_BITS": 256,
				"DH_PARAM":     511,
				"HASH_SIZE":    256,
				"SIGN_BITS":    512,
				"WEAK":         64,
				"MEDIUM":       128,
				"STRONG":       256,
			},
			wantNone: []string{"ALIGN", "MULTI"},
		},
		// --- Edge cases ---
		{
			name:     "empty file",
			path:     "empty.h",
			content:  ``,
			wantKeys: map[string]int{},
		},
		{
			name: "C++ namespace — extracts unqualified name",
			path: "ns.hpp",
			content: `namespace crypto {
    constexpr int KEY_SIZE = 256;
}`,
			wantKeys: map[string]int{
				"KEY_SIZE": 256,
			},
		},
		{
			name: "define with leading whitespace (indented in #if block)",
			path: "platform.h",
			content: `#ifdef PLATFORM
    #define PLATFORM_BITS 64
#endif`,
			wantKeys: map[string]int{
				"PLATFORM_BITS": 64,
			},
		},
		{
			name:    "define hex uppercase",
			path:    "crypto.h",
			content: `#define MASK 0xFF`,
			wantKeys: map[string]int{
				"MASK": 255,
			},
		},
		// --- Phase 9 review fixes ---
		{
			name: "enum class (C++11 scoped enum)",
			path: "scoped.hpp",
			content: `enum class KeySize {
    SMALL = 128,
    MEDIUM = 256,
    LARGE = 512,
};`,
			wantKeys: map[string]int{
				"SMALL":  128,
				"MEDIUM": 256,
				"LARGE":  512,
			},
		},
		{
			name: "enum struct (C++11 scoped enum)",
			path: "scoped2.hpp",
			content: `enum struct CipherMode {
    CBC = 1,
    GCM = 2,
};`,
			wantKeys: map[string]int{
				"CBC": 1,
				"GCM": 2,
			},
		},
		{
			name: "enum with base type",
			path: "based.hpp",
			content: `enum Algo : uint8_t {
    ALG_A = 10,
    ALG_B = 20,
};`,
			wantKeys: map[string]int{
				"ALG_A": 10,
				"ALG_B": 20,
			},
		},
		{
			name: "enum class with base type",
			path: "scoped_based.hpp",
			content: `enum class Strength : int {
    WEAK = 64,
    STRONG = 256,
};`,
			wantKeys: map[string]int{
				"WEAK":   64,
				"STRONG": 256,
			},
		},
		{
			name: "define with integer suffix L",
			path: "suffix.h",
			content: `#define KEY_SIZE 2048L
#define BLOCK_SIZE 128UL
#define BIG_VAL 4096ULL
#define UNSIGNED_MASK 0xFFu`,
			wantKeys: map[string]int{
				"KEY_SIZE":      2048,
				"BLOCK_SIZE":    128,
				"BIG_VAL":       4096,
				"UNSIGNED_MASK": 255,
			},
		},
		{
			name: "const with integer suffix",
			path: "const_suffix.cpp",
			content: `const int KEY_BITS = 2048L;
constexpr long long BIG = 4096LL;`,
			wantKeys: map[string]int{
				"KEY_BITS": 2048,
				"BIG":      4096,
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			p := &CppParser{}
			cm, err := p.ParseFile(tc.path, []byte(tc.content))
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			for k, want := range tc.wantKeys {
				if got, ok := cm[k]; !ok {
					t.Errorf("key %q not found in %v", k, cm)
				} else if got != want {
					t.Errorf("key %q: want %d, got %d", k, want, got)
				}
			}
			for _, k := range tc.wantNone {
				if _, ok := cm[k]; ok {
					t.Errorf("key %q should not be present, got %v", k, cm)
				}
			}
		})
	}
}

func TestCppParser_StripDigitSeparators(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"2'048", "2048"},
		{"1'000'000", "1000000"},
		{"0xFF", "0xFF"},
		{"0b1010'1010", "0b10101010"},
		{"256", "256"},
	}
	for _, tc := range tests {
		got := stripDigitSeparators(tc.input)
		if got != tc.want {
			t.Errorf("stripDigitSeparators(%q) = %q, want %q", tc.input, got, tc.want)
		}
	}
}

func TestCppParser_ParseCppInt(t *testing.T) {
	tests := []struct {
		input   string
		want    int64
		wantErr bool
	}{
		{"256", 256, false},
		{"0x100", 256, false},
		{"0xFF", 255, false},
		{"0777", 511, false},
		{"0b10000000", 128, false},
		{"0B10000000", 128, false},
		{"4096", 4096, false},
		{"0", 0, false},
		{"abc", 0, true},
		{"", 0, true},
	}
	for _, tc := range tests {
		got, err := parseCppInt(tc.input)
		if tc.wantErr {
			if err == nil {
				t.Errorf("parseCppInt(%q): expected error, got %d", tc.input, got)
			}
		} else {
			if err != nil {
				t.Errorf("parseCppInt(%q): unexpected error: %v", tc.input, err)
			} else if got != tc.want {
				t.Errorf("parseCppInt(%q) = %d, want %d", tc.input, got, tc.want)
			}
		}
	}
}
