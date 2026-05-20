package main

import (
	"strings"
	"testing"
)

// TestValidateEngineNames_KnownPasses asserts validation accepts any known
// engine name (matching the orchestrator's e.Name() canonical form).
func TestValidateEngineNames_KnownPasses(t *testing.T) {
	known := []string{"cipherscope", "cryptoscan", "astgrep", "tls-probe", "binary-scanner"}
	cases := [][]string{
		{},
		{"cipherscope"},
		{"cipherscope", "cryptoscan"},
		{"tls-probe"},
		{"binary-scanner", "astgrep", "cryptoscan"},
	}
	for _, names := range cases {
		if err := validateEngineNames(known, names); err != nil {
			t.Errorf("validateEngineNames(%v) returned error: %v", names, err)
		}
	}
}

// TestValidateEngineNames_TypoRejected asserts a typo'd engine name yields
// a clear error that includes the bad name AND the valid set. Without this
// check, the orchestrator silently filters to zero engines and the scan
// fails with the misleading "no scanner engines found" message.
func TestValidateEngineNames_TypoRejected(t *testing.T) {
	known := []string{"cipherscope", "cryptoscan", "tls-probe"}
	cases := []struct {
		name  string
		names []string
		want  string // substring expected in error
	}{
		{"single typo", []string{"cipherscop"}, "cipherscop"},
		{"mixed valid + typo", []string{"cipherscope", "cypto-scan"}, "cypto-scan"},
		{"two typos", []string{"foo", "bar"}, "foo, bar"},
		{"case-sensitive — Cipherscope != cipherscope", []string{"Cipherscope"}, "Cipherscope"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := validateEngineNames(known, tc.names)
			if err == nil {
				t.Fatalf("validateEngineNames(%v) returned nil, want error", tc.names)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error %q does not contain %q", err.Error(), tc.want)
			}
			// Sanity: the error should also list the available set.
			if !strings.Contains(err.Error(), "cipherscope") {
				t.Errorf("error should list available engines, got %q", err.Error())
			}
		})
	}
}

// TestValidateEngineNames_EmptyIsNoop confirms that an empty --engine list
// (the default) does not error — orchestrator interprets this as "use all".
func TestValidateEngineNames_EmptyIsNoop(t *testing.T) {
	if err := validateEngineNames([]string{"cipherscope"}, nil); err != nil {
		t.Errorf("nil names: %v", err)
	}
	if err := validateEngineNames([]string{"cipherscope"}, []string{}); err != nil {
		t.Errorf("empty slice: %v", err)
	}
}
