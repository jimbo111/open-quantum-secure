package main

// compliance_all_test.go — regression test for ultrareview bug_007.
//
// Before the fix: validateComplianceFlags whitelisted "all" but nothing
// expanded it into the registered framework IDs. evaluateCompliance then
// failed post-scan with "unsupported standard \"all\"", wasting the whole
// scan on TLS/SSH probes that had already run.
//
// After: expandComplianceAll is called before validateComplianceFlags, so
// "all" becomes the current compliance.SupportedIDs() slice.

import (
	"reflect"
	"sort"
	"testing"

	"github.com/jimbo111/open-quantum-secure/pkg/compliance"
)

func TestExpandComplianceAll_ExpandsSentinel(t *testing.T) {
	expanded := expandComplianceAll([]string{"all"})
	want := compliance.SupportedIDs()
	sort.Strings(expanded)
	sort.Strings(want)
	if !reflect.DeepEqual(expanded, want) {
		t.Errorf("expandComplianceAll([\"all\"]) = %v, want %v", expanded, want)
	}
}

func TestExpandComplianceAll_NoSentinel(t *testing.T) {
	in := []string{"cnsa-2.0", "pci-dss-4.0"}
	out := expandComplianceAll(in)
	if !reflect.DeepEqual(out, in) {
		t.Errorf("expandComplianceAll(%v) = %v, want unchanged", in, out)
	}
}

func TestExpandComplianceAll_MixedDedup(t *testing.T) {
	// "all" + an explicit cnsa-2.0 → dedup to one cnsa-2.0 entry.
	out := expandComplianceAll([]string{"all", "cnsa-2.0"})
	seen := make(map[string]int, len(out))
	for _, id := range out {
		seen[id]++
	}
	if seen["cnsa-2.0"] != 1 {
		t.Errorf("cnsa-2.0 appeared %d times after dedup, want 1. Full: %v", seen["cnsa-2.0"], out)
	}
}

func TestExpandComplianceAll_EmptyAndNil(t *testing.T) {
	if out := expandComplianceAll(nil); len(out) != 0 {
		t.Errorf("expandComplianceAll(nil) = %v, want empty", out)
	}
	if out := expandComplianceAll([]string{}); len(out) != 0 {
		t.Errorf("expandComplianceAll([]) = %v, want empty", out)
	}
}

// TestValidateComplianceFlags_AllFailsWithoutExpansion asserts that the
// validator now rejects raw "all" (since expansion is meant to happen first).
// If a future refactor re-introduces the whitelist shortcut without doing
// the expansion, this test fires.
func TestValidateComplianceFlags_AllFailsWithoutExpansion(t *testing.T) {
	err := validateComplianceFlags([]string{"all"})
	if err == nil {
		t.Error("validateComplianceFlags([\"all\"]) returned nil — \"all\" must be expanded before validation, never whitelisted through")
	}
}
