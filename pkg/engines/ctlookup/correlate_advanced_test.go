// correlate_advanced_test.go — Advanced tests for canonicalizeHostname,
// deduplicateHostnames edge cases, wildcard SAN paths, and IP-to-cert mapping
// scenarios. Complements ech_correlation_test.go with deeper boundary coverage.
package ctlookup

import (
	"testing"
)

// ── canonicalizeHostname ──────────────────────────────────────────────────────

func TestCanonicalizeHostname_LowercasesInput(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"EXAMPLE.COM", "example.com"},
		{"Example.COM", "example.com"},
		{"Sub.Domain.ORG", "sub.domain.org"},
		{"already.lower", "already.lower"},
	}
	for _, tc := range cases {
		got := canonicalizeHostname(tc.in)
		if got != tc.want {
			t.Errorf("canonicalizeHostname(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestCanonicalizeHostname_StripsPort(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"host.com:443", "host.com"},
		{"host.com:8443", "host.com"},
		{"host.com:0", "host.com"},
		{"host.com", "host.com"}, // no port — unchanged
	}
	for _, tc := range cases {
		got := canonicalizeHostname(tc.in)
		if got != tc.want {
			t.Errorf("canonicalizeHostname(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestCanonicalizeHostname_StripsTrailingDot(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"example.com.", "example.com"},
		{"example.com..", "example.com"}, // multiple dots stripped
		{"example.com", "example.com"},   // no trailing dot — unchanged
	}
	for _, tc := range cases {
		got := canonicalizeHostname(tc.in)
		if got != tc.want {
			t.Errorf("canonicalizeHostname(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestCanonicalizeHostname_CombinedNormalization(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"EXAMPLE.COM.:443", "example.com"},
		{"Sub.Domain.ORG.:8080", "sub.domain.org"},
	}
	for _, tc := range cases {
		got := canonicalizeHostname(tc.in)
		if got != tc.want {
			t.Errorf("canonicalizeHostname(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestCanonicalizeHostname_EmptyString(t *testing.T) {
	got := canonicalizeHostname("")
	if got != "" {
		t.Errorf("canonicalizeHostname(%q) = %q, want empty", "", got)
	}
}

// ── deduplicateHostnames — additional edge cases ──────────────────────────────

// TestDeduplicateHostnames_AllEmpty verifies that a slice of only empty strings
// produces an empty output.
func TestDeduplicateHostnames_AllEmpty(t *testing.T) {
	out := deduplicateHostnames([]string{"", "", ""})
	if len(out) != 0 {
		t.Errorf("all-empty input: expected 0, got %v", out)
	}
}

// TestDeduplicateHostnames_SingleItem verifies that a single non-empty item is
// passed through unchanged.
func TestDeduplicateHostnames_SingleItem(t *testing.T) {
	out := deduplicateHostnames([]string{"only.com"})
	if len(out) != 1 || out[0] != "only.com" {
		t.Errorf("single item: expected [only.com], got %v", out)
	}
}

// TestDeduplicateHostnames_CaseFolding verifies that "Example.COM" and
// "example.com" collapse to a single canonical entry.
func TestDeduplicateHostnames_CaseFolding(t *testing.T) {
	out := deduplicateHostnames([]string{"Example.COM", "example.com", "EXAMPLE.COM"})
	if len(out) != 1 {
		t.Errorf("case-folded dedup: expected 1, got %d: %v", len(out), out)
	}
	if out[0] != "example.com" {
		t.Errorf("case-folded dedup: expected example.com, got %q", out[0])
	}
}

// TestDeduplicateHostnames_PortStripping verifies that "host.com:443" and
// "host.com" collapse to one entry.
func TestDeduplicateHostnames_PortStripping(t *testing.T) {
	out := deduplicateHostnames([]string{"host.com:443", "host.com"})
	if len(out) != 1 {
		t.Errorf("port-stripped dedup: expected 1, got %d: %v", len(out), out)
	}
}

// TestDeduplicateHostnames_TrailingDot verifies that "example.com." and
// "example.com" collapse to one entry.
func TestDeduplicateHostnames_TrailingDot(t *testing.T) {
	out := deduplicateHostnames([]string{"example.com.", "example.com"})
	if len(out) != 1 {
		t.Errorf("trailing-dot dedup: expected 1, got %d: %v", len(out), out)
	}
}

// TestDeduplicateHostnames_OrderPreserved verifies that the first occurrence of
// each canonical hostname is kept and order is preserved.
func TestDeduplicateHostnames_OrderPreserved(t *testing.T) {
	in := []string{"alpha.com", "beta.com", "Alpha.COM", "gamma.com", "BETA.COM"}
	out := deduplicateHostnames(in)
	want := []string{"alpha.com", "beta.com", "gamma.com"}
	if len(out) != len(want) {
		t.Fatalf("order preserved: expected %v, got %v", want, out)
	}
	for i, w := range want {
		if out[i] != w {
			t.Errorf("order[%d]: expected %q, got %q", i, w, out[i])
		}
	}
}

// TestDeduplicateHostnames_MixedEmptyAndValid verifies that empty strings
// interspersed with valid hostnames are dropped but valid ones survive.
func TestDeduplicateHostnames_MixedEmptyAndValid(t *testing.T) {
	out := deduplicateHostnames([]string{"", "a.com", "", "b.com", ""})
	if len(out) != 2 {
		t.Errorf("mixed empty/valid: expected 2, got %d: %v", len(out), out)
	}
}

// ── Wildcard SAN scenarios ────────────────────────────────────────────────────

// TestHostnameFromFile_WildcardSAN verifies that a tls-probe finding for a
// wildcard SAN "*.example.com" is extracted correctly.
func TestHostnameFromFile_WildcardSAN(t *testing.T) {
	file := "(tls-probe)/*.example.com:443#kex"
	got := hostnameFromFile(file)
	want := "*.example.com"
	if got != want {
		t.Errorf("wildcard SAN: hostnameFromFile(%q) = %q, want %q", file, got, want)
	}
}

// TestHostnameFromFile_SubdomainDepth verifies that deeply-nested subdomain
// paths are extracted correctly.
func TestHostnameFromFile_SubdomainDepth(t *testing.T) {
	cases := []struct{ file, want string }{
		{"(tls-probe)/a.b.c.d.example.com:443#kex", "a.b.c.d.example.com"},
		{"(tls-probe)/a.b.c.d.example.com#vol", "a.b.c.d.example.com"},
	}
	for _, tc := range cases {
		got := hostnameFromFile(tc.file)
		if got != tc.want {
			t.Errorf("hostnameFromFile(%q) = %q, want %q", tc.file, got, tc.want)
		}
	}
}

// TestHostnameFromFile_NonStandardPort verifies that non-443 ports are stripped.
func TestHostnameFromFile_NonStandardPort(t *testing.T) {
	cases := []struct{ file, want string }{
		{"(tls-probe)/host.com:8443#kex", "host.com"},
		{"(tls-probe)/host.com:10443#kex", "host.com"},
	}
	for _, tc := range cases {
		got := hostnameFromFile(tc.file)
		if got != tc.want {
			t.Errorf("hostnameFromFile(%q) = %q, want %q", tc.file, got, tc.want)
		}
	}
}

// ── IP-to-cert mapping scenarios ─────────────────────────────────────────────

// TestHostnameFromFile_IPv4_RoundTrip verifies that an IPv4 address is
// extracted from a tls-probe path and passes through hostnameFromFile.
// (The engine will subsequently reject it via validateHostname; this test
// covers only the extraction layer.)
func TestHostnameFromFile_IPv4_RoundTrip(t *testing.T) {
	file := "(tls-probe)/203.0.113.1:443#kex"
	got := hostnameFromFile(file)
	if got != "203.0.113.1" {
		t.Errorf("IPv4 round-trip: hostnameFromFile(%q) = %q, want 203.0.113.1", file, got)
	}
}

// TestHostnameFromFile_IPv6_RoundTrip verifies that IPv6 brackets are stripped
// correctly by net.SplitHostPort.
func TestHostnameFromFile_IPv6_RoundTrip(t *testing.T) {
	file := "(tls-probe)/[2001:db8::1]:443#kex"
	got := hostnameFromFile(file)
	if got != "2001:db8::1" {
		t.Errorf("IPv6 round-trip: hostnameFromFile(%q) = %q, want 2001:db8::1", file, got)
	}
}

// TestDeduplicateHostnames_CanonicalizesIPLiterals verifies that IP literals
// are not canonicalized in a lossy way (they pass through as-is after lower).
func TestDeduplicateHostnames_IPLiteralsDedup(t *testing.T) {
	out := deduplicateHostnames([]string{"1.2.3.4", "1.2.3.4"})
	if len(out) != 1 || out[0] != "1.2.3.4" {
		t.Errorf("IP literal dedup: expected [1.2.3.4], got %v", out)
	}
}

// ── validateHostname ─────────────────────────────────────────────────────────

// TestValidateHostname_RejectsIPv4 verifies that IPv4 addresses are rejected.
func TestValidateHostname_RejectsIPv4(t *testing.T) {
	if err := validateHostname("1.2.3.4"); err == nil {
		t.Error("expected error for IPv4 literal, got nil")
	}
}

// TestValidateHostname_RejectsIPv6 verifies that IPv6 literals are rejected.
func TestValidateHostname_RejectsIPv6(t *testing.T) {
	if err := validateHostname("[::1]"); err == nil {
		t.Error("expected error for IPv6 literal, got nil")
	}
}

// TestValidateHostname_RejectsURIScheme verifies that URLs are rejected.
func TestValidateHostname_RejectsURIScheme(t *testing.T) {
	if err := validateHostname("https://example.com"); err == nil {
		t.Error("expected error for URL with scheme, got nil")
	}
}

// TestValidateHostname_RejectsEmpty verifies that empty string is rejected.
func TestValidateHostname_RejectsEmpty(t *testing.T) {
	if err := validateHostname(""); err == nil {
		t.Error("expected error for empty string, got nil")
	}
}

// TestValidateHostname_AcceptsValidHostnames verifies that valid hostnames
// (including port suffix) are accepted.
func TestValidateHostname_AcceptsValidHostnames(t *testing.T) {
	valid := []string{
		"example.com",
		"sub.example.com",
		"example.com:443",
		"a.b.c.d.example.co.uk",
		"xn--nxasmq6b.com",
		"example.com.",
	}
	for _, h := range valid {
		if err := validateHostname(h); err != nil {
			t.Errorf("validateHostname(%q) returned unexpected error: %v", h, err)
		}
	}
}

// TestValidateHostname_RejectsNewlineInjection verifies that hostnames with
// embedded newlines are rejected.
func TestValidateHostname_RejectsNewlineInjection(t *testing.T) {
	bad := []string{
		"example.com\nEvil: injected",
		"example.com\r\nInjected: header",
		"foo\x00bar.com",
	}
	for _, h := range bad {
		if err := validateHostname(h); err == nil {
			t.Errorf("validateHostname(%q): expected error for control characters, got nil", h)
		}
	}
}

// TestValidateHostname_RejectsExcessiveLength verifies that hostnames longer
// than 253 bytes are rejected.
func TestValidateHostname_RejectsExcessiveLength(t *testing.T) {
	long := ""
	for len(long) <= 253 {
		long += "a"
	}
	long += ".com"
	if err := validateHostname(long); err == nil {
		t.Error("expected error for 254+ char hostname, got nil")
	}
}
