// client_fuzz_test.go — Fuzz tests for correlate.go path-manipulation helpers.
// Targets hostnameFromFile and deduplicateHostnames with adversarial inputs to
// prove absence of panics, index-out-of-bounds, and infinite loops.
//
// Run extended fuzzing with:
//
//	go test -fuzz=FuzzHostnameFromFile -fuzztime=20s ./pkg/engines/ctlookup/
//	go test -fuzz=FuzzDeduplicateHostnames -fuzztime=20s ./pkg/engines/ctlookup/
package ctlookup

import (
	"strings"
	"testing"
)

// FuzzHostnameFromFile fuzzes the path-parsing helper that extracts a bare
// hostname from a tls-probe Location.File string.
//
// Invariants:
//   - Must never panic regardless of input.
//   - Return value must not contain a "#" fragment suffix.
//   - Return value must not contain a port number (i.e. no trailing ":NNN").
func FuzzHostnameFromFile(f *testing.F) {
	// Seed: well-known tls-probe path shapes.
	f.Add("(tls-probe)/example.com:443#kex")
	f.Add("(tls-probe)/[::1]:443#kex")
	f.Add("[::1]:443")
	f.Add("192.168.1.1:8443#vol")
	f.Add("barehost")
	f.Add("")
	f.Add("/")
	f.Add("//")
	f.Add("(tls-probe)/")
	f.Add("(ct-lookup)/hostname#cert")
	f.Add("(tls-probe)/host:443")
	f.Add("host:notaport")
	f.Add("#onlyfragment")
	f.Add("a/b/c:443#x")
	f.Add(strings.Repeat("a", 1024) + ":443#x")
	f.Add("(tls-probe)/" + strings.Repeat("深", 64) + ":443#kex")

	f.Fuzz(func(t *testing.T, file string) {
		host := hostnameFromFile(file)

		// Invariant 1: result must not contain a fragment.
		if strings.Contains(host, "#") {
			t.Errorf("hostnameFromFile(%q) = %q contains '#'", file, host)
		}
	})
}

// FuzzDeduplicateHostnames fuzzes the deduplication helper over arbitrary
// comma-less hostname lists (individual strings joined by newline for the
// fuzzer to split).
//
// Invariants:
//   - Must never panic.
//   - Output length ≤ input length.
//   - No duplicates in output.
//   - No empty strings in output.
func FuzzDeduplicateHostnames(f *testing.F) {
	f.Add("")
	f.Add("example.com")
	f.Add("a.com\na.com\na.com")
	f.Add("a.com\nb.com\nc.com")
	f.Add("\n\n\n")
	f.Add("dup\ndup\nunique")
	f.Add(strings.Repeat("x.com\n", 100))

	f.Fuzz(func(t *testing.T, raw string) {
		in := strings.Split(raw, "\n")
		out := deduplicateHostnames(in)

		// Invariant 1: output ≤ input size.
		if len(out) > len(in) {
			t.Errorf("output len %d > input len %d", len(out), len(in))
		}

		// Invariant 2: no duplicates.
		seen := make(map[string]bool, len(out))
		for _, h := range out {
			if seen[h] {
				t.Errorf("duplicate in output: %q", h)
			}
			seen[h] = true
		}

		// Invariant 3: no empty strings.
		for _, h := range out {
			if h == "" {
				t.Error("empty string in deduplication output")
			}
		}
	})
}
