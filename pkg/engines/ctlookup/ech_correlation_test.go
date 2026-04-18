// ech_correlation_test.go — Matrix tests for ExtractECHHostnames and the
// hostnameFromFile path parser. Exercises all documented input shapes to ensure
// the ECH → CT-lookup hostname extraction pipeline is complete and correct.
package ctlookup

import (
	"reflect"
	"sort"
	"testing"

	"github.com/jimbo111/open-quantum-secure/pkg/findings"
)

// ── hostnameFromFile ──────────────────────────────────────────────────────────

func TestHostnameFromFile_Matrix(t *testing.T) {
	cases := []struct {
		file string
		want string
	}{
		// Standard tls-probe path.
		{"(tls-probe)/example.com:443#kex", "example.com"},
		// Port-less host (SplitHostPort fails, returns file as-is after stripping fragment).
		{"(tls-probe)/bare.host#vol", "bare.host"},
		// IPv4 target.
		{"(tls-probe)/1.2.3.4:443#vol", "1.2.3.4"},
		// IPv6 literal target — brackets stripped by SplitHostPort.
		{"(tls-probe)/[::1]:443#kex", "::1"},
		// No engine prefix.
		{"host.com:443#kex", "host.com"},
		// No port, no fragment.
		{"bare.host.only", "bare.host.only"},
		// Empty string.
		{"", ""},
		// Fragment only.
		{"#fragment", ""},
		// ct-lookup prefix (shouldn't happen in practice but must not panic).
		{"(ct-lookup)/host.com:443#cert", "host.com"},
		// Multiple slashes — only first slash stripped.
		{"(tls-probe)//double.host:443#x", "/double.host"},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.file, func(t *testing.T) {
			got := hostnameFromFile(tc.file)
			if got != tc.want {
				t.Errorf("hostnameFromFile(%q) = %q, want %q", tc.file, got, tc.want)
			}
		})
	}
}

// ── ExtractECHHostnames ───────────────────────────────────────────────────────

func echFinding(file string) findings.UnifiedFinding {
	return findings.UnifiedFinding{
		Location:               findings.Location{File: file},
		PartialInventory:       true,
		PartialInventoryReason: "ECH_ENABLED",
		SourceEngine:           "tls-probe",
	}
}

func nonECHFinding(file string) findings.UnifiedFinding {
	return findings.UnifiedFinding{
		Location:     findings.Location{File: file},
		SourceEngine: "tls-probe",
	}
}

// TestExtractECHHostnames_EmptyInput expects nil output for an empty findings slice.
func TestExtractECHHostnames_EmptyInput(t *testing.T) {
	hosts := ExtractECHHostnames(nil)
	if len(hosts) != 0 {
		t.Errorf("empty input: expected 0 hosts, got %v", hosts)
	}

	hosts = ExtractECHHostnames([]findings.UnifiedFinding{})
	if len(hosts) != 0 {
		t.Errorf("empty slice: expected 0 hosts, got %v", hosts)
	}
}

// TestExtractECHHostnames_AllNonECH expects no hosts extracted from findings
// that have no ECH annotation.
func TestExtractECHHostnames_AllNonECH(t *testing.T) {
	ff := []findings.UnifiedFinding{
		nonECHFinding("(tls-probe)/a.com:443#kex"),
		nonECHFinding("(tls-probe)/b.com:443#vol"),
		{
			Location:               findings.Location{File: "(tls-probe)/c.com:443#kex"},
			PartialInventory:       false,        // explicit false
			PartialInventoryReason: "ECH_ENABLED", // reason set but flag false
		},
	}
	hosts := ExtractECHHostnames(ff)
	if len(hosts) != 0 {
		t.Errorf("all non-ECH: expected 0 hosts, got %v", hosts)
	}
}

// TestExtractECHHostnames_AllECH expects all unique hostnames from ECH findings.
func TestExtractECHHostnames_AllECH(t *testing.T) {
	ff := []findings.UnifiedFinding{
		echFinding("(tls-probe)/alpha.com:443#kex"),
		echFinding("(tls-probe)/beta.com:443#vol"),
		echFinding("(tls-probe)/gamma.com:443#kex"),
	}
	hosts := ExtractECHHostnames(ff)
	want := []string{"alpha.com", "beta.com", "gamma.com"}
	sort.Strings(hosts)
	sort.Strings(want)
	if !reflect.DeepEqual(hosts, want) {
		t.Errorf("all ECH: got %v, want %v", hosts, want)
	}
}

// TestExtractECHHostnames_Mixed expects only ECH-annotated findings extracted.
func TestExtractECHHostnames_Mixed(t *testing.T) {
	ff := []findings.UnifiedFinding{
		nonECHFinding("(tls-probe)/plain.com:443#kex"),
		echFinding("(tls-probe)/ech.com:443#kex"),
		nonECHFinding("(tls-probe)/also-plain.com:443#vol"),
		echFinding("(tls-probe)/ech2.com:443#vol"),
	}
	hosts := ExtractECHHostnames(ff)
	want := []string{"ech.com", "ech2.com"}
	sort.Strings(hosts)
	sort.Strings(want)
	if !reflect.DeepEqual(hosts, want) {
		t.Errorf("mixed: got %v, want %v", hosts, want)
	}
}

// TestExtractECHHostnames_DuplicateHostnames verifies that the same hostname
// appearing in multiple ECH findings is deduplicated to a single entry.
func TestExtractECHHostnames_DuplicateHostnames(t *testing.T) {
	ff := []findings.UnifiedFinding{
		echFinding("(tls-probe)/dup.com:443#kex"),
		echFinding("(tls-probe)/dup.com:443#vol"),
		echFinding("(tls-probe)/dup.com:443#cert"),
	}
	hosts := ExtractECHHostnames(ff)
	if len(hosts) != 1 {
		t.Errorf("duplicate dedup: expected 1 host, got %d: %v", len(hosts), hosts)
	}
	if hosts[0] != "dup.com" {
		t.Errorf("duplicate dedup: got %q, want dup.com", hosts[0])
	}
}

// TestExtractECHHostnames_PortSuffix verifies port stripping.
func TestExtractECHHostnames_PortSuffix(t *testing.T) {
	ff := []findings.UnifiedFinding{
		echFinding("(tls-probe)/host.com:443#kex"),
	}
	hosts := ExtractECHHostnames(ff)
	if len(hosts) != 1 || hosts[0] != "host.com" {
		t.Errorf("port suffix: got %v, want [host.com]", hosts)
	}
}

// TestExtractECHHostnames_IPv4Target verifies IPv4 addresses are extracted.
func TestExtractECHHostnames_IPv4Target(t *testing.T) {
	ff := []findings.UnifiedFinding{
		echFinding("(tls-probe)/192.0.2.1:443#kex"),
	}
	hosts := ExtractECHHostnames(ff)
	if len(hosts) != 1 || hosts[0] != "192.0.2.1" {
		t.Errorf("IPv4: got %v, want [192.0.2.1]", hosts)
	}
}

// TestExtractECHHostnames_IPv6Target verifies IPv6 bracket-stripping.
func TestExtractECHHostnames_IPv6Target(t *testing.T) {
	ff := []findings.UnifiedFinding{
		echFinding("(tls-probe)/[::1]:443#kex"),
	}
	hosts := ExtractECHHostnames(ff)
	if len(hosts) != 1 || hosts[0] != "::1" {
		t.Errorf("IPv6: got %v, want [::1]", hosts)
	}
}

// TestExtractECHHostnames_EmptyTargetString verifies that a finding with an
// empty Location.File is skipped gracefully (produces no hostname entry).
func TestExtractECHHostnames_EmptyTargetString(t *testing.T) {
	ff := []findings.UnifiedFinding{
		{
			Location:               findings.Location{File: ""},
			PartialInventory:       true,
			PartialInventoryReason: "ECH_ENABLED",
		},
	}
	hosts := ExtractECHHostnames(ff)
	if len(hosts) != 0 {
		t.Errorf("empty target: expected 0 hosts, got %v", hosts)
	}
}

// TestExtractECHHostnames_WrongReason verifies that PartialInventory=true with
// a non-ECH reason is ignored.
func TestExtractECHHostnames_WrongReason(t *testing.T) {
	ff := []findings.UnifiedFinding{
		{
			Location:               findings.Location{File: "(tls-probe)/host.com:443#kex"},
			PartialInventory:       true,
			PartialInventoryReason: "SOME_OTHER_REASON",
		},
	}
	hosts := ExtractECHHostnames(ff)
	if len(hosts) != 0 {
		t.Errorf("wrong reason: expected 0 hosts, got %v", hosts)
	}
}
