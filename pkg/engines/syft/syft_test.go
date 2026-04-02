package syft

import (
	"testing"

	"github.com/jimbo111/open-quantum-secure/pkg/engines"
	"github.com/jimbo111/open-quantum-secure/pkg/findings"
)

// --- normalize tests ---

func TestNormalize(t *testing.T) {
	tests := []struct {
		name       string
		component  rawComponent
		targetPath string
		wantLib    string
		wantFile   string
		wantLine   int
		wantConf   findings.Confidence
		wantEngine string
		wantRaw    string
	}{
		{
			name: "library component without purl",
			component: rawComponent{
				Type:    "library",
				Name:    "openssl",
				Version: "3.0.13",
			},
			targetPath: "/tmp/target",
			wantLib:    "openssl",
			wantFile:   "/tmp/target",
			wantLine:   0,
			wantConf:   findings.ConfidenceLow,
			wantEngine: "syft",
			wantRaw:    "openssl@3.0.13",
		},
		{
			name: "library component with version only",
			component: rawComponent{
				Type:    "library",
				Name:    "zlib",
				Version: "1.2.11",
			},
			targetPath: "/repo",
			wantLib:    "zlib",
			wantFile:   "/repo",
			wantLine:   0,
			wantConf:   findings.ConfidenceLow,
			wantEngine: "syft",
			wantRaw:    "zlib@1.2.11",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			bom := rawBOM{
				BOMFormat:  "CycloneDX",
				Components: []rawComponent{tc.component},
			}
			result := normalize(bom, tc.targetPath)

			if len(result) != 1 {
				t.Fatalf("normalize: got %d findings, want 1", len(result))
			}
			uf := result[0]

			if uf.Dependency == nil {
				t.Fatal("Dependency: got nil, want non-nil")
			}
			if uf.Dependency.Library != tc.wantLib {
				t.Errorf("Library: got %q, want %q", uf.Dependency.Library, tc.wantLib)
			}
			if uf.Location.File != tc.wantFile {
				t.Errorf("File: got %q, want %q", uf.Location.File, tc.wantFile)
			}
			if uf.Location.Line != tc.wantLine {
				t.Errorf("Line: got %d, want %d", uf.Location.Line, tc.wantLine)
			}
			if uf.Confidence != tc.wantConf {
				t.Errorf("Confidence: got %q, want %q", uf.Confidence, tc.wantConf)
			}
			if uf.SourceEngine != tc.wantEngine {
				t.Errorf("SourceEngine: got %q, want %q", uf.SourceEngine, tc.wantEngine)
			}
			if uf.RawIdentifier != tc.wantRaw {
				t.Errorf("RawIdentifier: got %q, want %q", uf.RawIdentifier, tc.wantRaw)
			}
			if uf.Reachable != findings.ReachableUnknown {
				t.Errorf("Reachable: got %q, want %q", uf.Reachable, findings.ReachableUnknown)
			}
		})
	}
}

func TestNormalize_WithPurl(t *testing.T) {
	purl := "pkg:deb/debian/openssl@3.0.13-1~deb12u1"
	bom := rawBOM{
		BOMFormat: "CycloneDX",
		Components: []rawComponent{
			{
				Type:    "library",
				Name:    "openssl",
				Version: "3.0.13",
				PURL:    purl,
				Properties: []rawProperty{
					{Name: "syft:package:foundBy", Value: "dpkg-db-cataloger"},
					{Name: "syft:package:type", Value: "deb"},
				},
			},
		},
	}

	result := normalize(bom, "/target")

	if len(result) != 1 {
		t.Fatalf("normalize: got %d findings, want 1", len(result))
	}
	uf := result[0]

	if uf.RawIdentifier != purl {
		t.Errorf("RawIdentifier: got %q, want purl %q", uf.RawIdentifier, purl)
	}
	// PURL "pkg:deb/debian/openssl@..." → namespace "debian" → library "debian:openssl"
	if uf.Dependency == nil || uf.Dependency.Library != "debian:openssl" {
		t.Errorf("Dependency.Library: want %q, got %v", "debian:openssl", uf.Dependency)
	}
}

func TestNormalize_EmptyComponents(t *testing.T) {
	bom := rawBOM{
		BOMFormat:  "CycloneDX",
		Components: []rawComponent{},
	}
	result := normalize(bom, "/target")
	if len(result) != 0 {
		t.Errorf("normalize: got %d findings, want 0", len(result))
	}
}

func TestNormalize_NonLibrarySkipped(t *testing.T) {
	bom := rawBOM{
		BOMFormat: "CycloneDX",
		Components: []rawComponent{
			{Type: "container", Name: "ubuntu", Version: "22.04"},
			{Type: "operating-system", Name: "debian", Version: "12"},
			{Type: "library", Name: "openssl", Version: "3.0.13"},
			{Type: "framework", Name: "spring", Version: "6.0.0"},
		},
	}

	result := normalize(bom, "/target")

	// Only the "library" type should produce a finding.
	if len(result) != 1 {
		t.Fatalf("normalize: got %d findings, want 1", len(result))
	}
	if result[0].Dependency.Library != "openssl" {
		t.Errorf("expected openssl, got %q", result[0].Dependency.Library)
	}
}

// --- binary lookup tests ---

func TestFindBinary_NotFound(t *testing.T) {
	e := &Engine{}
	result := e.findBinary([]string{"/nonexistent/path/that/does/not/exist"})
	// We only assert no panic. If syft happens to be on PATH the result is non-empty.
	_ = result
}

func TestAvailableFalseWhenNoBinary(t *testing.T) {
	e := &Engine{binaryPath: ""}
	if e.Available() {
		t.Error("Available() should return false when binaryPath is empty")
	}
}

// --- metadata tests ---

func TestEngineMetadata(t *testing.T) {
	e := &Engine{}

	if e.Name() != "syft" {
		t.Errorf("Name(): got %q, want %q", e.Name(), "syft")
	}
	if e.Tier() != engines.Tier3SCA {
		t.Errorf("Tier(): got %d, want %d (Tier3SCA)", e.Tier(), engines.Tier3SCA)
	}

	langs := e.SupportedLanguages()
	if len(langs) == 0 {
		t.Fatal("SupportedLanguages() returned empty slice")
	}

	langSet := make(map[string]bool, len(langs))
	for _, l := range langs {
		langSet[l] = true
	}
	for _, expected := range []string{"go", "java", "python", "javascript", "ruby", "rust", "dotnet", "php", "cpp", "c"} {
		if !langSet[expected] {
			t.Errorf("SupportedLanguages() missing %q", expected)
		}
	}
}

// --- full CycloneDX parsing test ---

func TestParseOutput(t *testing.T) {
	// Simulate a realistic syft CycloneDX output with multiple component types.
	bom := rawBOM{
		BOMFormat:   "CycloneDX",
		Components: []rawComponent{
			{
				Type:    "library",
				Name:    "openssl",
				Version: "3.0.13",
				PURL:    "pkg:deb/debian/openssl@3.0.13-1~deb12u1",
				Properties: []rawProperty{
					{Name: "syft:package:foundBy", Value: "dpkg-db-cataloger"},
					{Name: "syft:package:type", Value: "deb"},
				},
			},
			{
				Type:    "library",
				Name:    "libssl3",
				Version: "3.0.13",
				PURL:    "pkg:deb/debian/libssl3@3.0.13-1~deb12u1",
			},
			{
				// Should be skipped — not a library.
				Type:    "container",
				Name:    "debian",
				Version: "12",
			},
			{
				Type:    "library",
				Name:    "python3",
				Version: "3.11.2",
				PURL:    "pkg:deb/debian/python3@3.11.2-1",
			},
		},
	}

	result := normalize(bom, "/scan/target")

	if len(result) != 3 {
		t.Fatalf("ParseOutput: got %d findings, want 3", len(result))
	}

	// All findings must have SourceEngine="syft", ConfidenceLow, ReachableUnknown.
	for i, uf := range result {
		if uf.SourceEngine != "syft" {
			t.Errorf("[%d] SourceEngine: got %q, want %q", i, uf.SourceEngine, "syft")
		}
		if uf.Confidence != findings.ConfidenceLow {
			t.Errorf("[%d] Confidence: got %q, want %q", i, uf.Confidence, findings.ConfidenceLow)
		}
		if uf.Reachable != findings.ReachableUnknown {
			t.Errorf("[%d] Reachable: got %q, want %q", i, uf.Reachable, findings.ReachableUnknown)
		}
		if uf.Dependency == nil {
			t.Errorf("[%d] Dependency: got nil", i)
		}
		if uf.Location.File != "/scan/target" {
			t.Errorf("[%d] Location.File: got %q, want %q", i, uf.Location.File, "/scan/target")
		}
		if uf.Location.Line != 0 {
			t.Errorf("[%d] Location.Line: got %d, want 0", i, uf.Location.Line)
		}
	}

	// Verify purl is used as RawIdentifier when present.
	if result[0].RawIdentifier != "pkg:deb/debian/openssl@3.0.13-1~deb12u1" {
		t.Errorf("result[0] RawIdentifier: got %q, want purl", result[0].RawIdentifier)
	}
	// PURL namespace extraction: "pkg:deb/debian/openssl@..." → "debian:openssl"
	if result[0].Dependency.Library != "debian:openssl" {
		t.Errorf("result[0] Library: got %q, want %q", result[0].Dependency.Library, "debian:openssl")
	}

	if result[1].Dependency.Library != "debian:libssl3" {
		t.Errorf("result[1] Library: got %q, want %q", result[1].Dependency.Library, "debian:libssl3")
	}

	if result[2].Dependency.Library != "debian:python3" {
		t.Errorf("result[2] Library: got %q, want %q", result[2].Dependency.Library, "debian:python3")
	}
}

// --- edge case tests added by deep review ---

func TestNormalize_EmptyVersion(t *testing.T) {
	bom := rawBOM{
		BOMFormat: "CycloneDX",
		Components: []rawComponent{
			{Type: "library", Name: "openssl", Version: "", PURL: ""},
		},
	}
	result := normalize(bom, "/target")
	if len(result) != 1 {
		t.Fatalf("got %d findings, want 1", len(result))
	}
	// Empty version should NOT produce trailing "@"
	if result[0].RawIdentifier != "openssl" {
		t.Errorf("RawIdentifier: got %q, want %q (no trailing @)", result[0].RawIdentifier, "openssl")
	}
}

func TestPurlNamespace(t *testing.T) {
	tests := []struct {
		purl string
		want string
	}{
		{"pkg:maven/org.springframework/spring-core@5.3.0", "org.springframework"},
		{"pkg:deb/debian/openssl@3.0.13", "debian"},
		{"pkg:npm/lodash@4.17.21", ""},          // npm has no namespace
		{"pkg:golang/crypto/rsa@v0.0.0", "crypto"}, // go sub-packages
		{"", ""},
		{"pkg:gem/rails@7.0", ""},
	}
	for _, tc := range tests {
		t.Run(tc.purl, func(t *testing.T) {
			got := purlNamespace(tc.purl)
			if got != tc.want {
				t.Errorf("purlNamespace(%q): got %q, want %q", tc.purl, got, tc.want)
			}
		})
	}
}

func TestScan_NotAvailable(t *testing.T) {
	e := &Engine{binaryPath: ""}
	_, err := e.Scan(nil, engines.ScanOptions{TargetPath: "/tmp"})
	if err == nil {
		t.Fatal("expected error when engine is not available")
	}
	if e.Available() {
		t.Error("Available() should be false for empty binaryPath")
	}
}
