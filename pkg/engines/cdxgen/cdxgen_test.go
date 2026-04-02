package cdxgen

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/jimbo111/open-quantum-secure/pkg/engines"
	"github.com/jimbo111/open-quantum-secure/pkg/findings"
)

// --- normalize tests ---

func TestNormalize(t *testing.T) {
	tests := []struct {
		name        string
		component   rawComponent
		targetPath  string
		wantLibrary string
		wantRawID   string
		wantFile    string
		wantLine    int
		wantConf    findings.Confidence
		wantEngine  string
	}{
		{
			name: "npm library with purl",
			component: rawComponent{
				Type:    "library",
				Name:    "lodash",
				Version: "4.17.21",
				PURL:    "pkg:npm/lodash@4.17.21",
			},
			targetPath:  "/src",
			wantLibrary: "lodash",
			wantRawID:   "pkg:npm/lodash@4.17.21",
			wantFile:    "/src/package.json",
			wantLine:    0,
			wantConf:    findings.ConfidenceLow,
			wantEngine:  "cdxgen",
		},
		{
			name: "maven library with purl",
			component: rawComponent{
				Type:    "library",
				Name:    "spring-core",
				Version: "5.3.0",
				PURL:    "pkg:maven/org.springframework/spring-core@5.3.0",
			},
			targetPath:  "/java-app",
			wantLibrary: "spring-core",
			wantRawID:   "pkg:maven/org.springframework/spring-core@5.3.0",
			wantFile:    "/java-app/pom.xml",
			wantLine:    0,
			wantConf:    findings.ConfidenceLow,
			wantEngine:  "cdxgen",
		},
		{
			name: "go module with purl",
			component: rawComponent{
				Type:    "library",
				Name:    "rsa",
				Version: "v0.0.0",
				PURL:    "pkg:golang/crypto/rsa@v0.0.0",
			},
			targetPath:  "/go-app",
			wantLibrary: "rsa",
			wantRawID:   "pkg:golang/crypto/rsa@v0.0.0",
			wantFile:    "/go-app/go.mod",
			wantLine:    0,
			wantConf:    findings.ConfidenceLow,
			wantEngine:  "cdxgen",
		},
		{
			name: "library without purl uses name@version",
			component: rawComponent{
				Type:    "library",
				Name:    "openssl",
				Version: "3.0.0",
				PURL:    "",
			},
			targetPath:  "/c-app",
			wantLibrary: "openssl",
			wantRawID:   "openssl@3.0.0",
			wantFile:    "/c-app",
			wantLine:    0,
			wantConf:    findings.ConfidenceLow,
			wantEngine:  "cdxgen",
		},
		{
			name: "library without purl and without version uses name only",
			component: rawComponent{
				Type: "library",
				Name: "somelib",
			},
			targetPath:  "/app",
			wantLibrary: "somelib",
			wantRawID:   "somelib",
			wantFile:    "/app",
			wantLine:    0,
			wantConf:    findings.ConfidenceLow,
			wantEngine:  "cdxgen",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			uf := normalize(tc.component, tc.targetPath)

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
			if uf.RawIdentifier != tc.wantRawID {
				t.Errorf("RawIdentifier: got %q, want %q", uf.RawIdentifier, tc.wantRawID)
			}
			if uf.Reachable != findings.ReachableUnknown {
				t.Errorf("Reachable: got %q, want %q", uf.Reachable, findings.ReachableUnknown)
			}
			if uf.Dependency == nil {
				t.Fatal("Dependency: got nil, want non-nil")
			}
			if uf.Dependency.Library != tc.wantLibrary {
				t.Errorf("Dependency.Library: got %q, want %q", uf.Dependency.Library, tc.wantLibrary)
			}
		})
	}
}

func TestNormalize_WithGroup(t *testing.T) {
	tests := []struct {
		name        string
		component   rawComponent
		wantLibrary string
	}{
		{
			name: "group and name joined with colon",
			component: rawComponent{
				Type:    "library",
				Name:    "lodash",
				Group:   "com.example",
				Version: "4.17.21",
				PURL:    "pkg:npm/lodash@4.17.21",
			},
			wantLibrary: "com.example:lodash",
		},
		{
			name: "empty group uses name only",
			component: rawComponent{
				Type:    "library",
				Name:    "lodash",
				Group:   "",
				Version: "4.17.21",
				PURL:    "pkg:npm/lodash@4.17.21",
			},
			wantLibrary: "lodash",
		},
		{
			name: "maven-style group:artifact",
			component: rawComponent{
				Type:    "library",
				Name:    "spring-core",
				Group:   "org.springframework",
				Version: "5.3.0",
				PURL:    "pkg:maven/org.springframework/spring-core@5.3.0",
			},
			wantLibrary: "org.springframework:spring-core",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			uf := normalize(tc.component, "/tmp")
			if uf.Dependency == nil {
				t.Fatal("Dependency: got nil, want non-nil")
			}
			if uf.Dependency.Library != tc.wantLibrary {
				t.Errorf("Dependency.Library: got %q, want %q", uf.Dependency.Library, tc.wantLibrary)
			}
		})
	}
}

func TestNormalize_WithCryptoProperties(t *testing.T) {
	tests := []struct {
		name      string
		component rawComponent
		wantAlg   string
		hasAlg    bool
	}{
		{
			name: "crypto property extracts algorithm",
			component: rawComponent{
				Type:    "library",
				Name:    "lodash",
				Version: "4.17.21",
				PURL:    "pkg:npm/lodash@4.17.21",
				Properties: []rawProperty{
					{Name: "cdx:crypto:algorithmRef", Value: "AES-256"},
				},
			},
			wantAlg: "AES-256",
			hasAlg:  true,
		},
		{
			name: "first crypto property wins",
			component: rawComponent{
				Type:    "library",
				Name:    "lib",
				Version: "1.0.0",
				Properties: []rawProperty{
					{Name: "cdx:crypto:algorithmRef", Value: "RSA-2048"},
					{Name: "cdx:crypto:mode", Value: "CBC"},
				},
			},
			wantAlg: "RSA-2048",
			hasAlg:  true,
		},
		{
			name: "non-crypto property is ignored",
			component: rawComponent{
				Type:    "library",
				Name:    "lib",
				Version: "1.0.0",
				Properties: []rawProperty{
					{Name: "cdx:general:tag", Value: "something"},
				},
			},
			hasAlg: false,
		},
		{
			name: "no properties means no algorithm",
			component: rawComponent{
				Type:    "library",
				Name:    "lib",
				Version: "1.0.0",
			},
			hasAlg: false,
		},
		{
			name: "crypto property with empty value is skipped",
			component: rawComponent{
				Type:    "library",
				Name:    "lib",
				Version: "1.0.0",
				Properties: []rawProperty{
					{Name: "cdx:crypto:algorithmRef", Value: ""},
				},
			},
			hasAlg: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			uf := normalize(tc.component, "/tmp")
			if tc.hasAlg {
				if uf.Algorithm == nil {
					t.Fatalf("Algorithm: got nil, want %q", tc.wantAlg)
				}
				if uf.Algorithm.Name != tc.wantAlg {
					t.Errorf("Algorithm.Name: got %q, want %q", uf.Algorithm.Name, tc.wantAlg)
				}
			} else {
				if uf.Algorithm != nil {
					t.Errorf("Algorithm: got %+v, want nil", uf.Algorithm)
				}
			}
		})
	}
}

func TestNormalize_EmptyComponents(t *testing.T) {
	result := normalizeAll([]rawComponent{}, "/src")
	if len(result) != 0 {
		t.Errorf("normalizeAll(empty): got %d findings, want 0", len(result))
	}
}

func TestNormalize_NonLibrarySkipped(t *testing.T) {
	components := []rawComponent{
		{Type: "framework", Name: "spring", Version: "5.0"},
		{Type: "library", Name: "lodash", Version: "4.0", PURL: "pkg:npm/lodash@4.0"},
		{Type: "application", Name: "myapp", Version: "1.0"},
		{Type: "container", Name: "mycontainer", Version: "latest"},
		{Type: "device", Name: "mydevice", Version: "1.0"},
	}

	result := normalizeAll(components, "/src")
	if len(result) != 1 {
		t.Errorf("normalizeAll: got %d findings, want 1 (only library type)", len(result))
	}
	if result[0].Dependency.Library != "lodash" {
		t.Errorf("wrong library: got %q, want %q", result[0].Dependency.Library, "lodash")
	}
}

// --- binary discovery tests ---

func TestFindBinary_NotFound(t *testing.T) {
	e := &Engine{}
	result := e.findBinary([]string{"/nonexistent/path/that/does/not/exist"})
	// We only verify the function doesn't panic.
	// If cdxgen happens to be on PATH, result will be non-empty; that's acceptable.
	_ = result
}

func TestAvailableFalseWhenNoBinary(t *testing.T) {
	e := &Engine{binaryPath: ""}
	if e.Available() {
		t.Error("Available() should return false when binaryPath is empty")
	}
}

func TestFindBinary_ExtraDir(t *testing.T) {
	// Create a fake executable in a temp dir.
	dir := t.TempDir()
	binPath := filepath.Join(dir, "cdxgen")
	if err := os.WriteFile(binPath, []byte("#!/bin/sh\necho cdxgen"), 0755); err != nil {
		t.Fatalf("write fake binary: %v", err)
	}

	e := &Engine{}
	got := e.findBinary([]string{dir})
	if got != binPath {
		t.Errorf("findBinary: got %q, want %q", got, binPath)
	}
}

func TestFindBinary_ExtraDirNotExecutable(t *testing.T) {
	dir := t.TempDir()
	binPath := filepath.Join(dir, "cdxgen")
	// Write file without execute bit.
	if err := os.WriteFile(binPath, []byte("#!/bin/sh"), 0644); err != nil {
		t.Fatalf("write non-executable: %v", err)
	}

	e := &Engine{}
	got := e.findBinary([]string{dir})
	// Should NOT return the non-executable file.
	if got == binPath {
		t.Errorf("findBinary: returned non-executable file %q", got)
	}
}

// --- engine metadata tests ---

func TestEngineMetadata(t *testing.T) {
	e := &Engine{}

	if e.Name() != "cdxgen" {
		t.Errorf("Name(): got %q, want %q", e.Name(), "cdxgen")
	}
	if e.Tier() != engines.Tier3Formal {
		t.Errorf("Tier(): got %d, want %d", e.Tier(), engines.Tier3Formal)
	}

	langs := e.SupportedLanguages()
	if len(langs) == 0 {
		t.Error("SupportedLanguages() returned empty slice")
	}

	langSet := make(map[string]bool, len(langs))
	for _, l := range langs {
		langSet[l] = true
	}

	required := []string{
		"javascript", "typescript", "java", "python", "go",
		"ruby", "rust", "dotnet", "php", "swift", "kotlin",
		"scala", "cpp", "c",
	}
	for _, lang := range required {
		if !langSet[lang] {
			t.Errorf("SupportedLanguages() missing %q", lang)
		}
	}
}

// --- full JSON parsing test ---

func TestParseOutput(t *testing.T) {
	bomJSON := `{
		"bomFormat": "CycloneDX",
		"specVersion": "1.5",
		"components": [
			{
				"type": "library",
				"name": "lodash",
				"version": "4.17.21",
				"purl": "pkg:npm/lodash@4.17.21",
				"group": "com.example",
				"description": "A modern JavaScript utility library",
				"properties": [
					{"name": "cdx:crypto:algorithmRef", "value": "AES-256"}
				]
			},
			{
				"type": "library",
				"name": "spring-core",
				"version": "5.3.0",
				"purl": "pkg:maven/org.springframework/spring-core@5.3.0",
				"group": "org.springframework"
			},
			{
				"type": "framework",
				"name": "angular",
				"version": "15.0.0",
				"purl": "pkg:npm/angular@15.0.0"
			}
		]
	}`

	var bom rawBOM
	if err := json.Unmarshal([]byte(bomJSON), &bom); err != nil {
		t.Fatalf("json.Unmarshal: %v", err)
	}

	result := normalizeAll(bom.Components, "/project")

	// Only 2 library-type components should be emitted (framework is skipped).
	if len(result) != 2 {
		t.Fatalf("got %d findings, want 2", len(result))
	}

	// First component: lodash with group and crypto property.
	lodash := result[0]
	if lodash.Dependency == nil {
		t.Fatal("result[0] Dependency: got nil")
	}
	if lodash.Dependency.Library != "com.example:lodash" {
		t.Errorf("result[0] Library: got %q, want %q", lodash.Dependency.Library, "com.example:lodash")
	}
	if lodash.RawIdentifier != "pkg:npm/lodash@4.17.21" {
		t.Errorf("result[0] RawIdentifier: got %q, want %q", lodash.RawIdentifier, "pkg:npm/lodash@4.17.21")
	}
	if lodash.Location.File != filepath.Join("/project", "package.json") {
		t.Errorf("result[0] File: got %q, want %q", lodash.Location.File, filepath.Join("/project", "package.json"))
	}
	if lodash.Algorithm == nil {
		t.Fatal("result[0] Algorithm: got nil, want AES-256")
	}
	if lodash.Algorithm.Name != "AES-256" {
		t.Errorf("result[0] Algorithm.Name: got %q, want %q", lodash.Algorithm.Name, "AES-256")
	}
	if lodash.Confidence != findings.ConfidenceLow {
		t.Errorf("result[0] Confidence: got %q, want %q", lodash.Confidence, findings.ConfidenceLow)
	}
	if lodash.SourceEngine != "cdxgen" {
		t.Errorf("result[0] SourceEngine: got %q, want %q", lodash.SourceEngine, "cdxgen")
	}
	if lodash.Reachable != findings.ReachableUnknown {
		t.Errorf("result[0] Reachable: got %q, want %q", lodash.Reachable, findings.ReachableUnknown)
	}
	if lodash.Location.Line != 0 {
		t.Errorf("result[0] Line: got %d, want 0", lodash.Location.Line)
	}

	// Second component: spring-core with group, no crypto properties.
	spring := result[1]
	if spring.Dependency == nil {
		t.Fatal("result[1] Dependency: got nil")
	}
	if spring.Dependency.Library != "org.springframework:spring-core" {
		t.Errorf("result[1] Library: got %q, want %q", spring.Dependency.Library, "org.springframework:spring-core")
	}
	if spring.Algorithm != nil {
		t.Errorf("result[1] Algorithm: got %+v, want nil", spring.Algorithm)
	}
	if spring.Location.File != filepath.Join("/project", "pom.xml") {
		t.Errorf("result[1] File: got %q, want %q", spring.Location.File, filepath.Join("/project", "pom.xml"))
	}
}

// --- manifestFile helper tests ---

func TestManifestFile(t *testing.T) {
	tests := []struct {
		purl     string
		wantBase string // basename of the returned path
	}{
		{"pkg:npm/lodash@4.0", "package.json"},
		{"pkg:maven/org.springframework/spring@5.0", "pom.xml"},
		{"pkg:golang/crypto/rsa@v0.0.0", "go.mod"},
		{"pkg:pypi/requests@2.0", "requirements.txt"},
		{"pkg:gem/rails@7.0", "Gemfile"},
		{"pkg:cargo/tokio@1.0", "Cargo.toml"},
		{"pkg:nuget/Newtonsoft.Json@13.0", ""},
		{"pkg:composer/laravel/laravel@9.0", "composer.json"},
		{"pkg:swift/apple/swift-crypto@2.0", "Package.swift"},
		{"pkg:unknown/lib@1.0", ""},
	}

	const target = "/myapp"

	for _, tc := range tests {
		t.Run(tc.purl, func(t *testing.T) {
			got := manifestFile(target, tc.purl)
			base := filepath.Base(got)
			if tc.wantBase == "" {
				// Unknown purl or nuget → should return the target path unchanged.
				if got != target {
					t.Errorf("manifestFile(%q): got %q, want target %q", tc.purl, got, target)
				}
				return
			}
			if base != tc.wantBase {
				t.Errorf("manifestFile(%q): got basename %q, want %q", tc.purl, base, tc.wantBase)
			}
		})
	}
}

// --- edge case tests added by deep review ---

func TestNormalize_CryptoPropertyPrefixMatch(t *testing.T) {
	// Only "cdx:crypto:" prefix should match, not arbitrary "crypto" substring
	c := rawComponent{
		Type:    "library",
		Name:    "lib",
		Version: "1.0",
		PURL:    "pkg:npm/lib@1.0",
		Properties: []rawProperty{
			{Name: "cdx:general:cryptoExempt", Value: "true"},
			{Name: "internal:noncrypto:tag", Value: "ECDSA"},
			{Name: "cdx:crypto:algorithmRef", Value: "AES-256-GCM"},
		},
	}
	uf := normalize(c, "/tmp")
	if uf.Algorithm == nil {
		t.Fatal("expected Algorithm to be set from cdx:crypto: property")
	}
	if uf.Algorithm.Name != "AES-256-GCM" {
		t.Errorf("Algorithm.Name: got %q, want %q", uf.Algorithm.Name, "AES-256-GCM")
	}
}

func TestNormalize_NoCryptoPropertyWithBroadMatch(t *testing.T) {
	c := rawComponent{
		Type:    "library",
		Name:    "lib",
		Version: "1.0",
		PURL:    "pkg:npm/lib@1.0",
		Properties: []rawProperty{
			{Name: "internal:cryptocurrency:tag", Value: "BTC"},
		},
	}
	uf := normalize(c, "/tmp")
	if uf.Algorithm != nil {
		t.Errorf("expected nil Algorithm, got %+v", uf.Algorithm)
	}
}

func TestScan_NotAvailable(t *testing.T) {
	e := &Engine{binaryPath: ""}
	_, err := e.Scan(nil, engines.ScanOptions{TargetPath: "/tmp"})
	if err == nil {
		t.Fatal("expected error when engine is not available")
	}
}
