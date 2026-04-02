package cryptodeps

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/jimbo111/open-quantum-secure/pkg/engines"
	"github.com/jimbo111/open-quantum-secure/pkg/findings"
)

// boolPtr is a helper to create *bool values in test cases.
func boolPtr(v bool) *bool { return &v }

func TestNormalize(t *testing.T) {
	tests := []struct {
		name          string
		input         rawOutput
		wantCount     int
		wantFile      string
		wantLine      int
		wantAlg       string
		wantDepLib    string
		wantRawID     string
		wantReachable findings.Reachability
		wantEngine    string
		wantConf      findings.Confidence
	}{
		{
			name: "single dep with one RSA usage reachable",
			input: rawOutput{
				Dependencies: []rawDependency{
					{
						Name:      "golang.org/x/crypto",
						Version:   "v0.17.0",
						Ecosystem: "go",
						CryptoUsages: []rawCryptoUsage{
							{
								Algorithm:   "RSA",
								QuantumRisk: "VULNERABLE",
								Reachable:   boolPtr(true),
								File:        "vendor/golang.org/x/crypto/rsa/rsa.go",
								Line:        42,
							},
						},
					},
				},
			},
			// 1 dep finding + 1 algorithm finding = 2
			wantCount:     2,
			wantFile:      "vendor/golang.org/x/crypto/rsa/rsa.go",
			wantLine:      42,
			wantAlg:       "RSA",
			wantDepLib:    "golang.org/x/crypto",
			wantRawID:     "golang.org/x/crypto@v0.17.0",
			wantReachable: findings.ReachableYes,
			wantEngine:    "cryptodeps",
			wantConf:      findings.ConfidenceMedium,
		},
		{
			name: "dep without file falls back to targetPath",
			input: rawOutput{
				Dependencies: []rawDependency{
					{
						Name:      "org.bouncycastle:bcprov-jdk15on",
						Version:   "1.70",
						Ecosystem: "java",
						CryptoUsages: []rawCryptoUsage{
							{
								Algorithm:   "ECDH",
								QuantumRisk: "VULNERABLE",
								Reachable:   boolPtr(false),
								File:        "",
								Line:        0,
							},
						},
					},
				},
			},
			wantCount:     2,
			wantFile:      "/target", // fallback to targetPath
			wantLine:      0,
			wantAlg:       "ECDH",
			wantDepLib:    "org.bouncycastle:bcprov-jdk15on",
			wantRawID:     "org.bouncycastle:bcprov-jdk15on@1.70",
			wantReachable: findings.ReachableNo,
			wantEngine:    "cryptodeps",
			wantConf:      findings.ConfidenceMedium,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := normalize(tc.input, "/target")

			if len(result) != tc.wantCount {
				t.Fatalf("finding count: got %d, want %d", len(result), tc.wantCount)
			}

			// First finding is the dependency finding.
			depF := result[0]
			if depF.Dependency == nil {
				t.Fatal("first finding should be a dependency finding")
			}
			if depF.Dependency.Library != tc.wantDepLib {
				t.Errorf("Dependency.Library: got %q, want %q", depF.Dependency.Library, tc.wantDepLib)
			}
			if depF.RawIdentifier != tc.wantRawID {
				t.Errorf("dep RawIdentifier: got %q, want %q", depF.RawIdentifier, tc.wantRawID)
			}
			if depF.SourceEngine != tc.wantEngine {
				t.Errorf("dep SourceEngine: got %q, want %q", depF.SourceEngine, tc.wantEngine)
			}

			// Second finding is the algorithm finding.
			algF := result[1]
			if algF.Algorithm == nil {
				t.Fatal("second finding should be an algorithm finding")
			}
			if algF.Algorithm.Name != tc.wantAlg {
				t.Errorf("Algorithm.Name: got %q, want %q", algF.Algorithm.Name, tc.wantAlg)
			}
			if algF.Location.File != tc.wantFile {
				t.Errorf("Location.File: got %q, want %q", algF.Location.File, tc.wantFile)
			}
			if algF.Location.Line != tc.wantLine {
				t.Errorf("Location.Line: got %d, want %d", algF.Location.Line, tc.wantLine)
			}
			if algF.Reachable != tc.wantReachable {
				t.Errorf("Reachable: got %q, want %q", algF.Reachable, tc.wantReachable)
			}
			if algF.Confidence != tc.wantConf {
				t.Errorf("Confidence: got %q, want %q", algF.Confidence, tc.wantConf)
			}
			if algF.SourceEngine != tc.wantEngine {
				t.Errorf("SourceEngine: got %q, want %q", algF.SourceEngine, tc.wantEngine)
			}
			if algF.RawIdentifier != tc.wantAlg {
				t.Errorf("alg RawIdentifier: got %q, want %q (algorithm name)", algF.RawIdentifier, tc.wantAlg)
			}
		})
	}
}

func TestNormalize_Reachability(t *testing.T) {
	makeDep := func(r *bool) rawOutput {
		return rawOutput{
			Dependencies: []rawDependency{
				{
					Name:      "lib",
					Version:   "v1.0.0",
					Ecosystem: "go",
					CryptoUsages: []rawCryptoUsage{
						{Algorithm: "RSA", Reachable: r, File: "lib.go", Line: 1},
					},
				},
			},
		}
	}

	tests := []struct {
		name          string
		reachable     *bool
		wantReachable findings.Reachability
	}{
		{"reachable true", boolPtr(true), findings.ReachableYes},
		{"reachable false", boolPtr(false), findings.ReachableNo},
		{"reachable nil/missing", nil, findings.ReachableUnknown},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := normalize(makeDep(tc.reachable), "/target")
			// result[0] = dep finding, result[1] = algorithm finding
			if len(result) < 2 {
				t.Fatalf("expected at least 2 findings, got %d", len(result))
			}
			algF := result[1]
			if algF.Reachable != tc.wantReachable {
				t.Errorf("Reachable: got %q, want %q", algF.Reachable, tc.wantReachable)
			}
		})
	}
}

func TestNormalize_MultipleCryptoUsages(t *testing.T) {
	input := rawOutput{
		Dependencies: []rawDependency{
			{
				Name:      "golang.org/x/crypto",
				Version:   "v0.17.0",
				Ecosystem: "go",
				CryptoUsages: []rawCryptoUsage{
					{Algorithm: "RSA", Reachable: boolPtr(true), File: "rsa.go", Line: 10},
					{Algorithm: "ECDH", Reachable: boolPtr(false), File: "ecdh.go", Line: 20},
					{Algorithm: "AES-128-GCM", Reachable: nil, File: "aes.go", Line: 30},
				},
			},
		},
	}

	result := normalize(input, "/target")

	// 1 dep finding + 3 algorithm findings = 4 total
	if len(result) != 4 {
		t.Fatalf("expected 4 findings (1 dep + 3 alg), got %d", len(result))
	}

	// Verify dep finding is first.
	if result[0].Dependency == nil {
		t.Error("result[0] should be a dependency finding")
	}

	// Verify algorithm findings.
	type wantAlg struct {
		name      string
		file      string
		line      int
		reachable findings.Reachability
	}
	wantAlgs := []wantAlg{
		{"RSA", "rsa.go", 10, findings.ReachableYes},
		{"ECDH", "ecdh.go", 20, findings.ReachableNo},
		{"AES-128-GCM", "aes.go", 30, findings.ReachableUnknown},
	}

	for i, want := range wantAlgs {
		f := result[i+1]
		if f.Algorithm == nil {
			t.Fatalf("result[%d] should be an algorithm finding", i+1)
		}
		if f.Algorithm.Name != want.name {
			t.Errorf("result[%d] Algorithm.Name: got %q, want %q", i+1, f.Algorithm.Name, want.name)
		}
		if f.Location.File != want.file {
			t.Errorf("result[%d] Location.File: got %q, want %q", i+1, f.Location.File, want.file)
		}
		if f.Location.Line != want.line {
			t.Errorf("result[%d] Location.Line: got %d, want %d", i+1, f.Location.Line, want.line)
		}
		if f.Reachable != want.reachable {
			t.Errorf("result[%d] Reachable: got %q, want %q", i+1, f.Reachable, want.reachable)
		}
	}
}

func TestNormalize_EmptyDependencies(t *testing.T) {
	input := rawOutput{Dependencies: []rawDependency{}}
	result := normalize(input, "/target")
	if len(result) != 0 {
		t.Errorf("empty dependencies: got %d findings, want 0", len(result))
	}
}

func TestNormalize_NilDependencies(t *testing.T) {
	input := rawOutput{}
	result := normalize(input, "/target")
	if len(result) != 0 {
		t.Errorf("nil dependencies: got %d findings, want 0", len(result))
	}
}

func TestNormalize_MissingFields(t *testing.T) {
	// Dependency with no version and no crypto usages — should still produce a dep finding.
	input := rawOutput{
		Dependencies: []rawDependency{
			{
				Name:      "some-lib",
				Version:   "",
				Ecosystem: "",
			},
		},
	}
	result := normalize(input, "/target")

	// Only 1 dep finding; no algorithm findings since CryptoUsages is empty.
	if len(result) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(result))
	}
	if result[0].Dependency == nil {
		t.Error("expected dependency finding")
	}
	if result[0].Dependency.Library != "some-lib" {
		t.Errorf("Library: got %q, want %q", result[0].Dependency.Library, "some-lib")
	}
	if result[0].RawIdentifier != "some-lib" {
		t.Errorf("RawIdentifier: got %q, want %q", result[0].RawIdentifier, "some-lib")
	}
}

func TestNormalize_DepFindingReachability(t *testing.T) {
	// Dependency findings always have ReachableUnknown regardless of crypto usage reachability.
	input := rawOutput{
		Dependencies: []rawDependency{
			{
				Name:    "lib",
				Version: "v1.0.0",
				CryptoUsages: []rawCryptoUsage{
					{Algorithm: "RSA", Reachable: boolPtr(true), File: "lib.go", Line: 1},
				},
			},
		},
	}
	result := normalize(input, "/target")
	depF := result[0]
	if depF.Reachable != findings.ReachableUnknown {
		t.Errorf("dep finding Reachable: got %q, want %q", depF.Reachable, findings.ReachableUnknown)
	}
}

func TestReachabilityFrom(t *testing.T) {
	tests := []struct {
		name  string
		input *bool
		want  findings.Reachability
	}{
		{"nil pointer", nil, findings.ReachableUnknown},
		{"true pointer", boolPtr(true), findings.ReachableYes},
		{"false pointer", boolPtr(false), findings.ReachableNo},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := reachabilityFrom(tc.input)
			if got != tc.want {
				t.Errorf("reachabilityFrom: got %q, want %q", got, tc.want)
			}
		})
	}
}

func TestFindBinary_NotFound(t *testing.T) {
	e := &Engine{}
	result := e.findBinary([]string{"/nonexistent/path/that/does/not/exist"})
	// We can only check it does not panic; cryptodeps is unlikely on PATH in CI.
	_ = result
}

func TestAvailableFalseWhenNoBinary(t *testing.T) {
	e := &Engine{binaryPath: ""}
	if e.Available() {
		t.Error("Available() should return false when binaryPath is empty")
	}
}

func TestAvailableTrueWhenBinarySet(t *testing.T) {
	e := &Engine{binaryPath: "/usr/bin/cryptodeps"}
	if !e.Available() {
		t.Error("Available() should return true when binaryPath is set")
	}
}

func TestEngineMetadata(t *testing.T) {
	e := &Engine{}

	if e.Name() != "cryptodeps" {
		t.Errorf("Name(): got %q, want %q", e.Name(), "cryptodeps")
	}
	if e.Tier() != engines.Tier3SCA {
		t.Errorf("Tier(): got %d, want %d (Tier3SCA)", e.Tier(), engines.Tier3SCA)
	}

	langs := e.SupportedLanguages()
	if len(langs) == 0 {
		t.Error("SupportedLanguages() returned empty slice")
	}

	langSet := make(map[string]bool, len(langs))
	for _, l := range langs {
		langSet[l] = true
	}

	for _, expected := range []string{"go", "java", "python", "javascript", "rust", "ruby", "dotnet", "php"} {
		if !langSet[expected] {
			t.Errorf("SupportedLanguages() missing %q", expected)
		}
	}
}

func TestNormalize_MultipleDepsSameEngine(t *testing.T) {
	input := rawOutput{
		Dependencies: []rawDependency{
			{
				Name:    "lib-a",
				Version: "v1.0.0",
				CryptoUsages: []rawCryptoUsage{
					{Algorithm: "RSA", Reachable: boolPtr(true), File: "a.go", Line: 5},
				},
			},
			{
				Name:    "lib-b",
				Version: "v2.3.1",
				CryptoUsages: []rawCryptoUsage{
					{Algorithm: "ECDSA", Reachable: boolPtr(false), File: "b.go", Line: 12},
					{Algorithm: "SHA-256", Reachable: nil, File: "b.go", Line: 20},
				},
			},
		},
	}

	result := normalize(input, "/target")

	// lib-a: 1 dep + 1 alg = 2
	// lib-b: 1 dep + 2 alg = 3
	// total = 5
	if len(result) != 5 {
		t.Fatalf("expected 5 findings, got %d", len(result))
	}

	// Verify engine and raw IDs.
	for i, f := range result {
		if f.SourceEngine != "cryptodeps" {
			t.Errorf("result[%d] SourceEngine: got %q, want %q", i, f.SourceEngine, "cryptodeps")
		}
	}

	// result[0] = lib-a dep
	if result[0].Dependency == nil || result[0].Dependency.Library != "lib-a" {
		t.Error("result[0] should be lib-a dependency finding")
	}
	// result[1] = lib-a RSA
	if result[1].Algorithm == nil || result[1].Algorithm.Name != "RSA" {
		t.Error("result[1] should be RSA algorithm finding")
	}
	// result[2] = lib-b dep
	if result[2].Dependency == nil || result[2].Dependency.Library != "lib-b" {
		t.Error("result[2] should be lib-b dependency finding")
	}
	// result[3] = lib-b ECDSA
	if result[3].Algorithm == nil || result[3].Algorithm.Name != "ECDSA" {
		t.Error("result[3] should be ECDSA algorithm finding")
	}
	// result[4] = lib-b SHA-256
	if result[4].Algorithm == nil || result[4].Algorithm.Name != "SHA-256" {
		t.Error("result[4] should be SHA-256 algorithm finding")
	}
}

// --- edge case tests added by deep review ---

func TestNormalize_EmptyAlgorithmSkipped(t *testing.T) {
	input := rawOutput{
		Dependencies: []rawDependency{
			{
				Name:    "lib",
				Version: "v1.0.0",
				CryptoUsages: []rawCryptoUsage{
					{Algorithm: "", Reachable: boolPtr(true), File: "lib.go", Line: 1},
					{Algorithm: "RSA", Reachable: boolPtr(true), File: "rsa.go", Line: 10},
				},
			},
		},
	}
	result := normalize(input, "/target")
	// Should produce: 1 dep finding + 1 algorithm finding (empty skipped)
	if len(result) != 2 {
		t.Fatalf("expected 2 findings (empty alg skipped), got %d", len(result))
	}
	if result[1].Algorithm == nil || result[1].Algorithm.Name != "RSA" {
		t.Error("expected RSA algorithm finding after empty was skipped")
	}
}

func TestNormalize_DepLocationIsTargetPath(t *testing.T) {
	input := rawOutput{
		Dependencies: []rawDependency{
			{
				Name:    "golang.org/x/crypto",
				Version: "v0.17.0",
			},
		},
	}
	result := normalize(input, "/my/project")
	if result[0].Location.File != "/my/project" {
		t.Errorf("dep Location.File: got %q, want %q", result[0].Location.File, "/my/project")
	}
}

func TestNormalize_AlgRawIdentifierIsAlgorithmName(t *testing.T) {
	input := rawOutput{
		Dependencies: []rawDependency{
			{
				Name:    "lib",
				Version: "v1.0.0",
				CryptoUsages: []rawCryptoUsage{
					{Algorithm: "AES-256", File: "aes.go", Line: 5},
				},
			},
		},
	}
	result := normalize(input, "/target")
	algF := result[1]
	if algF.RawIdentifier != "AES-256" {
		t.Errorf("alg RawIdentifier should be algorithm name, got %q", algF.RawIdentifier)
	}
}

func TestScan_NotAvailable(t *testing.T) {
	e := &Engine{binaryPath: ""}
	_, err := e.Scan(nil, engines.ScanOptions{TargetPath: "/tmp"})
	if err == nil {
		t.Fatal("expected error when engine is not available")
	}
}

// ---------------------------------------------------------------------------
// Context cancellation propagation test
// ---------------------------------------------------------------------------

// makeSleepBinary writes a tiny shell script (or .bat on Windows) that sleeps
// for 10 seconds, giving the test enough time to cancel the context before the
// process produces any output. The binary path is returned.
func makeSleepBinary(t *testing.T) string {
	t.Helper()

	dir := t.TempDir()

	if runtime.GOOS == "windows" {
		bat := filepath.Join(dir, "cryptodeps.bat")
		if err := os.WriteFile(bat, []byte("@echo off\r\nping -n 11 127.0.0.1 >nul\r\n"), 0o755); err != nil {
			t.Fatalf("write sleep bat: %v", err)
		}
		return bat
	}

	sh := filepath.Join(dir, "cryptodeps")
	if err := os.WriteFile(sh, []byte("#!/bin/sh\nsleep 10\n"), 0o755); err != nil {
		t.Fatalf("write sleep script: %v", err)
	}
	return sh
}

// TestScan_ContextCancelledPropagates verifies that Scan returns context.Canceled
// (not a JSON parse error or nil) when the context is cancelled while the
// subprocess is running.
func TestScan_ContextCancelledPropagates(t *testing.T) {
	binary := makeSleepBinary(t)

	e := &Engine{binaryPath: binary}

	ctx, cancel := context.WithCancel(context.Background())
	// Cancel immediately so the subprocess is killed before it produces output.
	cancel()

	_, err := e.Scan(ctx, engines.ScanOptions{TargetPath: t.TempDir()})
	if err == nil {
		t.Fatal("expected error for cancelled context, got nil")
	}
	if !isContextError(err) {
		t.Errorf("expected context cancellation error, got: %v", err)
	}
}

// isContextError returns true when err (or any wrapped cause) is context.Canceled
// or context.DeadlineExceeded.
func isContextError(err error) bool {
	if err == nil {
		return false
	}
	return errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded)
}
