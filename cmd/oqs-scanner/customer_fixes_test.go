// customer_fixes_test.go covers the customer-facing CLI fixes:
//   - exit-code contract (0 clean / 1 policy violation / 2 scan failure)
//   - up-front --path validation on scan and diff
//   - missing-engine transparency note
//   - grouped compliance violation console rendering

package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jimbo111/open-quantum-secure/pkg/compliance"
	"github.com/jimbo111/open-quantum-secure/pkg/engines"
	"github.com/jimbo111/open-quantum-secure/pkg/findings"
)

// --- Exit-code contract -----------------------------------------------------

func TestExitCodeFor_Contract(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want int
	}{
		{"nil error is exit 0", nil, 0},
		{"errFailOn is exit 1", errFailOn, 1},
		{"wrapped errFailOn is exit 1", fmt.Errorf("compliance: %w", errFailOn), 1},
		{"generic error is exit 2", errors.New("scan failed: all engines failed"), 2},
		{"config error is exit 2", errors.New("load config: yaml: line 3"), 2},
		{"invalid path is exit 2", errors.New("scan path does not exist: /nope"), 2},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := exitCodeFor(tc.err); got != tc.want {
				t.Errorf("exitCodeFor(%v) = %d, want %d", tc.err, got, tc.want)
			}
		})
	}
}

// --- --path validation ------------------------------------------------------

func TestValidateScanPath(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "afile.txt")
	if err := os.WriteFile(file, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}

	if err := validateScanPath(dir); err != nil {
		t.Errorf("existing directory should validate, got %v", err)
	}
	if err := validateScanPath(filepath.Join(dir, "does-not-exist")); err == nil {
		t.Error("missing path must be rejected")
	} else if !strings.Contains(err.Error(), "does not exist") {
		t.Errorf("missing-path error should say so, got %q", err)
	}
	if err := validateScanPath(file); err == nil {
		t.Error("regular file must be rejected (scan targets are directories)")
	} else if !strings.Contains(err.Error(), "not a directory") {
		t.Errorf("file-path error should say so, got %q", err)
	}
}

// TestScanCmd_MissingPath_FailsBeforeEngines runs the scan command against a
// nonexistent --path and asserts it errors out (exit 2 path) instead of
// running engines and reporting "No findings detected" with exit 0.
func TestScanCmd_MissingPath_FailsBeforeEngines(t *testing.T) {
	cmd := scanCmd()
	cmd.SetArgs([]string{"--path", filepath.Join(t.TempDir(), "no-such-dir")})
	cmd.SilenceErrors = true
	cmd.SilenceUsage = true
	err := cmd.Execute()
	if err == nil {
		t.Fatal("scan of a nonexistent path must fail")
	}
	if !strings.Contains(err.Error(), "does not exist") {
		t.Errorf("expected clear missing-path error, got %q", err)
	}
	if errors.Is(err, errFailOn) {
		t.Error("path error must NOT map to the policy-violation exit code")
	}
	if got := exitCodeFor(err); got != 2 {
		t.Errorf("missing path should exit 2, got %d", got)
	}
}

func TestDiffCmd_MissingPath_FailsBeforeEngines(t *testing.T) {
	cmd := diffCmd()
	cmd.SetArgs([]string{"--path", filepath.Join(t.TempDir(), "no-such-dir"), "--base", "main"})
	cmd.SilenceErrors = true
	cmd.SilenceUsage = true
	err := cmd.Execute()
	if err == nil {
		t.Fatal("diff of a nonexistent path must fail")
	}
	if !strings.Contains(err.Error(), "does not exist") {
		t.Errorf("expected clear missing-path error, got %q", err)
	}
}

// --- Missing-engine transparency ---------------------------------------------

// fakeEngine implements engines.Engine with a controllable Available().
type fakeEngine struct {
	name      string
	available bool
}

func (e fakeEngine) Name() string                 { return e.name }
func (e fakeEngine) Tier() engines.Tier           { return engines.Tier1Pattern }
func (e fakeEngine) SupportedLanguages() []string { return nil }
func (e fakeEngine) Available() bool              { return e.available }
func (e fakeEngine) Version() string              { return "test" }
func (e fakeEngine) Scan(_ context.Context, _ engines.ScanOptions) ([]findings.UnifiedFinding, error) {
	return nil, nil
}

func TestPrintUnavailableEnginesNote(t *testing.T) {
	mk := func(name string, avail bool) fakeEngine { return fakeEngine{name: name, available: avail} }

	t.Run("all available prints nothing", func(t *testing.T) {
		var buf strings.Builder
		printUnavailableEnginesNote(&buf, []engines.Engine{mk("astgrep", true), mk("syft", true)})
		if buf.Len() != 0 {
			t.Errorf("expected no output, got %q", buf.String())
		}
	})

	t.Run("missing SCA and AST engines lists both gaps", func(t *testing.T) {
		var buf strings.Builder
		printUnavailableEnginesNote(&buf, []engines.Engine{
			mk("config-scanner", true),
			mk("binary-scanner", true),
			mk("tls-probe", true),
			mk("astgrep", false),
			mk("semgrep", false),
			mk("cryptodeps", false),
			mk("cdxgen", false),
			mk("syft", false),
			mk("cbomkit-theia", false),
		})
		out := buf.String()
		if !strings.Contains(out, "6 engine(s) unavailable") {
			t.Errorf("expected count of unavailable engines, got %q", out)
		}
		for _, name := range []string{"astgrep", "semgrep", "cryptodeps", "cdxgen", "syft", "cbomkit-theia"} {
			if !strings.Contains(out, name) {
				t.Errorf("expected %s to be named, got %q", name, out)
			}
		}
		if !strings.Contains(out, "engines doctor") {
			t.Errorf("expected doctor hint, got %q", out)
		}
		if !strings.Contains(out, "dependency/SBOM inventory") {
			t.Errorf("expected SBOM coverage gap, got %q", out)
		}
		if !strings.Contains(out, "source AST analysis") {
			t.Errorf("expected AST coverage gap, got %q", out)
		}
		if n := strings.Count(strings.TrimRight(out, "\n"), "\n"); n > 1 {
			t.Errorf("note must stay within 1-2 lines, got %d newlines: %q", n+1, out)
		}
	})

	t.Run("one SCA engine present suppresses SBOM gap", func(t *testing.T) {
		var buf strings.Builder
		printUnavailableEnginesNote(&buf, []engines.Engine{
			mk("astgrep", true),
			mk("syft", true),
			mk("cdxgen", false),
		})
		out := buf.String()
		if strings.Contains(out, "dependency/SBOM inventory") {
			t.Errorf("SBOM gap must not appear when an SCA engine is available, got %q", out)
		}
		if !strings.Contains(out, "cdxgen") {
			t.Errorf("still expected the missing engine named, got %q", out)
		}
	})
}

// --- Grouped compliance rendering --------------------------------------------

func TestGroupViolations_GroupsByRuleAndAlgorithm(t *testing.T) {
	mkFinding := func(name, file string, line int) findings.UnifiedFinding {
		return findings.UnifiedFinding{
			Location:  findings.Location{File: file, Line: line},
			Algorithm: &findings.Algorithm{Name: name},
		}
	}
	results := []findings.UnifiedFinding{
		mkFinding("RSA", "/repo/main.go", 7),
		mkFinding("RSA", "/repo/crypto.py", 12),
		mkFinding("RSA", "/repo/util.go", 3),
		mkFinding("ECDSA", "/repo/sign.go", 40),
	}
	violations := []compliance.Violation{
		{Algorithm: "RSA", Rule: "cnsa2-quantum-vulnerable", Message: "RSA is quantum-vulnerable"},
		{Algorithm: "RSA", Rule: "cnsa2-quantum-vulnerable", Message: "RSA is quantum-vulnerable"},
		{Algorithm: "RSA", Rule: "cnsa2-quantum-vulnerable", Message: "RSA is quantum-vulnerable"},
		{Algorithm: "ECDSA", Rule: "cnsa2-quantum-vulnerable", Message: "ECDSA is quantum-vulnerable"},
	}

	groups := groupViolations(violations, results)
	if len(groups) != 2 {
		t.Fatalf("expected 2 groups, got %d: %+v", len(groups), groups)
	}
	rsa := groups[0]
	if rsa.Algorithm != "RSA" || rsa.Count != 3 {
		t.Errorf("RSA group = %+v, want Count 3", rsa)
	}
	if len(rsa.Locations) != 2 {
		t.Errorf("RSA group locations = %v, want 2 examples", rsa.Locations)
	}
	if rsa.Locations[0] != "main.go:7" || rsa.Locations[1] != "crypto.py:12" {
		t.Errorf("RSA example locations = %v", rsa.Locations)
	}
	if groups[1].Algorithm != "ECDSA" || groups[1].Count != 1 {
		t.Errorf("ECDSA group = %+v, want Count 1", groups[1])
	}

	line := formatViolationGroup(rsa)
	for _, want := range []string{"[cnsa2-quantum-vulnerable]", "RSA is quantum-vulnerable", "3 findings", "e.g. main.go:7, crypto.py:12", "+1 more"} {
		if !strings.Contains(line, want) {
			t.Errorf("grouped line %q missing %q", line, want)
		}
	}

	single := formatViolationGroup(groups[1])
	if strings.Contains(single, "findings") {
		t.Errorf("single-violation line should not carry a count, got %q", single)
	}
	if !strings.Contains(single, "sign.go:40") {
		t.Errorf("single-violation line should carry its location, got %q", single)
	}
}

func TestGroupViolations_NoMatchingFindings(t *testing.T) {
	violations := []compliance.Violation{
		{Algorithm: "RSA", Rule: "r", Message: "m"},
		{Algorithm: "RSA", Rule: "r", Message: "m"},
	}
	groups := groupViolations(violations, nil)
	if len(groups) != 1 || groups[0].Count != 2 {
		t.Fatalf("groups = %+v", groups)
	}
	line := formatViolationGroup(groups[0])
	if !strings.Contains(line, "2 findings") {
		t.Errorf("expected count even without locations, got %q", line)
	}
	if strings.Contains(line, "e.g.") {
		t.Errorf("no example locations available, got %q", line)
	}
}
