package sshprobe

import (
	"strings"
	"testing"

	"github.com/jimbo111/open-quantum-secure/pkg/findings"
)

func TestKexInitToFindings_NMethodsYieldNFindings(t *testing.T) {
	methods := []string{
		"mlkem768x25519-sha256",
		"sntrup761x25519-sha512@openssh.com",
		"curve25519-sha256",
		"diffie-hellman-group14-sha256",
		"ecdh-sha2-nistp256",
	}
	result := ProbeResult{
		Target:     "198.51.100.1:22",
		ServerID:   "SSH-2.0-OpenSSH_10.0",
		KEXMethods: methods,
	}
	ff := kexInitToFindings(result)
	if len(ff) != len(methods) {
		t.Fatalf("got %d findings; want %d", len(ff), len(methods))
	}
	for i, f := range ff {
		if f.Algorithm == nil {
			t.Fatalf("finding[%d] has nil Algorithm", i)
		}
		if f.Algorithm.Name != methods[i] {
			t.Errorf("finding[%d].Algorithm.Name = %q; want %q", i, f.Algorithm.Name, methods[i])
		}
		if f.Algorithm.Primitive != "kex" {
			t.Errorf("finding[%d].Primitive = %q; want kex", i, f.Algorithm.Primitive)
		}
		if f.SourceEngine != engineName {
			t.Errorf("finding[%d].SourceEngine = %q; want %q", i, f.SourceEngine, engineName)
		}
		if f.Confidence != findings.ConfidenceHigh {
			t.Errorf("finding[%d].Confidence = %q; want high", i, f.Confidence)
		}
		if f.Reachable != findings.ReachableYes {
			t.Errorf("finding[%d].Reachable = %q; want yes", i, f.Reachable)
		}
		if !strings.HasPrefix(f.Location.File, "(ssh-probe)/") {
			t.Errorf("finding[%d].Location.File = %q; want (ssh-probe)/... prefix", i, f.Location.File)
		}
		if f.Location.ArtifactType != "ssh-endpoint" {
			t.Errorf("finding[%d].ArtifactType = %q; want ssh-endpoint", i, f.Location.ArtifactType)
		}
		if !strings.Contains(f.RawIdentifier, methods[i]) {
			t.Errorf("finding[%d].RawIdentifier does not contain method name", i)
		}
	}
}

func TestKexInitToFindings_QuantumRiskMapping(t *testing.T) {
	cases := []struct {
		method      string
		wantPQC     bool
		wantSafe    bool
	}{
		{"mlkem768x25519-sha256", true, true},
		{"sntrup761x25519-sha512@openssh.com", true, true},
		{"curve25519-sha256", false, false},
		{"diffie-hellman-group14-sha256", false, false},
	}
	for _, tc := range cases {
		t.Run(tc.method, func(t *testing.T) {
			result := ProbeResult{
				Target:     "203.0.113.1:22",
				ServerID:   "SSH-2.0-test",
				KEXMethods: []string{tc.method},
			}
			ff := kexInitToFindings(result)
			if len(ff) != 1 {
				t.Fatalf("expected 1 finding, got %d", len(ff))
			}
			f := ff[0]
			if f.PQCPresent != tc.wantPQC {
				t.Errorf("PQCPresent = %v; want %v", f.PQCPresent, tc.wantPQC)
			}
			isSafe := f.QuantumRisk == findings.QRSafe
			if isSafe != tc.wantSafe {
				t.Errorf("QuantumRisk = %q; wantSafe=%v", f.QuantumRisk, tc.wantSafe)
			}
		})
	}
}

func TestKexInitToFindings_SkipsEmptyMethod(t *testing.T) {
	result := ProbeResult{
		Target:     "203.0.113.2:22",
		ServerID:   "SSH-2.0-test",
		KEXMethods: []string{"", "curve25519-sha256", ""},
	}
	ff := kexInitToFindings(result)
	if len(ff) != 1 {
		t.Errorf("expected 1 finding (skipping empty methods), got %d", len(ff))
	}
}

func TestKexInitToFindings_TargetInFilePath(t *testing.T) {
	target := "203.0.113.3:22"
	result := ProbeResult{
		Target:     target,
		ServerID:   "SSH-2.0-test",
		KEXMethods: []string{"curve25519-sha256"},
	}
	ff := kexInitToFindings(result)
	if len(ff) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(ff))
	}
	if !strings.Contains(ff[0].Location.File, target) {
		t.Errorf("Location.File %q does not contain target %q", ff[0].Location.File, target)
	}
}
