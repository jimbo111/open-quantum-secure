package sshprobe

import (
	"fmt"
	"testing"

	"github.com/jimbo111/open-quantum-secure/pkg/findings"
)

func TestClassifyKex_KnownPQC(t *testing.T) {
	pqcMethods := []struct {
		method   string
		maturity string
	}{
		{"mlkem768x25519-sha256", "final"},
		{"sntrup761x25519-sha512@openssh.com", "draft"},
		{"kyber-512-sha256@pqc.ssh", "draft"},
		{"kyber-768-sha256@pqc.ssh", "draft"},
		{"kyber-1024-sha256@pqc.ssh", "draft"},
		{"x25519-kyber-512-sha256@ietf.org", "draft"},
		{"x25519-kyber-768-sha256@ietf.org", "draft"},
		{"ntruprime-ntrulpr761x25519-sha512@openssh.com", "draft"},
		{"ntruprime-sntrup761x25519-sha512@openssh.com", "draft"},
	}
	for _, tc := range pqcMethods {
		t.Run(tc.method, func(t *testing.T) {
			info := classifyKex(tc.method)
			if !info.pqcPresent {
				t.Errorf("classifyKex(%q).pqcPresent = false; want true", tc.method)
			}
			if info.maturity != tc.maturity {
				t.Errorf("classifyKex(%q).maturity = %q; want %q", tc.method, info.maturity, tc.maturity)
			}
		})
	}
}

func TestClassifyKex_Classical(t *testing.T) {
	classical := []string{
		"diffie-hellman-group14-sha256",
		"diffie-hellman-group14-sha1",
		"diffie-hellman-group16-sha512",
		"diffie-hellman-group18-sha512",
		"diffie-hellman-group-exchange-sha256",
		"diffie-hellman-group-exchange-sha1",
		"diffie-hellman-group1-sha1",
		"ecdh-sha2-nistp256",
		"ecdh-sha2-nistp384",
		"ecdh-sha2-nistp521",
		"curve25519-sha256",
		"curve25519-sha256@libssh.org",
		"curve448-sha512",
	}
	for _, method := range classical {
		t.Run(method, func(t *testing.T) {
			info := classifyKex(method)
			if info.pqcPresent {
				t.Errorf("classifyKex(%q).pqcPresent = true; want false (classical method)", method)
			}
		})
	}
}

func TestClassifyKex_UnknownPQCHeuristic(t *testing.T) {
	heuristic := []string{
		"mlkem1024x448-sha512@future.org",
		"frodokem1344-sha512@example.com",
		"sntrup1277x25519-sha512@openssh.com",
		"kyber-999-sha256@unknown.tld",
		"hqc256-sha512@draft.example",
		"ntruprime-new-sha256@vendor.com",
	}
	for _, method := range heuristic {
		t.Run(method, func(t *testing.T) {
			info := classifyKex(method)
			if !info.pqcPresent {
				t.Errorf("classifyKex(%q).pqcPresent = false; want true (PQC heuristic match)", method)
			}
		})
	}
}

func TestClassifyKex_UnknownClassical(t *testing.T) {
	unknown := []string{
		"totally-unknown-kex@example.com",
		"custom-group-sha256",
		"some-random-method",
	}
	for _, method := range unknown {
		t.Run(method, func(t *testing.T) {
			info := classifyKex(method)
			if info.pqcPresent {
				t.Errorf("classifyKex(%q).pqcPresent = true; want false (unrecognized method)", method)
			}
		})
	}
}

func TestKexInitToFindings_ClassicalOnly(t *testing.T) {
	result := ProbeResult{
		Target:   "192.0.2.1:22",
		ServerID: "SSH-2.0-OpenSSH_7.4",
		KEXMethods: []string{
			"curve25519-sha256",
			"diffie-hellman-group14-sha256",
		},
	}
	ff := kexInitToFindings(result)
	if len(ff) != 2 {
		t.Fatalf("expected 2 findings, got %d", len(ff))
	}
	for _, f := range ff {
		if f.PQCPresent {
			t.Errorf("finding for classical method has PQCPresent=true: %+v", f)
		}
		if f.QuantumRisk == findings.QRSafe {
			t.Errorf("classical method should not be QRSafe: %+v", f)
		}
		if f.Algorithm == nil || f.Algorithm.Primitive != "kex" {
			t.Errorf("expected Primitive=kex, got: %+v", f.Algorithm)
		}
		if f.SourceEngine != engineName {
			t.Errorf("SourceEngine = %q; want %q", f.SourceEngine, engineName)
		}
	}
}

func TestKexInitToFindings_PQCPresent(t *testing.T) {
	result := ProbeResult{
		Target:   "192.0.2.2:22",
		ServerID: "SSH-2.0-OpenSSH_10.0",
		KEXMethods: []string{
			"mlkem768x25519-sha256",
			"curve25519-sha256",
		},
	}
	ff := kexInitToFindings(result)
	if len(ff) != 2 {
		t.Fatalf("expected 2 findings, got %d", len(ff))
	}
	var pqcFound bool
	for _, f := range ff {
		if f.Algorithm.Name == "mlkem768x25519-sha256" {
			pqcFound = true
			if !f.PQCPresent {
				t.Errorf("mlkem768x25519-sha256 should have PQCPresent=true")
			}
			if f.QuantumRisk != findings.QRSafe {
				t.Errorf("mlkem768x25519-sha256 QuantumRisk = %q; want %q", f.QuantumRisk, findings.QRSafe)
			}
			if f.PQCMaturity != "final" {
				t.Errorf("PQCMaturity = %q; want final", f.PQCMaturity)
			}
		}
	}
	if !pqcFound {
		t.Fatal("PQC finding not emitted")
	}
}

func TestKexInitToFindings_Error(t *testing.T) {
	result := ProbeResult{
		Target: "192.0.2.3:22",
		Error:  fmt.Errorf("connection refused"),
	}
	ff := kexInitToFindings(result)
	if len(ff) != 0 {
		t.Errorf("expected no findings for error result, got %d", len(ff))
	}
}

func TestKexInitToFindings_EmptyMethods(t *testing.T) {
	result := ProbeResult{
		Target:     "192.0.2.4:22",
		ServerID:   "SSH-2.0-OpenSSH_9.0",
		KEXMethods: []string{},
	}
	ff := kexInitToFindings(result)
	if len(ff) != 0 {
		t.Errorf("expected no findings for empty method list, got %d", len(ff))
	}
}
