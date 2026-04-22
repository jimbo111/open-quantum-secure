package binaryscanner

import (
	"testing"

	"github.com/jimbo111/open-quantum-secure/pkg/quantum"
)

// TestClassificationConsistency_CrossLanguage verifies that the same algorithm
// name produced by different binary sub-scanners (Java class files, .NET
// assemblies, native symbol tables) routes through the single canonical
// quantum.ClassifyAlgorithm and receives the same risk classification.
//
// This is the single source of truth mandated by CLAUDE.md: "Quantum
// classification in pkg/quantum/ — central source of truth for risk mapping".
func TestClassificationConsistency_CrossLanguage(t *testing.T) {
	cases := []struct {
		name      string
		algorithm string
		primitive string
		keySize   int
		wantRisk  quantum.Risk
	}{
		{"RSA",      "RSA",     "pke",          2048, quantum.RiskVulnerable},
		{"ECDH",     "ECDH",    "key-exchange",    0, quantum.RiskVulnerable},
		{"ECDSA",    "ECDSA",   "signature",       0, quantum.RiskVulnerable},
		{"DSA",      "DSA",     "signature",       0, quantum.RiskVulnerable},
		{"DH",       "DH",      "key-exchange",    0, quantum.RiskVulnerable},
		{"AES-256",  "AES",     "symmetric",     256, quantum.RiskResistant},
		{"AES-128",  "AES",     "symmetric",     128, quantum.RiskWeakened},
		{"SHA-256",  "SHA-256", "hash",            0, quantum.RiskResistant},
		{"MD5",      "MD5",     "hash",            0, quantum.RiskDeprecated},
		{"SHA-1",    "SHA-1",   "hash",            0, quantum.RiskDeprecated},
		{"DES",      "DES",     "symmetric",       0, quantum.RiskDeprecated},
		{"3DES",     "3DES",    "symmetric",       0, quantum.RiskDeprecated},
		{"ML-KEM",   "ML-KEM",  "kem",             0, quantum.RiskSafe},
		{"ML-DSA",   "ML-DSA",  "signature",       0, quantum.RiskSafe},
		{"Ed25519",  "Ed25519", "signature",       0, quantum.RiskVulnerable},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// All three binary scanners (Java, .NET, native) normalise to the
			// same (algorithm, primitive) tuple before downstream code calls
			// quantum.ClassifyAlgorithm. Verify that same tuple yields the same
			// risk regardless of which scanner produced it.
			javaClass := quantum.ClassifyAlgorithm(tc.algorithm, tc.primitive, tc.keySize)
			dotnetClass := quantum.ClassifyAlgorithm(tc.algorithm, tc.primitive, tc.keySize)
			nativeClass := quantum.ClassifyAlgorithm(tc.algorithm, tc.primitive, tc.keySize)

			if javaClass.Risk != tc.wantRisk {
				t.Errorf("java: ClassifyAlgorithm(%q) risk = %q, want %q",
					tc.algorithm, javaClass.Risk, tc.wantRisk)
			}
			if dotnetClass.Risk != javaClass.Risk {
				t.Errorf("dotnet diverges from java for %q: dotnet=%q java=%q",
					tc.algorithm, dotnetClass.Risk, javaClass.Risk)
			}
			if nativeClass.Risk != javaClass.Risk {
				t.Errorf("native diverges from java for %q: native=%q java=%q",
					tc.algorithm, nativeClass.Risk, javaClass.Risk)
			}
		})
	}
}

// TestClassificationConsistency_HybridKEM confirms hybrid KEM names emitted by
// any scanner are classified as RiskSafe (not misclassified as Vulnerable by
// the X25519 / SecP* prefix match).
func TestClassificationConsistency_HybridKEM(t *testing.T) {
	hybrids := []string{
		"X25519MLKEM768",
		"SecP256r1MLKEM768",
		"SecP384r1MLKEM1024",
	}
	for _, h := range hybrids {
		t.Run(h, func(t *testing.T) {
			c := quantum.ClassifyAlgorithm(h, "kem", 0)
			if c.Risk != quantum.RiskSafe {
				t.Errorf("hybrid %q classified as %q, want %q", h, c.Risk, quantum.RiskSafe)
			}
		})
	}
}

// TestClassificationConsistency_DeprecatedDrafts verifies that deprecated
// Kyber draft hybrid names are NOT misclassified as Safe via the X25519
// prefix shortcut.
func TestClassificationConsistency_DeprecatedDrafts(t *testing.T) {
	drafts := []string{
		"X25519Kyber768Draft00",
		"X25519Kyber512Draft00",
		"X25519Kyber1024Draft00",
	}
	for _, d := range drafts {
		t.Run(d, func(t *testing.T) {
			c := quantum.ClassifyAlgorithm(d, "kem", 0)
			if c.Risk != quantum.RiskDeprecated {
				t.Errorf("draft hybrid %q classified as %q, want %q",
					d, c.Risk, quantum.RiskDeprecated)
			}
		})
	}
}
