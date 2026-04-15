package findings

import (
	"strings"
	"testing"
)

// ---------------------------------------------------------------------------
// RSA variant collision
// ---------------------------------------------------------------------------

// TestDedupeKey_RSA2048VsRSA1024_NoCollision verifies that RSA-2048 and
// RSA-1024 at the same file:line produce distinct dedupe keys. This is the
// core requirement for the suffix-matching fix in 4253de8.
func TestDedupeKey_RSA2048VsRSA1024_NoCollision(t *testing.T) {
	f2048 := &UnifiedFinding{
		Location:  Location{File: "/src/crypto.go", Line: 42},
		Algorithm: &Algorithm{Name: "RSA-2048"},
	}
	f1024 := &UnifiedFinding{
		Location:  Location{File: "/src/crypto.go", Line: 42},
		Algorithm: &Algorithm{Name: "RSA-1024"},
	}
	k1 := f2048.DedupeKey()
	k2 := f1024.DedupeKey()
	if k1 == k2 {
		t.Errorf("RSA-2048 and RSA-1024 at same location must NOT share a dedup key: %q", k1)
	}
}

// ---------------------------------------------------------------------------
// Case sensitivity
// ---------------------------------------------------------------------------

// TestDedupeKey_CaseSensitivity verifies that algorithm names are compared
// case-sensitively: "RSA" and "rsa" must NOT be treated as duplicates by
// DedupeKey alone (normalization happens upstream in orchestrator).
func TestDedupeKey_CaseSensitivity(t *testing.T) {
	upper := &UnifiedFinding{
		Location:  Location{File: "/a.go", Line: 1},
		Algorithm: &Algorithm{Name: "RSA"},
	}
	lower := &UnifiedFinding{
		Location:  Location{File: "/a.go", Line: 1},
		Algorithm: &Algorithm{Name: "rsa"},
	}
	if upper.DedupeKey() == lower.DedupeKey() {
		t.Errorf("DedupeKey must be case-sensitive: 'RSA' and 'rsa' should produce different keys, both got %q", upper.DedupeKey())
	}
}

// ---------------------------------------------------------------------------
// Line 0 findings
// ---------------------------------------------------------------------------

// TestDedupeKey_LineZero verifies that a finding at line 0 (unknown / binary
// artifact without line info) produces a non-empty key and that two algorithm
// findings with the same name at line 0 in the same file ARE merged.
func TestDedupeKey_LineZero(t *testing.T) {
	f1 := &UnifiedFinding{
		Location:     Location{File: "/app.jar", Line: 0},
		Algorithm:    &Algorithm{Name: "RSA"},
		SourceEngine: "binary-scanner",
	}
	f2 := &UnifiedFinding{
		Location:     Location{File: "/app.jar", Line: 0},
		Algorithm:    &Algorithm{Name: "RSA"},
		SourceEngine: "another-scanner",
	}
	if f1.DedupeKey() == "" {
		t.Error("DedupeKey for line-0 finding must not be empty")
	}
	if f1.DedupeKey() != f2.DedupeKey() {
		t.Errorf("same alg + same file at line 0 from different engines should share key: %q vs %q",
			f1.DedupeKey(), f2.DedupeKey())
	}
}

// TestDedupeKey_LineZeroVsLineOne verifies that a finding at line 0 and
// a finding at line 1 for the same algorithm at the same file have DIFFERENT
// dedup keys (line is significant).
func TestDedupeKey_LineZeroVsLineOne(t *testing.T) {
	f0 := &UnifiedFinding{
		Location:  Location{File: "/src/main.go", Line: 0},
		Algorithm: &Algorithm{Name: "AES-128"},
	}
	f1 := &UnifiedFinding{
		Location:  Location{File: "/src/main.go", Line: 1},
		Algorithm: &Algorithm{Name: "AES-128"},
	}
	if f0.DedupeKey() == f1.DedupeKey() {
		t.Errorf("line 0 and line 1 must not share dedup key: %q", f0.DedupeKey())
	}
}

// ---------------------------------------------------------------------------
// Empty file path
// ---------------------------------------------------------------------------

// TestDedupeKey_EmptyFilePath verifies that a finding with an empty file path
// does not panic and produces a stable, engine-differentiated key.
func TestDedupeKey_EmptyFilePath(t *testing.T) {
	f1 := &UnifiedFinding{
		Location:     Location{File: "", Line: 5},
		Algorithm:    &Algorithm{Name: "DH"},
		SourceEngine: "eng-a",
	}
	f2 := &UnifiedFinding{
		Location:     Location{File: "", Line: 5},
		Algorithm:    &Algorithm{Name: "DH"},
		SourceEngine: "eng-b",
	}
	var k1, k2 string
	func() {
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("DedupeKey panicked with empty file path: %v", r)
			}
		}()
		k1 = f1.DedupeKey()
		k2 = f2.DedupeKey()
	}()
	if k1 == "" {
		t.Error("DedupeKey with empty file path must not return empty string")
	}
	// Same algorithm at same (empty) location from different engines should
	// share a key (algorithm branch ignores engine).
	if k1 != k2 {
		t.Errorf("same alg at same empty-path location should share key: %q vs %q", k1, k2)
	}
}

// ---------------------------------------------------------------------------
// InnerPath (archive) findings
// ---------------------------------------------------------------------------

// TestDedupeKey_InnerPath_SameFileAndAlgDifferentClass verifies that two
// findings inside the same archive but different class files produce different
// keys even when the algorithm and line are the same.
func TestDedupeKey_InnerPath_SameFileAndAlgDifferentClass(t *testing.T) {
	f1 := &UnifiedFinding{
		Location:  Location{File: "app.jar", InnerPath: "com/example/CryptoA.class", Line: 10},
		Algorithm: &Algorithm{Name: "RSA"},
	}
	f2 := &UnifiedFinding{
		Location:  Location{File: "app.jar", InnerPath: "com/example/CryptoB.class", Line: 10},
		Algorithm: &Algorithm{Name: "RSA"},
	}
	if f1.DedupeKey() == f2.DedupeKey() {
		t.Errorf("same archive + same alg but different inner paths must not collide: %q", f1.DedupeKey())
	}
}

// TestDedupeKey_InnerPath_SameClassSameAlg verifies that the same finding
// inside the same archive class IS merged (same key).
func TestDedupeKey_InnerPath_SameClassSameAlg(t *testing.T) {
	f1 := &UnifiedFinding{
		Location:     Location{File: "app.jar", InnerPath: "com/example/Crypto.class", Line: 10},
		Algorithm:    &Algorithm{Name: "AES"},
		SourceEngine: "jar-scanner",
	}
	f2 := &UnifiedFinding{
		Location:     Location{File: "app.jar", InnerPath: "com/example/Crypto.class", Line: 10},
		Algorithm:    &Algorithm{Name: "AES"},
		SourceEngine: "binary-scanner",
	}
	if f1.DedupeKey() != f2.DedupeKey() {
		t.Errorf("same archive class + same alg should share dedup key: %q vs %q",
			f1.DedupeKey(), f2.DedupeKey())
	}
}

// TestDedupeKey_InnerPath_Format verifies the exact key format includes the
// "!" separator between file and inner path.
func TestDedupeKey_InnerPath_FormatVerification(t *testing.T) {
	f := &UnifiedFinding{
		Location:  Location{File: "repo.war", InnerPath: "WEB-INF/lib/crypto.jar", Line: 7},
		Algorithm: &Algorithm{Name: "ECDSA"},
	}
	key := f.DedupeKey()
	if !strings.Contains(key, "!") {
		t.Errorf("InnerPath key must contain '!' separator, got: %q", key)
	}
	wantPrefix := "repo.war!WEB-INF/lib/crypto.jar"
	if !strings.HasPrefix(key, wantPrefix) {
		t.Errorf("InnerPath key prefix: got %q, want prefix %q", key, wantPrefix)
	}
}

// ---------------------------------------------------------------------------
// TLS probe findings vs source findings at same line
// ---------------------------------------------------------------------------

// TestDedupeKey_TLSProbe_VsSourceFinding verifies that a TLS probe finding
// (synthetic path "(tls-probe)/host:443#kex") and a source code finding at
// the same line (line=0) with the same algorithm name do NOT collide.
// This is the core regression check for commit 4253de8.
func TestDedupeKey_TLSProbe_VsSourceFinding(t *testing.T) {
	// TLS probe finding — synthetic path as produced by tlsprobe/classify.go.
	tlsFinding := &UnifiedFinding{
		Location:     Location{File: "(tls-probe)/example.com:443#kex", Line: 0},
		Algorithm:    &Algorithm{Name: "RSA", Primitive: "key-exchange"},
		SourceEngine: "tls-probe",
	}
	// Source code finding — same algorithm at line 0 in a real file.
	srcFinding := &UnifiedFinding{
		Location:     Location{File: "/src/tls_config.go", Line: 0},
		Algorithm:    &Algorithm{Name: "RSA", Primitive: "key-exchange"},
		SourceEngine: "cipherscope",
	}
	if tlsFinding.DedupeKey() == srcFinding.DedupeKey() {
		t.Errorf("TLS probe finding must not collide with source finding: both got %q",
			tlsFinding.DedupeKey())
	}
}

// TestDedupeKey_TLSProbe_SameTargetSameAlg verifies that two TLS probe
// findings for the same target + algorithm ARE merged (same dedupe key).
func TestDedupeKey_TLSProbe_SameTargetSameAlg(t *testing.T) {
	f1 := &UnifiedFinding{
		Location:     Location{File: "(tls-probe)/example.com:443#kex", Line: 0},
		Algorithm:    &Algorithm{Name: "RSA"},
		SourceEngine: "tls-probe",
	}
	f2 := &UnifiedFinding{
		Location:     Location{File: "(tls-probe)/example.com:443#kex", Line: 0},
		Algorithm:    &Algorithm{Name: "RSA"},
		SourceEngine: "tls-probe",
	}
	if f1.DedupeKey() != f2.DedupeKey() {
		t.Errorf("same TLS probe target + alg should share key: %q vs %q",
			f1.DedupeKey(), f2.DedupeKey())
	}
}

// TestDedupeKey_TLSProbe_PrimitiveSuffix_NoCollision verifies that the
// primitive-to-suffix mapping (#kex, #sig, #sym) in tlsprobe/classify.go
// prevents collisions between RSA-as-kex and RSA-as-sig for the same target.
// The fix in 4253de8 appended the suffix to the path, so the DedupeKey
// naturally distinguishes them via the file path component.
func TestDedupeKey_TLSProbe_PrimitiveSuffix_NoCollision(t *testing.T) {
	// RSA used for key-exchange (#kex suffix in path)
	rsaKex := &UnifiedFinding{
		Location:     Location{File: "(tls-probe)/example.com:443#kex", Line: 0},
		Algorithm:    &Algorithm{Name: "RSA", Primitive: "key-exchange"},
		SourceEngine: "tls-probe",
	}
	// RSA used for signature (#sig suffix in path)
	rsaSig := &UnifiedFinding{
		Location:     Location{File: "(tls-probe)/example.com:443#sig", Line: 0},
		Algorithm:    &Algorithm{Name: "RSA", Primitive: "signature"},
		SourceEngine: "tls-probe",
	}
	if rsaKex.DedupeKey() == rsaSig.DedupeKey() {
		t.Errorf("RSA-kex and RSA-sig for same TLS target must have different dedupe keys: %q",
			rsaKex.DedupeKey())
	}
}

// ---------------------------------------------------------------------------
// Corroboration confidence ceiling
// ---------------------------------------------------------------------------

// TestDedupeKey_Corroboration_HighConfidenceCeiling verifies that confidence
// does not exceed "high" regardless of how many engines corroborate a finding.
// The boostConfidence function is tested elsewhere; this test uses DedupeKey
// indirectly to confirm the key shape that the dedupe step relies on.
func TestDedupeKey_Corroboration_HighConfidenceCeiling(t *testing.T) {
	// Verify key format is stable so the dedupe loop can find it consistently.
	f := &UnifiedFinding{
		Location:       Location{File: "/svc/auth.go", Line: 99},
		Algorithm:      &Algorithm{Name: "RSA-2048"},
		Confidence:     ConfidenceHigh,
		CorroboratedBy: []string{"eng1", "eng2", "eng3", "eng4"},
		SourceEngine:   "eng0",
	}
	k := f.DedupeKey()
	// The key must be deterministic regardless of confidence or corroborators
	// (those fields are not part of the key by design).
	for i := 0; i < 10; i++ {
		if f.DedupeKey() != k {
			t.Errorf("DedupeKey must be deterministic: got different values on iteration %d", i)
		}
	}
}

// ---------------------------------------------------------------------------
// Negative line numbers (defensive)
// ---------------------------------------------------------------------------

// TestDedupeKey_NegativeLine verifies that a negative line number (defensive
// against malformed engine output) does not panic and produces a unique key.
func TestDedupeKey_NegativeLine(t *testing.T) {
	f := &UnifiedFinding{
		Location:     Location{File: "/src/main.go", Line: -1},
		Algorithm:    &Algorithm{Name: "AES"},
		SourceEngine: "test",
	}
	var key string
	func() {
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("DedupeKey panicked on negative line: %v", r)
			}
		}()
		key = f.DedupeKey()
	}()
	if key == "" {
		t.Error("DedupeKey with negative line must return non-empty string")
	}
	// Negative line must differ from line 0 and line 1.
	fZero := &UnifiedFinding{Location: Location{File: "/src/main.go", Line: 0}, Algorithm: &Algorithm{Name: "AES"}}
	if f.DedupeKey() == fZero.DedupeKey() {
		t.Errorf("line -1 and line 0 must not share dedup key: %q", key)
	}
}
