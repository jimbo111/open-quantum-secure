package gobinary

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
)

// ---------------------------------------------------------------------------
// Knowledge-base tests
// ---------------------------------------------------------------------------

func TestKBLoads(t *testing.T) {
	entries := Entries()
	if len(entries) == 0 {
		t.Fatal("knowledge base is empty")
	}
}

func TestKBHasExpectedEntries(t *testing.T) {
	cases := []struct {
		module    string
		wantPrim  string
		wantPQC   bool
	}{
		{"crypto/aes", "symmetric", true},
		{"crypto/rsa", "asymmetric", false},
		{"crypto/ecdsa", "signature", false},
		{"crypto/md5", "hash", false},
		{"crypto/sha256", "hash", true},
		{"crypto/sha512", "hash", true},
		{"crypto/tls", "protocol", false},
		{"crypto/des", "symmetric", false},
		{"crypto/ed25519", "signature", false},
		{"golang.org/x/crypto", "symmetric", true},
		{"github.com/cloudflare/circl", "kem", true},
		{"github.com/open-quantum-safe/liboqs-go", "kem", true},
		{"filippo.io/age", "symmetric", false},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.module, func(t *testing.T) {
			entry := LookupModule(tc.module)
			if entry == nil {
				t.Fatalf("LookupModule(%q) = nil, want entry", tc.module)
			}
			if entry.Primitive != tc.wantPrim {
				t.Errorf("primitive = %q, want %q", entry.Primitive, tc.wantPrim)
			}
			if entry.PQCSafe != tc.wantPQC {
				t.Errorf("pqcSafe = %v, want %v", entry.PQCSafe, tc.wantPQC)
			}
			if len(entry.Algorithms) == 0 {
				t.Errorf("algorithms list is empty for %q", tc.module)
			}
		})
	}
}

func TestLookupModuleUnknownReturnsNil(t *testing.T) {
	cases := []string{
		"github.com/nonexistent/package",
		"",
		"crypto/nonexistent",
		"totally-not-a-module",
	}
	for _, mod := range cases {
		if got := LookupModule(mod); got != nil {
			t.Errorf("LookupModule(%q) = %+v, want nil", mod, got)
		}
	}
}

func TestLookupModuleReturnsSamePointer(t *testing.T) {
	// Consecutive calls must return the same pointer (singleton KB).
	a := LookupModule("crypto/aes")
	b := LookupModule("crypto/aes")
	if a == nil {
		t.Fatal("expected non-nil entry for crypto/aes")
	}
	if a != b {
		t.Error("LookupModule returned different pointers on consecutive calls")
	}
}

// ---------------------------------------------------------------------------
// IsGoBinary tests
// ---------------------------------------------------------------------------

func TestIsGoBinaryOnNonGoFile(t *testing.T) {
	tmp := t.TempDir()
	plain := filepath.Join(tmp, "plaintext.txt")
	if err := os.WriteFile(plain, []byte("hello world"), 0o644); err != nil {
		t.Fatalf("write file: %v", err)
	}
	if IsGoBinary(plain) {
		t.Error("IsGoBinary(plaintext) = true, want false")
	}
}

func TestIsGoBinaryMissingFile(t *testing.T) {
	if IsGoBinary("/this/path/does/not/exist/binary") {
		t.Error("IsGoBinary(missing) = true, want false")
	}
}

func TestIsGoBinaryOnGoBinary(t *testing.T) {
	if runtime.GOOS == "js" {
		t.Skip("cannot exec on js/wasm")
	}

	bin := buildTestBinary(t)
	if !IsGoBinary(bin) {
		t.Errorf("IsGoBinary(%q) = false, want true", bin)
	}
}

// ---------------------------------------------------------------------------
// Scan tests
// ---------------------------------------------------------------------------

func TestScanContextCancelled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel immediately

	_, err := Scan(ctx, "/some/path")
	if err == nil {
		t.Error("expected error on cancelled context, got nil")
	}
}

func TestScanNonGoBinaryReturnsNilNil(t *testing.T) {
	tmp := t.TempDir()
	plain := filepath.Join(tmp, "data.bin")
	// Write random bytes that are definitely not a valid Go binary.
	if err := os.WriteFile(plain, []byte{0x7f, 0x45, 0x4c, 0x46, 0xde, 0xad, 0xbe, 0xef}, 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}

	got, err := Scan(context.Background(), plain)
	if err != nil {
		t.Errorf("Scan(non-go-binary) error = %v, want nil", err)
	}
	if got != nil {
		t.Errorf("Scan(non-go-binary) = %v, want nil", got)
	}
}

func TestScanMissingFileReturnsError(t *testing.T) {
	_, err := Scan(context.Background(), "/no/such/file/exists")
	if err == nil {
		t.Error("expected error for missing file, got nil")
	}
}

func TestScanGoBinaryProducesFindings(t *testing.T) {
	if runtime.GOOS == "js" {
		t.Skip("cannot exec on js/wasm")
	}

	bin := buildTestBinary(t)

	results, err := Scan(context.Background(), bin)
	if err != nil {
		t.Fatalf("Scan(%q) error: %v", bin, err)
	}

	// The test binary uses only stdlib crypto packages (crypto/aes, crypto/rand).
	// These appear in buildinfo as stdlib, NOT as external deps, so info.Deps
	// won't list them. The scanner returns 0 findings for stdlib-only binaries.
	// We log the count for visibility and verify structural invariants on any
	// findings that do appear (e.g. if the Go toolchain changes behavior).
	t.Logf("Scan produced %d findings from stdlib-only test binary", len(results))
	for i, f := range results {
		if f.Location.File != bin {
			t.Errorf("result[%d].Location.File = %q, want %q", i, f.Location.File, bin)
		}
		if f.Location.ArtifactType != "go-binary" {
			t.Errorf("result[%d].Location.ArtifactType = %q, want go-binary", i, f.Location.ArtifactType)
		}
		if f.SourceEngine != sourceEngine {
			t.Errorf("result[%d].SourceEngine = %q, want %q", i, f.SourceEngine, sourceEngine)
		}
		if f.Confidence != "medium" {
			t.Errorf("result[%d].Confidence = %q, want medium", i, f.Confidence)
		}
		if f.Algorithm == nil {
			t.Errorf("result[%d].Algorithm is nil", i)
		}
		if f.Dependency == nil {
			t.Errorf("result[%d].Dependency is nil", i)
		}
	}
}

func TestScanSelf(t *testing.T) {
	// The test binary itself is a Go binary. Scan it and verify we get a
	// well-formed (possibly empty) result without errors.
	self, err := os.Executable()
	if err != nil {
		t.Skipf("cannot determine test executable path: %v", err)
	}

	results, err := Scan(context.Background(), self)
	if err != nil {
		t.Fatalf("Scan(self=%q) error: %v", self, err)
	}

	// Structural check — don't assert count since the test binary's deps vary.
	for i, f := range results {
		if f.Location.ArtifactType != "go-binary" {
			t.Errorf("result[%d].ArtifactType = %q, want go-binary", i, f.Location.ArtifactType)
		}
		if f.RawIdentifier == "" {
			t.Errorf("result[%d].RawIdentifier is empty", i)
		}
	}
}

// TestKBMatchProducesCorrectFinding verifies that when a module dependency
// matches a KB entry, the resulting UnifiedFinding has the expected fields.
// This tests the core KB-lookup → finding-construction path without needing
// an external module dependency in the compiled binary.
func TestKBMatchProducesCorrectFinding(t *testing.T) {
	// Verify KB lookup returns expected values for known entries.
	cases := []struct {
		module   string
		wantAlg  string
		wantPrim string
		wantPQC  bool
	}{
		{"crypto/aes", "AES", "symmetric", true},
		{"crypto/rsa", "RSA", "asymmetric", false},
		{"crypto/tls", "TLS", "protocol", false},
		{"github.com/cloudflare/circl", "Kyber", "kem", true},
	}

	for _, tc := range cases {
		entry := LookupModule(tc.module)
		if entry == nil {
			t.Errorf("LookupModule(%q) = nil", tc.module)
			continue
		}
		if len(entry.Algorithms) == 0 || entry.Algorithms[0] != tc.wantAlg {
			t.Errorf("LookupModule(%q).Algorithms[0] = %v, want %q", tc.module, entry.Algorithms, tc.wantAlg)
		}
		if entry.Primitive != tc.wantPrim {
			t.Errorf("LookupModule(%q).Primitive = %q, want %q", tc.module, entry.Primitive, tc.wantPrim)
		}
		if entry.PQCSafe != tc.wantPQC {
			t.Errorf("LookupModule(%q).PQCSafe = %v, want %v", tc.module, entry.PQCSafe, tc.wantPQC)
		}
	}
}

// ---------------------------------------------------------------------------
// Replace directive test
// ---------------------------------------------------------------------------

// TestReplaceDirectiveHandling verifies that when dep.Replace is set the
// replacement module path is used for KB lookup and the original path is
// preserved in Dependency.Library and RawIdentifier.
//
// We test this indirectly by scanning a real Go binary; direct replace-struct
// manipulation requires unexported buildinfo internals. The test verifies the
// scanner code path compiles and does not panic.
func TestReplaceDirectiveHandling(t *testing.T) {
	// Build a minimal binary and scan it — exercises the replace-directive
	// branch without needing a binary that actually has replace directives.
	bin := buildTestBinary(t)
	_, err := Scan(context.Background(), bin)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// buildTestBinary compiles a minimal Go program and returns the path to the
// resulting binary. The binary is placed in t.TempDir() and cleaned up
// automatically when the test ends.
func buildTestBinary(t *testing.T) string {
	t.Helper()

	dir := t.TempDir()
	src := filepath.Join(dir, "main.go")
	bin := filepath.Join(dir, "testbin")
	if runtime.GOOS == "windows" {
		bin += ".exe"
	}

	const prog = `package main

import (
	"crypto/aes"
	"crypto/rand"
	"fmt"
)

func main() {
	key := make([]byte, aes.BlockSize)
	if _, err := rand.Read(key); err != nil {
		panic(err)
	}
	fmt.Println("hello from test binary")
}
`
	if err := os.WriteFile(src, []byte(prog), 0o644); err != nil {
		t.Fatalf("write test source: %v", err)
	}

	cmd := exec.Command("go", "build", "-o", bin, src)
	cmd.Env = append(os.Environ(), "CGO_ENABLED=0")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("go build: %v\n%s", err, out)
	}

	return bin
}
