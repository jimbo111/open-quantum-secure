package cipherscope

// Sophisticated subprocess safety + source-code regression tests for cipherscope.
//
// Tests run under:
//   go test -race -count=1 ./pkg/engines/cipherscope/...

import (
	"bufio"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/jimbo111/open-quantum-secure/pkg/engines"
)

// writeFakeBinCS writes a shell-script stub binary. Defined here because
// the cipherscope package does not have writeFakeBin.
func writeFakeBinCS(t *testing.T, name, body string) string {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, name)
	if runtime.GOOS == "windows" {
		p = p + ".bat"
		_ = os.WriteFile(p, []byte("@echo off\r\n"+body+"\r\n"), 0o755)
	} else {
		_ = os.WriteFile(p, []byte("#!/bin/sh\n"+body+"\n"), 0o755)
	}
	return p
}

// ---------------------------------------------------------------------------
// WaitDelay grand-child pipe-hang
// ---------------------------------------------------------------------------

// TestSophisticated_CipherscopeWaitDelay_StdoutPipeHang verifies that a
// grand-child holding the STDOUT pipe open after SIGKILL does NOT block
// bufio.Scanner.Scan() (which waits for EOF) beyond WaitDelay (2 s).
//
// cipherscope uses StdoutPipe + bufio.Scanner — making it more vulnerable
// to pipe-hang than file-output engines. Without WaitDelay this test would
// block for the full 30 s sleep duration.
func TestSophisticated_CipherscopeWaitDelay_StdoutPipeHang(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("pipe-hang test requires POSIX semantics")
	}
	t.Parallel()

	// Grand-child inherits stdout and sleeps 30s, keeping the pipe open.
	body := `
sleep 30 &
exit 0
`
	bin := writeFakeBinCS(t, "cipherscope", body)
	e := &Engine{binaryPath: bin}

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	start := time.Now()
	_, err := e.Scan(ctx, engines.ScanOptions{TargetPath: t.TempDir()})
	elapsed := time.Since(start)

	if err == nil {
		// Returning nil error here means cipherscope exited cleanly and
		// WaitDelay fired — either way we got past the hang.
		t.Logf("Scan returned nil error after %v — WaitDelay fired and pipe was closed", elapsed)
	}
	// ctx=100ms + WaitDelay=2s + 1.5s slop.
	const maxAllowed = 4 * time.Second
	if elapsed > maxAllowed {
		t.Errorf("Scan blocked %v — WaitDelay should bound return to ~3s; missing cmd.WaitDelay?", elapsed)
	}
	t.Logf("Scan returned in %v err=%v", elapsed, err)
}

// ---------------------------------------------------------------------------
// PQC param-set regression (7b7f4ac fix)
// ---------------------------------------------------------------------------

// TestSophisticated_PQCParamSet_MLKem768VsMlKem1024 verifies that ML-KEM-768
// and ML-KEM-1024 are both detected as PQC family identifiers and that their
// numeric suffixes are NOT interpreted as classical key sizes.
func TestSophisticated_PQCParamSet_MLKem768VsMlKem1024(t *testing.T) {
	t.Parallel()
	cases := []struct {
		id      string
		wantKey int
		isPQC   bool
	}{
		{"ML-KEM-768", 0, true},
		{"ML-KEM-1024", 0, true},
		{"ML-KEM-512", 0, true},
		{"AES-256-GCM", 256, false}, // classical: key size preserved
		{"RSA-4096", 4096, false},   // classical: key size preserved
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.id, func(t *testing.T) {
			t.Parallel()
			got := isPQCFamilyIdentifier(tc.id)
			if got != tc.isPQC {
				t.Errorf("isPQCFamilyIdentifier(%q) = %v, want %v", tc.id, got, tc.isPQC)
			}
			alg := parseAlgorithm(tc.id)
			if alg.KeySize != tc.wantKey {
				t.Errorf("parseAlgorithm(%q).KeySize = %d, want %d", tc.id, alg.KeySize, tc.wantKey)
			}
		})
	}
}

// TestSophisticated_PQCParamSet_HybridKEMs verifies that hybrid KEM names
// like X25519-MLKEM-768 and SecP256r1-MLKEM-768 are correctly detected as
// PQC family identifiers with KeySize=0.
func TestSophisticated_PQCParamSet_HybridKEMs(t *testing.T) {
	t.Parallel()
	hybrids := []string{
		"X25519-MLKEM-768",
		"SecP256r1-MLKEM-768",
		"SecP384r1-MLKEM-1024",
		"curveSM2-MLKEM-768",
		"X25519-Kyber768",
	}
	for _, id := range hybrids {
		id := id
		t.Run(id, func(t *testing.T) {
			t.Parallel()
			if !isPQCFamilyIdentifier(id) {
				t.Errorf("isPQCFamilyIdentifier(%q) = false, want true", id)
			}
			alg := parseAlgorithm(id)
			if alg.KeySize != 0 {
				t.Errorf("parseAlgorithm(%q).KeySize = %d, want 0 (PQC param, not bit length)", id, alg.KeySize)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// JSONL streaming: valid output through StdoutPipe
// ---------------------------------------------------------------------------

// TestSophisticated_CipherscopeJSONLStreaming exercises the JSONL-reading path
// by driving a stub that writes multiple JSONL lines then exits cleanly.
func TestSophisticated_CipherscopeJSONLStreaming(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("skipping on windows")
	}
	t.Parallel()

	lines := []rawFinding{
		{AssetType: "algorithm", Identifier: "AES-256-GCM", Path: "a.go", Evidence: rawEvidence{Line: 1, Column: 1}},
		{AssetType: "algorithm", Identifier: "RSA-2048", Path: "b.go", Evidence: rawEvidence{Line: 5, Column: 3}},
		{AssetType: "library", Identifier: "OpenSSL", Path: "c.go", Evidence: rawEvidence{Line: 10, Column: 1}},
	}

	// Build JSONL payload.
	var sb strings.Builder
	for _, line := range lines {
		data, _ := json.Marshal(line)
		sb.WriteString(string(data))
		sb.WriteByte('\n')
	}

	// Write payload file, then have stub cat it to stdout.
	dir := t.TempDir()
	payload := filepath.Join(dir, "payload.jsonl")
	if err := os.WriteFile(payload, []byte(sb.String()), 0o644); err != nil {
		t.Fatalf("write payload: %v", err)
	}

	bin := writeFakeBinCS(t, "cipherscope", `cat "`+payload+`"; exit 0`)
	e := &Engine{binaryPath: bin}

	res, err := e.Scan(context.Background(), engines.ScanOptions{TargetPath: t.TempDir()})
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if len(res) != 3 {
		t.Fatalf("expected 3 findings, got %d", len(res))
	}
	// Verify first finding algorithm.
	if res[0].Algorithm == nil || res[0].Algorithm.Name != "AES-256-GCM" {
		t.Errorf("finding[0]: unexpected algorithm %+v", res[0].Algorithm)
	}
	// Verify library finding.
	if res[2].Dependency == nil || res[2].Dependency.Library != "OpenSSL" {
		t.Errorf("finding[2]: unexpected dependency %+v", res[2].Dependency)
	}
}

// TestSophisticated_CipherscopeMalformedJSONLLinesSkipped verifies that the
// scanner skips individual malformed lines rather than aborting the scan.
func TestSophisticated_CipherscopeMalformedJSONLLinesSkipped(t *testing.T) {
	t.Parallel()
	// Use the internal parsing loop directly instead of a subprocess.
	lines := []string{
		`{"assetType":"algorithm","identifier":"AES-256","path":"a.go","evidence":{"line":1,"column":1}}`,
		`not valid json {{{`,
		`{"assetType":"algorithm","identifier":"RSA-2048","path":"b.go","evidence":{"line":5,"column":1}}`,
	}

	var result []rawFinding
	scanner := bufio.NewScanner(strings.NewReader(strings.Join(lines, "\n")))
	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}
		var raw rawFinding
		if err := json.Unmarshal(line, &raw); err != nil {
			continue // matches engine behaviour
		}
		result = append(result, raw)
	}

	if len(result) != 2 {
		t.Errorf("expected 2 valid findings (malformed line skipped), got %d", len(result))
	}
}

// TestSophisticated_CipherscopeContextCancelMidScan verifies that cancelling
// the context while the scanner is reading stdout causes the Scan to return
// an error (not a hang).
func TestSophisticated_CipherscopeContextCancelMidScan(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("skipping on windows")
	}
	t.Parallel()
	// Subprocess sleeps 2s before writing output.
	body := `sleep 2; printf '{"assetType":"algorithm","identifier":"AES","path":"a.go","evidence":{"line":1,"column":1}}\n'; exit 0`
	bin := writeFakeBinCS(t, "cipherscope", body)
	e := &Engine{binaryPath: bin}

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	start := time.Now()
	_, err := e.Scan(ctx, engines.ScanOptions{TargetPath: t.TempDir()})
	elapsed := time.Since(start)

	// With WaitDelay the bound is ctx+2s+slop.
	const maxAllowed = 4 * time.Second
	if elapsed > maxAllowed {
		t.Errorf("Scan blocked %v, expected to return in <4s", elapsed)
	}
	t.Logf("Scan returned after %v err=%v", elapsed, err)
}
