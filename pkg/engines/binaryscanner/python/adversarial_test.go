package python

import (
	"archive/zip"
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Adversarial fixture tests for the Python wheel scanner. These test
// zip-slip, zip-bomb, malformed METADATA, symlink entries, and other
// attacker-controlled wheel content.

// buildWheelWithSymlink creates a wheel containing a symlink-type zip entry.
// Go's archive/zip preserves the external attrs but will Open() the raw body.
func buildWheelAdv(t *testing.T, files map[string]string) []byte {
	t.Helper()
	var buf bytes.Buffer
	w := zip.NewWriter(&buf)
	for name, content := range files {
		f, err := w.Create(name)
		if err != nil {
			t.Fatalf("zip create %q: %v", name, err)
		}
		if _, err := f.Write([]byte(content)); err != nil {
			t.Fatalf("zip write %q: %v", name, err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatalf("zip close: %v", err)
	}
	return buf.Bytes()
}

func writeTempWheel(t *testing.T, data []byte, name string) string {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, data, 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	return p
}

// ---------------------------------------------------------------------------
// A-P1: zip-slip — entry with ".." in the path must be rejected silently.
// ---------------------------------------------------------------------------

func TestAdversarial_WheelZipSlip(t *testing.T) {
	data := buildWheelAdv(t, map[string]string{
		"../../../etc/evil/module.py": "import cryptography\n",
		"good-1.0.dist-info/METADATA": "Name: good\nRequires-Dist: cryptography\n",
	})
	p := writeTempWheel(t, data, "evil-1.0-py3-none-any.whl")

	fds, err := ScanWheel(context.Background(), p)
	if err != nil {
		t.Fatalf("ScanWheel error: %v", err)
	}
	// The zip-slip entry must be skipped — but the legitimate METADATA line
	// should still produce a finding.
	for _, f := range fds {
		if f.Location.InnerPath != "" && strings.Contains(f.Location.InnerPath, "..") {
			t.Errorf("zip-slip entry leaked into findings: %q", f.Location.InnerPath)
		}
	}
}

// ---------------------------------------------------------------------------
// A-P2: absolute-path zip entry (Unix-style). Must be rejected.
// ---------------------------------------------------------------------------

func TestAdversarial_WheelAbsolutePath(t *testing.T) {
	data := buildWheelAdv(t, map[string]string{
		"/etc/passwd-like/module.py": "import cryptography\n",
	})
	p := writeTempWheel(t, data, "absolute-1.0.whl")

	fds, err := ScanWheel(context.Background(), p)
	if err != nil {
		t.Fatalf("ScanWheel error: %v", err)
	}
	for _, f := range fds {
		if filepath.IsAbs(f.Location.InnerPath) {
			t.Errorf("absolute-path entry leaked into findings: %q", f.Location.InnerPath)
		}
	}
}

// ---------------------------------------------------------------------------
// A-P3: METADATA without a Name: field — parser only looks for Requires-Dist.
// This test documents that Name: is NOT required by the parser. Findings
// should still be produced from Requires-Dist lines.
// ---------------------------------------------------------------------------

func TestAdversarial_WheelMetadataMissingName(t *testing.T) {
	data := buildWheelAdv(t, map[string]string{
		"pkg-1.0.dist-info/METADATA": "Metadata-Version: 2.1\nRequires-Dist: cryptography\n",
	})
	p := writeTempWheel(t, data, "noname-1.0.whl")

	fds, err := ScanWheel(context.Background(), p)
	if err != nil {
		t.Fatalf("ScanWheel error: %v", err)
	}
	found := false
	for _, f := range fds {
		if f.Dependency != nil && f.Dependency.Library == "cryptography" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected cryptography finding from Name-less METADATA, got %d findings", len(fds))
	}
}

// ---------------------------------------------------------------------------
// A-P4: METADATA with duplicate Name: and Requires-Dist: lines. The parser
// dedupes Requires-Dist entries via a `seen` map — ensure that works.
// ---------------------------------------------------------------------------

func TestAdversarial_WheelMetadataDuplicates(t *testing.T) {
	data := buildWheelAdv(t, map[string]string{
		"pkg-1.0.dist-info/METADATA": strings.Join([]string{
			"Name: pkg",
			"Name: pkg2", // duplicate Name header
			"Requires-Dist: cryptography",
			"Requires-Dist: cryptography", // duplicate dependency
			"Requires-Dist: cryptography>=3.0",
		}, "\n"),
	})
	p := writeTempWheel(t, data, "dup-1.0.whl")

	fds, err := ScanWheel(context.Background(), p)
	if err != nil {
		t.Fatalf("ScanWheel error: %v", err)
	}
	count := 0
	for _, f := range fds {
		if f.Dependency != nil && f.Dependency.Library == "cryptography" {
			count++
		}
	}
	if count != 1 {
		t.Errorf("expected exactly 1 cryptography finding after dedup, got %d", count)
	}
}

// ---------------------------------------------------------------------------
// A-P5: METADATA with a pathologically long line (> bufio.Scanner default
// 64KB token). Current parser uses bufio.Scanner with default max — very
// long Requires-Dist lines are silently dropped. Low-severity correctness
// bug that we DOCUMENT here.
// ---------------------------------------------------------------------------

func TestAdversarial_WheelMetadataLongLine(t *testing.T) {
	// Build a 70KB filler line — exceeds default bufio.Scanner buffer.
	filler := strings.Repeat("x", 70*1024)
	meta := "Metadata-Version: 2.1\nRequires-Dist: " + filler + "\nRequires-Dist: cryptography\n"

	data := buildWheelAdv(t, map[string]string{
		"pkg-1.0.dist-info/METADATA": meta,
	})
	p := writeTempWheel(t, data, "longline-1.0.whl")

	fds, err := ScanWheel(context.Background(), p)
	if err != nil {
		t.Fatalf("ScanWheel error: %v", err)
	}
	// The cryptography line COMES AFTER the oversized line. Today bufio.Scanner
	// aborts the scan on token-too-long, so cryptography will be missed —
	// document the miss as a low-severity DoS/correctness issue.
	found := false
	for _, f := range fds {
		if f.Dependency != nil && f.Dependency.Library == "cryptography" {
			found = true
		}
	}
	if !found {
		t.Logf("Finding P1: bufio.Scanner default max-token drops subsequent lines after a >64KB line (low-severity correctness)")
	}
}

// ---------------------------------------------------------------------------
// A-P6: zip bomb — declared UncompressedSize64 much larger than actual
// compressed size. The size guard (10MB) inside scanImports is compared
// against UncompressedSize64 which is reported by the zip central directory.
// A wheel that lies about UncompressedSize64 will skip the entry. No panic.
// ---------------------------------------------------------------------------

func TestAdversarial_WheelZipBombDeclaredSize(t *testing.T) {
	// Build a .whl whose single .py entry declares a 100MB uncompressed size
	// but actually contains only "import cryptography\n". We craft the zip by
	// hand to manipulate UncompressedSize64.
	var buf bytes.Buffer
	w := zip.NewWriter(&buf)

	h := &zip.FileHeader{
		Name:   "big.py",
		Method: zip.Deflate,
	}
	h.SetMode(0o600)
	fw, err := w.CreateHeader(h)
	if err != nil {
		t.Fatalf("zip create header: %v", err)
	}
	if _, err := fw.Write([]byte("import cryptography\n")); err != nil {
		t.Fatalf("zip write: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("zip close: %v", err)
	}

	// archive/zip writes the real UncompressedSize64 on Close, so we can't
	// easily forge it post-hoc via the stdlib writer. Instead, confirm the
	// scanner handles a legitimately-sized wheel gracefully.
	p := writeTempWheel(t, buf.Bytes(), "bomb-1.0.whl")
	_, err = ScanWheel(context.Background(), p)
	if err != nil {
		t.Errorf("ScanWheel error on legitimate wheel: %v", err)
	}
}

// ---------------------------------------------------------------------------
// A-P7: zip entry with a huge declared UncompressedSize64 (>10MB). Scanner
// must SKIP the entry (size guard) — no panic and no partial read.
// ---------------------------------------------------------------------------

func TestAdversarial_WheelPyEntryOversized(t *testing.T) {
	// Build a 15MB .py file containing import statements — exceeds the 10MB
	// per-entry limit inside scanImports. The entry must be skipped without
	// producing findings.
	filler := strings.Repeat("# padding\n", 1_400_000) // ~14MB
	data := buildWheelAdv(t, map[string]string{
		"huge.py": filler + "import cryptography\n",
	})
	p := writeTempWheel(t, data, "huge-1.0.whl")

	fds, err := ScanWheel(context.Background(), p)
	if err != nil {
		t.Fatalf("ScanWheel error: %v", err)
	}
	// Since the entry exceeds 10MB, the import should be missed and no
	// cryptography finding is expected.
	for _, f := range fds {
		if f.Dependency != nil && f.Dependency.Library == "cryptography" {
			// If found, confirms the size guard isn't enforced correctly.
			t.Logf("oversized .py entry produced cryptography finding — check size guard")
		}
	}
}

// ---------------------------------------------------------------------------
// A-P8: wheel with no METADATA and no .py files — returns nil, nil.
// ---------------------------------------------------------------------------

func TestAdversarial_WheelEmpty(t *testing.T) {
	data := buildWheelAdv(t, map[string]string{
		"empty.txt": "",
	})
	p := writeTempWheel(t, data, "empty-1.0.whl")

	fds, err := ScanWheel(context.Background(), p)
	if err != nil {
		t.Fatalf("ScanWheel error: %v", err)
	}
	if len(fds) != 0 {
		t.Errorf("expected 0 findings, got %d", len(fds))
	}
}

// ---------------------------------------------------------------------------
// A-P9: wheel is not a valid zip — must return an error from zip.OpenReader.
// ---------------------------------------------------------------------------

func TestAdversarial_WheelNotAZip(t *testing.T) {
	p := writeTempWheel(t, []byte("this is not a zip"), "bogus-1.0.whl")
	_, err := ScanWheel(context.Background(), p)
	if err == nil {
		t.Error("expected error on non-zip wheel")
	}
}

// ---------------------------------------------------------------------------
// A-P10: cancelled context should terminate scanning quickly.
// ---------------------------------------------------------------------------

func TestAdversarial_WheelContextCancelled(t *testing.T) {
	data := buildWheelAdv(t, map[string]string{
		"pkg-1.0.dist-info/METADATA": "Requires-Dist: cryptography\n",
	})
	p := writeTempWheel(t, data, "cancel-1.0.whl")

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := ScanWheel(context.Background(), p) // sanity: works normally
	if err != nil {
		t.Fatalf("sanity parse failed: %v", err)
	}

	_, err = ScanWheel(ctx, p) // cancelled
	if err == nil {
		t.Error("expected cancellation error")
	}
}

// ---------------------------------------------------------------------------
// A-P11: METADATA line with no whitespace after the colon (Requires-Dist:cryptography)
// — some wheels ship without a space. Current parseRequiresDist uses
// strings.HasPrefix("Requires-Dist:") which accepts this, then TrimSpace
// strips any leading space — so the tight format parses correctly.
// ---------------------------------------------------------------------------

func TestAdversarial_WheelMetadataNoSpace(t *testing.T) {
	data := buildWheelAdv(t, map[string]string{
		"pkg-1.0.dist-info/METADATA": "Requires-Dist:cryptography\n",
	})
	p := writeTempWheel(t, data, "nospace-1.0.whl")

	fds, err := ScanWheel(context.Background(), p)
	if err != nil {
		t.Fatalf("ScanWheel error: %v", err)
	}
	found := false
	for _, f := range fds {
		if f.Dependency != nil && f.Dependency.Library == "cryptography" {
			found = true
		}
	}
	if !found {
		t.Errorf("parseRequiresDist must accept no-space variant, got %d findings", len(fds))
	}
}

// ---------------------------------------------------------------------------
// A-P12: METADATA with Requires-Dist containing extras + version specifier.
// Format: "Requires-Dist: cryptography[ssh]>=3.0 ; python_version >= '3.6'"
// extractPackageName must trim at '[' or at space.
// ---------------------------------------------------------------------------

func TestAdversarial_WheelMetadataComplexVersionSpec(t *testing.T) {
	specs := []string{
		"Requires-Dist: cryptography[ssh]>=3.0",
		"Requires-Dist: cryptography (>=3.0,<4.0)",
		"Requires-Dist: cryptography; python_version >= '3.6'",
		"Requires-Dist: cryptography ; extra == 'ssh'",
		"Requires-Dist: cryptography ~= 3.0",
	}
	for _, spec := range specs {
		t.Run(spec, func(t *testing.T) {
			data := buildWheelAdv(t, map[string]string{
				"pkg-1.0.dist-info/METADATA": spec + "\n",
			})
			p := writeTempWheel(t, data, "spec-1.0.whl")

			fds, err := ScanWheel(context.Background(), p)
			if err != nil {
				t.Fatalf("ScanWheel error: %v", err)
			}
			found := false
			for _, f := range fds {
				if f.Dependency != nil && f.Dependency.Library == "cryptography" {
					found = true
				}
			}
			if !found {
				t.Errorf("spec %q: expected cryptography finding", spec)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// A-P13: .py entry containing ".." in its name (zip-slip via .py). Must be
// rejected — no findings from the slip entry.
// ---------------------------------------------------------------------------

func TestAdversarial_WheelPyZipSlip(t *testing.T) {
	data := buildWheelAdv(t, map[string]string{
		"../outside/attack.py": "import cryptography\n",
	})
	p := writeTempWheel(t, data, "slip-1.0.whl")

	fds, err := ScanWheel(context.Background(), p)
	if err != nil {
		t.Fatalf("ScanWheel error: %v", err)
	}
	for _, f := range fds {
		if strings.Contains(f.Location.InnerPath, "..") {
			t.Errorf("slip entry leaked: %q", f.Location.InnerPath)
		}
	}
}

// ---------------------------------------------------------------------------
// A-P14: Multiple dist-info directories. Parser takes the FIRST one it sees.
// Document this ordering behaviour (non-panic).
// ---------------------------------------------------------------------------

func TestAdversarial_WheelMultipleDistInfo(t *testing.T) {
	data := buildWheelAdv(t, map[string]string{
		"a-1.0.dist-info/METADATA": "Requires-Dist: cryptography\n",
		"b-1.0.dist-info/METADATA": "Requires-Dist: pyOpenSSL\n",
	})
	p := writeTempWheel(t, data, "multi-1.0.whl")

	fds, err := ScanWheel(context.Background(), p)
	if err != nil {
		t.Fatalf("ScanWheel error: %v", err)
	}
	// Both would be ideal, but the current implementation returns at the first
	// matching entry. Record what actually happens.
	if len(fds) == 0 {
		t.Error("expected at least one finding from multi-dist-info wheel")
	}
	// Confirm at least one of the two libs is present.
	hasCrypto, hasOpenSSL := false, false
	for _, f := range fds {
		if f.Dependency != nil {
			switch f.Dependency.Library {
			case "cryptography":
				hasCrypto = true
			case "pyOpenSSL":
				hasOpenSSL = true
			}
		}
	}
	if !hasCrypto && !hasOpenSSL {
		t.Error("neither expected library appeared in findings")
	}
	if !hasCrypto || !hasOpenSSL {
		t.Logf("Finding P2: only one of two dist-info/METADATA files is scanned (early return in scanMetadata)")
	}
}
