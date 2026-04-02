package python

import (
	"archive/zip"
	"bytes"
	"context"
	"os"
	"strings"
	"testing"
)

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// buildWheel creates an in-memory zip archive and returns its bytes. The files
// map keys are archive entry names and values are file contents.
func buildWheel(t *testing.T, files map[string]string) []byte {
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

// writeWheelFile writes a wheel byte slice to a temp file and returns the path.
func writeWheelFile(t *testing.T, data []byte, name string) string {
	t.Helper()
	dir := t.TempDir()
	path := dir + "/" + name
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatalf("write wheel file: %v", err)
	}
	return path
}

// ---------------------------------------------------------------------------
// ScanWheel tests
// ---------------------------------------------------------------------------

func TestScanWheelCryptoMetadata(t *testing.T) {
	data := buildWheel(t, map[string]string{
		"mypackage-1.0.dist-info/METADATA": strings.Join([]string{
			"Metadata-Version: 2.1",
			"Name: mypackage",
			"Requires-Dist: cryptography",
			"Requires-Dist: requests",
		}, "\n"),
	})
	path := writeWheelFile(t, data, "mypackage-1.0-py3-none-any.whl")

	got, err := ScanWheel(context.Background(), path)
	if err != nil {
		t.Fatalf("ScanWheel error: %v", err)
	}
	if len(got) == 0 {
		t.Fatal("expected findings, got none")
	}
	found := false
	for _, f := range got {
		if f.Dependency != nil && f.Dependency.Library == "cryptography" {
			found = true
			if f.Location.ArtifactType != "wheel" {
				t.Errorf("ArtifactType = %q, want wheel", f.Location.ArtifactType)
			}
			if f.Confidence != "low" {
				t.Errorf("Confidence = %q, want low", f.Confidence)
			}
			if f.SourceEngine != sourceEngine {
				t.Errorf("SourceEngine = %q, want %q", f.SourceEngine, sourceEngine)
			}
			if f.Location.InnerPath == "" {
				t.Error("InnerPath is empty, want METADATA path")
			}
		}
	}
	if !found {
		t.Error("cryptography finding not in results")
	}
}

func TestScanWheelNoMetadata(t *testing.T) {
	data := buildWheel(t, map[string]string{
		"mypackage/module.py": "# no imports\n",
	})
	path := writeWheelFile(t, data, "nomd-1.0-py3-none-any.whl")

	got, err := ScanWheel(context.Background(), path)
	if err != nil {
		t.Fatalf("ScanWheel error: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("expected no findings, got %d", len(got))
	}
}

func TestScanWheelMultipleCryptoMetadata(t *testing.T) {
	data := buildWheel(t, map[string]string{
		"pkg-2.0.dist-info/METADATA": strings.Join([]string{
			"Metadata-Version: 2.1",
			"Requires-Dist: cryptography",
			"Requires-Dist: pycryptodome",
			"Requires-Dist: bcrypt",
			"Requires-Dist: numpy",
		}, "\n"),
	})
	path := writeWheelFile(t, data, "pkg-2.0-py3-none-any.whl")

	got, err := ScanWheel(context.Background(), path)
	if err != nil {
		t.Fatalf("ScanWheel error: %v", err)
	}

	libs := make(map[string]bool)
	for _, f := range got {
		if f.Dependency != nil {
			libs[f.Dependency.Library] = true
		}
	}

	wantLibs := []string{"cryptography", "pycryptodome", "bcrypt"}
	for _, w := range wantLibs {
		if !libs[w] {
			t.Errorf("missing expected library %q in findings", w)
		}
	}
	if libs["numpy"] {
		t.Error("non-crypto library 'numpy' should not produce a finding")
	}
}

func TestScanWheelNonCryptoOnly(t *testing.T) {
	data := buildWheel(t, map[string]string{
		"mypkg-0.1.dist-info/METADATA": strings.Join([]string{
			"Requires-Dist: requests",
			"Requires-Dist: numpy",
			"Requires-Dist: flask",
		}, "\n"),
	})
	path := writeWheelFile(t, data, "mypkg-0.1-py3-none-any.whl")

	got, err := ScanWheel(context.Background(), path)
	if err != nil {
		t.Fatalf("ScanWheel error: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("expected 0 findings for non-crypto deps, got %d", len(got))
	}
}

// ---------------------------------------------------------------------------
// Requires-Dist format variety tests
// ---------------------------------------------------------------------------

func TestScanWheelRequiresDistFormats(t *testing.T) {
	cases := []struct {
		name        string
		requireLine string
		wantLib     string
	}{
		{
			name:        "bare name",
			requireLine: "Requires-Dist: cryptography",
			wantLib:     "cryptography",
		},
		{
			name:        "with minimum version",
			requireLine: "Requires-Dist: cryptography>=3.0",
			wantLib:     "cryptography",
		},
		{
			name:        "with range constraint",
			requireLine: "Requires-Dist: cryptography (>=3.0,<4.0)",
			wantLib:     "cryptography",
		},
		{
			name:        "pycryptodome bare",
			requireLine: "Requires-Dist: pycryptodome",
			wantLib:     "pycryptodome",
		},
		{
			name:        "paramiko with version",
			requireLine: "Requires-Dist: paramiko>=2.0",
			wantLib:     "paramiko",
		},
		{
			name:        "pynacl mixed case via normalisation",
			requireLine: "Requires-Dist: PyNaCl",
			wantLib:     "pynacl",
		},
		{
			name:        "argon2-cffi with extras bracket",
			requireLine: "Requires-Dist: argon2-cffi[dev]>=21.0",
			wantLib:     "argon2-cffi",
		},
		{
			name:        "pyOpenSSL normalised",
			requireLine: "Requires-Dist: pyOpenSSL>=22.0",
			wantLib:     "pyOpenSSL",
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			metadata := "Metadata-Version: 2.1\n" + tc.requireLine + "\n"
			data := buildWheel(t, map[string]string{
				"foo-1.0.dist-info/METADATA": metadata,
			})
			path := writeWheelFile(t, data, "foo-1.0-py3-none-any.whl")

			got, err := ScanWheel(context.Background(), path)
			if err != nil {
				t.Fatalf("ScanWheel: %v", err)
			}

			found := false
			for _, f := range got {
				if f.Dependency != nil && f.Dependency.Library == tc.wantLib {
					found = true
					break
				}
			}
			if !found {
				t.Errorf("library %q not found in findings; got: %v", tc.wantLib, got)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Python import detection tests
// ---------------------------------------------------------------------------

func TestScanWheelPythonImport(t *testing.T) {
	cases := []struct {
		name    string
		pyCode  string
		wantLib string
	}{
		{
			name:    "import cryptography",
			pyCode:  "import cryptography\n",
			wantLib: "cryptography",
		},
		{
			name:    "from cryptography import",
			pyCode:  "from cryptography import fernet\n",
			wantLib: "cryptography",
		},
		{
			name:    "import Crypto",
			pyCode:  "import Crypto\n",
			wantLib: "Crypto",
		},
		{
			name:    "from hashlib import",
			pyCode:  "from hashlib import sha256\n",
			wantLib: "hashlib",
		},
		{
			name:    "import ssl",
			pyCode:  "import ssl\n",
			wantLib: "ssl",
		},
		{
			name:    "import hmac",
			pyCode:  "import hmac\n",
			wantLib: "hmac",
		},
		{
			name:    "import nacl",
			pyCode:  "import nacl\n",
			wantLib: "nacl",
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			data := buildWheel(t, map[string]string{
				"mylib/crypto_utils.py": tc.pyCode,
			})
			path := writeWheelFile(t, data, "mylib-1.0-py3-none-any.whl")

			got, err := ScanWheel(context.Background(), path)
			if err != nil {
				t.Fatalf("ScanWheel: %v", err)
			}

			found := false
			for _, f := range got {
				if f.Dependency != nil && f.Dependency.Library == tc.wantLib {
					found = true
					if f.Location.InnerPath != "mylib/crypto_utils.py" {
						t.Errorf("InnerPath = %q, want mylib/crypto_utils.py", f.Location.InnerPath)
					}
					break
				}
			}
			if !found {
				t.Errorf("library %q not found in findings; got %v", tc.wantLib, got)
			}
		})
	}
}

func TestScanWheelContextCancelled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	// Path does not matter — context is checked before file open.
	_, err := ScanWheel(ctx, "/nonexistent/path.whl")
	if err == nil {
		t.Error("expected error for cancelled context, got nil")
	}
}

func TestScanWheelInvalidZip(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/bad.whl"
	if err := os.WriteFile(path, []byte("this is not a zip file"), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}

	_, err := ScanWheel(context.Background(), path)
	if err == nil {
		t.Error("expected error for non-zip file, got nil")
	}
}

// ---------------------------------------------------------------------------
// Unit tests for internal helpers
// ---------------------------------------------------------------------------

func TestParseRequiresDist(t *testing.T) {
	cases := []struct {
		line    string
		wantLib string
		wantOK  bool
	}{
		{"Requires-Dist: cryptography", "cryptography", true},
		{"Requires-Dist: cryptography>=3.0", "cryptography", true},
		{"Requires-Dist: cryptography (>=3.0,<4.0)", "cryptography", true},
		{"Requires-Dist: pycryptodome", "pycryptodome", true},
		{"Requires-Dist: PyNaCl", "pynacl", true},
		{"Requires-Dist: bcrypt", "bcrypt", true},
		{"Requires-Dist: requests", "", false},
		{"Requires-Dist: numpy>=1.0", "", false},
		{"Name: something", "", false},
		{"", "", false},
		{"Requires-Dist: ", "", false},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.line, func(t *testing.T) {
			lib, ok := parseRequiresDist(tc.line)
			if ok != tc.wantOK {
				t.Errorf("ok = %v, want %v (lib=%q)", ok, tc.wantOK, lib)
			}
			if lib != tc.wantLib {
				t.Errorf("lib = %q, want %q", lib, tc.wantLib)
			}
		})
	}
}

func TestCanonicalizePythonPackage(t *testing.T) {
	cases := []struct {
		input string
		want  string
	}{
		{"cryptography", "cryptography"},
		{"CRYPTOGRAPHY", "cryptography"},
		{"Cryptography", "cryptography"},
		{"pycryptodome", "pycryptodome"},
		{"PyCryptodome", "pycryptodome"},
		{"PyNaCl", "pynacl"},
		{"pynacl", "pynacl"},
		{"pyOpenSSL", "pyOpenSSL"},
		{"pyopenssl", "pyOpenSSL"},
		{"requests", ""},
		{"numpy", ""},
		{"", ""},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.input, func(t *testing.T) {
			got := canonicalizePythonPackage(tc.input)
			if got != tc.want {
				t.Errorf("canonicalizePythonPackage(%q) = %q, want %q", tc.input, got, tc.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Zip slip guard tests — absolute paths
// ---------------------------------------------------------------------------

// TestScanWheelAbsolutePathEntrySkipped verifies that zip entries with absolute
// paths are silently skipped and never produce findings. This covers both the
// scanMetadata and scanImports loops.
func TestScanWheelAbsolutePathEntrySkipped(t *testing.T) {
	cases := []struct {
		name    string
		entries map[string]string
	}{
		{
			name: "absolute path METADATA entry skipped",
			entries: map[string]string{
				// Absolute path that would resolve outside the archive root.
				"/etc/passwd.dist-info/METADATA": "Requires-Dist: cryptography\n",
				// Normal entry that should still be processed.
				"safe-1.0.dist-info/METADATA": "Requires-Dist: requests\n",
			},
		},
		{
			name: "absolute path .py entry skipped",
			entries: map[string]string{
				// Absolute-path .py entry — must not produce a finding.
				"/tmp/evil.py": "import cryptography\n",
			},
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			data := buildWheel(t, tc.entries)
			path := writeWheelFile(t, data, "test-1.0-py3-none-any.whl")

			got, err := ScanWheel(context.Background(), path)
			if err != nil {
				t.Fatalf("ScanWheel error: %v", err)
			}

			// The absolute-path entries must never produce a finding.
			for _, f := range got {
				if f.Location.InnerPath == "/etc/passwd.dist-info/METADATA" ||
					f.Location.InnerPath == "/tmp/evil.py" {
					t.Errorf("absolute path entry produced a finding: %+v", f)
				}
			}

			// Additionally, a crypto library from an absolute-path METADATA
			// entry must not appear (the safe entry has only non-crypto deps).
			for _, f := range got {
				if f.Dependency != nil && f.Dependency.Library == "cryptography" {
					t.Errorf("cryptography finding from absolute-path entry must be skipped: %+v", f)
				}
			}
		})
	}
}

func TestIsMetadataFile(t *testing.T) {
	cases := []struct {
		path string
		want bool
	}{
		{"cryptography-3.4.dist-info/METADATA", true},
		{"mypackage-1.0.0.dist-info/METADATA", true},
		{"mypackage-1.0.0.egg-info/PKG-INFO", true},
		{"EGG-INFO/PKG-INFO", true},
		{"mypackage/module.py", false},
		{"cryptography-3.4.dist-info/WHEEL", false},
		{"", false},
		{"METADATA", false},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.path, func(t *testing.T) {
			got := isMetadataFile(tc.path)
			if got != tc.want {
				t.Errorf("isMetadataFile(%q) = %v, want %v", tc.path, got, tc.want)
			}
		})
	}
}
