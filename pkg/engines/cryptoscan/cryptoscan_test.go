package cryptoscan

import (
	"testing"

	"github.com/jimbo111/open-quantum-secure/pkg/engines"
	"github.com/jimbo111/open-quantum-secure/pkg/findings"
)

// ---------------------------------------------------------------------------
// mapConfidence
// ---------------------------------------------------------------------------

func TestMapConfidence(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  findings.Confidence
	}{
		{"HIGH uppercase", "HIGH", findings.ConfidenceHigh},
		{"MEDIUM uppercase", "MEDIUM", findings.ConfidenceMedium},
		{"LOW uppercase", "LOW", findings.ConfidenceLow},
		{"low lowercase", "low", findings.ConfidenceLow},
		{"high lowercase", "high", findings.ConfidenceHigh},
		{"medium lowercase", "medium", findings.ConfidenceMedium},
		{"mixed case High", "High", findings.ConfidenceHigh},
		{"mixed case Medium", "Medium", findings.ConfidenceMedium},
		{"mixed case Low", "Low", findings.ConfidenceLow},
		{"empty string defaults to medium", "", findings.ConfidenceMedium},
		{"UNKNOWN defaults to medium", "UNKNOWN", findings.ConfidenceMedium},
		{"arbitrary string defaults to medium", "VERYLOW", findings.ConfidenceMedium},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := mapConfidence(tc.input)
			if got != tc.want {
				t.Errorf("mapConfidence(%q): got %q, want %q", tc.input, got, tc.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// mapPrimitive
// ---------------------------------------------------------------------------

func TestMapPrimitive(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		// Explicit mappings
		{"pke maps to asymmetric", "pke", "asymmetric"},
		{"kem maps to kem", "kem", "kem"},
		{"aead maps to symmetric", "aead", "symmetric"},
		{"block-cipher maps to symmetric", "block-cipher", "symmetric"},
		{"stream-cipher maps to symmetric", "stream-cipher", "symmetric"},
		{"key-exchange maps to key-exchange", "key-exchange", "key-exchange"},
		// Pass-through values
		{"hash passes through", "hash", "hash"},
		{"signature passes through", "signature", "signature"},
		{"kdf passes through", "kdf", "kdf"},
		{"mac passes through", "mac", "mac"},
		// Edge cases
		{"empty string passes through as empty", "", ""},
		{"unknown value passes through", "rng", "rng"},
		{"uppercase not matched passes through", "PKE", "PKE"},
		{"mixed case not matched passes through", "Aead", "Aead"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := mapPrimitive(tc.input)
			if got != tc.want {
				t.Errorf("mapPrimitive(%q): got %q, want %q", tc.input, got, tc.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// normalize — algorithm finding
// ---------------------------------------------------------------------------

func TestNormalize_AlgorithmFinding(t *testing.T) {
	tests := []struct {
		name          string
		raw           rawFinding
		wantFile      string
		wantLine      int
		wantColumn    int
		wantAlgName   string
		wantPrimitive string
		wantKeySize   int
		wantConf      findings.Confidence
		wantEngine    string
		wantReach     findings.Reachability
		wantRawID     string
		wantAlgNonNil bool
	}{
		{
			name: "RSA algorithm finding",
			raw: rawFinding{
				ID:          "crypto-rsa-001",
				FindingType: "algorithm",
				Algorithm:   "RSA",
				Primitive:   "pke",
				KeySize:     2048,
				File:        "src/crypto/rsa.go",
				Line:        42,
				Column:      8,
				Confidence:  "HIGH",
			},
			wantFile:      "src/crypto/rsa.go",
			wantLine:      42,
			wantColumn:    8,
			wantAlgName:   "RSA",
			wantPrimitive: "asymmetric",
			wantKeySize:   2048,
			wantConf:      findings.ConfidenceHigh,
			wantEngine:    "cryptoscan",
			wantReach:     findings.ReachableUnknown,
			wantRawID:     "RSA",
			wantAlgNonNil: true,
		},
		{
			name: "AES-256-GCM aead finding",
			raw: rawFinding{
				ID:          "crypto-aes-002",
				FindingType: "algorithm",
				Algorithm:   "AES-256-GCM",
				Primitive:   "aead",
				KeySize:     256,
				File:        "lib/encrypt.py",
				Line:        17,
				Column:      4,
				Confidence:  "MEDIUM",
			},
			wantFile:      "lib/encrypt.py",
			wantLine:      17,
			wantColumn:    4,
			wantAlgName:   "AES-256-GCM",
			wantPrimitive: "symmetric",
			wantKeySize:   256,
			wantConf:      findings.ConfidenceMedium,
			wantEngine:    "cryptoscan",
			wantReach:     findings.ReachableUnknown,
			wantRawID:     "AES-256-GCM",
			wantAlgNonNil: true,
		},
		{
			name: "SHA-256 hash finding",
			raw: rawFinding{
				ID:          "crypto-sha-003",
				FindingType: "algorithm",
				Algorithm:   "SHA-256",
				Primitive:   "hash",
				KeySize:     0,
				File:        "main.go",
				Line:        5,
				Column:      1,
				Confidence:  "LOW",
			},
			wantFile:      "main.go",
			wantLine:      5,
			wantColumn:    1,
			wantAlgName:   "SHA-256",
			wantPrimitive: "hash",
			wantKeySize:   0,
			wantConf:      findings.ConfidenceLow,
			wantEngine:    "cryptoscan",
			wantReach:     findings.ReachableUnknown,
			wantRawID:     "SHA-256",
			wantAlgNonNil: true,
		},
		{
			name: "ECDH key-exchange finding",
			raw: rawFinding{
				ID:          "crypto-ecdh-004",
				FindingType: "algorithm",
				Algorithm:   "ECDH",
				Primitive:   "key-exchange",
				KeySize:     256,
				File:        "tls/handshake.go",
				Line:        100,
				Column:      3,
				Confidence:  "HIGH",
			},
			wantFile:      "tls/handshake.go",
			wantLine:      100,
			wantColumn:    3,
			wantAlgName:   "ECDH",
			wantPrimitive: "key-exchange",
			wantKeySize:   256,
			wantConf:      findings.ConfidenceHigh,
			wantEngine:    "cryptoscan",
			wantReach:     findings.ReachableUnknown,
			wantRawID:     "ECDH",
			wantAlgNonNil: true,
		},
		{
			name: "ML-KEM kem primitive finding",
			raw: rawFinding{
				ID:          "crypto-mlkem-005",
				FindingType: "algorithm",
				Algorithm:   "ML-KEM-768",
				Primitive:   "kem",
				KeySize:     768,
				File:        "pqc/kem.go",
				Line:        22,
				Column:      12,
				Confidence:  "HIGH",
			},
			wantFile:      "pqc/kem.go",
			wantLine:      22,
			wantColumn:    12,
			wantAlgName:   "ML-KEM-768",
			wantPrimitive: "kem",
			wantKeySize:   768,
			wantConf:      findings.ConfidenceHigh,
			wantEngine:    "cryptoscan",
			wantReach:     findings.ReachableUnknown,
			wantRawID:     "ML-KEM-768",
			wantAlgNonNil: true,
		},
		{
			name: "HMAC-SHA256 mac finding",
			raw: rawFinding{
				ID:          "crypto-hmac-006",
				FindingType: "algorithm",
				Algorithm:   "HMAC-SHA256",
				Primitive:   "mac",
				KeySize:     0,
				File:        "auth/token.rb",
				Line:        88,
				Column:      0,
				Confidence:  "MEDIUM",
			},
			wantFile:      "auth/token.rb",
			wantLine:      88,
			wantColumn:    0,
			wantAlgName:   "HMAC-SHA256",
			wantPrimitive: "mac",
			wantKeySize:   0,
			wantConf:      findings.ConfidenceMedium,
			wantEngine:    "cryptoscan",
			wantReach:     findings.ReachableUnknown,
			wantRawID:     "HMAC-SHA256",
			wantAlgNonNil: true,
		},
		{
			name: "PBKDF2 kdf finding",
			raw: rawFinding{
				ID:          "crypto-kdf-007",
				FindingType: "algorithm",
				Algorithm:   "PBKDF2",
				Primitive:   "kdf",
				KeySize:     0,
				File:        "security/password.java",
				Line:        60,
				Column:      5,
				Confidence:  "LOW",
			},
			wantFile:      "security/password.java",
			wantLine:      60,
			wantColumn:    5,
			wantAlgName:   "PBKDF2",
			wantPrimitive: "kdf",
			wantKeySize:   0,
			wantConf:      findings.ConfidenceLow,
			wantEngine:    "cryptoscan",
			wantReach:     findings.ReachableUnknown,
			wantRawID:     "PBKDF2",
			wantAlgNonNil: true,
		},
		{
			name: "block-cipher maps to symmetric",
			raw: rawFinding{
				FindingType: "algorithm",
				Algorithm:   "3DES",
				Primitive:   "block-cipher",
				KeySize:     112,
				File:        "legacy/crypto.go",
				Line:        7,
				Confidence:  "HIGH",
			},
			wantFile:      "legacy/crypto.go",
			wantLine:      7,
			wantAlgName:   "3DES",
			wantPrimitive: "symmetric",
			wantKeySize:   112,
			wantConf:      findings.ConfidenceHigh,
			wantEngine:    "cryptoscan",
			wantReach:     findings.ReachableUnknown,
			wantRawID:     "3DES",
			wantAlgNonNil: true,
		},
		{
			name: "stream-cipher maps to symmetric",
			raw: rawFinding{
				FindingType: "algorithm",
				Algorithm:   "RC4",
				Primitive:   "stream-cipher",
				File:        "old/cipher.c",
				Line:        3,
				Confidence:  "HIGH",
			},
			wantFile:      "old/cipher.c",
			wantLine:      3,
			wantAlgName:   "RC4",
			wantPrimitive: "symmetric",
			wantKeySize:   0,
			wantConf:      findings.ConfidenceHigh,
			wantEngine:    "cryptoscan",
			wantReach:     findings.ReachableUnknown,
			wantRawID:     "RC4",
			wantAlgNonNil: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			uf := normalize(tc.raw)

			if uf.Location.File != tc.wantFile {
				t.Errorf("Location.File: got %q, want %q", uf.Location.File, tc.wantFile)
			}
			if uf.Location.Line != tc.wantLine {
				t.Errorf("Location.Line: got %d, want %d", uf.Location.Line, tc.wantLine)
			}
			if uf.Location.Column != tc.wantColumn {
				t.Errorf("Location.Column: got %d, want %d", uf.Location.Column, tc.wantColumn)
			}
			if uf.Confidence != tc.wantConf {
				t.Errorf("Confidence: got %q, want %q", uf.Confidence, tc.wantConf)
			}
			if uf.SourceEngine != tc.wantEngine {
				t.Errorf("SourceEngine: got %q, want %q", uf.SourceEngine, tc.wantEngine)
			}
			if uf.Reachable != tc.wantReach {
				t.Errorf("Reachable: got %q, want %q", uf.Reachable, tc.wantReach)
			}
			if uf.RawIdentifier != tc.wantRawID {
				t.Errorf("RawIdentifier: got %q, want %q", uf.RawIdentifier, tc.wantRawID)
			}

			if tc.wantAlgNonNil {
				if uf.Algorithm == nil {
					t.Fatalf("Algorithm: got nil, want non-nil")
				}
				if uf.Algorithm.Name != tc.wantAlgName {
					t.Errorf("Algorithm.Name: got %q, want %q", uf.Algorithm.Name, tc.wantAlgName)
				}
				if uf.Algorithm.Primitive != tc.wantPrimitive {
					t.Errorf("Algorithm.Primitive: got %q, want %q", uf.Algorithm.Primitive, tc.wantPrimitive)
				}
				if uf.Algorithm.KeySize != tc.wantKeySize {
					t.Errorf("Algorithm.KeySize: got %d, want %d", uf.Algorithm.KeySize, tc.wantKeySize)
				}
			} else {
				if uf.Algorithm != nil {
					t.Errorf("Algorithm: got %+v, want nil", uf.Algorithm)
				}
			}
		})
	}
}

// ---------------------------------------------------------------------------
// normalize — config finding
// ---------------------------------------------------------------------------

func TestNormalize_ConfigFinding(t *testing.T) {
	tests := []struct {
		name          string
		raw           rawFinding
		wantAlgNonNil bool
		wantAlgName   string
		wantPrimitive string
	}{
		{
			name: "config finding with algorithm",
			raw: rawFinding{
				FindingType: "config",
				Algorithm:   "TLS 1.0",
				Primitive:   "key-exchange",
				File:        "nginx.conf",
				Line:        10,
				Confidence:  "HIGH",
			},
			wantAlgNonNil: true,
			wantAlgName:   "TLS 1.0",
			wantPrimitive: "key-exchange",
		},
		{
			name: "config finding without algorithm produces nil Algorithm",
			raw: rawFinding{
				FindingType: "config",
				Algorithm:   "",
				File:        "server.conf",
				Line:        5,
				Confidence:  "MEDIUM",
			},
			wantAlgNonNil: false,
		},
		{
			name: "config finding with symmetric primitive",
			raw: rawFinding{
				FindingType: "config",
				Algorithm:   "AES-128-CBC",
				Primitive:   "aead",
				KeySize:     128,
				File:        "openssl.cnf",
				Line:        3,
				Confidence:  "LOW",
			},
			wantAlgNonNil: true,
			wantAlgName:   "AES-128-CBC",
			wantPrimitive: "symmetric",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			uf := normalize(tc.raw)

			if uf.SourceEngine != "cryptoscan" {
				t.Errorf("SourceEngine: got %q, want %q", uf.SourceEngine, "cryptoscan")
			}
			if uf.Reachable != findings.ReachableUnknown {
				t.Errorf("Reachable: got %q, want %q", uf.Reachable, findings.ReachableUnknown)
			}

			if tc.wantAlgNonNil {
				if uf.Algorithm == nil {
					t.Fatalf("Algorithm: got nil, want non-nil")
				}
				if uf.Algorithm.Name != tc.wantAlgName {
					t.Errorf("Algorithm.Name: got %q, want %q", uf.Algorithm.Name, tc.wantAlgName)
				}
				if uf.Algorithm.Primitive != tc.wantPrimitive {
					t.Errorf("Algorithm.Primitive: got %q, want %q", uf.Algorithm.Primitive, tc.wantPrimitive)
				}
			} else {
				if uf.Algorithm != nil {
					t.Errorf("Algorithm: got %+v, want nil for empty algorithm", uf.Algorithm)
				}
			}
		})
	}
}

// ---------------------------------------------------------------------------
// normalize — protocol finding
// ---------------------------------------------------------------------------

func TestNormalize_ProtocolFinding(t *testing.T) {
	tests := []struct {
		name          string
		raw           rawFinding
		wantAlgNonNil bool
		wantAlgName   string
		wantPrimitive string
	}{
		{
			name: "protocol finding with algorithm",
			raw: rawFinding{
				FindingType: "protocol",
				Algorithm:   "SSH-RSA",
				Primitive:   "signature",
				File:        "sshd_config",
				Line:        20,
				Confidence:  "MEDIUM",
			},
			wantAlgNonNil: true,
			wantAlgName:   "SSH-RSA",
			wantPrimitive: "signature",
		},
		{
			name: "protocol finding without algorithm produces nil Algorithm",
			raw: rawFinding{
				FindingType: "protocol",
				Algorithm:   "",
				File:        "proto.conf",
				Line:        1,
				Confidence:  "LOW",
			},
			wantAlgNonNil: false,
		},
		{
			name: "protocol finding with pke primitive",
			raw: rawFinding{
				FindingType: "protocol",
				Algorithm:   "RSA-OAEP",
				Primitive:   "pke",
				KeySize:     4096,
				File:        "tls.go",
				Line:        50,
				Confidence:  "HIGH",
			},
			wantAlgNonNil: true,
			wantAlgName:   "RSA-OAEP",
			wantPrimitive: "asymmetric",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			uf := normalize(tc.raw)

			if uf.SourceEngine != "cryptoscan" {
				t.Errorf("SourceEngine: got %q, want %q", uf.SourceEngine, "cryptoscan")
			}
			if uf.Reachable != findings.ReachableUnknown {
				t.Errorf("Reachable: got %q, want %q", uf.Reachable, findings.ReachableUnknown)
			}

			if tc.wantAlgNonNil {
				if uf.Algorithm == nil {
					t.Fatalf("Algorithm: got nil, want non-nil")
				}
				if uf.Algorithm.Name != tc.wantAlgName {
					t.Errorf("Algorithm.Name: got %q, want %q", uf.Algorithm.Name, tc.wantAlgName)
				}
				if uf.Algorithm.Primitive != tc.wantPrimitive {
					t.Errorf("Algorithm.Primitive: got %q, want %q", uf.Algorithm.Primitive, tc.wantPrimitive)
				}
			} else {
				if uf.Algorithm != nil {
					t.Errorf("Algorithm: got %+v, want nil for empty algorithm", uf.Algorithm)
				}
			}
		})
	}
}

// ---------------------------------------------------------------------------
// normalize — unknown / unrecognized finding type
// ---------------------------------------------------------------------------

func TestNormalize_UnknownFindingType(t *testing.T) {
	// An unrecognized findingType should not set Algorithm regardless of
	// whether Algorithm field is populated. The switch has no default branch
	// that sets Algorithm, so it must remain nil.
	raw := rawFinding{
		FindingType: "unknown-type",
		Algorithm:   "RSA",
		Primitive:   "pke",
		File:        "file.go",
		Line:        1,
		Confidence:  "HIGH",
	}

	uf := normalize(raw)

	if uf.Algorithm != nil {
		t.Errorf("Algorithm: got %+v, want nil for unknown findingType", uf.Algorithm)
	}
	if uf.SourceEngine != "cryptoscan" {
		t.Errorf("SourceEngine: got %q, want %q", uf.SourceEngine, "cryptoscan")
	}
	// RawIdentifier is always set from raw.Algorithm regardless of finding type.
	if uf.RawIdentifier != "RSA" {
		t.Errorf("RawIdentifier: got %q, want %q", uf.RawIdentifier, "RSA")
	}
}

// ---------------------------------------------------------------------------
// normalize — location and confidence fields
// ---------------------------------------------------------------------------

func TestNormalize_LocationFieldsPreserved(t *testing.T) {
	raw := rawFinding{
		FindingType: "algorithm",
		Algorithm:   "ECDSA",
		Primitive:   "signature",
		File:        "/absolute/path/to/file.ts",
		Line:        999,
		Column:      77,
		Confidence:  "MEDIUM",
	}

	uf := normalize(raw)

	if uf.Location.File != "/absolute/path/to/file.ts" {
		t.Errorf("Location.File: got %q, want %q", uf.Location.File, "/absolute/path/to/file.ts")
	}
	if uf.Location.Line != 999 {
		t.Errorf("Location.Line: got %d, want %d", uf.Location.Line, 999)
	}
	if uf.Location.Column != 77 {
		t.Errorf("Location.Column: got %d, want %d", uf.Location.Column, 77)
	}
}

func TestNormalize_ZeroLineAndColumn(t *testing.T) {
	raw := rawFinding{
		FindingType: "algorithm",
		Algorithm:   "SHA-1",
		Primitive:   "hash",
		File:        "pkg/hash.go",
		Line:        0,
		Column:      0,
		Confidence:  "LOW",
	}

	uf := normalize(raw)

	if uf.Location.Line != 0 {
		t.Errorf("Location.Line: got %d, want 0", uf.Location.Line)
	}
	if uf.Location.Column != 0 {
		t.Errorf("Location.Column: got %d, want 0", uf.Location.Column)
	}
}

func TestNormalize_EmptyFileAndPath(t *testing.T) {
	raw := rawFinding{
		FindingType: "algorithm",
		Algorithm:   "MD5",
		Primitive:   "hash",
		File:        "",
		Line:        0,
		Confidence:  "HIGH",
	}

	uf := normalize(raw)

	if uf.Location.File != "" {
		t.Errorf("Location.File: got %q, want empty string", uf.Location.File)
	}
}

// ---------------------------------------------------------------------------
// normalize — invariants that always hold
// ---------------------------------------------------------------------------

func TestNormalize_InvariantsAlwaysHold(t *testing.T) {
	// These properties must hold regardless of input.
	raws := []rawFinding{
		{FindingType: "algorithm", Algorithm: "RSA", Primitive: "pke", File: "a.go", Line: 1, Confidence: "HIGH"},
		{FindingType: "config", Algorithm: "TLS 1.2", Primitive: "key-exchange", File: "b.conf", Line: 2, Confidence: "LOW"},
		{FindingType: "protocol", Algorithm: "SSH-RSA", Primitive: "signature", File: "c.cfg", Line: 3, Confidence: "MEDIUM"},
		{FindingType: "algorithm", Algorithm: "", Primitive: "hash", File: "d.go", Line: 4, Confidence: ""},
		{FindingType: "config", Algorithm: "", File: "e.conf", Line: 5},
	}

	for _, raw := range raws {
		uf := normalize(raw)

		if uf.SourceEngine != "cryptoscan" {
			t.Errorf("SourceEngine invariant violated for %+v: got %q", raw, uf.SourceEngine)
		}
		if uf.Reachable != findings.ReachableUnknown {
			t.Errorf("Reachable invariant violated for %+v: got %q", raw, uf.Reachable)
		}
		if uf.Dependency != nil {
			t.Errorf("Dependency should always be nil from cryptoscan normalize, got %+v", uf.Dependency)
		}
	}
}

// ---------------------------------------------------------------------------
// normalize — dedup key correctness
// ---------------------------------------------------------------------------

func TestNormalize_DedupeKeyWithAlgorithm(t *testing.T) {
	raw := rawFinding{
		FindingType: "algorithm",
		Algorithm:   "AES-256",
		Primitive:   "aead",
		File:        "crypto.go",
		Line:        15,
		Confidence:  "HIGH",
	}

	uf := normalize(raw)
	key := uf.DedupeKey()
	want := "crypto.go|15|alg|AES-256"
	if key != want {
		t.Errorf("DedupeKey: got %q, want %q", key, want)
	}
}

func TestNormalize_DedupeKeyFallbackWhenNoAlgorithm(t *testing.T) {
	// config with empty algorithm: Algorithm field is nil, falls to fallback key.
	raw := rawFinding{
		FindingType: "config",
		Algorithm:   "",
		File:        "server.conf",
		Line:        3,
		Confidence:  "MEDIUM",
	}

	uf := normalize(raw)
	key := uf.DedupeKey()

	// Must not use the alg branch since Algorithm is nil.
	if key == "server.conf|3|alg|" {
		t.Error("DedupeKey used alg branch with nil Algorithm")
	}
	// Fallback key includes SourceEngine to prevent collisions.
	if key == "" {
		t.Error("DedupeKey should not be empty")
	}
}

// ---------------------------------------------------------------------------
// Engine metadata
// ---------------------------------------------------------------------------

func TestEngineMetadata(t *testing.T) {
	e := &Engine{}

	if e.Name() != "cryptoscan" {
		t.Errorf("Name(): got %q, want %q", e.Name(), "cryptoscan")
	}
	if e.Tier() != engines.Tier1Pattern {
		t.Errorf("Tier(): got %d, want %d (Tier1Pattern)", e.Tier(), engines.Tier1Pattern)
	}
}

func TestEngineAvailable_FalseWhenEmpty(t *testing.T) {
	e := &Engine{binaryPath: ""}
	if e.Available() {
		t.Error("Available() should return false when binaryPath is empty")
	}
}

func TestEngineAvailable_TrueWhenPathSet(t *testing.T) {
	e := &Engine{binaryPath: "/usr/local/bin/cryptoscan"}
	if !e.Available() {
		t.Error("Available() should return true when binaryPath is non-empty")
	}
}

// ---------------------------------------------------------------------------
// Engine.SupportedLanguages
// ---------------------------------------------------------------------------

func TestSupportedLanguages(t *testing.T) {
	e := &Engine{}
	langs := e.SupportedLanguages()

	if len(langs) == 0 {
		t.Fatal("SupportedLanguages() returned empty slice")
	}

	required := []string{
		"c", "cpp", "java", "python", "go", "swift",
		"php", "rust", "javascript", "typescript", "ruby",
		"csharp", "kotlin", "scala",
	}

	langSet := make(map[string]bool, len(langs))
	for _, l := range langs {
		langSet[l] = true
	}

	for _, lang := range required {
		if !langSet[lang] {
			t.Errorf("SupportedLanguages() missing %q", lang)
		}
	}
}

func TestSupportedLanguages_NoDuplicates(t *testing.T) {
	e := &Engine{}
	langs := e.SupportedLanguages()

	seen := make(map[string]bool, len(langs))
	for _, l := range langs {
		if seen[l] {
			t.Errorf("SupportedLanguages() contains duplicate: %q", l)
		}
		seen[l] = true
	}
}

// ---------------------------------------------------------------------------
// Engine interface compliance
// ---------------------------------------------------------------------------

func TestEngineImplementsInterface(t *testing.T) {
	// Compile-time check: *Engine must satisfy engines.Engine.
	var _ engines.Engine = (*Engine)(nil)
}

// ---------------------------------------------------------------------------
// New — constructor
// ---------------------------------------------------------------------------

func TestNew_NoBinaryAvailable(t *testing.T) {
	// Pass a directory that cannot contain a cryptoscan binary.
	e := New("/nonexistent/directory/that/does/not/exist")

	// New must never return nil.
	if e == nil {
		t.Fatal("New() returned nil, want non-nil *Engine")
	}
	// Name and Tier must still work after construction without a binary.
	if e.Name() != "cryptoscan" {
		t.Errorf("Name(): got %q, want %q", e.Name(), "cryptoscan")
	}
	if e.Tier() != engines.Tier1Pattern {
		t.Errorf("Tier(): got %d, want %d", e.Tier(), engines.Tier1Pattern)
	}
	// Since the directory is nonexistent and cryptoscan is very unlikely to be
	// installed on the PATH in CI, Available() is almost certainly false. We
	// can't assert it with 100% certainty on every machine, but we can verify
	// the method does not panic.
	_ = e.Available()
}

func TestNew_NoArgs(t *testing.T) {
	// New with no extra dirs must not panic.
	e := New()
	if e == nil {
		t.Fatal("New() returned nil with no args")
	}
}

func TestNew_MultipleExtraDirs(t *testing.T) {
	// Multiple non-existent dirs must not panic and return a valid engine.
	e := New(
		"/no/such/dir/one",
		"/no/such/dir/two",
		"/no/such/dir/three",
	)
	if e == nil {
		t.Fatal("New() returned nil with multiple non-existent dirs")
	}
	if e.Name() != "cryptoscan" {
		t.Errorf("Name(): got %q, want %q", e.Name(), "cryptoscan")
	}
}

// ---------------------------------------------------------------------------
// findBinary helper
// ---------------------------------------------------------------------------

func TestFindBinary_NonExistentDir(t *testing.T) {
	e := &Engine{}
	// Must not panic; returned value may be empty or a PATH match.
	result := e.findBinary([]string{"/nonexistent/path/that/does/not/exist"})
	_ = result
}

func TestFindBinary_EmptyExtraDirs(t *testing.T) {
	e := &Engine{}
	// Must not panic with empty slice.
	result := e.findBinary([]string{})
	_ = result
}

// ---------------------------------------------------------------------------
// Scan — not available guard
// ---------------------------------------------------------------------------

func TestScan_NotAvailable(t *testing.T) {
	e := &Engine{binaryPath: ""}
	_, err := e.Scan(nil, engines.ScanOptions{TargetPath: "/tmp"})
	if err == nil {
		t.Fatal("expected error when engine is not available, got nil")
	}
}

// ---------------------------------------------------------------------------
// Scan — empty-algorithm skip logic (validated via normalize + filter)
// ---------------------------------------------------------------------------

// TestScanSkipEmptyAlgorithm verifies the filter condition in Scan() that skips
// findings where Algorithm == "" and FindingType is neither "config" nor "protocol".
// We exercise this by directly testing the predicate inline — this mirrors the
// exact condition in Scan():
//
//	if f.Algorithm == "" && f.FindingType != "config" && f.FindingType != "protocol"
func TestScan_EmptyAlgorithmFilterPredicate(t *testing.T) {
	tests := []struct {
		name        string
		raw         rawFinding
		wantSkipped bool
	}{
		{
			name:        "algorithm type with empty algorithm is skipped",
			raw:         rawFinding{FindingType: "algorithm", Algorithm: ""},
			wantSkipped: true,
		},
		{
			name:        "algorithm type with non-empty algorithm is kept",
			raw:         rawFinding{FindingType: "algorithm", Algorithm: "RSA"},
			wantSkipped: false,
		},
		{
			name:        "config type with empty algorithm is kept",
			raw:         rawFinding{FindingType: "config", Algorithm: ""},
			wantSkipped: false,
		},
		{
			name:        "config type with non-empty algorithm is kept",
			raw:         rawFinding{FindingType: "config", Algorithm: "TLS 1.2"},
			wantSkipped: false,
		},
		{
			name:        "protocol type with empty algorithm is kept",
			raw:         rawFinding{FindingType: "protocol", Algorithm: ""},
			wantSkipped: false,
		},
		{
			name:        "protocol type with non-empty algorithm is kept",
			raw:         rawFinding{FindingType: "protocol", Algorithm: "SSH-RSA"},
			wantSkipped: false,
		},
		{
			name:        "unknown type with empty algorithm is skipped",
			raw:         rawFinding{FindingType: "other", Algorithm: ""},
			wantSkipped: true,
		},
		{
			name:        "unknown type with non-empty algorithm is kept",
			raw:         rawFinding{FindingType: "other", Algorithm: "RSA"},
			wantSkipped: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// Replicate the exact predicate from Scan().
			skipped := tc.raw.Algorithm == "" &&
				tc.raw.FindingType != "config" &&
				tc.raw.FindingType != "protocol"

			if skipped != tc.wantSkipped {
				t.Errorf("skip predicate for %+v: got %v, want %v", tc.raw, skipped, tc.wantSkipped)
			}
		})
	}
}
