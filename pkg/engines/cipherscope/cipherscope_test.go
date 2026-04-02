package cipherscope

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/jimbo111/open-quantum-secure/pkg/engines"
	"github.com/jimbo111/open-quantum-secure/pkg/findings"
)

// ----------------------------------------------------------------------------
// parseKeySize
// ----------------------------------------------------------------------------

func TestParseKeySize(t *testing.T) {
	tests := []struct {
		name string
		in   interface{}
		want int
	}{
		{
			name: "float64 256",
			in:   float64(256),
			want: 256,
		},
		{
			name: "float64 128",
			in:   float64(128),
			want: 128,
		},
		{
			name: "float64 zero",
			in:   float64(0),
			want: 0,
		},
		{
			name: "int 128",
			in:   int(128),
			want: 128,
		},
		{
			name: "int 4096",
			in:   int(4096),
			want: 4096,
		},
		{
			name: "int zero",
			in:   int(0),
			want: 0,
		},
		{
			name: "string 256",
			in:   "256",
			want: 256,
		},
		{
			name: "string 512",
			in:   "512",
			want: 512,
		},
		{
			name: "string zero",
			in:   "0",
			want: 0,
		},
		{
			name: "string non-numeric abc",
			in:   "abc",
			want: 0,
		},
		{
			name: "string empty",
			in:   "",
			want: 0,
		},
		{
			name: "nil",
			in:   nil,
			want: 0,
		},
		{
			name: "bool true (unsupported type)",
			in:   true,
			want: 0,
		},
		{
			name: "float64 fractional rejected",
			in:   float64(256.9),
			want: 0,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := parseKeySize(tc.in)
			if got != tc.want {
				t.Errorf("parseKeySize(%v) = %d, want %d", tc.in, got, tc.want)
			}
		})
	}
}

// ----------------------------------------------------------------------------
// parseAlgorithm
// ----------------------------------------------------------------------------

func TestParseAlgorithm(t *testing.T) {
	tests := []struct {
		name       string
		identifier string
		wantName   string
		wantKey    int
		wantMode   string
		wantCurve  string
	}{
		{
			name:       "simple RSA no parts",
			identifier: "RSA",
			wantName:   "RSA",
			wantKey:    0,
			wantMode:   "",
			wantCurve:  "",
		},
		{
			name:       "AES-256-GCM keysize and mode",
			identifier: "AES-256-GCM",
			wantName:   "AES-256-GCM",
			wantKey:    256,
			wantMode:   "GCM",
			wantCurve:  "",
		},
		{
			name:       "AES-128-CBC",
			identifier: "AES-128-CBC",
			wantName:   "AES-128-CBC",
			wantKey:    128,
			wantMode:   "CBC",
			wantCurve:  "",
		},
		{
			name:       "ECDH-P256 curve extraction",
			identifier: "ECDH-P256",
			wantName:   "ECDH-P256",
			wantKey:    0,
			wantMode:   "",
			wantCurve:  "P256",
		},
		{
			name:       "ECDSA-P384 curve extraction",
			identifier: "ECDSA-P384",
			wantName:   "ECDSA-P384",
			wantKey:    0,
			wantMode:   "",
			wantCurve:  "P384",
		},
		{
			name:       "ECDH-X25519 curve extraction",
			identifier: "ECDH-X25519",
			wantName:   "ECDH-X25519",
			wantKey:    0,
			wantMode:   "",
			wantCurve:  "X25519",
		},
		{
			name: "SHA-1 number less than 64 should NOT be treated as keysize",
			// "1" < 64, so the numeric part should not set KeySize
			identifier: "SHA-1",
			wantName:   "SHA-1",
			wantKey:    0,
			wantMode:   "",
			wantCurve:  "",
		},
		{
			name: "SHA-3 number less than 64 should NOT be treated as keysize",
			identifier: "SHA-3",
			wantName:   "SHA-3",
			wantKey:    0,
			wantMode:   "",
			wantCurve:  "",
		},
		{
			name: "SHA-256 number exactly 256 treated as keysize",
			// 256 >= 64, so it will be treated as a keysize (by design)
			identifier: "SHA-256",
			wantName:   "SHA-256",
			wantKey:    256,
			wantMode:   "",
			wantCurve:  "",
		},
		{
			name:       "AES-128-CBC-PKCS5 multiple parts unknown suffix ignored",
			identifier: "AES-128-CBC-PKCS5",
			wantName:   "AES-128-CBC-PKCS5",
			wantKey:    128,
			wantMode:   "CBC",
			wantCurve:  "",
		},
		{
			name:       "AES-256-CTR mode CTR",
			identifier: "AES-256-CTR",
			wantName:   "AES-256-CTR",
			wantKey:    256,
			wantMode:   "CTR",
			wantCurve:  "",
		},
		{
			name:       "AES-256-ECB mode ECB",
			identifier: "AES-256-ECB",
			wantName:   "AES-256-ECB",
			wantKey:    256,
			wantMode:   "ECB",
			wantCurve:  "",
		},
		{
			name:       "AES-256-XTS mode XTS",
			identifier: "AES-256-XTS",
			wantName:   "AES-256-XTS",
			wantKey:    256,
			wantMode:   "XTS",
			wantCurve:  "",
		},
		{
			name:       "RSA-4096 keysize only",
			identifier: "RSA-4096",
			wantName:   "RSA-4096",
			wantKey:    4096,
			wantMode:   "",
			wantCurve:  "",
		},
		{
			name:       "ED25519 curve as sole suffix part",
			identifier: "ED-ED25519",
			wantName:   "ED-ED25519",
			wantKey:    0,
			wantMode:   "",
			wantCurve:  "ED25519",
		},
		{
			name:       "CURVE25519 as curve part",
			identifier: "DH-CURVE25519",
			wantName:   "DH-CURVE25519",
			wantKey:    0,
			wantMode:   "",
			wantCurve:  "CURVE25519",
		},
		{
			name:       "mode lowercase normalised to upper",
			identifier: "AES-128-gcm",
			wantName:   "AES-128-gcm",
			wantKey:    128,
			wantMode:   "GCM",
			wantCurve:  "",
		},
		{
			name:       "unknown suffix not a number, not a mode, not a curve — ignored",
			identifier: "ALGO-FOOBAR",
			wantName:   "ALGO-FOOBAR",
			wantKey:    0,
			wantMode:   "",
			wantCurve:  "",
		},
		{
			name:       "empty identifier",
			identifier: "",
			wantName:   "",
			wantKey:    0,
			wantMode:   "",
			wantCurve:  "",
		},
		{
			name: "number exactly 63 should NOT be keysize",
			// 63 < 64, must not be treated as key size
			identifier: "ALGO-63",
			wantName:   "ALGO-63",
			wantKey:    0,
			wantMode:   "",
			wantCurve:  "",
		},
		{
			name: "number exactly 64 should be keysize",
			identifier: "ALGO-64",
			wantName:   "ALGO-64",
			wantKey:    64,
			wantMode:   "",
			wantCurve:  "",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := parseAlgorithm(tc.identifier)

			if got.Name != tc.wantName {
				t.Errorf("Name: got %q, want %q", got.Name, tc.wantName)
			}
			if got.KeySize != tc.wantKey {
				t.Errorf("KeySize: got %d, want %d", got.KeySize, tc.wantKey)
			}
			if got.Mode != tc.wantMode {
				t.Errorf("Mode: got %q, want %q", got.Mode, tc.wantMode)
			}
			if got.Curve != tc.wantCurve {
				t.Errorf("Curve: got %q, want %q", got.Curve, tc.wantCurve)
			}
		})
	}
}

// ----------------------------------------------------------------------------
// normalize
// ----------------------------------------------------------------------------

func TestNormalize(t *testing.T) {
	tests := []struct {
		name string
		raw  rawFinding
		// expected top-level fields
		wantFile       string
		wantLine       int
		wantColumn     int
		wantConfidence findings.Confidence
		wantEngine     string
		wantReachable  findings.Reachability
		wantRawID      string
		// algorithm expectations (nil = expect no Algorithm)
		wantAlgName  string
		wantAlgKey   int
		wantAlgMode  string
		wantAlgCurve string
		wantAlgPrim  string
		// dependency expectation (empty = expect no Dependency)
		wantLibrary string
	}{
		{
			name: "algorithm AES-256-GCM no metadata",
			raw: rawFinding{
				AssetType:  "algorithm",
				Identifier: "AES-256-GCM",
				Path:       "src/crypto.go",
				Evidence:   rawEvidence{Line: 42, Column: 7},
			},
			wantFile:       "src/crypto.go",
			wantLine:       42,
			wantColumn:     7,
			wantConfidence: findings.ConfidenceMedium,
			wantEngine:     "cipherscope",
			wantReachable:  findings.ReachableUnknown,
			wantRawID:      "AES-256-GCM",
			wantAlgName:    "AES-256-GCM",
			wantAlgKey:     256,
			wantAlgMode:    "GCM",
		},
		{
			name: "algorithm with metadata overlay overrides parsed fields",
			raw: rawFinding{
				AssetType:  "algorithm",
				Identifier: "AES-256-GCM",
				Path:       "lib/enc.c",
				Evidence:   rawEvidence{Line: 10, Column: 1},
				Metadata:   mustMarshalMeta(rawMetadata{Primitive: "symmetric", Mode: "CBC", KeySize: float64(128)}),
			},
			wantFile:       "lib/enc.c",
			wantLine:       10,
			wantColumn:     1,
			wantConfidence: findings.ConfidenceMedium,
			wantEngine:     "cipherscope",
			wantReachable:  findings.ReachableUnknown,
			wantRawID:      "AES-256-GCM",
			// Metadata wins: mode=CBC, primitive=symmetric, keysize=128
			wantAlgName: "AES-256-GCM",
			wantAlgKey:  128,
			wantAlgMode: "CBC",
			wantAlgPrim: "symmetric",
		},
		{
			name: "algorithm metadata partial overlay only non-empty fields replace",
			raw: rawFinding{
				AssetType:  "algorithm",
				Identifier: "AES-256-GCM",
				Path:       "a.py",
				Evidence:   rawEvidence{Line: 5, Column: 0},
				// Only primitive in metadata; mode and keysize absent (empty/zero)
				Metadata: mustMarshalMeta(rawMetadata{Primitive: "symmetric"}),
			},
			wantFile:      "a.py",
			wantLine:      5,
			wantColumn:    0,
			wantConfidence: findings.ConfidenceMedium,
			wantEngine:    "cipherscope",
			wantReachable: findings.ReachableUnknown,
			wantRawID:     "AES-256-GCM",
			// parseAlgorithm sets Key=256, Mode=GCM; metadata adds Primitive only
			wantAlgName: "AES-256-GCM",
			wantAlgKey:  256,
			wantAlgMode: "GCM",
			wantAlgPrim: "symmetric",
		},
		{
			name: "algorithm metadata curve overlay",
			raw: rawFinding{
				AssetType:  "algorithm",
				Identifier: "ECDH",
				Path:       "keys/gen.rs",
				Evidence:   rawEvidence{Line: 99, Column: 3},
				Metadata:   mustMarshalMeta(rawMetadata{Curve: "P256", Primitive: "asymmetric"}),
			},
			wantFile:      "keys/gen.rs",
			wantLine:      99,
			wantColumn:    3,
			wantConfidence: findings.ConfidenceMedium,
			wantEngine:    "cipherscope",
			wantReachable: findings.ReachableUnknown,
			wantRawID:     "ECDH",
			wantAlgName:   "ECDH",
			wantAlgKey:    0,
			wantAlgMode:   "",
			wantAlgCurve:  "P256",
			wantAlgPrim:   "asymmetric",
		},
		{
			name: "algorithm metadata keysize zero does not override parsed keysize",
			raw: rawFinding{
				AssetType:  "algorithm",
				Identifier: "AES-256-GCM",
				Path:       "b.java",
				Evidence:   rawEvidence{Line: 1, Column: 0},
				// keysize = 0 in metadata — should NOT override the 256 from parsing
				Metadata: mustMarshalMeta(rawMetadata{KeySize: float64(0)}),
			},
			wantFile:      "b.java",
			wantLine:      1,
			wantColumn:    0,
			wantConfidence: findings.ConfidenceMedium,
			wantEngine:    "cipherscope",
			wantReachable: findings.ReachableUnknown,
			wantRawID:     "AES-256-GCM",
			wantAlgName:   "AES-256-GCM",
			wantAlgKey:    256, // parsed value preserved
			wantAlgMode:   "GCM",
		},
		{
			name: "library finding produces Dependency not Algorithm",
			raw: rawFinding{
				AssetType:  "library",
				Identifier: "OpenSSL",
				Path:       "CMakeLists.txt",
				Evidence:   rawEvidence{Line: 3, Column: 0},
			},
			wantFile:       "CMakeLists.txt",
			wantLine:       3,
			wantColumn:     0,
			wantConfidence: findings.ConfidenceMedium,
			wantEngine:     "cipherscope",
			wantReachable:  findings.ReachableUnknown,
			wantRawID:      "OpenSSL",
			wantLibrary:    "OpenSSL",
		},
		{
			name: "library finding has nil Algorithm",
			raw: rawFinding{
				AssetType:  "library",
				Identifier: "BouncyCastle",
				Path:       "pom.xml",
				Evidence:   rawEvidence{Line: 12, Column: 5},
			},
			wantFile:      "pom.xml",
			wantLine:      12,
			wantColumn:    5,
			wantConfidence: findings.ConfidenceMedium,
			wantEngine:    "cipherscope",
			wantReachable: findings.ReachableUnknown,
			wantRawID:     "BouncyCastle",
			wantLibrary:   "BouncyCastle",
			// wantAlgName left empty → caller checks uf.Algorithm == nil
		},
		{
			name: "unknown assetType sets neither Algorithm nor Dependency",
			raw: rawFinding{
				AssetType:  "unknown",
				Identifier: "something",
				Path:       "x.go",
				Evidence:   rawEvidence{Line: 1, Column: 1},
			},
			wantFile:       "x.go",
			wantLine:       1,
			wantColumn:     1,
			wantConfidence: findings.ConfidenceMedium,
			wantEngine:     "cipherscope",
			wantReachable:  findings.ReachableUnknown,
			wantRawID:      "something",
			// neither algorithm nor library
		},
		{
			name: "algorithm simple RSA without metadata",
			raw: rawFinding{
				AssetType:  "algorithm",
				Identifier: "RSA",
				Path:       "crypto/rsa.go",
				Evidence:   rawEvidence{Line: 7, Column: 2},
			},
			wantFile:       "crypto/rsa.go",
			wantLine:       7,
			wantColumn:     2,
			wantConfidence: findings.ConfidenceMedium,
			wantEngine:     "cipherscope",
			wantReachable:  findings.ReachableUnknown,
			wantRawID:      "RSA",
			wantAlgName:    "RSA",
			wantAlgKey:     0,
			wantAlgMode:    "",
			wantAlgCurve:   "",
		},
		{
			name: "algorithm ECDH-P256 no metadata",
			raw: rawFinding{
				AssetType:  "algorithm",
				Identifier: "ECDH-P256",
				Path:       "tls/conn.go",
				Evidence:   rawEvidence{Line: 200, Column: 10},
			},
			wantFile:       "tls/conn.go",
			wantLine:       200,
			wantColumn:     10,
			wantConfidence: findings.ConfidenceMedium,
			wantEngine:     "cipherscope",
			wantReachable:  findings.ReachableUnknown,
			wantRawID:      "ECDH-P256",
			wantAlgName:    "ECDH-P256",
			wantAlgKey:     0,
			wantAlgMode:    "",
			wantAlgCurve:   "P256",
		},
		{
			name: "malformed metadata JSON is silently ignored",
			raw: rawFinding{
				AssetType:  "algorithm",
				Identifier: "AES-128-CBC",
				Path:       "enc.go",
				Evidence:   rawEvidence{Line: 55, Column: 0},
				Metadata:   json.RawMessage(`{invalid json`),
			},
			wantFile:       "enc.go",
			wantLine:       55,
			wantColumn:     0,
			wantConfidence: findings.ConfidenceMedium,
			wantEngine:     "cipherscope",
			wantReachable:  findings.ReachableUnknown,
			wantRawID:      "AES-128-CBC",
			// Parsing still runs from identifier; metadata unmarshal fails silently
			wantAlgName: "AES-128-CBC",
			wantAlgKey:  128,
			wantAlgMode: "CBC",
		},
		{
			name: "zero line and column preserved",
			raw: rawFinding{
				AssetType:  "algorithm",
				Identifier: "MD5",
				Path:       "hash.c",
				Evidence:   rawEvidence{Line: 0, Column: 0},
			},
			wantFile:       "hash.c",
			wantLine:       0,
			wantColumn:     0,
			wantConfidence: findings.ConfidenceMedium,
			wantEngine:     "cipherscope",
			wantReachable:  findings.ReachableUnknown,
			wantRawID:      "MD5",
			wantAlgName:    "MD5",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			uf := normalize(tc.raw)

			// --- Location ---
			if uf.Location.File != tc.wantFile {
				t.Errorf("Location.File: got %q, want %q", uf.Location.File, tc.wantFile)
			}
			if uf.Location.Line != tc.wantLine {
				t.Errorf("Location.Line: got %d, want %d", uf.Location.Line, tc.wantLine)
			}
			if uf.Location.Column != tc.wantColumn {
				t.Errorf("Location.Column: got %d, want %d", uf.Location.Column, tc.wantColumn)
			}

			// --- Fixed fields ---
			if uf.Confidence != tc.wantConfidence {
				t.Errorf("Confidence: got %q, want %q", uf.Confidence, tc.wantConfidence)
			}
			if uf.SourceEngine != tc.wantEngine {
				t.Errorf("SourceEngine: got %q, want %q", uf.SourceEngine, tc.wantEngine)
			}
			if uf.Reachable != tc.wantReachable {
				t.Errorf("Reachable: got %q, want %q", uf.Reachable, tc.wantReachable)
			}
			if uf.RawIdentifier != tc.wantRawID {
				t.Errorf("RawIdentifier: got %q, want %q", uf.RawIdentifier, tc.wantRawID)
			}

			// --- Algorithm branch ---
			if tc.wantAlgName != "" {
				if uf.Algorithm == nil {
					t.Fatalf("Algorithm: got nil, want name %q", tc.wantAlgName)
				}
				if uf.Algorithm.Name != tc.wantAlgName {
					t.Errorf("Algorithm.Name: got %q, want %q", uf.Algorithm.Name, tc.wantAlgName)
				}
				if uf.Algorithm.KeySize != tc.wantAlgKey {
					t.Errorf("Algorithm.KeySize: got %d, want %d", uf.Algorithm.KeySize, tc.wantAlgKey)
				}
				if uf.Algorithm.Mode != tc.wantAlgMode {
					t.Errorf("Algorithm.Mode: got %q, want %q", uf.Algorithm.Mode, tc.wantAlgMode)
				}
				if uf.Algorithm.Curve != tc.wantAlgCurve {
					t.Errorf("Algorithm.Curve: got %q, want %q", uf.Algorithm.Curve, tc.wantAlgCurve)
				}
				if tc.wantAlgPrim != "" && uf.Algorithm.Primitive != tc.wantAlgPrim {
					t.Errorf("Algorithm.Primitive: got %q, want %q", uf.Algorithm.Primitive, tc.wantAlgPrim)
				}
				// Library must be nil when algorithm is set
				if uf.Dependency != nil {
					t.Errorf("Dependency: expected nil when Algorithm is set, got %+v", uf.Dependency)
				}
			}

			// --- Dependency branch ---
			if tc.wantLibrary != "" {
				if uf.Dependency == nil {
					t.Fatalf("Dependency: got nil, want library %q", tc.wantLibrary)
				}
				if uf.Dependency.Library != tc.wantLibrary {
					t.Errorf("Dependency.Library: got %q, want %q", uf.Dependency.Library, tc.wantLibrary)
				}
				// Algorithm must be nil when library is set
				if uf.Algorithm != nil {
					t.Errorf("Algorithm: expected nil when Dependency is set, got %+v", uf.Algorithm)
				}
			}

			// --- Unknown assetType: neither Algorithm nor Dependency ---
			if tc.raw.AssetType == "unknown" {
				if uf.Algorithm != nil {
					t.Errorf("Algorithm: expected nil for unknown assetType, got %+v", uf.Algorithm)
				}
				if uf.Dependency != nil {
					t.Errorf("Dependency: expected nil for unknown assetType, got %+v", uf.Dependency)
				}
			}
		})
	}
}

// TestNormalize_UnknownAssetType verifies that a rawFinding with an unknown
// assetType (e.g. "certificate") produces a finding with no Algorithm and no
// Dependency, while RawIdentifier is still populated from the identifier field.
func TestNormalize_UnknownAssetType(t *testing.T) {
	raw := rawFinding{
		AssetType:  "certificate",
		Identifier: "CN=example.com",
		Path:       "certs/server.pem",
		Evidence:   rawEvidence{Line: 1, Column: 0},
	}

	uf := normalize(raw)

	// Algorithm must be nil for unknown asset types.
	if uf.Algorithm != nil {
		t.Errorf("Algorithm: expected nil for unknown assetType %q, got %+v", raw.AssetType, uf.Algorithm)
	}

	// Dependency must be nil for unknown asset types.
	if uf.Dependency != nil {
		t.Errorf("Dependency: expected nil for unknown assetType %q, got %+v", raw.AssetType, uf.Dependency)
	}

	// RawIdentifier must be set from the identifier field.
	if uf.RawIdentifier != raw.Identifier {
		t.Errorf("RawIdentifier = %q, want %q", uf.RawIdentifier, raw.Identifier)
	}

	// Location must be populated.
	if uf.Location.File != raw.Path {
		t.Errorf("Location.File = %q, want %q", uf.Location.File, raw.Path)
	}

	// SourceEngine must always be "cipherscope".
	if uf.SourceEngine != "cipherscope" {
		t.Errorf("SourceEngine = %q, want %q", uf.SourceEngine, "cipherscope")
	}
}

// ----------------------------------------------------------------------------
// Engine metadata
// ----------------------------------------------------------------------------

func TestEngineNameAndTier(t *testing.T) {
	e := New()

	if got := e.Name(); got != "cipherscope" {
		t.Errorf("Name() = %q, want %q", got, "cipherscope")
	}

	if got := e.Tier(); got != engines.Tier1Pattern {
		t.Errorf("Tier() = %v, want Tier1Pattern (%d)", got, engines.Tier1Pattern)
	}
}

func TestEngineImplementsInterface(t *testing.T) {
	// Compile-time assertion via assignment to interface variable.
	var _ engines.Engine = New()
}

func TestEngineAvailable_EmptyDirs(t *testing.T) {
	// No extra directories and assuming "cipherscope" is not on PATH in CI.
	// We cannot guarantee Available() == false when the binary is installed,
	// but we can verify the function does not panic.
	e := New()
	_ = e.Available() // must not panic
}

func TestEngineAvailable_NoBinaryPath(t *testing.T) {
	e := &Engine{binaryPath: ""}
	if e.Available() {
		t.Error("Available() = true, want false when binaryPath is empty string")
	}
}

func TestEngineAvailable_NonEmptyBinaryPath(t *testing.T) {
	// Any non-empty string makes Available() return true (path existence is
	// checked only in findBinary, not in Available).
	e := &Engine{binaryPath: "/fake/path/cipherscope"}
	if !e.Available() {
		t.Error("Available() = false, want true when binaryPath is set")
	}
}

func TestEngineSupportedLanguages(t *testing.T) {
	e := New()
	langs := e.SupportedLanguages()

	if len(langs) == 0 {
		t.Fatal("SupportedLanguages() returned empty slice")
	}

	required := []string{
		"c", "cpp", "java", "python", "go",
		"swift", "php", "objc", "rust", "javascript", "typescript",
	}
	set := make(map[string]bool, len(langs))
	for _, l := range langs {
		set[l] = true
	}
	for _, want := range required {
		if !set[want] {
			t.Errorf("SupportedLanguages() missing %q", want)
		}
	}
}

func TestEngineSupportedLanguages_NoDuplicates(t *testing.T) {
	e := New()
	langs := e.SupportedLanguages()
	seen := make(map[string]int, len(langs))
	for _, l := range langs {
		seen[l]++
	}
	for lang, count := range seen {
		if count > 1 {
			t.Errorf("SupportedLanguages() contains duplicate %q (%d times)", lang, count)
		}
	}
}

// ----------------------------------------------------------------------------
// New / findBinary
// ----------------------------------------------------------------------------

func TestNew_NoArgs_DoesNotPanic(t *testing.T) {
	e := New()
	if e == nil {
		t.Fatal("New() returned nil")
	}
}

func TestNew_NonexistentDir_AvailableFalse(t *testing.T) {
	// Provide only a directory that cannot contain the binary.
	e := New("/nonexistent/directory/that/should/never/exist")
	// Available is false unless the binary happens to be on PATH.
	// We only assert no panic; the binary might legitimately be installed.
	_ = e.Available()
}

func TestFindBinary_ExtraDirWithExecutable(t *testing.T) {
	// Create a temp directory with a fake executable named "cipherscope".
	dir := t.TempDir()
	fakeBin := filepath.Join(dir, "cipherscope")

	f, err := os.Create(fakeBin)
	if err != nil {
		t.Fatalf("create fake binary: %v", err)
	}
	f.Close()

	// Mark executable.
	if err := os.Chmod(fakeBin, 0755); err != nil {
		t.Fatalf("chmod fake binary: %v", err)
	}

	e := &Engine{}
	got := e.findBinary([]string{dir})
	if got != fakeBin {
		t.Errorf("findBinary: got %q, want %q", got, fakeBin)
	}
}

func TestFindBinary_ExtraDirWithNonExecutable(t *testing.T) {
	// A file that exists but is not executable should NOT be returned.
	dir := t.TempDir()
	fakeBin := filepath.Join(dir, "cipherscope")

	f, err := os.Create(fakeBin)
	if err != nil {
		t.Fatalf("create fake binary: %v", err)
	}
	f.Close()

	// Mode 0644 — readable but not executable.
	if err := os.Chmod(fakeBin, 0644); err != nil {
		t.Fatalf("chmod fake binary: %v", err)
	}

	e := &Engine{}
	got := e.findBinary([]string{dir})
	// Should not return the non-executable file (may fall back to PATH).
	if got == fakeBin {
		t.Errorf("findBinary: returned non-executable file %q", got)
	}
}

func TestFindBinary_FirstMatchWins(t *testing.T) {
	// Two directories both containing "cipherscope"; first dir should win.
	dir1 := t.TempDir()
	dir2 := t.TempDir()

	for _, dir := range []string{dir1, dir2} {
		p := filepath.Join(dir, "cipherscope")
		f, err := os.Create(p)
		if err != nil {
			t.Fatalf("create %s: %v", p, err)
		}
		f.Close()
		if err := os.Chmod(p, 0755); err != nil {
			t.Fatalf("chmod %s: %v", p, err)
		}
	}

	e := &Engine{}
	got := e.findBinary([]string{dir1, dir2})
	want := filepath.Join(dir1, "cipherscope")
	if got != want {
		t.Errorf("findBinary: got %q, want %q (first dir should win)", got, want)
	}
}

func TestFindBinary_EmptyExtraDirs(t *testing.T) {
	// Empty slice for extra dirs — should not panic, falls through to PATH.
	e := &Engine{}
	_ = e.findBinary([]string{})
}

func TestNew_FindsBinaryFromExtraDir(t *testing.T) {
	dir := t.TempDir()
	fakeBin := filepath.Join(dir, "cipherscope")

	f, err := os.Create(fakeBin)
	if err != nil {
		t.Fatalf("create fake binary: %v", err)
	}
	f.Close()
	if err := os.Chmod(fakeBin, 0755); err != nil {
		t.Fatalf("chmod: %v", err)
	}

	e := New(dir)
	if !e.Available() {
		t.Error("Available() = false, want true after New() with valid binary dir")
	}
}

// ----------------------------------------------------------------------------
// isExecutable
// ----------------------------------------------------------------------------

func TestIsExecutable_RegularExecutableFile(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "bin")
	f, err := os.Create(p)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	f.Close()
	if err := os.Chmod(p, 0755); err != nil {
		t.Fatalf("chmod: %v", err)
	}

	if !isExecutable(p) {
		t.Errorf("isExecutable(%q) = false, want true", p)
	}
}

func TestIsExecutable_RegularNonExecutableFile(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "data.txt")
	f, err := os.Create(p)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	f.Close()
	if err := os.Chmod(p, 0644); err != nil {
		t.Fatalf("chmod: %v", err)
	}

	if isExecutable(p) {
		t.Errorf("isExecutable(%q) = true, want false", p)
	}
}

func TestIsExecutable_Directory(t *testing.T) {
	dir := t.TempDir()
	// Directories have executable bits set on Unix but isExecutable must
	// exclude them because info.IsDir() is checked.
	if isExecutable(dir) {
		t.Errorf("isExecutable(%q) = true for directory, want false", dir)
	}
}

func TestIsExecutable_NonexistentPath(t *testing.T) {
	if isExecutable("/nonexistent/path/to/binary") {
		t.Error("isExecutable = true for nonexistent path, want false")
	}
}

// ----------------------------------------------------------------------------
// helpers
// ----------------------------------------------------------------------------

// mustMarshalMeta encodes rawMetadata as json.RawMessage or panics.
func mustMarshalMeta(m rawMetadata) json.RawMessage {
	b, err := json.Marshal(m)
	if err != nil {
		panic("mustMarshalMeta: " + err.Error())
	}
	return json.RawMessage(b)
}
