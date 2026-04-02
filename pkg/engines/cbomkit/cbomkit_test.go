package cbomkit

import (
	"testing"

	"github.com/jimbo111/open-quantum-secure/pkg/engines"
	"github.com/jimbo111/open-quantum-secure/pkg/findings"
)

func TestNormalize(t *testing.T) {
	tests := []struct {
		name          string
		asset         rawAsset
		wantFile      string
		wantLine      int
		wantAlgName   string
		wantPrimitive string
		wantKeySize   int
		wantCurve     string
		wantRawID     string
		wantEngine    string
		wantConf      findings.Confidence
		wantReach     findings.Reachability
	}{
		{
			name: "certificate RSA 2048",
			asset: rawAsset{
				Type:      "certificate",
				Algorithm: "RSA",
				KeySize:   2048,
				File:      "/etc/ssl/certs/server.crt",
				Line:      0,
			},
			wantFile:      "/etc/ssl/certs/server.crt",
			wantLine:      0,
			wantAlgName:   "RSA",
			wantPrimitive: "asymmetric",
			wantKeySize:   2048,
			wantCurve:     "",
			wantRawID:     "certificate:RSA",
			wantEngine:    "cbomkit-theia",
			wantConf:      findings.ConfidenceMedium,
			wantReach:     findings.ReachableUnknown,
		},
		{
			name: "private-key EC 256",
			asset: rawAsset{
				Type:      "private-key",
				Algorithm: "EC",
				KeySize:   256,
				File:      "/etc/ssl/private/key.pem",
				Line:      0,
			},
			wantFile:      "/etc/ssl/private/key.pem",
			wantLine:      0,
			wantAlgName:   "EC",
			wantPrimitive: "asymmetric",
			wantKeySize:   256,
			wantCurve:     "",
			wantRawID:     "private-key:EC",
			wantEngine:    "cbomkit-theia",
			wantConf:      findings.ConfidenceMedium,
			wantReach:     findings.ReachableUnknown,
		},
		{
			name: "keystore RSA 4096",
			asset: rawAsset{
				Type:      "keystore",
				Algorithm: "RSA",
				KeySize:   4096,
				File:      "/opt/app/keystore.jks",
				Line:      0,
			},
			wantFile:      "/opt/app/keystore.jks",
			wantLine:      0,
			wantAlgName:   "RSA",
			wantPrimitive: "asymmetric",
			wantKeySize:   4096,
			wantCurve:     "",
			wantRawID:     "keystore:RSA",
			wantEngine:    "cbomkit-theia",
			wantConf:      findings.ConfidenceMedium,
			wantReach:     findings.ReachableUnknown,
		},
		{
			name: "config TLS 1.2",
			asset: rawAsset{
				Type:      "config",
				Algorithm: "TLS 1.2",
				File:      "/etc/nginx/nginx.conf",
				Line:      15,
			},
			wantFile:      "/etc/nginx/nginx.conf",
			wantLine:      15,
			wantAlgName:   "TLS 1.2",
			wantPrimitive: "protocol",
			wantKeySize:   0,
			wantCurve:     "",
			wantRawID:     "config:TLS 1.2",
			wantEngine:    "cbomkit-theia",
			wantConf:      findings.ConfidenceMedium,
			wantReach:     findings.ReachableUnknown,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			uf := normalize(tc.asset)

			if uf.Location.File != tc.wantFile {
				t.Errorf("File: got %q, want %q", uf.Location.File, tc.wantFile)
			}
			if uf.Location.Line != tc.wantLine {
				t.Errorf("Line: got %d, want %d", uf.Location.Line, tc.wantLine)
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
			if uf.Algorithm.Curve != tc.wantCurve {
				t.Errorf("Algorithm.Curve: got %q, want %q", uf.Algorithm.Curve, tc.wantCurve)
			}
		})
	}
}

func TestNormalize_WithCurve(t *testing.T) {
	asset := rawAsset{
		Type:      "private-key",
		Algorithm: "EC",
		KeySize:   256,
		Curve:     "P-256",
		File:      "/etc/ssl/private/ec-key.pem",
		Line:      0,
	}

	uf := normalize(asset)

	if uf.Algorithm == nil {
		t.Fatal("Algorithm: got nil, want non-nil")
	}
	if uf.Algorithm.Curve != "P-256" {
		t.Errorf("Algorithm.Curve: got %q, want %q", uf.Algorithm.Curve, "P-256")
	}
	if uf.Algorithm.Name != "EC" {
		t.Errorf("Algorithm.Name: got %q, want %q", uf.Algorithm.Name, "EC")
	}
	if uf.Algorithm.Primitive != "asymmetric" {
		t.Errorf("Algorithm.Primitive: got %q, want %q", uf.Algorithm.Primitive, "asymmetric")
	}
	if uf.Algorithm.KeySize != 256 {
		t.Errorf("Algorithm.KeySize: got %d, want %d", uf.Algorithm.KeySize, 256)
	}
}

func TestNormalize_EmptyAssets(t *testing.T) {
	var assets []rawAsset
	result := make([]findings.UnifiedFinding, 0, len(assets))
	for _, a := range assets {
		result = append(result, normalize(a))
	}
	if len(result) != 0 {
		t.Errorf("expected 0 findings, got %d", len(result))
	}
}

func TestPrimitiveFromAssetType(t *testing.T) {
	tests := []struct {
		assetType string
		want      string
	}{
		{"certificate", "asymmetric"},
		{"private-key", "asymmetric"},
		{"keystore", "asymmetric"},
		{"config", "protocol"},
		{"ssh-key", "asymmetric"},
		{"pgp-key", "asymmetric"},
		{"unknown-type", ""},
		{"", ""},
	}

	for _, tc := range tests {
		t.Run(tc.assetType, func(t *testing.T) {
			got := primitiveFromAssetType(tc.assetType)
			if got != tc.want {
				t.Errorf("primitiveFromAssetType(%q): got %q, want %q", tc.assetType, got, tc.want)
			}
		})
	}
}

func TestFindBinary_NotFound(t *testing.T) {
	e := &Engine{}
	// Provide a non-existent directory; binary should not be found via extra dirs.
	// We can't assert it's always empty (cbomkit-theia might be on the test machine's PATH),
	// but we verify the function doesn't panic.
	_ = e.findBinary([]string{"/nonexistent/path/that/does/not/exist"})
}

func TestAvailableFalseWhenNoBinary(t *testing.T) {
	e := &Engine{binaryPath: ""}
	if e.Available() {
		t.Error("Available() should return false when binaryPath is empty")
	}
}

func TestEngineMetadata(t *testing.T) {
	e := &Engine{}

	if e.Name() != "cbomkit-theia" {
		t.Errorf("Name(): got %q, want %q", e.Name(), "cbomkit-theia")
	}

	if e.Tier() != engines.Tier3Formal {
		t.Errorf("Tier(): got %d, want %d (Tier3Formal)", e.Tier(), engines.Tier3Formal)
	}

	// SupportedLanguages must return ["(artifacts)"] to match the engine registry entry
	// in pkg/enginemgr/enginemgr.go. cbomkit-theia operates on deployed artifacts
	// (certificates, keystores, config files), not source-code languages.
	langs := e.SupportedLanguages()
	if len(langs) != 1 || langs[0] != "(artifacts)" {
		t.Errorf("SupportedLanguages() = %v, want [(artifacts)]", langs)
	}
}

func TestNormalize_MissingFields(t *testing.T) {
	tests := []struct {
		name    string
		asset   rawAsset
		wantAlg bool // true if Algorithm should be non-nil
	}{
		{
			name:    "empty asset",
			asset:   rawAsset{},
			wantAlg: false,
		},
		{
			name: "no algorithm",
			asset: rawAsset{
				Type: "certificate",
				File: "/some/file.crt",
			},
			wantAlg: false,
		},
		{
			name: "no file",
			asset: rawAsset{
				Type:      "private-key",
				Algorithm: "RSA",
				KeySize:   2048,
			},
			wantAlg: true,
		},
		{
			name: "zero line",
			asset: rawAsset{
				Type:      "config",
				Algorithm: "TLS 1.3",
				File:      "/etc/nginx/nginx.conf",
				Line:      0,
			},
			wantAlg: true,
		},
		{
			name: "unknown type no panic",
			asset: rawAsset{
				Type:      "pgp-key",
				Algorithm: "DSA",
				KeySize:   1024,
				File:      "/home/user/.gnupg/pubring.gpg",
				Line:      0,
			},
			wantAlg: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// Must not panic
			uf := normalize(tc.asset)

			if tc.wantAlg && uf.Algorithm == nil {
				t.Error("Algorithm: got nil, want non-nil struct")
			}
			if !tc.wantAlg && uf.Algorithm != nil {
				t.Errorf("Algorithm: got %+v, want nil (empty algorithm name)", uf.Algorithm)
			}
			if uf.SourceEngine != "cbomkit-theia" {
				t.Errorf("SourceEngine: got %q, want %q", uf.SourceEngine, "cbomkit-theia")
			}
			if uf.Confidence != findings.ConfidenceMedium {
				t.Errorf("Confidence: got %q, want %q", uf.Confidence, findings.ConfidenceMedium)
			}
			if uf.Reachable != findings.ReachableUnknown {
				t.Errorf("Reachable: got %q, want %q", uf.Reachable, findings.ReachableUnknown)
			}
		})
	}
}

// --- edge case tests added by deep review ---

func TestNormalize_EmptyAlgorithmProducesNilAlg(t *testing.T) {
	uf := normalize(rawAsset{
		Type: "certificate",
		File: "/tmp/cert.pem",
		Line: 0,
	})
	if uf.Algorithm != nil {
		t.Errorf("expected nil Algorithm for empty algorithm name, got %+v", uf.Algorithm)
	}
}

func TestNormalize_DedupeKeyWithAlgorithm(t *testing.T) {
	uf := normalize(rawAsset{
		Type:      "certificate",
		Algorithm: "RSA",
		File:      "/a.pem",
		Line:      1,
	})
	key := uf.DedupeKey()
	want := "/a.pem|1|alg|RSA"
	if key != want {
		t.Errorf("DedupeKey: got %q, want %q", key, want)
	}
}

func TestNormalize_DedupeKeyWithoutAlgorithm(t *testing.T) {
	uf := normalize(rawAsset{
		Type: "certificate",
		File: "/a.pem",
		Line: 1,
	})
	key := uf.DedupeKey()
	// With empty algorithm, falls to fallback which includes SourceEngine
	if key == "/a.pem|1|alg|" {
		t.Error("DedupeKey should not use alg branch for empty algorithm")
	}
}

func TestScan_NotAvailable(t *testing.T) {
	e := &Engine{binaryPath: ""}
	_, err := e.Scan(nil, engines.ScanOptions{TargetPath: "/tmp"})
	if err == nil {
		t.Fatal("expected error when engine is not available")
	}
}
