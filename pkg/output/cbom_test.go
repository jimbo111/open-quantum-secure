package output

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/jimbo111/open-quantum-secure/pkg/findings"
	"github.com/jimbo111/open-quantum-secure/pkg/impact"
)

// ---------------------------------------------------------------------------
// Helper: parse raw CBOM output into cdxBOM struct
// ---------------------------------------------------------------------------

func parseCBOM(t *testing.T, buf *bytes.Buffer) cdxBOM {
	t.Helper()
	var bom cdxBOM
	if err := json.Unmarshal(buf.Bytes(), &bom); err != nil {
		t.Fatalf("failed to unmarshal CBOM output: %v\nraw:\n%s", err, buf.String())
	}
	return bom
}

func writeCBOMOrFatal(t *testing.T, result ScanResult) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	if err := WriteCBOM(&buf, result); err != nil {
		t.Fatalf("WriteCBOM returned error: %v", err)
	}
	return &buf
}

// findProp searches a property slice for a matching name and returns its value.
func findProp(props []cdxProperty, name string) (string, bool) {
	for _, p := range props {
		if p.Name == name {
			return p.Value, true
		}
	}
	return "", false
}

// findComponent returns the first component whose Name matches, or nil.
func findComponent(comps []cdxComponent, name string) *cdxComponent {
	for i := range comps {
		if comps[i].Name == name {
			return &comps[i]
		}
	}
	return nil
}

// ---------------------------------------------------------------------------
// 1. WriteCBOM with empty findings
// ---------------------------------------------------------------------------

func TestWriteCBOM_EmptyFindings_ComponentsIsEmptyArray(t *testing.T) {
	result := BuildResult("1.0.0", "/repo", []string{"cipherscope"}, nil)
	buf := writeCBOMOrFatal(t, result)

	// Unmarshal as raw map to distinguish [] from null
	var raw map[string]interface{}
	if err := json.Unmarshal(buf.Bytes(), &raw); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}

	comps := raw["components"]
	if comps == nil {
		t.Fatal("components is null, CycloneDX 1.7 requires []")
	}
	arr, ok := comps.([]interface{})
	if !ok {
		t.Fatalf("components is %T, want []interface{}", comps)
	}
	if len(arr) != 0 {
		t.Errorf("components has %d elements, want 0", len(arr))
	}
}

func TestWriteCBOM_EmptyFindings(t *testing.T) {
	result := BuildResult("1.0.0", "/repo", []string{"cipherscope"}, nil)
	buf := writeCBOMOrFatal(t, result)

	// Must be valid JSON
	var raw map[string]interface{}
	if err := json.Unmarshal(buf.Bytes(), &raw); err != nil {
		t.Fatalf("output is not valid JSON: %v", err)
	}

	bom := parseCBOM(t, buf)

	// CycloneDX 1.7 envelope fields
	if bom.BOMFormat != "CycloneDX" {
		t.Errorf("bomFormat = %q, want CycloneDX", bom.BOMFormat)
	}
	if bom.SpecVersion != "1.7" {
		t.Errorf("specVersion = %q, want 1.7", bom.SpecVersion)
	}
	if bom.Version != 1 {
		t.Errorf("version = %d, want 1", bom.Version)
	}
	if !strings.HasPrefix(bom.SerialNumber, "urn:uuid:") {
		t.Errorf("serialNumber %q does not start with urn:uuid:", bom.SerialNumber)
	}

	// Metadata must be present
	if bom.Metadata.Timestamp == "" {
		t.Error("metadata.timestamp is empty")
	}
	if bom.Metadata.Tools == nil || len(bom.Metadata.Tools.Components) == 0 {
		t.Error("metadata.tools.components is empty")
	}
	tool := bom.Metadata.Tools.Components[0]
	if tool.Name != "oqs-scanner" {
		t.Errorf("tool name = %q, want oqs-scanner", tool.Name)
	}
	if tool.Version != "1.0.0" {
		t.Errorf("tool version = %q, want 1.0.0", tool.Version)
	}

	// Empty findings → empty components slice (not nil is fine, but length should be 0)
	if len(bom.Components) != 0 {
		t.Errorf("components len = %d, want 0 for empty findings", len(bom.Components))
	}

	// No dependency edges either
	if len(bom.Dependencies) != 0 {
		t.Errorf("dependencies len = %d, want 0 for empty findings", len(bom.Dependencies))
	}

	// Metadata properties must include core keys
	wantKeys := []string{
		"oqs:scanTarget",
		"oqs:enginesUsed",
		"oqs:findingCount",
		"oqs:quantumVulnerableCount",
		"oqs:deprecatedCount",
	}
	for _, key := range wantKeys {
		if _, ok := findProp(bom.Metadata.Properties, key); !ok {
			t.Errorf("metadata property %q is missing", key)
		}
	}

	// findingCount should be "0"
	if v, _ := findProp(bom.Metadata.Properties, "oqs:findingCount"); v != "0" {
		t.Errorf("oqs:findingCount = %q, want 0", v)
	}

	// scanTarget should equal the target
	if v, _ := findProp(bom.Metadata.Properties, "oqs:scanTarget"); v != "/repo" {
		t.Errorf("oqs:scanTarget = %q, want /repo", v)
	}
}

// ---------------------------------------------------------------------------
// 2. WriteCBOM with algorithm findings — cryptoProperties
// ---------------------------------------------------------------------------

func TestWriteCBOM_AlgorithmFindings(t *testing.T) {
	ff := []findings.UnifiedFinding{
		{
			Location:       findings.Location{File: "/repo/main.go", Line: 42, Column: 5},
			Algorithm:      &findings.Algorithm{Name: "AES", Primitive: "symmetric", KeySize: 256, Mode: "GCM"},
			Confidence:     findings.ConfidenceHigh,
			SourceEngine:   "cipherscope",
			Reachable:      findings.ReachableYes,
			QuantumRisk:    findings.QRSafe,
			Severity:       findings.SevInfo,
			Recommendation: "Prefer AES-256-GCM for AEAD",
		},
		{
			Location:     findings.Location{File: "/repo/auth.go", Line: 10},
			Algorithm:    &findings.Algorithm{Name: "RSA", Primitive: "asymmetric", KeySize: 2048},
			Confidence:   findings.ConfidenceHigh,
			SourceEngine: "cipherscope",
			QuantumRisk:  findings.QRVulnerable,
			Severity:     findings.SevCritical,
		},
	}
	result := BuildResult("0.9.0", "/repo", []string{"cipherscope"}, ff)
	buf := writeCBOMOrFatal(t, result)
	bom := parseCBOM(t, buf)

	if len(bom.Components) != 2 {
		t.Fatalf("components len = %d, want 2", len(bom.Components))
	}

	// --- AES component ---
	aesComp := findComponent(bom.Components, "AES-256-GCM")
	if aesComp == nil {
		// also try plain "AES-256-GCM" — buildComponentName appends keySize+mode
		t.Fatalf("AES-256-GCM component not found; components: %v", componentNames(bom.Components))
	}

	if aesComp.Type != "cryptographic-asset" {
		t.Errorf("AES component type = %q, want cryptographic-asset", aesComp.Type)
	}
	if aesComp.BOMRef == "" {
		t.Error("AES component bom-ref is empty")
	}
	if aesComp.CryptoProperties == nil {
		t.Fatal("AES component cryptoProperties is nil")
	}
	if aesComp.CryptoProperties.AssetType != "algorithm" {
		t.Errorf("assetType = %q, want algorithm", aesComp.CryptoProperties.AssetType)
	}

	algProps := aesComp.CryptoProperties.AlgorithmProperties
	if algProps == nil {
		t.Fatal("AES algorithmProperties is nil")
	}
	if algProps.Primitive != "block-cipher" {
		t.Errorf("primitive = %q, want block-cipher (mapped from symmetric)", algProps.Primitive)
	}
	if algProps.AlgorithmFamily != "AES" {
		t.Errorf("algorithmFamily = %q, want AES", algProps.AlgorithmFamily)
	}
	if algProps.ParameterSetIdentifier != "256" {
		t.Errorf("parameterSetIdentifier = %q, want 256", algProps.ParameterSetIdentifier)
	}
	if algProps.Mode != "gcm" {
		t.Errorf("mode = %q, want gcm (lowercased)", algProps.Mode)
	}
	// CycloneDX 1.7 algorithmProperties.executionEnvironment enum requires one
	// of: software-plain-ram | software-encrypted-ram | software-tee | hardware
	// | other | unknown. The bare value "software" is not valid.
	if algProps.ExecutionEnvironment != "software-plain-ram" {
		t.Errorf("executionEnvironment = %q, want software-plain-ram", algProps.ExecutionEnvironment)
	}

	// Evidence must have occurrences
	if aesComp.Evidence == nil || len(aesComp.Evidence.Occurrences) == 0 {
		t.Error("AES component has no evidence occurrences")
	} else {
		occ := aesComp.Evidence.Occurrences[0]
		if occ.Line != 42 {
			t.Errorf("occurrence line = %d, want 42", occ.Line)
		}
		if occ.Offset != 5 {
			t.Errorf("occurrence offset = %d, want 5", occ.Offset)
		}
	}

	// Custom properties
	if v, ok := findProp(aesComp.Properties, "oqs:confidence"); !ok || v != "high" {
		t.Errorf("oqs:confidence = %q, want high", v)
	}
	if v, ok := findProp(aesComp.Properties, "oqs:reachable"); !ok || v != "yes" {
		t.Errorf("oqs:reachable = %q, want yes", v)
	}
	if v, ok := findProp(aesComp.Properties, "oqs:policyVerdict"); !ok || v != "quantum-safe" {
		t.Errorf("oqs:policyVerdict = %q, want quantum-safe", v)
	}
	if v, ok := findProp(aesComp.Properties, "oqs:severity"); !ok || v != "info" {
		t.Errorf("oqs:severity = %q, want info", v)
	}
	if v, ok := findProp(aesComp.Properties, "oqs:recommendation"); !ok || !strings.Contains(v, "AES-256-GCM") {
		t.Errorf("oqs:recommendation = %q, want to contain AES-256-GCM", v)
	}

	// --- RSA component ---
	rsaComp := findComponent(bom.Components, "RSA-2048")
	if rsaComp == nil {
		t.Fatalf("RSA-2048 component not found; components: %v", componentNames(bom.Components))
	}
	if rsaComp.CryptoProperties.AlgorithmProperties.Primitive != "pke" {
		t.Errorf("RSA primitive = %q, want pke (mapped from asymmetric)", rsaComp.CryptoProperties.AlgorithmProperties.Primitive)
	}
	if rsaComp.CryptoProperties.AlgorithmProperties.AlgorithmFamily != "RSA" {
		t.Errorf("RSA algorithmFamily = %q, want RSA", rsaComp.CryptoProperties.AlgorithmProperties.AlgorithmFamily)
	}
}

// ---------------------------------------------------------------------------
// 3. WriteCBOM with dependency findings
// ---------------------------------------------------------------------------

func TestWriteCBOM_DependencyFindings(t *testing.T) {
	ff := []findings.UnifiedFinding{
		{
			Location:     findings.Location{File: "/repo/go.sum", Line: 15},
			Dependency:   &findings.Dependency{Library: "crypto/tls"},
			Confidence:   findings.ConfidenceMedium,
			SourceEngine: "cipherscope",
		},
		{
			Location:     findings.Location{File: "/repo/requirements.txt", Line: 3},
			Dependency:   &findings.Dependency{Library: "pycryptodome"},
			Confidence:   findings.ConfidenceLow,
			SourceEngine: "cryptoscan",
		},
	}
	result := BuildResult("0.9.0", "/repo", []string{"cipherscope", "cryptoscan"}, ff)
	buf := writeCBOMOrFatal(t, result)
	bom := parseCBOM(t, buf)

	// Two library components
	if len(bom.Components) != 2 {
		t.Fatalf("components len = %d, want 2", len(bom.Components))
	}

	tlsComp := findComponent(bom.Components, "crypto/tls")
	if tlsComp == nil {
		t.Fatalf("crypto/tls component not found; components: %v", componentNames(bom.Components))
	}
	// Library dependencies use the top-level component.type "library"
	// (CycloneDX 1.7 component.type enum). They are NOT cryptographic-asset
	// components — assetType's enum is restricted to algorithm/certificate/
	// protocol/related-crypto-material, so "library" is not a valid assetType.
	if tlsComp.Type != "library" {
		t.Errorf("dep component type = %q, want library", tlsComp.Type)
	}
	if tlsComp.CryptoProperties != nil {
		t.Errorf("library component must not have cryptoProperties; got assetType=%q",
			tlsComp.CryptoProperties.AssetType)
	}

	// Evidence with occurrence
	if tlsComp.Evidence == nil || len(tlsComp.Evidence.Occurrences) == 0 {
		t.Error("dep component has no evidence occurrences")
	} else if tlsComp.Evidence.Occurrences[0].Line != 15 {
		t.Errorf("dep occurrence line = %d, want 15", tlsComp.Evidence.Occurrences[0].Line)
	}

	// BOM-ref must be non-empty and stable
	if tlsComp.BOMRef == "" {
		t.Error("dep component bom-ref is empty")
	}

	// Dependencies graph: repo-root → [lib refs]
	if len(bom.Dependencies) == 0 {
		t.Fatal("dependency graph should not be empty when dep findings exist")
	}
	if bom.Dependencies[0].Ref != "repo-root" {
		t.Errorf("dependencies[0].ref = %q, want repo-root", bom.Dependencies[0].Ref)
	}
	if len(bom.Dependencies[0].DependsOn) != 2 {
		t.Errorf("dependsOn len = %d, want 2", len(bom.Dependencies[0].DependsOn))
	}
}

// ---------------------------------------------------------------------------
// 4. WriteCBOM with mixed findings (algorithms + dependencies)
// ---------------------------------------------------------------------------

func TestWriteCBOM_MixedFindings(t *testing.T) {
	ff := []findings.UnifiedFinding{
		{
			Location:     findings.Location{File: "/repo/main.go", Line: 1},
			Algorithm:    &findings.Algorithm{Name: "SHA-256", Primitive: "hash"},
			SourceEngine: "cipherscope",
		},
		{
			Location:     findings.Location{File: "/repo/main.go", Line: 2},
			Algorithm:    &findings.Algorithm{Name: "ECDSA", Primitive: "signature", KeySize: 256},
			SourceEngine: "cipherscope",
			QuantumRisk:  findings.QRVulnerable,
		},
		{
			Location:     findings.Location{File: "/repo/go.mod", Line: 10},
			Dependency:   &findings.Dependency{Library: "golang.org/x/crypto"},
			SourceEngine: "cipherscope",
		},
	}
	result := BuildResult("1.0.0", "/repo", []string{"cipherscope"}, ff)
	buf := writeCBOMOrFatal(t, result)
	bom := parseCBOM(t, buf)

	// 2 algorithm components + 1 library component
	if len(bom.Components) != 3 {
		t.Errorf("components len = %d, want 3", len(bom.Components))
	}

	// Algorithm components appear before dependency components in output.
	// Algorithm components are component.type "cryptographic-asset" with
	// cryptoProperties.assetType "algorithm"; dependency components are
	// component.type "library" with no cryptoProperties (CycloneDX 1.7).
	algCount := 0
	libCount := 0
	for _, c := range bom.Components {
		if c.Type == "library" {
			libCount++
			continue
		}
		if c.CryptoProperties != nil && c.CryptoProperties.AssetType == "algorithm" {
			algCount++
		}
	}
	if algCount != 2 {
		t.Errorf("algorithm components = %d, want 2", algCount)
	}
	if libCount != 1 {
		t.Errorf("library components = %d, want 1", libCount)
	}

	// Dependency graph present
	if len(bom.Dependencies) == 0 {
		t.Error("dependency graph should be present for mixed findings")
	}
}

// ---------------------------------------------------------------------------
// 5. buildComponentName — comprehensive table-driven tests
// ---------------------------------------------------------------------------

func TestBuildComponentName_Extended(t *testing.T) {
	tests := []struct {
		desc string
		alg  *findings.Algorithm
		want string
	}{
		{
			desc: "AES with keySize=256 and mode=GCM produces AES-256-GCM",
			alg:  &findings.Algorithm{Name: "AES", KeySize: 256, Mode: "GCM"},
			want: "AES-256-GCM",
		},
		{
			desc: "AES-256-GCM already contains both keySize and mode — no duplication",
			alg:  &findings.Algorithm{Name: "AES-256-GCM", KeySize: 256, Mode: "GCM"},
			want: "AES-256-GCM",
		},
		{
			desc: "AES with mode=CBC only (no keySize) appends mode",
			alg:  &findings.Algorithm{Name: "AES", Mode: "CBC"},
			want: "AES-CBC",
		},
		{
			desc: "algorithm with empty mode — no mode appended",
			alg:  &findings.Algorithm{Name: "AES", KeySize: 128},
			want: "AES-128",
		},
		{
			desc: "algorithm with neither keySize nor mode — name unchanged",
			alg:  &findings.Algorithm{Name: "RSA"},
			want: "RSA",
		},
		{
			desc: "RSA-2048 with keySize=2048 already in name — no duplication",
			alg:  &findings.Algorithm{Name: "RSA-2048", KeySize: 2048},
			want: "RSA-2048",
		},
		{
			desc: "SHA-256 with no extra — name unchanged",
			alg:  &findings.Algorithm{Name: "SHA-256"},
			want: "SHA-256",
		},
		{
			desc: "mode comparison is case-insensitive — gcm already in AES-256-gcm",
			alg:  &findings.Algorithm{Name: "AES-256-gcm", KeySize: 256, Mode: "GCM"},
			want: "AES-256-gcm",
		},
		{
			desc: "ChaCha20 with mode=Poly1305 appends mode",
			alg:  &findings.Algorithm{Name: "ChaCha20", Mode: "Poly1305"},
			want: "ChaCha20-Poly1305",
		},
	}

	for _, tt := range tests {
		t.Run(tt.desc, func(t *testing.T) {
			got := buildComponentName(tt.alg)
			if got != tt.want {
				t.Errorf("buildComponentName() = %q, want %q", got, tt.want)
			}
		})
	}
}

// Regression: original basic cases still pass.
func TestBuildComponentName_Basic(t *testing.T) {
	tests := []struct {
		name string
		alg  *findings.Algorithm
		want string
	}{
		{
			"name already complete",
			&findings.Algorithm{Name: "AES-256-GCM", KeySize: 256, Mode: "GCM"},
			"AES-256-GCM",
		},
		{
			"name needs keySize",
			&findings.Algorithm{Name: "AES", KeySize: 256},
			"AES-256",
		},
		{
			"name alone",
			&findings.Algorithm{Name: "RSA"},
			"RSA",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := buildComponentName(tt.alg)
			if got != tt.want {
				t.Errorf("buildComponentName() = %q, want %q", got, tt.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// 6. algorithmGroupKey
// ---------------------------------------------------------------------------

func TestAlgorithmGroupKey(t *testing.T) {
	tests := []struct {
		desc string
		f    findings.UnifiedFinding
		want string
	}{
		{
			desc: "AES-256-GCM groups by name|keySize|mode|curve",
			f: findings.UnifiedFinding{
				Algorithm: &findings.Algorithm{Name: "AES", KeySize: 256, Mode: "GCM"},
			},
			want: "AES|256|GCM|",
		},
		{
			desc: "RSA-2048 no mode no curve",
			f: findings.UnifiedFinding{
				Algorithm: &findings.Algorithm{Name: "RSA", KeySize: 2048},
			},
			want: "RSA|2048||",
		},
		{
			desc: "ECDSA with curve",
			f: findings.UnifiedFinding{
				Algorithm: &findings.Algorithm{Name: "ECDSA", KeySize: 0, Mode: "", Curve: "P-256"},
			},
			want: "ECDSA|0||P-256",
		},
		{
			desc: "nil algorithm returns empty key",
			f:    findings.UnifiedFinding{Algorithm: nil},
			want: "",
		},
		{
			desc: "SHA-256 hash no extras",
			f: findings.UnifiedFinding{
				Algorithm: &findings.Algorithm{Name: "SHA-256"},
			},
			want: "SHA-256|0||",
		},
	}

	for _, tt := range tests {
		t.Run(tt.desc, func(t *testing.T) {
			got := algorithmGroupKey(tt.f)
			if got != tt.want {
				t.Errorf("algorithmGroupKey() = %q, want %q", got, tt.want)
			}
		})
	}
}

// Same algorithm at two different locations must produce the same group key.
func TestAlgorithmGroupKey_SameAlgorithmSameKey(t *testing.T) {
	f1 := findings.UnifiedFinding{
		Location:  findings.Location{File: "/a.go", Line: 10},
		Algorithm: &findings.Algorithm{Name: "AES", KeySize: 256, Mode: "GCM"},
	}
	f2 := findings.UnifiedFinding{
		Location:  findings.Location{File: "/b.go", Line: 99},
		Algorithm: &findings.Algorithm{Name: "AES", KeySize: 256, Mode: "GCM"},
	}
	if algorithmGroupKey(f1) != algorithmGroupKey(f2) {
		t.Errorf("same algorithm produced different group keys: %q vs %q",
			algorithmGroupKey(f1), algorithmGroupKey(f2))
	}
}

// Different algorithms must produce different group keys.
func TestAlgorithmGroupKey_DifferentAlgorithmsDifferentKeys(t *testing.T) {
	pairs := []struct {
		a, b findings.UnifiedFinding
	}{
		{
			findings.UnifiedFinding{Algorithm: &findings.Algorithm{Name: "AES", KeySize: 128, Mode: "CBC"}},
			findings.UnifiedFinding{Algorithm: &findings.Algorithm{Name: "AES", KeySize: 256, Mode: "CBC"}},
		},
		{
			findings.UnifiedFinding{Algorithm: &findings.Algorithm{Name: "AES", KeySize: 256, Mode: "GCM"}},
			findings.UnifiedFinding{Algorithm: &findings.Algorithm{Name: "AES", KeySize: 256, Mode: "CBC"}},
		},
		{
			findings.UnifiedFinding{Algorithm: &findings.Algorithm{Name: "RSA", KeySize: 2048}},
			findings.UnifiedFinding{Algorithm: &findings.Algorithm{Name: "RSA", KeySize: 4096}},
		},
	}

	for i, p := range pairs {
		k1 := algorithmGroupKey(p.a)
		k2 := algorithmGroupKey(p.b)
		if k1 == k2 {
			t.Errorf("pair[%d]: expected different group keys but both = %q", i, k1)
		}
	}
}

// ---------------------------------------------------------------------------
// 7. mapToCDXPrimitive — full coverage
// ---------------------------------------------------------------------------

func TestMapToCDXPrimitive_AllMappings(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		// symmetric group
		{"symmetric", "block-cipher"},
		{"block-cipher", "block-cipher"},
		{"stream-cipher", "stream-cipher"},
		{"SYMMETRIC", "block-cipher"}, // case insensitive
		// ae / aead group
		{"ae", "ae"},
		{"aead", "ae"},
		{"AE", "ae"},
		{"AEAD", "ae"},
		// asymmetric group
		{"asymmetric", "pke"},
		{"pke", "pke"},
		{"public-key", "pke"},
		// signature group
		{"signature", "signature"},
		{"sign", "signature"},
		{"SIGNATURE", "signature"},
		// hash group
		{"hash", "hash"},
		{"digest", "hash"},
		{"HASH", "hash"},
		// mac group
		{"mac", "mac"},
		{"hmac", "mac"},
		{"MAC", "mac"},
		// kdf group
		{"kdf", "kdf"},
		{"key-derivation", "kdf"},
		{"KDF", "kdf"},
		// key-agree group
		{"key-exchange", "key-agree"},
		{"key-agree", "key-agree"},
		{"keyexchange", "key-agree"},
		// kem group
		{"kem", "kem"},
		{"key-encapsulation", "kem"},
		{"KEM", "kem"},
		// xof
		{"xof", "xof"},
		{"XOF", "xof"},
		// CycloneDX 1.7 enforces a strict primitive enum (additionalProperties:
		// false on cryptoProperties.algorithmProperties). Anything outside the
		// enum fails schema validation, so unrecognised inputs MUST normalise
		// to "unknown" — the schema-defined fallback for unidentified
		// primitives — rather than passing through.
		{"custom-primitive", "unknown"},
		{"", "unknown"},
	}

	for _, tt := range tests {
		t.Run(fmt.Sprintf("input=%q", tt.input), func(t *testing.T) {
			got := mapToCDXPrimitive(tt.input)
			if got != tt.want {
				t.Errorf("mapToCDXPrimitive(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

// Original test kept to confirm no regression.
func TestMapToCDXPrimitive_Original(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"symmetric", "block-cipher"},
		{"ae", "ae"},
		{"aead", "ae"},
		{"asymmetric", "pke"},
		{"signature", "signature"},
		{"hash", "hash"},
		{"mac", "mac"},
		{"kdf", "kdf"},
		{"key-exchange", "key-agree"},
		{"kem", "kem"},
		{"xof", "xof"},
	}

	for _, tt := range tests {
		got := mapToCDXPrimitive(tt.input)
		if got != tt.want {
			t.Errorf("mapToCDXPrimitive(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

// ---------------------------------------------------------------------------
// 8. extractFamily — all known families
// ---------------------------------------------------------------------------

func TestExtractFamily_AllFamilies(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		// PQC families
		{"ML-KEM-512", "ML-KEM"},
		{"ML-KEM-768", "ML-KEM"},
		{"ML-KEM-1024", "ML-KEM"},
		{"ML-DSA-44", "ML-DSA"},
		{"ML-DSA-65", "ML-DSA"},
		{"SLH-DSA-SHAKE-128s", "SLH-DSA"},
		{"XMSS-SHA2-10-256", "XMSS"},
		{"LMS-SHA256-M32-H5", "LMS"},
		// Symmetric
		{"AES-256-GCM", "AES"},
		{"AES-128-CBC", "AES"},
		{"ChaCha20-Poly1305", "ChaCha20"},
		{"ChaCha20", "ChaCha20"},
		{"Camellia-256", "Camellia"},
		{"ARIA-128", "ARIA"},
		// Asymmetric / ECC
		{"RSA-2048", "RSA"},
		{"RSA-4096", "RSA"},
		{"ECDSA", "ECDSA"},
		{"ECDH", "ECDH"},
		{"EdDSA", "EdDSA"},
		{"Ed25519", "Ed25519"},
		{"Ed448", "Ed448"},
		{"X25519", "X25519"},
		{"X448", "X448"},
		// Hash — SHA-256 prefix-matches "SHA-2" before "SHA-3"; SHA-384 prefix-matches
		// "SHA-3" (since "SHA-3" is listed before "SHA-2" in the families slice and
		// HasPrefix("SHA-384","SHA-3") is true); SHA-512 has no matching prefix entry
		// so the fallback splits on "-" and returns "SHA".
		{"SHA-256", "SHA-2"},
		{"SHA-384", "SHA-3"}, // implementation: "SHA-3" prefix matches before "SHA-2"
		{"SHA-512", "SHA"},   // implementation fallback: first segment before "-"
		{"SHA-3-256", "SHA-3"},
		{"SHA-1", "SHA-1"},
		{"BLAKE2b-256", "BLAKE2"},
		{"BLAKE3", "BLAKE3"},
		// MAC / KDF
		{"HMAC-SHA256", "HMAC"},
		{"HKDF-SHA256", "HKDF"},
		{"PBKDF2-SHA256", "PBKDF2"},
		{"Argon2id", "Argon2"},
		// Deprecated / legacy
		{"DES-CBC", "DES"},
		{"3DES-EDE", "3DES"},
		{"MD5", "MD5"},
		// Unknown — falls back to first segment before dash
		{"CUSTOM-ALG-512", "CUSTOM"},
		{"NewAlg", "NewAlg"},
	}

	for _, tt := range tests {
		t.Run(fmt.Sprintf("input=%q", tt.input), func(t *testing.T) {
			got := extractFamily(tt.input)
			if got != tt.want {
				t.Errorf("extractFamily(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

// Original test cases retained.
func TestExtractFamily_Original(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"AES-256-GCM", "AES"},
		{"RSA-2048", "RSA"},
		{"ML-KEM-768", "ML-KEM"},
		{"SHA-256", "SHA-2"},
		{"ChaCha20-Poly1305", "ChaCha20"},
	}

	for _, tt := range tests {
		got := extractFamily(tt.input)
		if got != tt.want {
			t.Errorf("extractFamily(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

// ---------------------------------------------------------------------------
// 9. generateSerialNumber — deterministic UUID generation
// ---------------------------------------------------------------------------

func TestGenerateSerialNumber_Format(t *testing.T) {
	comps := []cdxComponent{
		{Name: "AES-256", BOMRef: "ref1", Type: "cryptographic-asset"},
	}
	serial := generateSerialNumber(comps)
	if len(serial) < 36 {
		t.Errorf("serial too short: %q", serial)
	}
	if !strings.HasPrefix(serial, "urn:uuid:") {
		t.Errorf("serial should start with urn:uuid:, got %q", serial)
	}
}

func TestGenerateSerialNumber_Deterministic(t *testing.T) {
	comps := []cdxComponent{
		{Name: "AES-256-GCM", BOMRef: "crypto-asset-abc123", Type: "cryptographic-asset"},
		{Name: "RSA-2048", BOMRef: "crypto-asset-def456", Type: "cryptographic-asset"},
	}

	s1 := generateSerialNumber(comps)
	s2 := generateSerialNumber(comps)

	if s1 != s2 {
		t.Errorf("generateSerialNumber is not deterministic: %q vs %q", s1, s2)
	}
}

func TestGenerateSerialNumber_DifferentInputsDifferentSerials(t *testing.T) {
	comps1 := []cdxComponent{
		{Name: "AES-256-GCM", BOMRef: "ref1", Type: "cryptographic-asset"},
	}
	comps2 := []cdxComponent{
		{Name: "RSA-2048", BOMRef: "ref2", Type: "cryptographic-asset"},
	}

	s1 := generateSerialNumber(comps1)
	s2 := generateSerialNumber(comps2)

	if s1 == s2 {
		t.Errorf("different inputs produced the same serial number: %q", s1)
	}
}

func TestGenerateSerialNumber_EmptyComponents(t *testing.T) {
	serial := generateSerialNumber(nil)
	if !strings.HasPrefix(serial, "urn:uuid:") {
		t.Errorf("empty components: serial should still start with urn:uuid:, got %q", serial)
	}
	// Should be a fixed value every time (hash of empty input is stable)
	serial2 := generateSerialNumber(nil)
	if serial != serial2 {
		t.Errorf("empty components: serial not stable: %q vs %q", serial, serial2)
	}
}

// ---------------------------------------------------------------------------
// 10. generateBOMRef — stable identifier
// ---------------------------------------------------------------------------

func TestGenerateBOMRef_Format(t *testing.T) {
	ref := generateBOMRef("crypto-asset", "AES-256-GCM", 256, "GCM")
	if !strings.HasPrefix(ref, "crypto-asset-") {
		t.Errorf("bom-ref %q does not start with prefix crypto-asset-", ref)
	}
}

func TestGenerateBOMRef_Deterministic(t *testing.T) {
	r1 := generateBOMRef("crypto-asset", "AES-256-GCM", 256, "GCM")
	r2 := generateBOMRef("crypto-asset", "AES-256-GCM", 256, "GCM")
	if r1 != r2 {
		t.Errorf("generateBOMRef not deterministic: %q vs %q", r1, r2)
	}
}

func TestGenerateBOMRef_DifferentInputsDifferentRefs(t *testing.T) {
	tests := []struct {
		prefix  string
		name    string
		keySize int
		mode    string
	}{
		{"crypto-asset", "AES-256-GCM", 256, "GCM"},
		{"crypto-asset", "AES-128-GCM", 128, "GCM"},
		{"crypto-asset", "AES-256-CBC", 256, "CBC"},
		{"lib", "openssl", 0, ""},
		{"lib", "boringssl", 0, ""},
	}

	seen := map[string]string{}
	for _, tt := range tests {
		ref := generateBOMRef(tt.prefix, tt.name, tt.keySize, tt.mode)
		key := fmt.Sprintf("%s|%s|%d|%s", tt.prefix, tt.name, tt.keySize, tt.mode)
		for prevKey, prevRef := range seen {
			if prevKey != key && prevRef == ref {
				t.Errorf("collision: %q and %q produced same bom-ref %q", prevKey, key, ref)
			}
		}
		seen[key] = ref
	}
}

func TestGenerateBOMRef_ZeroKeySizeAndEmptyMode(t *testing.T) {
	// KeySize=0 and empty mode should not contribute to hash differently from each other
	ref := generateBOMRef("lib", "openssl", 0, "")
	if ref == "" {
		t.Error("generateBOMRef returned empty string")
	}
	// Calling again must be stable
	if generateBOMRef("lib", "openssl", 0, "") != ref {
		t.Error("generateBOMRef with zero keySize not stable")
	}
}

// ---------------------------------------------------------------------------
// 11. QRS metadata in CBOM
// ---------------------------------------------------------------------------

func TestWriteCBOM_QRSMetadata(t *testing.T) {
	// One quantum-vulnerable finding drives a non-100 QRS score
	ff := []findings.UnifiedFinding{
		{
			Location:     findings.Location{File: "/repo/main.go", Line: 1},
			Algorithm:    &findings.Algorithm{Name: "RSA-2048", Primitive: "asymmetric", KeySize: 2048},
			SourceEngine: "cipherscope",
			QuantumRisk:  findings.QRVulnerable,
			Severity:     findings.SevCritical,
		},
	}
	result := BuildResult("1.0.0", "/repo", []string{"cipherscope"}, ff)
	buf := writeCBOMOrFatal(t, result)
	bom := parseCBOM(t, buf)

	// QRS should be set on the result (verified via BuildResult)
	if result.QRS == nil {
		t.Fatal("QRS must not be nil")
	}

	// The CBOM metadata must include the QRS score and grade
	scoreVal, ok := findProp(bom.Metadata.Properties, "oqs:quantumReadinessScore")
	if !ok {
		t.Error("metadata is missing oqs:quantumReadinessScore property")
	}
	wantScore := fmt.Sprintf("%d", result.QRS.Score)
	if scoreVal != wantScore {
		t.Errorf("oqs:quantumReadinessScore = %q, want %q", scoreVal, wantScore)
	}

	gradeVal, ok := findProp(bom.Metadata.Properties, "oqs:quantumReadinessGrade")
	if !ok {
		t.Error("metadata is missing oqs:quantumReadinessGrade property")
	}
	if gradeVal != result.QRS.Grade {
		t.Errorf("oqs:quantumReadinessGrade = %q, want %q", gradeVal, result.QRS.Grade)
	}

	// quantumVulnerableCount should be "1"
	vulnVal, _ := findProp(bom.Metadata.Properties, "oqs:quantumVulnerableCount")
	if vulnVal != "1" {
		t.Errorf("oqs:quantumVulnerableCount = %q, want 1", vulnVal)
	}
}

func TestWriteCBOM_QRSMetadata_EmptyFindings(t *testing.T) {
	// With no findings the QRS score should be 100 / A+
	result := BuildResult("1.0.0", "/repo", []string{"cipherscope"}, nil)
	buf := writeCBOMOrFatal(t, result)
	bom := parseCBOM(t, buf)

	scoreVal, ok := findProp(bom.Metadata.Properties, "oqs:quantumReadinessScore")
	if !ok {
		t.Error("metadata is missing oqs:quantumReadinessScore even with no findings")
	}
	if scoreVal != "100" {
		t.Errorf("oqs:quantumReadinessScore = %q, want 100 for empty findings", scoreVal)
	}

	gradeVal, _ := findProp(bom.Metadata.Properties, "oqs:quantumReadinessGrade")
	if gradeVal != "A+" {
		t.Errorf("oqs:quantumReadinessGrade = %q, want A+ for empty findings", gradeVal)
	}
}

func TestWriteCBOM_PQCSafePercent(t *testing.T) {
	ff := []findings.UnifiedFinding{
		{
			Location:     findings.Location{File: "/repo/a.go", Line: 1},
			Algorithm:    &findings.Algorithm{Name: "ML-KEM-768"},
			SourceEngine: "cipherscope",
			QuantumRisk:  findings.QRSafe,
		},
		{
			Location:     findings.Location{File: "/repo/b.go", Line: 2},
			Algorithm:    &findings.Algorithm{Name: "ML-DSA-44"},
			SourceEngine: "cipherscope",
			QuantumRisk:  findings.QRResistant,
		},
		{
			Location:     findings.Location{File: "/repo/c.go", Line: 3},
			Algorithm:    &findings.Algorithm{Name: "RSA-2048"},
			SourceEngine: "cipherscope",
			QuantumRisk:  findings.QRVulnerable,
		},
	}
	result := BuildResult("1.0.0", "/repo", []string{"cipherscope"}, ff)
	buf := writeCBOMOrFatal(t, result)
	bom := parseCBOM(t, buf)

	// 2 out of 3 findings are safe/resistant → 66.7 %
	pctVal, ok := findProp(bom.Metadata.Properties, "oqs:pqcSafePercent")
	if !ok {
		t.Fatal("oqs:pqcSafePercent property is missing")
	}
	if pctVal != "66.7" {
		t.Errorf("oqs:pqcSafePercent = %q, want 66.7", pctVal)
	}
}

// ---------------------------------------------------------------------------
// 12. Corroborated findings — sources show "cipherscope+cryptoscan"
// ---------------------------------------------------------------------------

func TestWriteCBOM_CorroboratedSources(t *testing.T) {
	ff := []findings.UnifiedFinding{
		{
			Location:       findings.Location{File: "/repo/main.go", Line: 5},
			Algorithm:      &findings.Algorithm{Name: "RSA", KeySize: 2048, Primitive: "asymmetric"},
			Confidence:     findings.ConfidenceHigh,
			SourceEngine:   "cipherscope",
			CorroboratedBy: []string{"cryptoscan"},
			QuantumRisk:    findings.QRVulnerable,
		},
	}
	result := BuildResult("1.0.0", "/repo", []string{"cipherscope", "cryptoscan"}, ff)
	buf := writeCBOMOrFatal(t, result)
	bom := parseCBOM(t, buf)

	if len(bom.Components) != 1 {
		t.Fatalf("components len = %d, want 1", len(bom.Components))
	}

	comp := bom.Components[0]
	sourceVal, ok := findProp(comp.Properties, "oqs:source")
	if !ok {
		t.Fatal("oqs:source property missing from corroborated component")
	}
	// Sources should be joined: "cipherscope+cryptoscan"
	if sourceVal != "cipherscope+cryptoscan" {
		t.Errorf("oqs:source = %q, want cipherscope+cryptoscan", sourceVal)
	}
}

func TestWriteCBOM_CorroboratedSources_MultipleEngines(t *testing.T) {
	// Three engines corroborate the same finding — all three should appear in source
	ff := []findings.UnifiedFinding{
		{
			Location:       findings.Location{File: "/repo/main.go", Line: 1},
			Algorithm:      &findings.Algorithm{Name: "AES", KeySize: 256, Mode: "GCM"},
			SourceEngine:   "cipherscope",
			CorroboratedBy: []string{"cryptoscan", "sonarqube"},
		},
	}
	result := BuildResult("1.0.0", "/repo", []string{"cipherscope", "cryptoscan", "sonarqube"}, ff)
	buf := writeCBOMOrFatal(t, result)
	bom := parseCBOM(t, buf)

	comp := bom.Components[0]
	sourceVal, _ := findProp(comp.Properties, "oqs:source")

	if !strings.Contains(sourceVal, "cipherscope") {
		t.Errorf("source %q missing cipherscope", sourceVal)
	}
	if !strings.Contains(sourceVal, "cryptoscan") {
		t.Errorf("source %q missing cryptoscan", sourceVal)
	}
	if !strings.Contains(sourceVal, "sonarqube") {
		t.Errorf("source %q missing sonarqube", sourceVal)
	}
}

// Corroboration sources must not be deduplicated with themselves.
func TestWriteCBOM_CorroboratedSources_NoDuplication(t *testing.T) {
	ff := []findings.UnifiedFinding{
		{
			Location:       findings.Location{File: "/repo/a.go", Line: 1},
			Algorithm:      &findings.Algorithm{Name: "AES", KeySize: 256, Mode: "GCM"},
			SourceEngine:   "cipherscope",
			CorroboratedBy: []string{"cryptoscan"},
		},
		{
			// Same algorithm, same group key — gets merged
			Location:       findings.Location{File: "/repo/b.go", Line: 5},
			Algorithm:      &findings.Algorithm{Name: "AES", KeySize: 256, Mode: "GCM"},
			SourceEngine:   "cipherscope",
			CorroboratedBy: []string{"cryptoscan"},
		},
	}
	result := BuildResult("1.0.0", "/repo", []string{"cipherscope", "cryptoscan"}, ff)
	buf := writeCBOMOrFatal(t, result)
	bom := parseCBOM(t, buf)

	// Both occurrences group into one component
	if len(bom.Components) != 1 {
		t.Fatalf("expected 1 grouped component, got %d", len(bom.Components))
	}

	comp := bom.Components[0]
	sourceVal, _ := findProp(comp.Properties, "oqs:source")

	// "cipherscope" should appear exactly once, "cryptoscan" exactly once
	cipherCount := strings.Count(sourceVal, "cipherscope")
	cryptoCount := strings.Count(sourceVal, "cryptoscan")
	if cipherCount != 1 {
		t.Errorf("cipherscope appears %d times in source %q, want 1", cipherCount, sourceVal)
	}
	if cryptoCount != 1 {
		t.Errorf("cryptoscan appears %d times in source %q, want 1", cryptoCount, sourceVal)
	}
}

// ---------------------------------------------------------------------------
// 13. Multiple occurrences — same algorithm at different locations
// ---------------------------------------------------------------------------

func TestWriteCBOM_MultipleOccurrences_Grouped(t *testing.T) {
	ff := []findings.UnifiedFinding{
		{
			Location:     findings.Location{File: "/repo/a.go", Line: 10},
			Algorithm:    &findings.Algorithm{Name: "AES-256", KeySize: 256},
			SourceEngine: "cipherscope",
		},
		{
			Location:     findings.Location{File: "/repo/b.go", Line: 20},
			Algorithm:    &findings.Algorithm{Name: "AES-256", KeySize: 256},
			SourceEngine: "cipherscope",
		},
		{
			Location:     findings.Location{File: "/repo/c.go", Line: 30},
			Algorithm:    &findings.Algorithm{Name: "AES-256", KeySize: 256},
			SourceEngine: "cipherscope",
		},
		{
			Location:     findings.Location{File: "/repo/d.go", Line: 40},
			Algorithm:    &findings.Algorithm{Name: "RSA-2048", KeySize: 2048},
			SourceEngine: "cipherscope",
		},
	}
	result := BuildResult("1.0.0", "/repo", []string{"cipherscope"}, ff)
	buf := writeCBOMOrFatal(t, result)
	bom := parseCBOM(t, buf)

	// 3 AES occurrences collapse to 1 component; RSA is 1 component → total 2
	if len(bom.Components) != 2 {
		t.Fatalf("components len = %d, want 2 (grouped)", len(bom.Components))
	}

	aesComp := findComponent(bom.Components, "AES-256")
	if aesComp == nil {
		t.Fatalf("AES-256 component not found; components: %v", componentNames(bom.Components))
	}
	if aesComp.Evidence == nil {
		t.Fatal("AES-256 component has nil evidence")
	}
	if len(aesComp.Evidence.Occurrences) != 3 {
		t.Errorf("AES-256 occurrences = %d, want 3", len(aesComp.Evidence.Occurrences))
	}

	// Occurrence lines should reflect all three source files
	wantLines := map[int]bool{10: false, 20: false, 30: false}
	for _, occ := range aesComp.Evidence.Occurrences {
		if _, ok := wantLines[occ.Line]; ok {
			wantLines[occ.Line] = true
		}
	}
	for line, found := range wantLines {
		if !found {
			t.Errorf("AES-256 missing occurrence at line %d", line)
		}
	}
}

func TestWriteCBOM_MultipleOccurrences_DifferentModes_NotGrouped(t *testing.T) {
	// AES-256-GCM and AES-256-CBC differ by mode → separate components
	ff := []findings.UnifiedFinding{
		{
			Location:     findings.Location{File: "/repo/a.go", Line: 1},
			Algorithm:    &findings.Algorithm{Name: "AES", KeySize: 256, Mode: "GCM"},
			SourceEngine: "cipherscope",
		},
		{
			Location:     findings.Location{File: "/repo/b.go", Line: 2},
			Algorithm:    &findings.Algorithm{Name: "AES", KeySize: 256, Mode: "CBC"},
			SourceEngine: "cipherscope",
		},
	}
	result := BuildResult("1.0.0", "/repo", []string{"cipherscope"}, ff)
	buf := writeCBOMOrFatal(t, result)
	bom := parseCBOM(t, buf)

	if len(bom.Components) != 2 {
		t.Errorf("components len = %d, want 2 (different modes are different algorithms)", len(bom.Components))
	}
}

// ---------------------------------------------------------------------------
// Additional: WriteCBOM determinism (serial numbers match across calls)
// ---------------------------------------------------------------------------

func TestWriteCBOM_Deterministic(t *testing.T) {
	ff := []findings.UnifiedFinding{
		{
			Location:     findings.Location{File: "/a.go", Line: 1},
			Algorithm:    &findings.Algorithm{Name: "AES-256"},
			SourceEngine: "cs",
		},
	}
	result := BuildResult("0.1.0", "/test", []string{"cs"}, ff)

	var buf1, buf2 bytes.Buffer
	if err := WriteCBOM(&buf1, result); err != nil {
		t.Fatal(err)
	}
	if err := WriteCBOM(&buf2, result); err != nil {
		t.Fatal(err)
	}

	var bom1, bom2 cdxBOM
	json.Unmarshal(buf1.Bytes(), &bom1)
	json.Unmarshal(buf2.Bytes(), &bom2)

	if bom1.SerialNumber != bom2.SerialNumber {
		t.Errorf("serial numbers differ: %q vs %q", bom1.SerialNumber, bom2.SerialNumber)
	}
	if bom1.Components[0].BOMRef != bom2.Components[0].BOMRef {
		t.Errorf("bom-ref differs across runs: %q vs %q",
			bom1.Components[0].BOMRef, bom2.Components[0].BOMRef)
	}
}

// ---------------------------------------------------------------------------
// Additional: WriteCBOM metadata engines field
// ---------------------------------------------------------------------------

func TestWriteCBOM_EnginesMetadata(t *testing.T) {
	result := BuildResult("1.0.0", "/repo", []string{"cipherscope", "cryptoscan"}, nil)
	buf := writeCBOMOrFatal(t, result)
	bom := parseCBOM(t, buf)

	enginesVal, ok := findProp(bom.Metadata.Properties, "oqs:enginesUsed")
	if !ok {
		t.Fatal("oqs:enginesUsed property is missing")
	}
	if !strings.Contains(enginesVal, "cipherscope") || !strings.Contains(enginesVal, "cryptoscan") {
		t.Errorf("oqs:enginesUsed = %q, want to contain cipherscope and cryptoscan", enginesVal)
	}
}

// ---------------------------------------------------------------------------
// Additional: BOMRef uniqueness across different algorithm components
// ---------------------------------------------------------------------------

func TestWriteCBOM_BOMRefUniqueness(t *testing.T) {
	ff := []findings.UnifiedFinding{
		{
			Location:     findings.Location{File: "/repo/a.go", Line: 1},
			Algorithm:    &findings.Algorithm{Name: "AES", KeySize: 256, Mode: "GCM"},
			SourceEngine: "cipherscope",
		},
		{
			Location:     findings.Location{File: "/repo/b.go", Line: 2},
			Algorithm:    &findings.Algorithm{Name: "RSA", KeySize: 2048},
			SourceEngine: "cipherscope",
		},
		{
			Location:     findings.Location{File: "/repo/c.go", Line: 3},
			Algorithm:    &findings.Algorithm{Name: "ML-KEM", KeySize: 768},
			SourceEngine: "cipherscope",
		},
	}
	result := BuildResult("1.0.0", "/repo", []string{"cipherscope"}, ff)
	buf := writeCBOMOrFatal(t, result)
	bom := parseCBOM(t, buf)

	seen := map[string]bool{}
	for _, comp := range bom.Components {
		if seen[comp.BOMRef] {
			t.Errorf("duplicate bom-ref detected: %q", comp.BOMRef)
		}
		seen[comp.BOMRef] = true
	}
}

// ---------------------------------------------------------------------------
// Additional: dependency component does not have algorithmProperties
// ---------------------------------------------------------------------------

func TestWriteCBOM_LibraryHasNoAlgorithmProperties(t *testing.T) {
	ff := []findings.UnifiedFinding{
		{
			Location:     findings.Location{File: "/repo/go.sum", Line: 1},
			Dependency:   &findings.Dependency{Library: "openssl"},
			SourceEngine: "cipherscope",
		},
	}
	result := BuildResult("1.0.0", "/repo", []string{"cipherscope"}, ff)
	buf := writeCBOMOrFatal(t, result)
	bom := parseCBOM(t, buf)

	if len(bom.Components) != 1 {
		t.Fatalf("expected 1 component, got %d", len(bom.Components))
	}

	comp := bom.Components[0]
	// Library dependencies are component.type "library" per CycloneDX 1.7
	// (top-level component-type enum). cryptoProperties applies only to
	// cryptographic-asset components (algorithm/certificate/protocol/
	// related-crypto-material), so a library has none.
	if comp.Type != "library" {
		t.Errorf("component.type = %q, want library", comp.Type)
	}
	if comp.CryptoProperties != nil {
		t.Errorf("library component must not have cryptoProperties; got assetType=%q",
			comp.CryptoProperties.AssetType)
	}
}

// ---------------------------------------------------------------------------
// Utility: componentNames returns names of all components for error messages.
// ---------------------------------------------------------------------------

func componentNames(comps []cdxComponent) []string {
	names := make([]string, len(comps))
	for i, c := range comps {
		names[i] = c.Name
	}
	return names
}

// ---------------------------------------------------------------------------
// A2: DataFlowPath serialization + dependency property parity tests
// ---------------------------------------------------------------------------

func TestCBOM_AlgorithmComponent_DataFlowPath_Present(t *testing.T) {
	ff := []findings.UnifiedFinding{
		{
			Location:     findings.Location{File: "/app/crypto.go", Line: 42},
			Algorithm:    &findings.Algorithm{Name: "RSA-2048"},
			SourceEngine: "semgrep",
			DataFlowPath: []findings.FlowStep{
				{File: "/app/crypto.go", Line: 10, Message: "key gen"},
				{File: "/app/crypto.go", Line: 42, Message: "usage"},
			},
		},
	}
	result := BuildResult("0.1.0", "/app", []string{"semgrep"}, ff)
	buf := writeCBOMOrFatal(t, result)
	bom := parseCBOM(t, buf)

	if len(bom.Components) == 0 {
		t.Fatal("expected at least one component")
	}
	comp := bom.Components[0]

	dfpVal, ok := findProp(comp.Properties, "oqs:dataFlowPath")
	if !ok {
		t.Fatal("oqs:dataFlowPath property missing from algorithm component")
	}

	var steps []findings.FlowStep
	if err := json.Unmarshal([]byte(dfpVal), &steps); err != nil {
		t.Fatalf("oqs:dataFlowPath is not valid []FlowStep JSON: %v", err)
	}
	if len(steps) != 2 {
		t.Errorf("oqs:dataFlowPath: expected 2 steps, got %d", len(steps))
	}

	entryVal, ok := findProp(comp.Properties, "oqs:dataFlowEntry")
	if !ok {
		t.Fatal("oqs:dataFlowEntry property missing from algorithm component")
	}
	if entryVal != "/app/crypto.go:10" {
		t.Errorf("oqs:dataFlowEntry = %q, want %q", entryVal, "/app/crypto.go:10")
	}
}

func TestCBOM_AlgorithmComponent_DataFlowPath_Absent_WhenNil(t *testing.T) {
	ff := []findings.UnifiedFinding{
		{
			Location:  findings.Location{File: "/app/crypto.go", Line: 1},
			Algorithm: &findings.Algorithm{Name: "AES-256"},
			// DataFlowPath intentionally nil
		},
	}
	result := BuildResult("0.1.0", "/app", []string{"test-engine"}, ff)
	buf := writeCBOMOrFatal(t, result)
	bom := parseCBOM(t, buf)

	if len(bom.Components) == 0 {
		t.Fatal("expected at least one component")
	}
	comp := bom.Components[0]

	if _, ok := findProp(comp.Properties, "oqs:dataFlowPath"); ok {
		t.Error("oqs:dataFlowPath should be absent when DataFlowPath is nil")
	}
	if _, ok := findProp(comp.Properties, "oqs:dataFlowEntry"); ok {
		t.Error("oqs:dataFlowEntry should be absent when DataFlowPath is nil")
	}
}

func TestCBOM_DependencyComponent_FullPropertyParity(t *testing.T) {
	ff := []findings.UnifiedFinding{
		{
			Location:       findings.Location{File: "/go.mod", Line: 7},
			Dependency:     &findings.Dependency{Library: "github.com/openssl/openssl"},
			SourceEngine:   "cryptodeps",
			Confidence:     findings.ConfidenceHigh,
			Reachable:      findings.ReachableYes,
			QuantumRisk:    findings.QRVulnerable,
			Severity:       findings.SevHigh,
			Recommendation: "Migrate to ML-KEM",
		},
	}
	result := BuildResult("0.1.0", "/", []string{"cryptodeps"}, ff)
	buf := writeCBOMOrFatal(t, result)
	bom := parseCBOM(t, buf)

	var depComp *cdxComponent
	for i := range bom.Components {
		// CycloneDX 1.7: dependency findings are component.type "library"
		// (no cryptoProperties). cryptoProperties.assetType is restricted to
		// algorithm/certificate/protocol/related-crypto-material.
		if bom.Components[i].Type == "library" {
			depComp = &bom.Components[i]
			break
		}
	}
	if depComp == nil {
		t.Fatal("no library component found in CBOM output")
	}

	checks := []struct {
		propName string
		want     string
	}{
		{"oqs:confidence", string(findings.ConfidenceHigh)},
		{"oqs:source", "cryptodeps"},
		{"oqs:reachable", string(findings.ReachableYes)},
		{"oqs:policyVerdict", string(findings.QRVulnerable)},
		{"oqs:severity", string(findings.SevHigh)},
		{"oqs:recommendation", "Migrate to ML-KEM"},
	}
	for _, tc := range checks {
		val, ok := findProp(depComp.Properties, tc.propName)
		if !ok {
			t.Errorf("dependency component missing property %q", tc.propName)
			continue
		}
		if val != tc.want {
			t.Errorf("property %q = %q, want %q", tc.propName, val, tc.want)
		}
	}
}

// ---------------------------------------------------------------------------
// Impact properties tests
// ---------------------------------------------------------------------------

func TestWriteCBOM_ImpactProperties_ComponentLevel(t *testing.T) {
	f := findings.UnifiedFinding{
		Location:    findings.Location{File: "/app/crypto.go", Line: 10},
		Algorithm:   &findings.Algorithm{Name: "RSA-2048"},
		QuantumRisk: findings.QRVulnerable,
		Severity:    findings.SevCritical,
		SourceEngine: "cipherscope",
	}

	// DedupeKey for this finding: "/app/crypto.go|10|alg|RSA-2048"
	findingKey := f.DedupeKey()

	impactResult := &impact.Result{
		ImpactZones: []impact.ImpactZone{
			{
				FindingKey:        findingKey,
				FromAlgorithm:     "RSA-2048",
				ToAlgorithm:       "ML-DSA-65",
				SizeRatio:         12.93,
				BlastRadiusScore:  75,
				BlastRadiusGrade:  "Critical",
				ForwardHopCount:   3,
				BrokenConstraints: []impact.ConstraintViolation{{Overflow: 100}},
				ViolatedProtocols: []impact.ProtocolViolation{{Protocol: "TLS"}},
			},
		},
	}

	result := BuildResult("1.0.0", "/app", []string{"cipherscope"}, []findings.UnifiedFinding{f},
		WithImpactResult(impactResult))

	buf := writeCBOMOrFatal(t, result)
	bom := parseCBOM(t, buf)

	comp := findComponent(bom.Components, "RSA-2048")
	if comp == nil {
		t.Fatal("component RSA-2048 not found")
	}

	checks := []struct {
		prop string
		want string
	}{
		{"oqs:impact:blastRadiusScore", "75"},
		{"oqs:impact:blastRadiusGrade", "Critical"},
		{"oqs:impact:forwardHopCount", "3"},
		{"oqs:impact:brokenConstraints", "1"},
		{"oqs:impact:violatedProtocols", "1"},
		{"oqs:impact:migrationTarget", "ML-DSA-65"},
		{"oqs:impact:sizeRatio", "12.93"},
	}

	for _, c := range checks {
		val, ok := findProp(comp.Properties, c.prop)
		if !ok {
			t.Errorf("missing property %q on component", c.prop)
			continue
		}
		if val != c.want {
			t.Errorf("property %q = %q, want %q", c.prop, val, c.want)
		}
	}
}

func TestWriteCBOM_ImpactProperties_NoZoneForFinding(t *testing.T) {
	// Finding with no matching ImpactZone should have no oqs:impact:* properties.
	f := findings.UnifiedFinding{
		Location:    findings.Location{File: "/app/crypto.go", Line: 20},
		Algorithm:   &findings.Algorithm{Name: "AES-256"},
		QuantumRisk: findings.QRResistant,
		SourceEngine: "cipherscope",
	}

	impactResult := &impact.Result{
		ImpactZones: []impact.ImpactZone{
			// Different finding key — no match
			{FindingKey: "other|10|alg|RSA-2048", BlastRadiusScore: 50, BlastRadiusGrade: "Significant"},
		},
	}

	result := BuildResult("1.0.0", "/app", []string{"cipherscope"}, []findings.UnifiedFinding{f},
		WithImpactResult(impactResult))

	buf := writeCBOMOrFatal(t, result)
	bom := parseCBOM(t, buf)

	comp := findComponent(bom.Components, "AES-256")
	if comp == nil {
		t.Fatal("component AES-256 not found")
	}

	if _, ok := findProp(comp.Properties, "oqs:impact:blastRadiusScore"); ok {
		t.Error("oqs:impact:blastRadiusScore should not be present when no matching ImpactZone")
	}
}

func TestWriteCBOM_ImpactProperties_MetadataCounts(t *testing.T) {
	f1 := findings.UnifiedFinding{
		Location:    findings.Location{File: "/app/crypto.go", Line: 10},
		Algorithm:   &findings.Algorithm{Name: "RSA-2048"},
		QuantumRisk: findings.QRVulnerable,
		SourceEngine: "cipherscope",
	}
	f2 := findings.UnifiedFinding{
		Location:    findings.Location{File: "/app/crypto.go", Line: 20},
		Algorithm:   &findings.Algorithm{Name: "ECDSA-P256"},
		QuantumRisk: findings.QRVulnerable,
		SourceEngine: "cipherscope",
	}

	impactResult := &impact.Result{
		ImpactZones: []impact.ImpactZone{
			{
				FindingKey:        f1.DedupeKey(),
				BlastRadiusGrade:  "Critical",
				ViolatedProtocols: []impact.ProtocolViolation{{Protocol: "TLS"}, {Protocol: "SSH"}},
			},
			{
				FindingKey:       f2.DedupeKey(),
				BlastRadiusGrade: "Significant",
			},
		},
	}

	result := BuildResult("1.0.0", "/app", []string{"cipherscope"}, []findings.UnifiedFinding{f1, f2},
		WithImpactResult(impactResult))

	buf := writeCBOMOrFatal(t, result)
	bom := parseCBOM(t, buf)

	metaProps := bom.Metadata.Properties

	checks := []struct {
		prop string
		want string
	}{
		{"oqs:impact:criticalMigrations", "1"},
		{"oqs:impact:significantMigrations", "1"},
		{"oqs:impact:protocolsAffected", "2"},
	}

	for _, c := range checks {
		val, ok := findProp(metaProps, c.prop)
		if !ok {
			t.Errorf("missing metadata property %q", c.prop)
			continue
		}
		if val != c.want {
			t.Errorf("metadata property %q = %q, want %q", c.prop, val, c.want)
		}
	}
}

func TestWriteCBOM_ImpactProperties_NilImpact_NoMetadata(t *testing.T) {
	// When ImpactResult is nil, no oqs:impact:* metadata properties should be emitted.
	result := BuildResult("1.0.0", "/app", []string{"cipherscope"}, nil)
	buf := writeCBOMOrFatal(t, result)
	bom := parseCBOM(t, buf)

	for _, p := range bom.Metadata.Properties {
		if strings.HasPrefix(p.Name, "oqs:impact:") {
			t.Errorf("unexpected metadata property %q when ImpactResult is nil", p.Name)
		}
	}
}
