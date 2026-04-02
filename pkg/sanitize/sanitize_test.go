package sanitize

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

// buildCBOM is a helper that constructs a minimal CBOM-like JSON document.
func buildCBOM(props []map[string]string) []byte {
	propItems := make([]interface{}, len(props))
	for i, p := range props {
		propItems[i] = map[string]interface{}{
			"name":  p["name"],
			"value": p["value"],
		}
	}
	doc := map[string]interface{}{
		"bomFormat":   "CycloneDX",
		"specVersion": "1.7",
		"components": []interface{}{
			map[string]interface{}{
				"type":       "cryptographicAsset",
				"name":       "AES-256",
				"properties": propItems,
			},
		},
	}
	b, _ := json.Marshal(doc)
	return b
}

func TestForUpload_StripsCodeSnippet(t *testing.T) {
	input := buildCBOM([]map[string]string{
		{"name": "oqs:codeSnippet", "value": "secret source code"},
		{"name": "oqs:algorithm", "value": "AES"},
	})

	out, err := ForUpload(input)
	if err != nil {
		t.Fatalf("ForUpload: %v", err)
	}

	if strings.Contains(string(out), "oqs:codeSnippet") {
		t.Error("output still contains oqs:codeSnippet")
	}
	if strings.Contains(string(out), "secret source code") {
		t.Error("output still contains sensitive snippet value")
	}
	if !strings.Contains(string(out), "oqs:algorithm") {
		t.Error("oqs:algorithm should be preserved")
	}
}

func TestForUpload_StripsSourceContext(t *testing.T) {
	input := buildCBOM([]map[string]string{
		{"name": "oqs:sourceContext", "value": "func main() { ... }"},
		{"name": "oqs:keySize", "value": "256"},
	})

	out, err := ForUpload(input)
	if err != nil {
		t.Fatalf("ForUpload: %v", err)
	}

	if strings.Contains(string(out), "oqs:sourceContext") {
		t.Error("output still contains oqs:sourceContext")
	}
	if !strings.Contains(string(out), "oqs:keySize") {
		t.Error("oqs:keySize should be preserved")
	}
}

func TestForUpload_NoSensitiveProperties_Unchanged(t *testing.T) {
	input := buildCBOM([]map[string]string{
		{"name": "oqs:algorithm", "value": "AES-256"},
		{"name": "oqs:keySize", "value": "256"},
	})

	out, err := ForUpload(input)
	if err != nil {
		t.Fatalf("ForUpload: %v", err)
	}

	// Both properties must still be present
	if !strings.Contains(string(out), "oqs:algorithm") {
		t.Error("oqs:algorithm should be preserved")
	}
	if !strings.Contains(string(out), "oqs:keySize") {
		t.Error("oqs:keySize should be preserved")
	}
}

func TestForUpload_MixedProperties_OnlySensitiveRemoved(t *testing.T) {
	input := buildCBOM([]map[string]string{
		{"name": "oqs:codeSnippet", "value": "sensitive"},
		{"name": "oqs:sourceContext", "value": "also sensitive"},
		{"name": "oqs:algorithm", "value": "RSA"},
		{"name": "oqs:keySize", "value": "4096"},
	})

	out, err := ForUpload(input)
	if err != nil {
		t.Fatalf("ForUpload: %v", err)
	}

	if strings.Contains(string(out), "oqs:codeSnippet") {
		t.Error("oqs:codeSnippet should be removed")
	}
	if strings.Contains(string(out), "oqs:sourceContext") {
		t.Error("oqs:sourceContext should be removed")
	}
	if !strings.Contains(string(out), "oqs:algorithm") {
		t.Error("oqs:algorithm should be preserved")
	}
	if !strings.Contains(string(out), "oqs:keySize") {
		t.Error("oqs:keySize should be preserved")
	}
}

func TestForUpload_EmptyJSONObject(t *testing.T) {
	out, err := ForUpload([]byte("{}"))
	if err != nil {
		t.Fatalf("ForUpload on empty object: %v", err)
	}
	if len(out) == 0 {
		t.Error("expected non-empty output for empty input object")
	}
}

func TestForUpload_NilInput(t *testing.T) {
	_, err := ForUpload(nil)
	if err == nil {
		t.Error("ForUpload(nil) should return error")
	}
}

func TestForUpload_EmptyInput(t *testing.T) {
	_, err := ForUpload([]byte(""))
	if err == nil {
		t.Error("ForUpload(empty) should return error")
	}
}

func TestForUpload_MalformedJSON(t *testing.T) {
	_, err := ForUpload([]byte("{not valid json"))
	if err == nil {
		t.Error("ForUpload(malformed) should return error")
	}
}

func TestForUpload_NestedComponents(t *testing.T) {
	// Build a CBOM with nested components, each having properties at multiple levels.
	doc := map[string]interface{}{
		"bomFormat": "CycloneDX",
		"components": []interface{}{
			map[string]interface{}{
				"name": "outer",
				"properties": []interface{}{
					map[string]interface{}{"name": "oqs:codeSnippet", "value": "outer snippet"},
					map[string]interface{}{"name": "oqs:algorithm", "value": "AES"},
				},
				"components": []interface{}{
					map[string]interface{}{
						"name": "inner",
						"properties": []interface{}{
							map[string]interface{}{"name": "oqs:sourceContext", "value": "inner ctx"},
							map[string]interface{}{"name": "oqs:keySize", "value": "128"},
						},
					},
				},
			},
		},
	}
	input, _ := json.Marshal(doc)

	out, err := ForUpload(input)
	if err != nil {
		t.Fatalf("ForUpload: %v", err)
	}

	s := string(out)
	if strings.Contains(s, "oqs:codeSnippet") {
		t.Error("nested oqs:codeSnippet should be removed")
	}
	if strings.Contains(s, "outer snippet") {
		t.Error("outer snippet value should be removed")
	}
	if strings.Contains(s, "oqs:sourceContext") {
		t.Error("nested oqs:sourceContext should be removed")
	}
	if strings.Contains(s, "inner ctx") {
		t.Error("inner ctx value should be removed")
	}
	if !strings.Contains(s, "oqs:algorithm") {
		t.Error("oqs:algorithm should be preserved")
	}
	if !strings.Contains(s, "oqs:keySize") {
		t.Error("oqs:keySize should be preserved")
	}
}

func TestForUpload_LargeCBOM(t *testing.T) {
	// Generate 1000 components, each with mixed properties.
	components := make([]interface{}, 1000)
	for i := range components {
		components[i] = map[string]interface{}{
			"name": fmt.Sprintf("component-%d", i),
			"properties": []interface{}{
				map[string]interface{}{"name": "oqs:codeSnippet", "value": fmt.Sprintf("snippet-%d", i)},
				map[string]interface{}{"name": "oqs:algorithm", "value": "AES-256"},
			},
		}
	}
	doc := map[string]interface{}{
		"bomFormat":  "CycloneDX",
		"components": components,
	}
	input, _ := json.Marshal(doc)

	out, err := ForUpload(input)
	if err != nil {
		t.Fatalf("ForUpload on 1000 components: %v", err)
	}
	if strings.Contains(string(out), "oqs:codeSnippet") {
		t.Error("large CBOM still contains oqs:codeSnippet")
	}
	if !strings.Contains(string(out), "oqs:algorithm") {
		t.Error("large CBOM lost oqs:algorithm")
	}
}
