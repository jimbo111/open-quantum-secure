// Package sanitize provides utilities for stripping sensitive fields from
// CBOM JSON documents before they are uploaded to external services.
package sanitize

import (
	"encoding/json"
	"fmt"
)

// sensitivePropertyNames is the set of oqs: property names that must never
// be included in an uploaded CBOM. Hard-coded — not configurable.
var sensitivePropertyNames = map[string]bool{
	"oqs:codeSnippet":    true,
	"oqs:sourceContext":  true,
}

// ForUpload removes any properties that could contain source code from a CBOM
// JSON document. This is always applied before upload and is not configurable.
//
// Strips properties with name:
//   - "oqs:codeSnippet"
//   - "oqs:sourceContext"
//
// Works on raw JSON (parse → filter → re-serialize) to avoid coupling to the
// CBOM struct types.
func ForUpload(cbomJSON []byte) ([]byte, error) {
	if len(cbomJSON) == 0 {
		return nil, fmt.Errorf("sanitize: input is empty")
	}

	var doc interface{}
	if err := json.Unmarshal(cbomJSON, &doc); err != nil {
		return nil, fmt.Errorf("sanitize: invalid JSON: %w", err)
	}

	sanitizeNode(doc)

	out, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("sanitize: marshal: %w", err)
	}
	return out, nil
}

// sanitizeNode recursively walks a JSON tree and removes sensitive entries
// from any "properties" arrays it encounters.
func sanitizeNode(node interface{}) {
	switch v := node.(type) {
	case map[string]interface{}:
		if props, ok := v["properties"]; ok {
			v["properties"] = filterProperties(props)
		}
		for _, child := range v {
			sanitizeNode(child)
		}
	case []interface{}:
		for _, elem := range v {
			sanitizeNode(elem)
		}
	}
}

// filterProperties removes sensitive entries from a "properties" value.
// The CycloneDX properties field is an array of {"name": ..., "value": ...}
// objects. Non-array values are returned unchanged (defensive).
func filterProperties(props interface{}) interface{} {
	arr, ok := props.([]interface{})
	if !ok {
		return props
	}

	filtered := make([]interface{}, 0, len(arr))
	for _, item := range arr {
		obj, ok := item.(map[string]interface{})
		if !ok {
			filtered = append(filtered, item)
			continue
		}
		name, _ := obj["name"].(string)
		if sensitivePropertyNames[name] {
			continue
		}
		filtered = append(filtered, item)
	}
	return filtered
}
