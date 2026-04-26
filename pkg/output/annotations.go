package output

import (
	"encoding/json"
	"fmt"

	"github.com/jimbo111/open-quantum-secure/pkg/findings"
)

// cdxPropertyFromAnnotation converts a shared findingAnnotation into a
// cdxProperty with the CBOM "oqs:" namespace prefix. Two name overrides:
//   - "quantumRisk" → "oqs:policyVerdict" (CBOM uses CycloneDX-aligned naming)
//
// Value normalisation:
//   - bool          → "true" (annotations only emit true; false is omitted upstream)
//   - string        → as-is
//   - int / int64   → "%d"
//   - uint16        → "0x%04x" (IANA codepoint hex, used for serverPreferredGroup)
//   - other (slices)→ json.Marshal then string (matches legacy CBOM behaviour
//     for supportedGroups / supportedSigAlgs)
func cdxPropertyFromAnnotation(a findingAnnotation) cdxProperty {
	name := "oqs:" + a.Name
	if a.Name == "quantumRisk" {
		name = "oqs:policyVerdict"
	}
	var value string
	switch v := a.Value.(type) {
	case bool:
		value = fmt.Sprintf("%t", v)
	case string:
		value = v
	case int:
		value = fmt.Sprintf("%d", v)
	case int64:
		value = fmt.Sprintf("%d", v)
	case uint16:
		value = fmt.Sprintf("0x%04x", v)
	default:
		if b, err := json.Marshal(v); err == nil {
			value = string(b)
		}
	}
	return cdxProperty{Name: name, Value: value}
}

// findingAnnotation is a single (name, value) annotation emitted by
// emitFindingAnnotations. Format adapters convert these into SARIF map
// entries or CBOM cdxProperty values.
//
// Name is the canonical (un-prefixed) field name — e.g. "negotiatedGroupName",
// not "oqs:negotiatedGroupName". CBOM prepends its "oqs:" namespace; SARIF
// uses Name directly.
//
// Value is typed: bool stays bool, slices stay slices, ints stay ints. CBOM
// stringifies (with json.Marshal for slices); SARIF stores as-is.
type findingAnnotation struct {
	Name  string
	Value any
}

// emitFindingAnnotations invokes emit for each annotation field that should
// appear in both SARIF and CBOM output for f. Order is canonical: risk →
// migration → TLS probe (Sprint 1) → observability (Sprint 2) → enumeration
// (Sprint 8). Fields are skipped when their finding-side value is the zero
// value (empty string, false, zero number, nil/empty slice).
//
// Format-specific fields (SARIF's targetAlgorithm/migrationSnippet, CBOM's
// detectionMethod/impact zones) are NOT emitted here — adapters handle those
// in their own post-processing step.
func emitFindingAnnotations(f findings.UnifiedFinding, emit func(findingAnnotation)) {
	if f.QuantumRisk != "" {
		emit(findingAnnotation{Name: "quantumRisk", Value: string(f.QuantumRisk)})
	}
	if f.Severity != "" {
		emit(findingAnnotation{Name: "severity", Value: string(f.Severity)})
	}
	if f.Recommendation != "" {
		emit(findingAnnotation{Name: "recommendation", Value: f.Recommendation})
	}
	if f.HNDLRisk != "" {
		emit(findingAnnotation{Name: "hndlRisk", Value: f.HNDLRisk})
	}
	if f.MigrationEffort != "" {
		emit(findingAnnotation{Name: "migrationEffort", Value: f.MigrationEffort})
	}
	if f.NegotiatedGroupName != "" {
		emit(findingAnnotation{Name: "negotiatedGroupName", Value: f.NegotiatedGroupName})
	}
	if f.PQCPresent {
		emit(findingAnnotation{Name: "pqcPresent", Value: true})
	}
	if f.PQCMaturity != "" {
		emit(findingAnnotation{Name: "pqcMaturity", Value: f.PQCMaturity})
	}
	if f.PartialInventory {
		emit(findingAnnotation{Name: "partialInventory", Value: true})
		if f.PartialInventoryReason != "" {
			emit(findingAnnotation{Name: "partialInventoryReason", Value: f.PartialInventoryReason})
		}
	}
	if f.HandshakeVolumeClass != "" {
		emit(findingAnnotation{Name: "handshakeVolumeClass", Value: f.HandshakeVolumeClass})
	}
	if f.HandshakeBytes > 0 {
		emit(findingAnnotation{Name: "handshakeBytes", Value: f.HandshakeBytes})
	}
	if len(f.SupportedGroups) > 0 {
		emit(findingAnnotation{Name: "supportedGroups", Value: f.SupportedGroups})
	}
	if len(f.SupportedSigAlgs) > 0 {
		emit(findingAnnotation{Name: "supportedSigAlgs", Value: f.SupportedSigAlgs})
	}
	if f.ServerPreferredGroup != 0 {
		emit(findingAnnotation{Name: "serverPreferredGroup", Value: f.ServerPreferredGroup})
	}
	if f.ServerPreferenceMode != "" {
		emit(findingAnnotation{Name: "serverPreferenceMode", Value: f.ServerPreferenceMode})
	}
	if f.EnumerationMode != "" {
		emit(findingAnnotation{Name: "enumerationMode", Value: f.EnumerationMode})
	}
}
