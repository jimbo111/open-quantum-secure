package registry

import "strings"

// CurveResult holds the result of resolving a curve name, alias, or OID.
type CurveResult struct {
	Canonical string
	Name      string
	OID       string
	Form      string
}

// ResolveCurve looks up a curve by canonical name, alias, or OID.
// Returns the resolved CurveResult and true on success, or an empty result and false if not found.
func (r *Registry) ResolveCurve(input string) (CurveResult, bool) {
	// Stage 1: Direct canonical name match (e.g., "P-256" or "nist/P-256")
	if c, ok := r.curveNameIndex[input]; ok {
		return CurveResult{
			Canonical: input,
			Name:      c.Name,
			OID:       c.OID,
			Form:      c.Form,
		}, true
	}

	// Stage 2: Alias match (case-insensitive, e.g., "secp256r1" → "nist/P-256")
	cleaned := strings.ToLower(strings.TrimSpace(input))
	if canonical, ok := r.curveAliasIndex[cleaned]; ok {
		if c, ok2 := r.curveNameIndex[canonical]; ok2 {
			return CurveResult{
				Canonical: canonical,
				Name:      c.Name,
				OID:       c.OID,
				Form:      c.Form,
			}, true
		}
	}

	// Stage 3: OID match (e.g., "1.2.840.10045.3.1.7" → "nist/P-256")
	if canonical, ok := r.curveOIDIndex[input]; ok {
		if c, ok2 := r.curveNameIndex[canonical]; ok2 {
			return CurveResult{
				Canonical: canonical,
				Name:      c.Name,
				OID:       c.OID,
				Form:      c.Form,
			}, true
		}
	}

	return CurveResult{}, false
}
