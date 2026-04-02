package constraints

import "github.com/jimbo111/open-quantum-secure/pkg/impact"

// Check evaluates whether the given algorithm size profile violates a constraint.
//
// Projected bytes are determined in priority order:
//  1. SignatureBytes (> 0)
//  2. CiphertextBytes (> 0)
//  3. PublicKeyBytes (fallback)
//
// The projected value is then passed through CalculateEncodedSize with the
// constraint's Encoding field. If the encoded size exceeds the effective limit
// (ConstraintHit.EffectiveMax, or ConstraintHit.MaxBytes when EffectiveMax is
// zero), a non-nil ConstraintViolation is returned. Otherwise nil is returned.
func Check(profile AlgorithmSizeProfile, constraint impact.ConstraintHit) *impact.ConstraintViolation {
	var projected int
	switch {
	case profile.SignatureBytes > 0:
		projected = profile.SignatureBytes
	case profile.CiphertextBytes > 0:
		projected = profile.CiphertextBytes
	default:
		projected = profile.PublicKeyBytes
	}

	projected = CalculateEncodedSize(projected, constraint.Encoding)

	effectiveMax := constraint.EffectiveMax
	if effectiveMax == 0 {
		effectiveMax = constraint.MaxBytes
	}

	if projected > effectiveMax {
		return &impact.ConstraintViolation{
			ConstraintHit:  constraint,
			Algorithm:      "",
			ProjectedBytes: projected,
			Overflow:       projected - effectiveMax,
		}
	}
	return nil
}
