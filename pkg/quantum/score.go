package quantum

import (
	"math"
	"strings"

	"github.com/jimbo111/open-quantum-secure/pkg/findings"
	"github.com/jimbo111/open-quantum-secure/pkg/impact"
)

// QRS holds the Quantum Readiness Score result.
type QRS struct {
	Score int    `json:"score"` // 0-100
	Grade string `json:"grade"` // A+, A, B, C, D, F
}

// protocolMultipliers maps lowercase protocol names to a penalty multiplier
// applied when a finding is associated with that protocol context via an
// ImpactZone's ViolatedProtocols. TLS and DTLS carry the highest urgency due
// to active Harvest-Now-Decrypt-Later (HNDL) exposure; S/MIME is lowest because
// it covers offline email with no live key exchange.
//
// All 8 protocols from the impact registry are represented.
var protocolMultipliers = map[string]float64{
	"tls":    1.2,  // Active HNDL risk, most common deployment context
	"dtls":   1.2,  // Same risk profile as TLS
	"ssh":    1.1,  // Active sessions, persistent host keys
	"x.509":  1.15, // Certificate lifecycle urgency (CA/B Forum 47-day timeline)
	"grpc":   1.1,  // Service-to-service key exchange
	"jwt":    1.0,  // Token-based, typically short-lived; no additional penalty
	"ocsp":   1.0,  // Response signing; no additional penalty
	"s/mime": 0.9,  // Offline email, lower urgency
}

// findingPenalty returns the base QRS penalty for a finding (before multipliers).
// Returns 0 for QRSafe and unknown risk levels.
func findingPenalty(f findings.UnifiedFinding) float64 {
	switch f.QuantumRisk {
	case findings.QRVulnerable:
		return vulnerablePenalty(f)
	case findings.QRDeprecated:
		return 1.5
	case findings.QRWeakened:
		return 0.5
	default:
		return 0
	}
}

// vulnerablePenalty returns the per-finding penalty based on severity.
func vulnerablePenalty(f findings.UnifiedFinding) float64 {
	switch f.Severity {
	case findings.SevCritical:
		return 2.0
	case findings.SevHigh:
		return 1.5
	case findings.SevMedium:
		return 1.0
	default:
		return 1.0
	}
}

// adjustedPenalty returns a finding's penalty after corroboration, protocol-
// context, and data-lifetime multipliers. Returns 0 for QRSafe (which is
// scored as a bonus, not a penalty). Multipliers default to 1.0 when their
// inputs are zero or absent (nil impact / non-positive lifetime).
func adjustedPenalty(f findings.UnifiedFinding, impactResult *impact.Result, lifetimeMult float64) float64 {
	base := findingPenalty(f)
	if base == 0 {
		return 0
	}
	mult := 1.0
	if len(f.CorroboratedBy) > 0 {
		mult = 1.5
	}
	mult *= protocolMultiplierForFinding(f.DedupeKey(), impactResult)
	if lifetimeMult > 0 {
		mult *= lifetimeMult
	}
	return base * mult
}

// protocolMultiplierForFinding returns the highest protocol severity multiplier
// applicable to the finding identified by key. The key is matched against
// ImpactZone.FindingKey values (which equal finding.DedupeKey()). When no
// matching zone exists, or the zone has no ViolatedProtocols, 1.0 is returned.
// Matching against protocolMultipliers is case-insensitive via strings.ToLower.
func protocolMultiplierForFinding(key string, impactResult *impact.Result) float64 {
	if impactResult == nil {
		return 1.0
	}
	zone := impactResult.ImpactDataForFinding(key)
	if zone == nil {
		return 1.0
	}
	// Use 0 as a sentinel meaning "no protocol matched yet". This allows
	// multipliers below 1.0 (e.g. S/MIME = 0.9) to be selected when they
	// are the only protocol present. When multiple protocols violate a
	// finding, the highest multiplier dominates (most urgent protocol wins).
	best := 0.0
	for _, pv := range zone.ViolatedProtocols {
		if m, ok := protocolMultipliers[strings.ToLower(pv.Protocol)]; ok && m > best {
			best = m
		}
	}
	if best == 0.0 {
		return 1.0 // no known protocol matched — no adjustment
	}
	return best
}

// applyBlastRadius reduces score by up to 15% based on average blast radius
// across impact zones. No-op when impactResult is nil or has no zones.
func applyBlastRadius(score float64, impactResult *impact.Result) float64 {
	if impactResult == nil || len(impactResult.ImpactZones) == 0 {
		return score
	}
	var sum float64
	for _, z := range impactResult.ImpactZones {
		sum += float64(z.BlastRadiusScore)
	}
	avgBlast := sum / float64(len(impactResult.ImpactZones))
	adjusted := score * (1.0 - 0.15*avgBlast/100.0)
	if adjusted < 0 {
		adjusted = 0
	}
	if adjusted > 100 {
		adjusted = 100
	}
	return adjusted
}

// scoreFromValue clamps a raw score to [0,100], rounds to int, and packages
// it as a QRS with the corresponding letter grade.
func scoreFromValue(score float64) QRS {
	if score < 0 {
		score = 0
	}
	if score > 100 {
		score = 100
	}
	s := int(math.Round(score))
	return QRS{Score: s, Grade: scoreToGrade(s)}
}

// calculateQRSEndClamp implements the standard scoring policy used by
// CalculateQRS, CalculateQRSWithLifetime, and CalculateQRSWithImpact:
// penalties accumulate without per-finding clamping, the PQC bonus (+0.5
// per QRSafe finding) is applied inline during the loop, and the final
// score is clamped at the end. When applyBlast is true the impactResult's
// blast radius further reduces the score.
//
// CalculateQRSFull uses a different policy (per-finding clamp + bonus
// applied after the loop) and is implemented separately.
func calculateQRSEndClamp(ff []findings.UnifiedFinding, impactResult *impact.Result, lifetimeMult float64, applyBlast bool) QRS {
	if len(ff) == 0 {
		return QRS{Score: 100, Grade: "A+"}
	}
	score := 100.0
	for _, f := range ff {
		if f.QuantumRisk == findings.QRSafe {
			score += 0.5 // PQC adoption bonus, not multiplied
			continue
		}
		score -= adjustedPenalty(f, impactResult, lifetimeMult)
	}
	if applyBlast {
		// Clamp before blast so a deeply negative score doesn't get scaled
		// against blast and then clamped — mirrors the legacy step ordering.
		if score < 0 {
			score = 0
		}
		if score > 100 {
			score = 100
		}
		score = applyBlastRadius(score, impactResult)
	}
	return scoreFromValue(score)
}

// CalculateQRS computes the Quantum Readiness Score from classified findings.
//
// Scoring methodology (from spec doc 12):
//   - Start at 100
//   - Each quantum-vulnerable finding:  -2.0 points (critical: key exchange/KEM)
//     -1.5 points (high: signatures)
//     -1.0 points (medium: other asymmetric)
//   - Each deprecated finding:          -1.5 points
//   - Each quantum-weakened finding:    -0.5 points
//   - Each quantum-safe finding:        +0.5 points (bonus for PQC adoption)
//   - Corroborated findings have 1.5x weight (higher confidence = more impact)
//   - Score is clamped to [0, 100]
//
// Grading:
//
//	A+ = 95-100, A = 85-94, B = 70-84, C = 50-69, D = 30-49, F = 0-29
func CalculateQRS(ff []findings.UnifiedFinding) QRS {
	return calculateQRSEndClamp(ff, nil, 1.0, false)
}

// DataLifetimeMultiplier returns a QRS penalty multiplier based on data retention.
//
//   - Years > 10: 1.15 (amplifies penalties — long-lived data is higher HNDL risk)
//   - Years 5-10: 1.0  (standard, no adjustment)
//   - Years 1-4:  0.85 (reduces penalties — short-lived data has lower HNDL risk)
//   - Years 0:    1.0  (disabled / unknown)
func DataLifetimeMultiplier(years int) float64 {
	if years <= 0 {
		return 1.0
	}
	if years > 10 {
		return 1.15
	}
	if years >= 5 {
		return 1.0
	}
	return 0.85
}

// CalculateQRSWithLifetime computes the Quantum Readiness Score with a data-lifetime
// penalty multiplier applied to each finding's penalty. Use DataLifetimeMultiplier to
// obtain the multiplier from a retention period in years.
//
// A multiplier > 1.0 amplifies penalties (long-lived data → lower QRS).
// A multiplier < 1.0 reduces penalties (short-lived data → higher QRS).
// Passing 1.0 is identical to CalculateQRS.
func CalculateQRSWithLifetime(ff []findings.UnifiedFinding, lifetimeMult float64) QRS {
	return calculateQRSEndClamp(ff, nil, lifetimeMult, false)
}

// CalculateQRSWithImpact computes the Quantum Readiness Score adjusted for both
// protocol context and migration difficulty. When impactResult is nil or has no
// impact zones, it returns the same result as CalculateQRS.
//
// Two independent adjustments are applied in order:
//
//  1. Per-finding protocol multiplier: the penalty for each vulnerable/deprecated/
//     weakened finding is scaled by the highest protocolMultipliers entry matched
//     against that finding's ViolatedProtocols in the ImpactZone. Findings with no
//     protocol context use 1.0 (no change). S/MIME (0.9) can reduce a penalty.
//
//  2. Blast-radius reduction on the resulting score:
//     adjustedScore = penaltyScore × (1 - 0.15 × avgBlast/100)
//     Maximum reduction is 15% (when avgBlast = 100). Score is clamped to [0, 100].
func CalculateQRSWithImpact(ff []findings.UnifiedFinding, impactResult *impact.Result) QRS {
	return calculateQRSEndClamp(ff, impactResult, 1.0, true)
}

// CalculateQRSFull computes the Quantum Readiness Score with both a data-lifetime
// multiplier and a blast-radius impact adjustment applied. It is the canonical
// full-pipeline scorer when both inputs are available.
//
// Computation order:
//  1. Apply lifetime + protocol multipliers to per-finding penalties, with
//     score clamped at 0 mid-loop (penalties cannot drag score below 0 before
//     PQC bonuses are added).
//  2. Apply PQC adoption bonus (+0.5 per QRSafe finding) AFTER the penalty loop.
//  3. Apply blast-radius reduction (no-op when impactResult is nil/empty).
//
// The mid-loop clamp + post-loop bonus distinguishes this from
// CalculateQRSWithImpact / CalculateQRSWithLifetime, which apply the bonus
// inline and clamp once at the end.
func CalculateQRSFull(ff []findings.UnifiedFinding, impactResult *impact.Result, lifetimeMult float64) QRS {
	if lifetimeMult <= 0 {
		lifetimeMult = 1.0
	}
	score := 100.0
	for _, f := range ff {
		penalty := adjustedPenalty(f, impactResult, lifetimeMult)
		if penalty == 0 {
			continue
		}
		score -= penalty
		if score < 0 {
			score = 0
		}
	}
	for _, f := range ff {
		if f.QuantumRisk == findings.QRSafe {
			score += 0.5
		}
	}
	base := scoreFromValue(score)
	if impactResult == nil || len(impactResult.ImpactZones) == 0 {
		return base
	}
	return scoreFromValue(applyBlastRadius(float64(base.Score), impactResult))
}

func scoreToGrade(score int) string {
	switch {
	case score >= 95:
		return "A+"
	case score >= 85:
		return "A"
	case score >= 70:
		return "B"
	case score >= 50:
		return "C"
	case score >= 30:
		return "D"
	default:
		return "F"
	}
}
