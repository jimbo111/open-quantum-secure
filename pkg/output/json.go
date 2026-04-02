package output

import (
	"encoding/json"
	"io"
	"time"

	"github.com/jimbo111/open-quantum-secure/pkg/findings"
	"github.com/jimbo111/open-quantum-secure/pkg/impact"
	"github.com/jimbo111/open-quantum-secure/pkg/quantum"
)

// WithMetrics attaches pre-serialized scan metrics to the ScanResult.
// Use json.Marshal on an *orchestrator.ScanMetrics before passing here to
// avoid a circular import (output → orchestrator → output).
func WithMetrics(data json.RawMessage) BuildOption {
	return func(r *ScanResult) {
		r.Metrics = data
	}
}

// ScanResult is the top-level JSON output structure.
type ScanResult struct {
	Version      string                    `json:"version"`
	Target       string                    `json:"target"`
	Engines      []string                  `json:"engines"`
	ScanDuration string                    `json:"scanDuration,omitempty"`
	Summary      Summary                   `json:"summary"`
	QRS          *quantum.QRS              `json:"quantumReadinessScore,omitempty"`
	Findings     []findings.UnifiedFinding `json:"findings"`
	ImpactResult *impact.Result            `json:"impact,omitempty"`
	Metrics      json.RawMessage           `json:"metrics,omitempty"`

	// LifetimeMult is applied during QRS calculation. It is not serialized to JSON.
	// Set via WithLifetimeMultiplier. A value of 0 is treated as 1.0 (no adjustment).
	LifetimeMult float64 `json:"-"`
}

// Summary contains aggregate counts.
type Summary struct {
	TotalFindings     int `json:"totalFindings"`
	Algorithms        int `json:"algorithms"`
	Dependencies      int `json:"dependencies"`
	Corroborated      int `json:"corroborated"`
	QuantumVulnerable int `json:"quantumVulnerable"`
	QuantumWeakened   int `json:"quantumWeakened"`
	QuantumSafe       int `json:"quantumSafe"`
	QuantumResistant  int `json:"quantumResistant"`
	Deprecated        int `json:"deprecated"`
	Unknown           int `json:"unknown"`
}

// WriteJSON writes findings as a structured JSON document.
func WriteJSON(w io.Writer, result ScanResult) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(result)
}

// BuildResult constructs a ScanResult from findings.
func BuildResult(version, target string, engineNames []string, f []findings.UnifiedFinding, opts ...BuildOption) ScanResult {
	if f == nil {
		f = []findings.UnifiedFinding{}
	}
	algCount := 0
	depCount := 0
	corrCount := 0
	qvCount := 0
	qwCount := 0
	qsCount := 0
	qrCount := 0
	deprcCount := 0
	unknCount := 0

	for _, finding := range f {
		if finding.Algorithm != nil {
			algCount++
		}
		if finding.Dependency != nil {
			depCount++
		}
		if len(finding.CorroboratedBy) > 0 {
			corrCount++
		}
		switch finding.QuantumRisk {
		case findings.QRVulnerable:
			qvCount++
		case findings.QRWeakened:
			qwCount++
		case findings.QRSafe:
			qsCount++
		case findings.QRResistant:
			qrCount++
		case findings.QRDeprecated:
			deprcCount++
		case findings.QRUnknown:
			unknCount++
		}
	}

	// Build a partial result so options (including WithImpactResult) can be
	// applied before QRS calculation, allowing CalculateQRSWithImpact to use
	// the impact result when available.
	result := ScanResult{
		Version: version,
		Target:  target,
		Engines: engineNames,
		Summary: Summary{
			TotalFindings:     len(f),
			Algorithms:        algCount,
			Dependencies:      depCount,
			Corroborated:      corrCount,
			QuantumVulnerable: qvCount,
			QuantumWeakened:   qwCount,
			QuantumSafe:       qsCount,
			QuantumResistant:  qrCount,
			Deprecated:        deprcCount,
			Unknown:           unknCount,
		},
		Findings: f,
	}

	for _, opt := range opts {
		opt(&result)
	}

	// Compute QRS. When a data-lifetime multiplier is set, apply it to the
	// per-finding penalty calculation before applying the blast-radius impact
	// adjustment. A zero LifetimeMult means "not set" and is treated as 1.0.
	var qrs quantum.QRS
	if result.LifetimeMult != 0 && result.LifetimeMult != 1.0 {
		qrs = quantum.CalculateQRSFull(f, result.ImpactResult, result.LifetimeMult)
	} else {
		qrs = quantum.CalculateQRSWithImpact(f, result.ImpactResult)
	}
	result.QRS = &qrs

	return result
}

// BuildOption allows optional parameters for BuildResult.
type BuildOption func(*ScanResult)

// WithDuration sets the scan duration on the result.
func WithDuration(d time.Duration) BuildOption {
	return func(r *ScanResult) {
		r.ScanDuration = d.Round(time.Millisecond).String()
	}
}

// WithImpactResult attaches an impact analysis result to the ScanResult.
// When set, BuildResult uses CalculateQRSWithImpact instead of CalculateQRS
// so that migration difficulty is reflected in the Quantum Readiness Score.
func WithImpactResult(r *impact.Result) BuildOption {
	return func(s *ScanResult) {
		s.ImpactResult = r
	}
}

// WithLifetimeMultiplier sets a data-lifetime penalty multiplier on the result.
// Use quantum.DataLifetimeMultiplier to derive the value from years.
// A multiplier of 0 or 1.0 disables the adjustment.
func WithLifetimeMultiplier(mult float64) BuildOption {
	return func(s *ScanResult) {
		s.LifetimeMult = mult
	}
}
