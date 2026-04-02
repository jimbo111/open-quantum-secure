package orchestrator

import "time"

// EngineMetrics records timing and results for a single engine execution.
type EngineMetrics struct {
	Name     string        `json:"name"`
	Duration time.Duration `json:"duration"`
	Findings int           `json:"findings"`
	Error    string        `json:"error,omitempty"`
}

// ScanMetrics collects timing data for the entire scan pipeline.
type ScanMetrics struct {
	TotalDuration time.Duration   `json:"totalDuration"`
	Engines       []EngineMetrics `json:"engines"`
	NormalizeDur  time.Duration   `json:"normalizeDuration"`
	DedupeDur     time.Duration   `json:"dedupeDuration"`
	ClassifyDur   time.Duration   `json:"classifyDuration"`
	EnrichDur     time.Duration   `json:"enrichDuration,omitempty"`
	ImpactDur       time.Duration `json:"impactDuration,omitempty"`
	SuppressedCount int           `json:"suppressedCount,omitempty"`
}
