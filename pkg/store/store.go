// Package store provides an abstraction for persisting and retrieving scan
// records, with a local flat-file implementation and a remote API wrapper.
package store

import "context"

// ScanStore is the interface for persisting and querying scan records.
// Implementations must be safe for concurrent use.
type ScanStore interface {
	// SaveScan persists a single scan record for the given project.
	SaveScan(ctx context.Context, project string, record ScanRecord) error

	// ListScans returns scan records for the given project, subject to opts.
	// Implementations must return an empty (non-nil) slice when no records exist,
	// never a nil slice, and never an error for a missing project.
	ListScans(ctx context.Context, project string, opts ListOptions) ([]ScanRecord, error)
}

// ScanRecord holds the persisted summary of a completed scan.
type ScanRecord struct {
	ScanID                string         `json:"scanId"`
	Timestamp             string         `json:"timestamp"`             // RFC3339
	Branch                string         `json:"branch,omitempty"`
	CommitSHA             string         `json:"commitSha,omitempty"`
	ScanMode              string         `json:"scanMode"`
	QuantumReadinessScore int            `json:"quantumReadinessScore"`
	QuantumReadinessGrade string         `json:"quantumReadinessGrade"`
	FindingSummary        FindingSummary `json:"findingSummary"`
	Duration              string           `json:"duration,omitempty"`
	DataLifetimeYears     int              `json:"dataLifetimeYears,omitempty"`
	TopFindings           []FindingDetail  `json:"topFindings,omitempty"`
}

// FindingDetail is a lightweight per-finding record for dashboard drill-down.
// Stored in ScanRecord.TopFindings (capped at MaxTopFindings).
type FindingDetail struct {
	File            string `json:"file"`
	Line            int    `json:"line,omitempty"`
	Algorithm       string `json:"algorithm"`
	Primitive       string `json:"primitive,omitempty"`
	QuantumRisk     string `json:"quantumRisk"`
	Severity        string `json:"severity"`
	MigrationEffort string `json:"migrationEffort,omitempty"`
	HNDLRisk        string `json:"hndlRisk,omitempty"`
	Recommendation  string `json:"recommendation,omitempty"`
	TargetAlgorithm string `json:"targetAlgorithm,omitempty"`
	TargetStandard  string `json:"targetStandard,omitempty"`
	MigrationSnippet *FindingSnippet `json:"migrationSnippet,omitempty"`
	SourceEngine    string `json:"sourceEngine,omitempty"`
}

// FindingSnippet is a lightweight migration snippet stored with findings.
type FindingSnippet struct {
	Language    string `json:"language"`
	Before      string `json:"before"`
	After       string `json:"after"`
	Explanation string `json:"explanation"`
}

// MaxTopFindings caps the number of individual findings stored per scan record.
const MaxTopFindings = 100

// FindingSummary holds per-severity and per-quantum-risk finding counts.
type FindingSummary struct {
	Total    int `json:"total"`
	Critical int `json:"critical"`
	High     int `json:"high"`
	Medium   int `json:"medium"`
	Low      int `json:"low"`
	Info     int `json:"info"`

	// Quantum-risk counts (for trend tracking accuracy).
	QuantumVulnerable int `json:"quantumVulnerable,omitempty"`
	QuantumWeakened   int `json:"quantumWeakened,omitempty"`
	QuantumSafe       int `json:"quantumSafe,omitempty"`
	QuantumResistant  int `json:"quantumResistant,omitempty"`
	Deprecated        int `json:"deprecated,omitempty"`
}

// ListOptions controls how ListScans filters results.
type ListOptions struct {
	// Limit is the maximum number of records to return. The most recent N
	// records are returned (i.e., the last N appended). Zero means no limit.
	Limit int
}
