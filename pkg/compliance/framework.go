package compliance

import (
	"fmt"
	"sort"
	"strings"

	"github.com/jimbo111/open-quantum-secure/pkg/findings"
)

// Violation is a single compliance rule breach for a finding.
type Violation struct {
	// Algorithm is the algorithm name that triggered the violation (may be empty
	// for quantum-vulnerable dependency findings).
	Algorithm string

	// Rule is the machine-readable rule identifier, e.g. "cnsa2-slh-dsa-excluded".
	Rule string

	// Message is the human-readable description.
	Message string

	// Deadline is the ISO 8601 date by which the issue must be resolved.
	Deadline string

	// Remediation is actionable guidance for fixing the violation.
	// Populated by the framework's Evaluate implementation.
	Remediation string

	// Severity indicates the gravity of the violation: "error" (default, empty string)
	// for hard requirements, or "warn" for strong recommendations that are not
	// formally required by the framework's normative text.
	Severity string
}

// ApprovedAlgoRef describes one row in a framework's approved-algorithm reference table.
type ApprovedAlgoRef struct {
	UseCase   string // e.g. "Key Exchange"
	Algorithm string // e.g. "ML-KEM-1024"
	Standard  string // e.g. "FIPS 203"
}

// DeadlineRef describes one compliance transition deadline.
type DeadlineRef struct {
	Date        string // ISO 8601, e.g. "2030-01-01"
	Description string
}

// Framework is the interface implemented by every compliance framework.
type Framework interface {
	// ID returns the machine-readable framework identifier, e.g. "cnsa-2.0".
	ID() string
	// Name returns the short human-readable name, e.g. "CNSA 2.0".
	Name() string
	// Description returns the long-form authority/version string, e.g. "NSA CNSA 2.0 (May 2025)".
	Description() string
	// Evaluate checks findings against this framework's rules and returns all violations.
	// Returns nil (not an empty slice) when there are no violations.
	Evaluate([]findings.UnifiedFinding) []Violation
	// ApprovedAlgos returns the approved-algorithm reference table rows for this framework.
	ApprovedAlgos() []ApprovedAlgoRef
	// Deadlines returns the transition deadline entries for this framework.
	Deadlines() []DeadlineRef
}

// Note: Register must only be called from init(); the registry is read without
// locks at runtime. Concurrent Register + Get is a data race.
var registry = map[string]Framework{}

// Register adds fw to the registry. Each framework calls this from its init().
func Register(fw Framework) {
	registry[fw.ID()] = fw
}

// Get returns the Framework for id, plus a boolean indicating whether it was found.
func Get(id string) (Framework, bool) {
	fw, ok := registry[id]
	return fw, ok
}

// EvaluateByID runs the named framework's Evaluate against ff.
// Returns an error when id is not a registered framework.
func EvaluateByID(id string, ff []findings.UnifiedFinding) ([]Violation, error) {
	fw, ok := Get(id)
	if !ok {
		return nil, fmt.Errorf("unsupported compliance standard %q (supported: %s)",
			id, strings.Join(SupportedIDs(), ", "))
	}
	return fw.Evaluate(ff), nil
}

// SupportedIDs returns a sorted list of all registered framework IDs.
func SupportedIDs() []string {
	ids := make([]string, 0, len(registry))
	for id := range registry {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids
}
