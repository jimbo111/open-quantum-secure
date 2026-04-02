package impact

// ImpactOpts configures how the impact graph is traversed.
type ImpactOpts struct {
	MaxHops    int
	TargetPath string
}

// ConsumerType describes how a cryptographic value is consumed at a hop.
type ConsumerType string

const (
	ConsumerAssignment    ConsumerType = "assignment"
	ConsumerReturn        ConsumerType = "return"
	ConsumerSerialization ConsumerType = "serialization"
	ConsumerStorage       ConsumerType = "storage"
	ConsumerNetwork       ConsumerType = "network"
	ConsumerAggregation   ConsumerType = "aggregation"
)

// ForwardEdge is a single hop in the forward propagation path from a crypto finding.
type ForwardEdge struct {
	Hop            int          `json:"hop"`
	SourceFile     string       `json:"sourceFile"`
	SourceLine     int          `json:"sourceLine"`
	TargetFile     string       `json:"targetFile"`
	TargetLine     int          `json:"targetLine"`
	Consumer       ConsumerType `json:"consumer"`
	Encoding       string       `json:"encoding,omitempty"`
	ProjectedBytes int          `json:"projectedBytes"`
}

// ConstraintHit records a detected size constraint along the forward path.
type ConstraintHit struct {
	Type         string `json:"type"`
	File         string `json:"file"`
	Line         int    `json:"line"`
	MaxBytes     int    `json:"maxBytes"`
	Encoding     string `json:"encoding,omitempty"`
	EffectiveMax int    `json:"effectiveMax"`
}

// ConstraintViolation is a ConstraintHit that exceeds the projected crypto size.
type ConstraintViolation struct {
	ConstraintHit
	Algorithm      string `json:"algorithm"`
	ProjectedBytes int    `json:"projectedBytes"`
	Overflow       int    `json:"overflow"`
}

// ProtocolViolation records a protocol boundary where the projected size exceeds the limit.
type ProtocolViolation struct {
	Protocol       string `json:"protocol"`
	MaxBytes       int    `json:"maxBytes"`
	ProjectedBytes int    `json:"projectedBytes"`
	Overflow       int    `json:"overflow"`
	HardLimit      bool   `json:"hardLimit"`
	File           string `json:"file"`
	Line           int    `json:"line"`
}

// BoundaryHit records where a crypto value crosses a protocol boundary.
type BoundaryHit struct {
	Protocol string `json:"protocol"`
	File     string `json:"file"`
	Line     int    `json:"line"`
}

// ImpactZone summarizes the blast radius of migrating one algorithm to another.
type ImpactZone struct {
	FindingKey        string                `json:"findingKey"`
	FromAlgorithm     string                `json:"fromAlgorithm"`
	ToAlgorithm       string                `json:"toAlgorithm"`
	SizeRatio         float64               `json:"sizeRatio"`
	BlastRadiusScore  int                   `json:"blastRadiusScore"`
	BlastRadiusGrade  string                `json:"blastRadiusGrade"`
	ForwardHopCount   int                   `json:"forwardHopCount"`
	BrokenConstraints []ConstraintViolation `json:"brokenConstraints,omitempty"`
	ViolatedProtocols []ProtocolViolation   `json:"violatedProtocols,omitempty"`
	ForwardPath       []ForwardEdge         `json:"forwardPath,omitempty"`
}

// Result aggregates all impact graph outputs for a single scan.
type Result struct {
	ForwardEdges []ForwardEdge `json:"forwardEdges,omitempty"`
	Constraints  []ConstraintHit `json:"constraints,omitempty"`
	Boundaries   []BoundaryHit   `json:"boundaries,omitempty"`
	ImpactZones  []ImpactZone    `json:"impactZones,omitempty"`
}

// ImpactDataForFinding returns the first ImpactZone whose FindingKey matches key.
// Returns nil when no matching zone exists.
func (r *Result) ImpactDataForFinding(key string) *ImpactZone {
	for i := range r.ImpactZones {
		if r.ImpactZones[i].FindingKey == key {
			return &r.ImpactZones[i]
		}
	}
	return nil
}
