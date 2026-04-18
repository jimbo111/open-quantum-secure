package findings

// Confidence represents how certain a finding is.
type Confidence string

const (
	ConfidenceHigh       Confidence = "high"
	ConfidenceMediumHigh Confidence = "medium-high"
	ConfidenceMedium     Confidence = "medium"
	ConfidenceMediumLow  Confidence = "medium-low"
	ConfidenceLow        Confidence = "low"
)

// Reachability indicates whether a crypto usage is reachable from application code.
type Reachability string

const (
	ReachableYes     Reachability = "yes"
	ReachableNo      Reachability = "no"
	ReachableUnknown Reachability = "unknown"
)

// FlowStep represents a single step in a data-flow (taint) path.
type FlowStep struct {
	File    string `json:"file"`
	Line    int    `json:"line"`
	Column  int    `json:"column,omitempty"`
	Message string `json:"message,omitempty"`
}

// Location pinpoints where a finding was detected.
type Location struct {
	File         string `json:"file"`
	Line         int    `json:"line"`
	Column       int    `json:"column"`
	InnerPath    string `json:"innerPath,omitempty"`    // path within archive (e.g. "com/foo/Bar.class")
	ArtifactType string `json:"artifactType,omitempty"` // binary artifact type (e.g. "jar", "elf", "go-binary")
}

// Algorithm describes a detected cryptographic algorithm.
type Algorithm struct {
	Name      string `json:"name"`
	Primitive string `json:"primitive,omitempty"` // symmetric, asymmetric, hash, signature, kdf, mac, rng
	KeySize   int    `json:"keySize,omitempty"`
	Mode      string `json:"mode,omitempty"` // GCM, CBC, CTR, etc.
	Curve     string `json:"curve,omitempty"`
}

// Dependency describes a detected cryptographic library import.
type Dependency struct {
	Library string `json:"library"`
}

// QuantumRisk represents the quantum computing threat level.
type QuantumRisk string

const (
	QRVulnerable QuantumRisk = "quantum-vulnerable"
	QRWeakened   QuantumRisk = "quantum-weakened"
	QRSafe       QuantumRisk = "quantum-safe"
	QRResistant  QuantumRisk = "quantum-resistant"
	QRDeprecated QuantumRisk = "deprecated"
	QRUnknown    QuantumRisk = "unknown"
)

// MigrationEffort constants classify how hard it is to migrate away from a finding.
const (
	EffortSimple   = "simple"   // Config change or cipher suite swap
	EffortModerate = "moderate" // Code change, replace API calls
	EffortComplex  = "complex"  // Protocol-level, PKI rebuild, library replacement
)

// Severity for policy/reporting.
type Severity string

const (
	SevCritical Severity = "critical"
	SevHigh     Severity = "high"
	SevMedium   Severity = "medium"
	SevLow      Severity = "low"
	SevInfo     Severity = "info"
)

// UnifiedFinding is the normalized output from any engine.
type UnifiedFinding struct {
	Location       Location     `json:"location"`
	Algorithm      *Algorithm   `json:"algorithm,omitempty"`
	Dependency     *Dependency  `json:"dependency,omitempty"`
	Confidence     Confidence   `json:"confidence"`
	SourceEngine   string       `json:"sourceEngine"`
	CorroboratedBy []string     `json:"corroboratedBy,omitempty"`
	Reachable      Reachability `json:"reachable"`
	RawIdentifier  string       `json:"rawIdentifier,omitempty"`
	QuantumRisk    QuantumRisk  `json:"quantumRisk,omitempty"`
	Severity       Severity     `json:"severity,omitempty"`
	Recommendation string       `json:"recommendation,omitempty"`
	DataFlowPath   []FlowStep   `json:"dataFlowPath,omitempty"`
	HNDLRisk       string       `json:"hndlRisk,omitempty"`       // "immediate" (classical KEM), "deferred" (signature), or "" (PQC/symmetric/no risk). PFS/ECDHE does NOT lower this — see pkg/quantum classify.go.
	Priority       string       `json:"priority,omitempty"`       // P1, P2, P3, P4
	BlastRadius    int          `json:"blastRadius,omitempty"`    // 0-100, copied from impact analysis
	TestFile        bool         `json:"testFile,omitempty"`        // true when finding is from a test file
	GeneratedFile   bool         `json:"generatedFile,omitempty"`   // true when finding is from generated code
	MigrationEffort  string            `json:"migrationEffort,omitempty"`  // "simple", "moderate", or "complex"
	TargetAlgorithm  string            `json:"targetAlgorithm,omitempty"`  // PQC replacement algorithm
	TargetStandard   string            `json:"targetStandard,omitempty"`   // NIST standard reference
	MigrationSnippet *MigrationSnippet `json:"migrationSnippet,omitempty"` // language-specific PQC migration example

	// TLS network probe fields (populated by tls-probe engine, Sprint 1).
	NegotiatedGroup     uint16 `json:"negotiatedGroup,omitempty"`     // IANA TLS SupportedGroup codepoint (0 = none/unknown)
	NegotiatedGroupName string `json:"negotiatedGroupName,omitempty"` // human-readable name, e.g. "X25519MLKEM768"
	PQCPresent          bool   `json:"pqcPresent,omitempty"`          // true when an ML-KEM-based group was negotiated
	PQCMaturity         string `json:"pqcMaturity,omitempty"`         // "final", "draft", or "" (classical/unknown)

	// Partial-inventory annotation fields (populated by tls-probe ECH detection, Sprint 2).
	// When PartialInventory is true the finding is incomplete because some crypto
	// signals are hidden by ECH. Downstream steps (e.g., CT log lookup in Sprint 3)
	// should treat these findings as requiring further enrichment.
	PartialInventory       bool   `json:"partialInventory,omitempty"`       // true when inventory is known to be incomplete
	PartialInventoryReason string `json:"partialInventoryReason,omitempty"` // "ECH_ENABLED" or ""

	// Handshake volume fields (populated by tls-probe size-based detection, Sprint 2).
	// HandshakeVolumeClass is the classifier output: "classical", "hybrid-kem",
	// "full-pqc", or "unknown". HandshakeBytes is the sum of BytesIn+BytesOut for
	// the TLS handshake exchange.
	HandshakeVolumeClass string `json:"handshakeVolumeClass,omitempty"` // "classical", "hybrid-kem", "full-pqc", "unknown"
	HandshakeBytes       int64  `json:"handshakeBytes,omitempty"`       // total handshake bytes (in+out)
}

// MigrationSnippet holds a language-specific PQC migration code example.
type MigrationSnippet struct {
	Language    string `json:"language"`
	Before      string `json:"before"`
	After       string `json:"after"`
	Explanation string `json:"explanation"`
}

// Clone returns a deep copy of f. Pointer fields (Algorithm, Dependency,
// MigrationSnippet) and slice fields (CorroboratedBy, DataFlowPath) are copied
// so that subsequent mutations on the clone do not affect the original. Used
// by the orchestrator before in-place pipeline stages (normalizeFindings,
// classifyFindings, attachMigrationSnippets) to keep concurrent Scan calls on
// the same Orchestrator safe when engines return shared result slices.
func (f *UnifiedFinding) Clone() UnifiedFinding {
	c := *f
	if f.Algorithm != nil {
		a := *f.Algorithm
		c.Algorithm = &a
	}
	if f.Dependency != nil {
		d := *f.Dependency
		c.Dependency = &d
	}
	if f.MigrationSnippet != nil {
		m := *f.MigrationSnippet
		c.MigrationSnippet = &m
	}
	if f.CorroboratedBy != nil {
		c.CorroboratedBy = append([]string(nil), f.CorroboratedBy...)
	}
	if f.DataFlowPath != nil {
		c.DataFlowPath = append([]FlowStep(nil), f.DataFlowPath...)
	}
	return c
}

// DedupeKey returns a string key for deduplication. Findings with the same key
// from different engines are considered duplicates and should be merged.
func (f *UnifiedFinding) DedupeKey() string {
	// Prefix with InnerPath when present (binary findings inside archives).
	// Format: "file!innerPath|..." — backward compatible when InnerPath is empty.
	fileKey := f.Location.File
	if f.Location.InnerPath != "" {
		fileKey = f.Location.File + "!" + f.Location.InnerPath
	}

	// For algorithms: file + line + algorithm name (ignore column — engines differ)
	if f.Algorithm != nil && f.Algorithm.Name != "" {
		return fileKey + "|" + itoa(f.Location.Line) + "|alg|" + f.Algorithm.Name
	}
	// For dependencies: file + library name (line varies between engines)
	if f.Dependency != nil && f.Dependency.Library != "" {
		return fileKey + "|dep|" + f.Dependency.Library
	}
	// Fallback: file + line + raw identifier + source engine to avoid collisions
	return fileKey + "|" + itoa(f.Location.Line) + "|" + f.RawIdentifier + "|" + f.SourceEngine
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	if n < 0 {
		// Use unsigned to handle math.MinInt without overflow
		return "-" + utoa(uint(-int64(n)))
	}
	return utoa(uint(n))
}

func utoa(n uint) string {
	if n == 0 {
		return "0"
	}
	digits := make([]byte, 0, 20)
	for n > 0 {
		digits = append(digits, byte('0'+n%10))
		n /= 10
	}
	// reverse
	for i, j := 0, len(digits)-1; i < j; i, j = i+1, j-1 {
		digits[i], digits[j] = digits[j], digits[i]
	}
	return string(digits)
}
