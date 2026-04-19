package engines

import (
	"context"
	"os/exec"
	"strings"
	"time"

	"github.com/jimbo111/open-quantum-secure/pkg/findings"
)

// Tier represents the analysis depth of an engine.
type Tier int

const (
	Tier1Pattern Tier = iota + 1 // Pattern/AST matching
	Tier2Flow                    // Data-flow / taint analysis
	Tier3Formal                  // Formal verification / deep semantic
	Tier4Binary                  // Binary artifact scanning
)

// Tier5Network is for engines that probe live network endpoints (e.g., TLS).
// Defined outside the iota block to avoid shifting existing tier values.
const Tier5Network Tier = 5

// Tier3SCA is an alias for Tier3Formal used by SCA/supply-chain engines.
const Tier3SCA = Tier3Formal

func (t Tier) String() string {
	switch t {
	case Tier1Pattern:
		return "pattern"
	case Tier2Flow:
		return "flow"
	case Tier3Formal:
		return "formal"
	case Tier4Binary:
		return "binary"
	case Tier5Network:
		return "network"
	default:
		return "unknown"
	}
}

// ScanMode represents the scan execution mode.
type ScanMode string

const (
	ModeFull  ScanMode = "full"  // Scan all files
	ModeQuick ScanMode = "quick" // Tier 1 only, no taint
	ModeDiff  ScanMode = "diff"  // Only changed files
)

// ScanOptions configures a scan run.
type ScanOptions struct {
	TargetPath      string
	Languages       []string // empty = all supported
	Timeout         int      // seconds, 0 = no timeout
	MaxFileMB       int      // max file size in MB, 0 = engine default
	EngineNames     []string // empty = all available engines
	ExcludePatterns []string // glob patterns to exclude from scan
	Mode            ScanMode // full, quick, or diff
	ChangedFiles    []string // for diff mode: only scan these files (relative to TargetPath)
	ImpactGraph     bool     // enable Tier 2.5 forward impact analysis
	MaxImpactHops   int      // maximum forward hops for impact analysis (0 = default 10)
	ScanType        string   // "source" (default), "binary", or "all"
	BinaryPaths     []string // explicit binary artifact paths to scan

	// Incremental scan options (Phase 9).
	Incremental bool   // enable incremental mode: skip unchanged files using cache
	CachePath   string // override default cache path; default: <TargetPath>/.oqs-scanner-cache.json
	NoCache     bool   // force full scan, ignore and do not update cache

	// Suppression options (Phase 13).
	NoSuppress bool // disable oqs:ignore and .oqs-ignore filtering (for audits)

	// TLS probe options (Phase: TLS Network Scan).
	TLSTargets     []string // host:port targets to probe (empty = skip tls-probe engine)
	TLSInsecure    bool     // skip manual certificate verification after capture
	TLSDenyPrivate bool     // reject RFC 1918 / loopback / link-local target IPs
	TLSTimeout     int      // per-target dial+handshake timeout in seconds (0 = default 10s)
	TLSCACert      string   // path to custom CA cert PEM for manual verification

	// Network kill-switch: disables all outbound calls across all network engines.
	// Equivalent to running in an air-gapped environment.
	NoNetwork bool // when true, all Tier5Network engines return nil findings immediately

	// CT log lookup options (Sprint 3).
	CTLookupTargets []string // hostnames to query CT logs for cert algorithm discovery
	CTLookupFromECH bool     // auto-query CT logs for hostnames found via ECH partial-inventory findings

	// SSH probe options (Sprint 4).
	SSHTargets     []string // host:port targets to probe SSH KEX advertisement (empty = skip ssh-probe)
	SSHTimeout     int      // per-target dial+KEXINIT timeout in seconds (0 = default 10s)
	SSHDenyPrivate bool     // reject RFC 1918 / loopback / link-local target IPs (--ssh-strict)

	// Deep-probe options (Sprint 7).
	// When DeepProbe is true, the tls-probe engine opens a second raw TCP
	// connection per target and probes DefaultProbeGroups individually using
	// hand-crafted ClientHellos. This reveals PQC group support that Go's
	// stdlib crypto/tls does not expose via CurveID (e.g. pure ML-KEM groups).
	DeepProbe bool // enable raw ClientHello deep-probe for PQC group detection

	// Group + sig-alg enumeration options (Sprint 8).
	// These flags are additive — any combination can be enabled.
	// --deep-probe (Sprint 7) is the fast 6-group path; the Sprint 8 flags add
	// richer enumeration over a larger group/sigalg universe.
	EnumerateGroups        bool // probe all 13 groups in fullEnumGroups individually (--enumerate-groups)
	EnumerateSigAlgs       bool // probe each sig alg in fullSigAlgList individually (--enumerate-sigalgs)
	DetectServerPreference bool // send all accepted groups at once; record server's chosen group (--detect-server-preference)

	// MaxProbesPerTarget caps the total number of TCP probe connections opened
	// per target across all passes (initial probe + deep-probe + enumeration).
	// 0 = unlimited. Default 30 guards against runaway probe counts when all
	// Sprint 8 flags are enabled simultaneously (worst case ~39 connections).
	MaxProbesPerTarget int

	// SkipTLS12Fallback disables the TLS 1.2 fallback probe (Sprint 9, Feature 3).
	// When false (the default), after a primary TLS 1.3 probe that detects PQC
	// key exchange, the engine runs a secondary TLS 1.2 handshake to detect
	// downgrade vulnerabilities. Set to true to suppress this extra connection.
	SkipTLS12Fallback bool

	// Verbose enables detailed progress logging to stderr. When false (the
	// default), enum pass progress is suppressed to avoid leaking inventory
	// counts (accepted groups, preferred codepoints) into CI logs.
	Verbose bool

	// Zeek log ingestion options (Sprint 5).
	ZeekSSLPath  string // path to ssl.log (TSV, JSON, or .gz); empty = skip zeek-log engine
	ZeekX509Path string // path to x509.log (TSV, JSON, or .gz); empty = skip when no ssl path either

	// Suricata log ingestion options (Sprint 6).
	SuricataEvePath string // path to eve.json (plain or .gz); empty = skip suricata-log engine
}

// Engine is the interface every scanner engine must implement.
type Engine interface {
	// Name returns the engine identifier (e.g. "cipherscope").
	Name() string

	// Tier returns the analysis depth tier.
	Tier() Tier

	// SupportedLanguages returns the set of languages this engine can scan.
	SupportedLanguages() []string

	// Available reports whether the engine binary is accessible.
	Available() bool

	// Version returns the engine version string. Subprocess engines probe
	// the binary via --version; embedded engines return a fixed string.
	// Returns "unknown" if the version cannot be determined.
	Version() string

	// Scan runs the engine and returns normalized findings.
	Scan(ctx context.Context, opts ScanOptions) ([]findings.UnifiedFinding, error)
}

// ProbeVersion runs `<binaryPath> --version` with a 5-second timeout and
// returns the trimmed first line of output. Returns "unknown" on any failure.
// This is a convenience helper for subprocess-based engines implementing Version().
func ProbeVersion(binaryPath string) string {
	if binaryPath == "" {
		return "unknown"
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	out, err := exec.CommandContext(ctx, binaryPath, "--version").Output()
	if err != nil {
		return "unknown"
	}
	line, _, _ := strings.Cut(strings.TrimSpace(string(out)), "\n")
	return strings.TrimSpace(line)
}
