// Package forward implements the Crypto Impact Graph forward propagation engine.
// It walks the DataFlowPath of each finding, detects size constraints and protocol
// boundaries, runs the constraint solver and blast radius calculator, and returns
// an aggregated impact.Result.
package forward

import (
	"context"
	"strings"

	"github.com/jimbo111/open-quantum-secure/pkg/findings"
	"github.com/jimbo111/open-quantum-secure/pkg/impact"
	"github.com/jimbo111/open-quantum-secure/pkg/impact/blast"
	"github.com/jimbo111/open-quantum-secure/pkg/impact/constraints"
	"github.com/jimbo111/open-quantum-secure/pkg/impact/protocols"
)

const defaultMaxHops = 10

// Propagator runs forward impact analysis over a slice of findings.
type Propagator struct {
	maxHops int
}

// New returns a Propagator. If maxHops is <= 0 the default of 10 is used.
func New(maxHops int) *Propagator {
	if maxHops <= 0 {
		maxHops = defaultMaxHops
	}
	return &Propagator{maxHops: maxHops}
}

// Analyze iterates findings that have a non-nil Algorithm and a non-empty
// DataFlowPath. For each such finding it:
//
//  1. Builds ForwardEdges from the DataFlowPath steps (capped at maxHops).
//  2. Detects size constraints via constraints.DetectFromPath.
//  3. Detects protocol boundaries via protocols.DetectFromPath.
//  4. For each PQC migration target of the algorithm:
//     - Looks up source and target size profiles.
//     - Calculates the size ratio.
//     - Runs the constraint solver to identify violations.
//     - Checks protocol violations.
//     - Computes blast radius score and grade.
//     - Builds an ImpactZone.
//
// Context cancellation is checked between findings; Analyze returns early with
// the results accumulated so far when ctx is cancelled.
func (p *Propagator) Analyze(
	ctx context.Context,
	ff []findings.UnifiedFinding,
	opts impact.ImpactOpts,
) (*impact.Result, error) {
	result := &impact.Result{}

	for i := range ff {
		// Honour context cancellation between findings.
		if ctx.Err() != nil {
			return result, nil
		}

		f := &ff[i]
		if f.Algorithm == nil || len(f.DataFlowPath) == 0 {
			continue
		}

		// Respect caller-supplied TargetPath filter if set.
		if opts.TargetPath != "" && f.Location.File != "" {
			if !hasPathPrefix(f.Location.File, opts.TargetPath) {
				continue
			}
		}

		// --- 1. Build ForwardEdges ---
		hops := len(f.DataFlowPath)
		if hops > p.maxHops {
			hops = p.maxHops
		}

		var edges []impact.ForwardEdge
		for hop := 0; hop < hops; hop++ {
			step := f.DataFlowPath[hop]
			edge := impact.ForwardEdge{
				Hop:        hop + 1,
				SourceFile: f.Location.File,
				SourceLine: f.Location.Line,
				TargetFile: step.File,
				TargetLine: step.Line,
				Consumer:   consumerFromMessage(step.Message),
			}
			if hop > 0 {
				prev := f.DataFlowPath[hop-1]
				edge.SourceFile = prev.File
				edge.SourceLine = prev.Line
			}
			edges = append(edges, edge)
		}
		result.ForwardEdges = append(result.ForwardEdges, edges...)

		// --- 2. Detect constraints ---
		constHits := constraints.DetectFromPath(f.DataFlowPath)
		result.Constraints = append(result.Constraints, constHits...)

		// --- 3. Detect protocol boundaries ---
		boundaryHits := protocols.DetectFromPath(f.DataFlowPath)
		result.Boundaries = append(result.Boundaries, boundaryHits...)

		// --- 4. Build ImpactZones per migration target ---
		targets := constraints.MigrationTargets(f.Algorithm.Name)
		if len(targets) == 0 {
			// No migration path known — still record edges, no zone.
			continue
		}

		srcProfile, srcOK := constraints.Lookup(f.Algorithm.Name)

		for _, target := range targets {
			tgtProfile, tgtOK := constraints.Lookup(target)
			if !srcOK || !tgtOK {
				continue
			}

			// Compute size ratio using the dominant size field.
			srcSize := dominantSize(srcProfile)
			tgtSize := dominantSize(tgtProfile)
			var ratio float64
			if srcSize > 0 {
				ratio = float64(tgtSize) / float64(srcSize)
			}

			// --- Constraint violations ---
			var brokenConstraints []impact.ConstraintViolation
			for _, ch := range constHits {
				v := constraints.Check(tgtProfile, ch)
				if v != nil {
					v.Algorithm = target
					brokenConstraints = append(brokenConstraints, *v)
				}
			}

			// --- Protocol violations ---
			var violatedProtocols []impact.ProtocolViolation
			for _, bh := range boundaryHits {
				pc, ok := protocols.Lookup(bh.Protocol)
				if !ok {
					continue
				}
				raw := dominantSize(tgtProfile)
			projected := constraints.CalculateEncodedSize(raw, protocolEncoding(pc.Name))
				if projected > pc.MaxBytes {
					violatedProtocols = append(violatedProtocols, impact.ProtocolViolation{
						Protocol:       pc.Name,
						MaxBytes:       pc.MaxBytes,
						ProjectedBytes: projected,
						Overflow:       projected - pc.MaxBytes,
						HardLimit:      pc.HardLimit,
						File:           bh.File,
						Line:           bh.Line,
					})
				}
			}

			// --- Blast radius ---
			score, grade := blast.Calculate(blast.Input{
				HopCount:             len(edges),
				ConstraintViolations: len(brokenConstraints),
				ProtocolViolations:   len(violatedProtocols),
				SizeRatio:            ratio,
			})

			zone := impact.ImpactZone{
				FindingKey:        f.DedupeKey(),
				FromAlgorithm:     f.Algorithm.Name,
				ToAlgorithm:       target,
				SizeRatio:         ratio,
				BlastRadiusScore:  score,
				BlastRadiusGrade:  grade,
				ForwardHopCount:   len(edges),
				BrokenConstraints: brokenConstraints,
				ViolatedProtocols: violatedProtocols,
				ForwardPath:       edges,
			}
			result.ImpactZones = append(result.ImpactZones, zone)
		}
	}

	return result, nil
}

// dominantSize returns the most significant size field for blast radius
// calculations, using the same priority as the constraint solver.
func dominantSize(p constraints.AlgorithmSizeProfile) int {
	if p.SignatureBytes > 0 {
		return p.SignatureBytes
	}
	if p.CiphertextBytes > 0 {
		return p.CiphertextBytes
	}
	return p.PublicKeyBytes
}

// consumerFromMessage heuristically maps a FlowStep message to a ConsumerType.
func consumerFromMessage(msg string) impact.ConsumerType {
	switch {
	case containsAny(msg, "serialize", "marshal", "encode", "JSON", "XML", "protobuf"):
		return impact.ConsumerSerialization
	case containsAny(msg, "store", "save", "write", "insert", "VARCHAR", "database", "column"):
		return impact.ConsumerStorage
	case containsAny(msg, "send", "dial", "listen", "socket", "HTTP", "gRPC", "TLS", "JWT"):
		return impact.ConsumerNetwork
	case containsAny(msg, "return", "result"):
		return impact.ConsumerReturn
	case containsAny(msg, "append", "concat", "aggregate", "collect"):
		return impact.ConsumerAggregation
	default:
		return impact.ConsumerAssignment
	}
}

// containsAny reports whether s contains any of the given substrings.
// Matching is case-insensitive so FlowStep messages with lowercase
// API names (e.g. "json.Marshal", "http.Post") are correctly classified.
func containsAny(s string, subs ...string) bool {
	lower := strings.ToLower(s)
	for _, sub := range subs {
		if sub == "" {
			continue
		}
		if strings.Contains(lower, strings.ToLower(sub)) {
			return true
		}
	}
	return false
}

// protocolEncoding returns the likely wire encoding for a protocol.
// Used to apply encoding overhead when checking protocol size violations.
func protocolEncoding(protocol string) string {
	switch protocol {
	case "JWT":
		return "base64"
	case "X.509", "OCSP":
		return "der"
	case "S/MIME":
		return "pem"
	default:
		// TLS, DTLS, SSH, gRPC use binary framing.
		return "raw"
	}
}

// hasPathPrefix reports whether path starts with prefix, handling both
// exact matches and prefix/ forms.
func hasPathPrefix(path, prefix string) bool {
	if len(prefix) == 0 {
		return true
	}
	if path == prefix {
		return true
	}
	if len(path) > len(prefix) && path[:len(prefix)] == prefix && (path[len(prefix)] == '/' || path[len(prefix)] == '\\') {
		return true
	}
	return false
}
