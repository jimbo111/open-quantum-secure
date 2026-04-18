package sshprobe

import (
	"fmt"

	"github.com/jimbo111/open-quantum-secure/pkg/findings"
	"github.com/jimbo111/open-quantum-secure/pkg/quantum"
)

const engineName = "ssh-probe"

// kexInitToFindings converts a ProbeResult into one UnifiedFinding per KEX method
// advertised by the server in its SSH_MSG_KEXINIT. Each finding carries the quantum
// risk classification derived from the method name.
func kexInitToFindings(result ProbeResult) []findings.UnifiedFinding {
	if result.Error != nil {
		return nil
	}

	basePath := fmt.Sprintf("(ssh-probe)/%s", result.Target)
	var ff []findings.UnifiedFinding

	for _, method := range result.KEXMethods {
		if method == "" {
			continue
		}

		info := classifyKex(method)

		// For PQC-safe SSH KEX methods (e.g. mlkem768x25519-sha256) ClassifyAlgorithm
		// returns RiskUnknown because it has no SSH-specific entry — kex.go is the
		// authoritative source. We use ClassifyAlgorithm only for classical method
		// names that map to quantum-vulnerable families (DH, ECDH, X25519, etc.).
		c := quantum.ClassifyAlgorithm(method, "kex", 0)

		// Override: if our kex table marks the method as PQC-present, trust it over
		// the generic classifier which may not know SSH-specific name formats.
		if info.pqcPresent {
			c.Risk = quantum.RiskSafe
			c.Severity = quantum.SeverityInfo
			c.Recommendation = "PQC-capable KEX method advertised. No migration required."
			c.HNDLRisk = ""
		}

		f := findings.UnifiedFinding{
			Location: findings.Location{
				File:         basePath + "#kex",
				Line:         0,
				ArtifactType: "ssh-endpoint",
			},
			Algorithm: &findings.Algorithm{
				Name:      method,
				Primitive: "kex",
			},
			Confidence:   findings.ConfidenceHigh,
			SourceEngine: engineName,
			Reachable:    findings.ReachableYes,
			RawIdentifier: fmt.Sprintf("ssh-kex:%s|%s", method, result.Target),
			QuantumRisk:  findings.QuantumRisk(c.Risk),
			Severity:     findings.Severity(c.Severity),
			PQCPresent:   info.pqcPresent,
			PQCMaturity:  info.maturity,
		}

		if c.Recommendation != "" {
			f.Recommendation = c.Recommendation
		}
		if c.HNDLRisk != "" {
			f.HNDLRisk = c.HNDLRisk
		}
		if c.TargetAlgorithm != "" {
			f.TargetAlgorithm = c.TargetAlgorithm
		}
		if c.TargetStandard != "" {
			f.TargetStandard = c.TargetStandard
		}
		if c.MigrationEffort != "" {
			f.MigrationEffort = c.MigrationEffort
		}

		ff = append(ff, f)
	}

	return ff
}
