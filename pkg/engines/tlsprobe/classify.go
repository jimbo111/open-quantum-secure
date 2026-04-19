package tlsprobe

import (
	"crypto/tls"
	"strings"

	"github.com/jimbo111/open-quantum-secure/pkg/findings"
	"github.com/jimbo111/open-quantum-secure/pkg/quantum"
)

// CipherComponent represents one cryptographic primitive extracted from a cipher suite.
type CipherComponent struct {
	Name      string // "ECDHE", "RSA", "AES", "SHA-256", etc.
	Primitive string // "key-exchange", "signature", "symmetric", "hash"
	KeySize   int    // 128, 256, etc. (0 if not applicable)
	Mode      string // "GCM", "CBC", etc. (empty if not applicable)
}

// cipherRegistry maps Go TLS cipher suite IDs to their decomposed components.
var cipherRegistry = map[uint16][]CipherComponent{
	// TLS 1.2 suites
	tls.TLS_RSA_WITH_AES_128_CBC_SHA: {
		{Name: "RSA", Primitive: "key-exchange"},
		{Name: "RSA", Primitive: "signature"},
		{Name: "AES", Primitive: "symmetric", KeySize: 128, Mode: "CBC"},
		{Name: "SHA-1", Primitive: "hash"},
	},
	tls.TLS_RSA_WITH_AES_256_CBC_SHA: {
		{Name: "RSA", Primitive: "key-exchange"},
		{Name: "RSA", Primitive: "signature"},
		{Name: "AES", Primitive: "symmetric", KeySize: 256, Mode: "CBC"},
		{Name: "SHA-1", Primitive: "hash"},
	},
	tls.TLS_RSA_WITH_AES_128_GCM_SHA256: {
		{Name: "RSA", Primitive: "key-exchange"},
		{Name: "RSA", Primitive: "signature"},
		{Name: "AES", Primitive: "symmetric", KeySize: 128, Mode: "GCM"},
		{Name: "SHA-256", Primitive: "hash"},
	},
	tls.TLS_RSA_WITH_AES_256_GCM_SHA384: {
		{Name: "RSA", Primitive: "key-exchange"},
		{Name: "RSA", Primitive: "signature"},
		{Name: "AES", Primitive: "symmetric", KeySize: 256, Mode: "GCM"},
		{Name: "SHA-384", Primitive: "hash"},
	},
	tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA: {
		{Name: "ECDHE", Primitive: "key-exchange"},
		{Name: "RSA", Primitive: "signature"},
		{Name: "AES", Primitive: "symmetric", KeySize: 128, Mode: "CBC"},
		{Name: "SHA-1", Primitive: "hash"},
	},
	tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA: {
		{Name: "ECDHE", Primitive: "key-exchange"},
		{Name: "RSA", Primitive: "signature"},
		{Name: "AES", Primitive: "symmetric", KeySize: 256, Mode: "CBC"},
		{Name: "SHA-1", Primitive: "hash"},
	},
	tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256: {
		{Name: "ECDHE", Primitive: "key-exchange"},
		{Name: "RSA", Primitive: "signature"},
		{Name: "AES", Primitive: "symmetric", KeySize: 128, Mode: "GCM"},
		{Name: "SHA-256", Primitive: "hash"},
	},
	tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384: {
		{Name: "ECDHE", Primitive: "key-exchange"},
		{Name: "RSA", Primitive: "signature"},
		{Name: "AES", Primitive: "symmetric", KeySize: 256, Mode: "GCM"},
		{Name: "SHA-384", Primitive: "hash"},
	},
	tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256: {
		{Name: "ECDHE", Primitive: "key-exchange"},
		{Name: "ECDSA", Primitive: "signature"},
		{Name: "AES", Primitive: "symmetric", KeySize: 128, Mode: "GCM"},
		{Name: "SHA-256", Primitive: "hash"},
	},
	tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384: {
		{Name: "ECDHE", Primitive: "key-exchange"},
		{Name: "ECDSA", Primitive: "signature"},
		{Name: "AES", Primitive: "symmetric", KeySize: 256, Mode: "GCM"},
		{Name: "SHA-384", Primitive: "hash"},
	},
	tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256: {
		{Name: "ECDHE", Primitive: "key-exchange"},
		{Name: "RSA", Primitive: "signature"},
		{Name: "ChaCha20-Poly1305", Primitive: "symmetric", KeySize: 256},
		{Name: "SHA-256", Primitive: "hash"},
	},
	tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256: {
		{Name: "ECDHE", Primitive: "key-exchange"},
		{Name: "ECDSA", Primitive: "signature"},
		{Name: "ChaCha20-Poly1305", Primitive: "symmetric", KeySize: 256},
		{Name: "SHA-256", Primitive: "hash"},
	},
	// Additional TLS 1.2 suites
	tls.TLS_RSA_WITH_AES_128_CBC_SHA256: {
		{Name: "RSA", Primitive: "key-exchange"},
		{Name: "RSA", Primitive: "signature"},
		{Name: "AES", Primitive: "symmetric", KeySize: 128, Mode: "CBC"},
		{Name: "SHA-256", Primitive: "hash"},
	},
	tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA: {
		{Name: "ECDHE", Primitive: "key-exchange"},
		{Name: "ECDSA", Primitive: "signature"},
		{Name: "AES", Primitive: "symmetric", KeySize: 128, Mode: "CBC"},
		{Name: "SHA-1", Primitive: "hash"},
	},
	tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA: {
		{Name: "ECDHE", Primitive: "key-exchange"},
		{Name: "ECDSA", Primitive: "signature"},
		{Name: "AES", Primitive: "symmetric", KeySize: 256, Mode: "CBC"},
		{Name: "SHA-1", Primitive: "hash"},
	},
	tls.TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA: {
		{Name: "ECDHE", Primitive: "key-exchange"},
		{Name: "RSA", Primitive: "signature"},
		{Name: "3DES", Primitive: "symmetric", KeySize: 168, Mode: "CBC"},
		{Name: "SHA-1", Primitive: "hash"},
	},
	tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256: {
		{Name: "ECDHE", Primitive: "key-exchange"},
		{Name: "ECDSA", Primitive: "signature"},
		{Name: "AES", Primitive: "symmetric", KeySize: 128, Mode: "CBC"},
		{Name: "SHA-256", Primitive: "hash"},
	},
	tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256: {
		{Name: "ECDHE", Primitive: "key-exchange"},
		{Name: "RSA", Primitive: "signature"},
		{Name: "AES", Primitive: "symmetric", KeySize: 128, Mode: "CBC"},
		{Name: "SHA-256", Primitive: "hash"},
	},
	// Deprecated suites
	tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA: {
		{Name: "RSA", Primitive: "key-exchange"},
		{Name: "RSA", Primitive: "signature"},
		{Name: "3DES", Primitive: "symmetric", KeySize: 168, Mode: "CBC"},
		{Name: "SHA-1", Primitive: "hash"},
	},
	tls.TLS_RSA_WITH_RC4_128_SHA: {
		{Name: "RSA", Primitive: "key-exchange"},
		{Name: "RSA", Primitive: "signature"},
		{Name: "RC4", Primitive: "symmetric", KeySize: 128},
		{Name: "SHA-1", Primitive: "hash"},
	},
	// TLS 1.3 suites (key exchange is implicit ECDHE/X25519, not in suite name)
	tls.TLS_AES_128_GCM_SHA256: {
		{Name: "AES", Primitive: "symmetric", KeySize: 128, Mode: "GCM"},
		{Name: "SHA-256", Primitive: "hash"},
	},
	tls.TLS_AES_256_GCM_SHA384: {
		{Name: "AES", Primitive: "symmetric", KeySize: 256, Mode: "GCM"},
		{Name: "SHA-384", Primitive: "hash"},
	},
	tls.TLS_CHACHA20_POLY1305_SHA256: {
		{Name: "ChaCha20-Poly1305", Primitive: "symmetric", KeySize: 256},
		{Name: "SHA-256", Primitive: "hash"},
	},
}

// decomposeCipherSuite breaks a cipher suite ID into its algorithm components.
// Falls back to string parsing of the IANA name if the ID is not in the registry.
func decomposeCipherSuite(id uint16) []CipherComponent {
	if comps, ok := cipherRegistry[id]; ok {
		return comps
	}
	// Fallback: parse the IANA name string.
	name := tls.CipherSuiteName(id)
	return parseCipherSuiteName(name)
}

// parseCipherSuiteName parses an IANA cipher suite name into components.
// Example: "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"
func parseCipherSuiteName(name string) []CipherComponent {
	if name == "" {
		return nil
	}
	name = strings.TrimPrefix(name, "TLS_")

	// TLS 1.3 format: no _WITH_ separator
	if !strings.Contains(name, "_WITH_") {
		return parseTLS13Name(name)
	}

	// TLS 1.2 format: <KEX>_<AUTH>_WITH_<CIPHER>_<MAC>
	parts := strings.SplitN(name, "_WITH_", 2)
	if len(parts) != 2 {
		return nil
	}

	var comps []CipherComponent

	// Parse key exchange and auth.
	// RSA-only suites (e.g., TLS_RSA_WITH_AES_128_CBC_SHA) use RSA for both
	// key exchange and authentication. When the left side has only one part,
	// emit RSA as both roles.
	kexAuth := parts[0]
	kexAuthParts := strings.SplitN(kexAuth, "_", 2)
	if len(kexAuthParts) == 1 {
		comps = append(comps, CipherComponent{Name: kexAuthParts[0], Primitive: "key-exchange"})
		comps = append(comps, CipherComponent{Name: kexAuthParts[0], Primitive: "signature"})
	} else {
		comps = append(comps, CipherComponent{Name: kexAuthParts[0], Primitive: "key-exchange"})
		comps = append(comps, CipherComponent{Name: kexAuthParts[1], Primitive: "signature"})
	}

	// Parse cipher and MAC from right side
	comps = append(comps, parseBulkAndMAC(parts[1])...)

	return comps
}

// parseTLS13Name handles TLS 1.3 cipher suite names (no KEX/Auth).
func parseTLS13Name(name string) []CipherComponent {
	return parseBulkAndMAC(name)
}

// parseBulkAndMAC extracts the bulk cipher and MAC from a cipher suite fragment.
func parseBulkAndMAC(s string) []CipherComponent {
	var comps []CipherComponent

	// Common patterns: AES_128_GCM_SHA256, CHACHA20_POLY1305_SHA256, 3DES_EDE_CBC_SHA
	switch {
	case strings.HasPrefix(s, "AES_128_GCM"):
		comps = append(comps, CipherComponent{Name: "AES", Primitive: "symmetric", KeySize: 128, Mode: "GCM"})
	case strings.HasPrefix(s, "AES_256_GCM"):
		comps = append(comps, CipherComponent{Name: "AES", Primitive: "symmetric", KeySize: 256, Mode: "GCM"})
	case strings.HasPrefix(s, "AES_128_CBC"):
		comps = append(comps, CipherComponent{Name: "AES", Primitive: "symmetric", KeySize: 128, Mode: "CBC"})
	case strings.HasPrefix(s, "AES_256_CBC"):
		comps = append(comps, CipherComponent{Name: "AES", Primitive: "symmetric", KeySize: 256, Mode: "CBC"})
	case strings.HasPrefix(s, "CHACHA20_POLY1305"):
		comps = append(comps, CipherComponent{Name: "ChaCha20-Poly1305", Primitive: "symmetric", KeySize: 256})
	case strings.HasPrefix(s, "3DES_EDE_CBC"):
		comps = append(comps, CipherComponent{Name: "3DES", Primitive: "symmetric", KeySize: 168, Mode: "CBC"})
	case strings.HasPrefix(s, "RC4_128"):
		comps = append(comps, CipherComponent{Name: "RC4", Primitive: "symmetric", KeySize: 128})
	}

	// Extract MAC hash from the end
	switch {
	case strings.HasSuffix(s, "_SHA256"):
		comps = append(comps, CipherComponent{Name: "SHA-256", Primitive: "hash"})
	case strings.HasSuffix(s, "_SHA384"):
		comps = append(comps, CipherComponent{Name: "SHA-384", Primitive: "hash"})
	case strings.HasSuffix(s, "_SHA"):
		comps = append(comps, CipherComponent{Name: "SHA-1", Primitive: "hash"})
	}

	return comps
}

// primitiveToSuffix maps a cryptographic primitive to a short suffix appended
// to the synthetic Location.File path. This prevents DedupeKey collisions when
// the same algorithm name (e.g., "RSA") appears in multiple roles (key-exchange
// vs signature) for the same target — without modifying the global DedupeKey().
var primitiveToSuffix = map[string]string{
	"key-exchange": "#kex",
	"signature":    "#sig",
	"symmetric":    "#sym",
	"hash":         "#mac",
}

// observationToFindings converts a ProbeResult into UnifiedFinding entries.
// One finding is emitted per cryptographic component identified.
func observationToFindings(result ProbeResult) []findings.UnifiedFinding {
	if result.Error != nil {
		return nil
	}

	basePath := "(tls-probe)/" + result.Target

	// Classify the negotiated key-share group. CurveID is 0 for TLS 1.2 sessions
	// that used an RSA KEM (no named group). Unknown codepoints yield ok=false;
	// in both cases PQCPresent stays false.
	groupInfo, groupKnown := quantum.ClassifyTLSGroup(result.NegotiatedGroupID)

	var ff []findings.UnifiedFinding

	// Findings from cipher suite components.
	comps := decomposeCipherSuite(result.CipherSuiteID)
	for _, comp := range comps {
		suffix := primitiveToSuffix[comp.Primitive]
		f := findings.UnifiedFinding{
			Location: findings.Location{
				File:         basePath + suffix,
				Line:         0,
				ArtifactType: "tls-endpoint",
			},
			Algorithm: &findings.Algorithm{
				Name:      comp.Name,
				Primitive: comp.Primitive,
				KeySize:   comp.KeySize,
				Mode:      comp.Mode,
			},
			Confidence:    findings.ConfidenceHigh,
			SourceEngine:  "tls-probe",
			Reachable:     findings.ReachableYes,
			RawIdentifier: comp.Primitive + ":" + comp.Name + "|" + result.CipherSuiteName + "|" + result.Target,
		}
		applyGroupFields(&f, result.NegotiatedGroupID, groupInfo, groupKnown)
		ff = append(ff, f)
	}

	// Finding for the leaf certificate signing key (public key algorithm).
	if result.LeafCertKeyAlgo != "" {
		f := findings.UnifiedFinding{
			Location: findings.Location{
				File:         basePath + "#cert",
				Line:         0,
				ArtifactType: "tls-endpoint",
			},
			Algorithm: &findings.Algorithm{
				Name:      result.LeafCertKeyAlgo,
				Primitive: "signature",
				KeySize:   result.LeafCertKeySize,
			},
			Confidence:    findings.ConfidenceHigh,
			SourceEngine:  "tls-probe",
			Reachable:     findings.ReachableYes,
			RawIdentifier: "cert:" + result.LeafCertKeyAlgo + "|" + result.Target,
		}
		applyGroupFields(&f, result.NegotiatedGroupID, groupInfo, groupKnown)
		ff = append(ff, f)
	}

	// Finding for the certificate signature algorithm (the algorithm used to sign
	// this certificate — distinct from the public key type). Suffix #cert-sig
	// prevents DedupeKey collisions with the #cert (key type) finding above.
	if result.LeafCertSigAlgo != "" {
		f := findings.UnifiedFinding{
			Location: findings.Location{
				File:         basePath + "#cert-sig",
				Line:         0,
				ArtifactType: "tls-endpoint",
			},
			Algorithm: &findings.Algorithm{
				Name:      result.LeafCertSigAlgo,
				Primitive: "digital-signature",
			},
			Confidence:    findings.ConfidenceHigh,
			SourceEngine:  "tls-probe",
			Reachable:     findings.ReachableYes,
			RawIdentifier: "cert-sig:" + result.LeafCertSigAlgo + "|" + result.Target,
		}
		applyGroupFields(&f, result.NegotiatedGroupID, groupInfo, groupKnown)
		ff = append(ff, f)
	}

	// For TLS 1.3, the key exchange is implicit (not in the cipher suite name).
	// Emit a dedicated kex finding using the actual negotiated group name when
	// known, so that PQC hybrid groups (e.g., X25519MLKEM768) are classified as
	// quantum-safe rather than falling back to the generic "ECDHE" label.
	if result.TLSVersion == tls.VersionTLS13 {
		kexName := "ECDHE"
		rawID := "kex:ECDHE|" + result.Target
		if groupKnown && groupInfo.PQCPresent {
			// PQC hybrid: use the group name so ClassifyAlgorithm identifies it as safe.
			kexName = groupInfo.Name
			rawID = "kex:" + groupInfo.Name + "|" + result.Target
		}
		f := findings.UnifiedFinding{
			Location: findings.Location{
				File:         basePath + "#kex",
				Line:         0,
				ArtifactType: "tls-endpoint",
			},
			Algorithm: &findings.Algorithm{
				Name:      kexName,
				Primitive: "key-exchange",
			},
			Confidence:    findings.ConfidenceHigh,
			SourceEngine:  "tls-probe",
			Reachable:     findings.ReachableYes,
			RawIdentifier: rawID,
		}
		applyGroupFields(&f, result.NegotiatedGroupID, groupInfo, groupKnown)
		ff = append(ff, f)
	}

	// TLS 1.2 fallback finding (Sprint 9, Feature 3): when the server negotiated
	// PQC via TLS 1.3 but also accepted a classical-only TLS 1.2 handshake, emit
	// a downgrade-vulnerability finding. An HNDL attacker can force the client to
	// use TLS 1.2, bypassing the ML-KEM protection negotiated in TLS 1.3.
	if result.AcceptedTLS12 && groupKnown && groupInfo.PQCPresent {
		f := findings.UnifiedFinding{
			Location: findings.Location{
				File:         basePath + "#tls12-fallback",
				Line:         0,
				ArtifactType: "tls-endpoint",
			},
			Algorithm: &findings.Algorithm{
				Name:      "TLS_1.2_Fallback",
				Primitive: "key-exchange",
			},
			Confidence:    findings.ConfidenceHigh,
			SourceEngine:  "tls-probe",
			Reachable:     findings.ReachableYes,
			QuantumRisk:   findings.QRVulnerable,
			Severity:      findings.SevHigh,
			HNDLRisk:      "immediate",
			Recommendation: "Server supports ML-KEM via TLS 1.3 but also accepts classical-only TLS 1.2 — " +
				"an HNDL attacker can force downgrade. Disable TLS 1.2 to eliminate the vulnerability. " +
				"TLS 1.2 cipher: " + result.TLS12CipherSuiteName + ". CNSA 2.0 deadline: 2030.",
			RawIdentifier: "tls12-fallback:" + result.TLS12CipherSuiteName + "|" + result.Target,
		}
		applyGroupFields(&f, result.NegotiatedGroupID, groupInfo, groupKnown)
		ff = append(ff, f)
	}

	// If ECH was detected (S2.4), annotate every finding for this probe session
	// as partial inventory. The cipher suite and cert algorithm are hidden behind
	// the outer ClientHello; only size-based signals and the outer handshake are
	// observable. Sprint 3 (CT log lookup) will attempt to recover the cert info.
	if result.ECHDetected {
		for i := range ff {
			ff[i].PartialInventory = true
			ff[i].PartialInventoryReason = "ECH_ENABLED"
		}
	}

	// Apply session-level Sprint 2 volume fields to every finding.
	for i := range ff {
		applyVolumeFields(&ff[i], result)
	}

	// Deep-probe results (Sprint 7): annotate the kex finding with accepted and
	// HRR groups. Only the kex finding carries these fields because it is the
	// finding consumers use for key-exchange risk assessment.
	if len(result.DeepProbeAcceptedGroups) > 0 || len(result.DeepProbeHRRGroups) > 0 {
		for i := range ff {
			if ff[i].Algorithm != nil && ff[i].Algorithm.Primitive == "key-exchange" {
				ff[i].DeepProbeSupportedGroups = result.DeepProbeAcceptedGroups
				ff[i].DeepProbeHRRGroups = result.DeepProbeHRRGroups
			}
		}
	}

	// Sprint 8 enumeration results: annotate the kex finding with the richer
	// group/sigalg/preference data collected by the enumeration passes.
	if result.EnumerationMode != "" {
		// Merge accepted + HRR groups into SupportedGroups for the kex finding.
		// HRR groups are "supported but not preferred" — positive PQC evidence
		// that belongs in the supported list alongside full-acceptance groups.
		var allSupported []uint16
		allSupported = append(allSupported, result.EnumAcceptedGroups...)
		allSupported = append(allSupported, result.EnumHRRGroups...)

		for i := range ff {
			if ff[i].Algorithm != nil && ff[i].Algorithm.Primitive == "key-exchange" {
				if len(allSupported) > 0 {
					ff[i].SupportedGroups = allSupported
				}
				if len(result.EnumSupportedSigAlgs) > 0 {
					ff[i].SupportedSigAlgs = result.EnumSupportedSigAlgs
				}
				if result.EnumServerPrefGroup != 0 {
					ff[i].ServerPreferredGroup = result.EnumServerPrefGroup
				}
				if result.EnumServerPrefMode != "" {
					ff[i].ServerPreferenceMode = result.EnumServerPrefMode
				}
				ff[i].EnumerationMode = result.EnumerationMode
			}
		}
	}

	// R1: propagate truncation signal — partial enum results mean the inventory
	// is incomplete. Mark all findings for this target so callers can signal
	// that further probing may reveal additional supported groups or sig algs.
	// If an earlier reason was set (e.g. S2's "ECH_ENABLED"), compose with "+"
	// so both signals survive — consumers use strings.HasPrefix/Contains to
	// detect specific reasons. A plain overwrite here would clobber the ECH
	// signal and break the S3 CT-lookup auto-chain (orchestrator.go:1178).
	if result.EnumTruncated {
		reason := result.EnumTruncationReason
		if reason == "" {
			reason = "ENUMERATION_TRUNCATED"
		}
		for i := range ff {
			ff[i].PartialInventory = true
			if ff[i].PartialInventoryReason != "" {
				ff[i].PartialInventoryReason = ff[i].PartialInventoryReason + "+" + reason
			} else {
				ff[i].PartialInventoryReason = reason
			}
		}
	}

	return ff
}

// applyGroupFields sets the session-level TLS group metadata on a finding.
// These fields describe the key-share negotiated in the handshake and apply
// uniformly to all findings emitted for the same probe session.
func applyGroupFields(f *findings.UnifiedFinding, groupID uint16, info quantum.GroupInfo, known bool) {
	f.NegotiatedGroup = groupID
	if known {
		f.NegotiatedGroupName = info.Name
		f.PQCPresent = info.PQCPresent
		f.PQCMaturity = info.Maturity
	}
}

// applyVolumeFields copies the Sprint 2 size-based detection fields from a
// ProbeResult onto a finding. These fields are session-level (same values for
// every finding emitted for one probe) and describe the handshake byte volume
// and its classifier output.
func applyVolumeFields(f *findings.UnifiedFinding, result ProbeResult) {
	if result.HandshakeVolumeClass != "" && result.HandshakeVolumeClass != "unknown" {
		f.HandshakeVolumeClass = result.HandshakeVolumeClass
	} else if result.HandshakeVolumeClass != "" {
		// Preserve "unknown" so consumers can distinguish "not probed" (empty)
		// from "probed but unclassified" ("unknown").
		f.HandshakeVolumeClass = result.HandshakeVolumeClass
	}
	total := result.BytesIn + result.BytesOut
	if total > 0 {
		f.HandshakeBytes = total
	}
}
