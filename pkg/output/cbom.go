package output

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/jimbo111/open-quantum-secure/pkg/findings"
	"github.com/jimbo111/open-quantum-secure/pkg/impact"
)

// CycloneDX 1.7 CBOM structures
// https://cyclonedx.org/docs/1.7/json/

type cdxBOM struct {
	BOMFormat    string        `json:"bomFormat"`
	SpecVersion  string        `json:"specVersion"`
	SerialNumber string        `json:"serialNumber"`
	Version      int           `json:"version"`
	Metadata     cdxMetadata   `json:"metadata"`
	Components   []cdxComponent `json:"components"`
	Dependencies []cdxDependency `json:"dependencies,omitempty"`
}

type cdxMetadata struct {
	Timestamp  string         `json:"timestamp"`
	Tools      *cdxTools      `json:"tools,omitempty"`
	Properties []cdxProperty  `json:"properties,omitempty"`
}

type cdxTools struct {
	Components []cdxToolComponent `json:"components"`
}

type cdxToolComponent struct {
	Type        string `json:"type"`
	Name        string `json:"name"`
	Version     string `json:"version"`
	Description string `json:"description,omitempty"`
}

type cdxComponent struct {
	Type             string            `json:"type"`
	BOMRef           string            `json:"bom-ref"`
	Name             string            `json:"name"`
	CryptoProperties *cdxCryptoProps   `json:"cryptoProperties,omitempty"`
	Evidence         *cdxEvidence      `json:"evidence,omitempty"`
	Properties       []cdxProperty     `json:"properties,omitempty"`
}

type cdxCryptoProps struct {
	AssetType           string                 `json:"assetType"`
	AlgorithmProperties *cdxAlgorithmProps      `json:"algorithmProperties,omitempty"`
	ProtocolProperties  *cdxProtocolProps       `json:"protocolProperties,omitempty"`
}

type cdxAlgorithmProps struct {
	Primitive              string   `json:"primitive,omitempty"`
	AlgorithmFamily        string   `json:"algorithmFamily,omitempty"`
	ParameterSetIdentifier string   `json:"parameterSetIdentifier,omitempty"`
	Curve                  string   `json:"curve,omitempty"`
	Mode                   string   `json:"mode,omitempty"`
	ExecutionEnvironment   string   `json:"executionEnvironment,omitempty"`
	CryptoFunctions        []string `json:"cryptoFunctions,omitempty"`
}

type cdxProtocolProps struct {
	Type string `json:"type,omitempty"`
}

type cdxEvidence struct {
	Occurrences []cdxOccurrence `json:"occurrences,omitempty"`
}

type cdxOccurrence struct {
	Location string `json:"location"`
	Line     int    `json:"line,omitempty"`
	Offset   int    `json:"offset,omitempty"`
}

type cdxProperty struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type cdxDependency struct {
	Ref       string   `json:"ref"`
	DependsOn []string `json:"dependsOn,omitempty"`
}

// WriteCBOM writes findings in CycloneDX 1.7 CBOM format.
func WriteCBOM(w io.Writer, result ScanResult) error {
	components := buildCBOMComponents(result, result.ImpactResult)
	deps := buildCBOMDependencies(result)

	serialNumber := generateSerialNumber(components)

	// Build metadata properties
	var metaProps []cdxProperty
	metaProps = append(metaProps, cdxProperty{Name: "oqs:scanTarget", Value: result.Target})
	metaProps = append(metaProps, cdxProperty{Name: "oqs:enginesUsed", Value: strings.Join(result.Engines, ",")})
	metaProps = append(metaProps, cdxProperty{Name: "oqs:findingCount", Value: fmt.Sprintf("%d", result.Summary.TotalFindings)})

	if result.QRS != nil {
		metaProps = append(metaProps, cdxProperty{Name: "oqs:quantumReadinessScore", Value: fmt.Sprintf("%d", result.QRS.Score)})
		metaProps = append(metaProps, cdxProperty{Name: "oqs:quantumReadinessGrade", Value: result.QRS.Grade})
	}

	metaProps = append(metaProps, cdxProperty{Name: "oqs:quantumVulnerableCount", Value: fmt.Sprintf("%d", result.Summary.QuantumVulnerable)})
	metaProps = append(metaProps, cdxProperty{Name: "oqs:deprecatedCount", Value: fmt.Sprintf("%d", result.Summary.Deprecated)})

	if result.Summary.TotalFindings > 0 {
		safeCount := 0
		for _, f := range result.Findings {
			if f.QuantumRisk == findings.QRSafe || f.QuantumRisk == findings.QRResistant {
				safeCount++
			}
		}
		pct := float64(safeCount) / float64(result.Summary.TotalFindings) * 100
		metaProps = append(metaProps, cdxProperty{Name: "oqs:pqcSafePercent", Value: fmt.Sprintf("%.1f", pct)})
	}

	// Impact metadata: aggregate counts across all impact zones.
	if result.ImpactResult != nil && len(result.ImpactResult.ImpactZones) > 0 {
		criticalMigrations := 0
		significantMigrations := 0
		protocolsAffected := 0
		for _, z := range result.ImpactResult.ImpactZones {
			switch z.BlastRadiusGrade {
			case "Critical":
				criticalMigrations++
			case "Significant":
				significantMigrations++
			}
			protocolsAffected += len(z.ViolatedProtocols)
		}
		metaProps = append(metaProps,
			cdxProperty{Name: "oqs:impact:criticalMigrations", Value: fmt.Sprintf("%d", criticalMigrations)},
			cdxProperty{Name: "oqs:impact:significantMigrations", Value: fmt.Sprintf("%d", significantMigrations)},
			cdxProperty{Name: "oqs:impact:protocolsAffected", Value: fmt.Sprintf("%d", protocolsAffected)},
		)
	}

	bom := cdxBOM{
		BOMFormat:    "CycloneDX",
		SpecVersion:  "1.7",
		SerialNumber: serialNumber,
		Version:      1,
		Metadata: cdxMetadata{
			Timestamp: time.Now().UTC().Format(time.RFC3339),
			Tools: &cdxTools{
				Components: []cdxToolComponent{
					{
						Type:        "application",
						Name:        "oqs-scanner",
						Version:     result.Version,
						Description: "Cryptographic Bill of Materials scanner for PQC readiness",
					},
				},
			},
			Properties: metaProps,
		},
		Components:   components,
		Dependencies: deps,
	}

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(bom)
}

// buildCBOMComponents converts findings into CycloneDX components.
// Algorithm findings become cryptographic-asset components.
// Dependency findings become library components.
// impactResult is optional; when provided, per-algorithm impact properties are added.
func buildCBOMComponents(result ScanResult, impactResult *impact.Result) []cdxComponent {
	// Index impact zones by FindingKey for O(1) lookup.
	var impactIndex map[string]*impact.ImpactZone
	if impactResult != nil && len(impactResult.ImpactZones) > 0 {
		impactIndex = make(map[string]*impact.ImpactZone, len(impactResult.ImpactZones))
		for i := range impactResult.ImpactZones {
			z := &impactResult.ImpactZones[i]
			impactIndex[z.FindingKey] = z
		}
	}

	// Group algorithm findings by canonical key to create one component per unique algorithm
	type algGroup struct {
		finding     findings.UnifiedFinding
		occurrences []cdxOccurrence
		sources     []string
	}

	algGroups := make(map[string]*algGroup)
	var algOrder []string

	// Group dependency findings by library name for unique bom-refs.
	type depGroup struct {
		finding     findings.UnifiedFinding
		occurrences []cdxOccurrence
	}
	depGroups := make(map[string]*depGroup)
	var depOrder []string

	for _, f := range result.Findings {
		if f.Algorithm != nil && f.Algorithm.Name != "" {
			key := algorithmGroupKey(f)
			loc := relativePath(f.Location.File, result.Target)
			if f.Location.InnerPath != "" {
				loc += "!" + f.Location.InnerPath
			}
			occ := cdxOccurrence{
				Location: loc,
				Line:     f.Location.Line,
				Offset:   f.Location.Column,
			}
			if g, ok := algGroups[key]; ok {
				g.occurrences = append(g.occurrences, occ)
				if f.SourceEngine != "" && !containsStr(g.sources, f.SourceEngine) {
					g.sources = append(g.sources, f.SourceEngine)
				}
				for _, ce := range f.CorroboratedBy {
					if !containsStr(g.sources, ce) {
						g.sources = append(g.sources, ce)
					}
				}
			} else {
				sources := []string{f.SourceEngine}
				for _, ce := range f.CorroboratedBy {
					sources = append(sources, ce)
				}
				algGroups[key] = &algGroup{
					finding:     f,
					occurrences: []cdxOccurrence{occ},
					sources:     sources,
				}
				algOrder = append(algOrder, key)
			}
		} else if f.Dependency != nil {
			libName := f.Dependency.Library
			if libName == "" {
				libName = f.RawIdentifier
			}
			loc := relativePath(f.Location.File, result.Target)
			occ := cdxOccurrence{Location: loc, Line: f.Location.Line}
			if g, ok := depGroups[libName]; ok {
				g.occurrences = append(g.occurrences, occ)
			} else {
				depGroups[libName] = &depGroup{finding: f, occurrences: []cdxOccurrence{occ}}
				depOrder = append(depOrder, libName)
			}
		}
	}

	// Build algorithm components in stable order
	components := make([]cdxComponent, 0, len(algOrder)+len(depOrder))
	for _, key := range algOrder {
		g := algGroups[key]
		var zone *impact.ImpactZone
		if impactIndex != nil {
			zone = impactIndex[g.finding.DedupeKey()]
		}
		comp := buildAlgorithmComponent(g.finding, g.occurrences, g.sources, zone)
		components = append(components, comp)
	}

	// Build dependency components with merged occurrences (unique bom-ref per library).
	for _, libName := range depOrder {
		g := depGroups[libName]
		comp := buildDependencyComponent(g.finding, result.Target)
		// Replace single occurrence with all merged occurrences.
		comp.Evidence = &cdxEvidence{Occurrences: g.occurrences}
		components = append(components, comp)
	}
	return components
}

// buildAlgorithmComponent creates a CycloneDX cryptographic-asset component from a finding.
// zone is optional; when non-nil, oqs:impact:* properties are added to the component.
func buildAlgorithmComponent(f findings.UnifiedFinding, occurrences []cdxOccurrence, sources []string, zone *impact.ImpactZone) cdxComponent {
	alg := f.Algorithm
	bomRef := generateBOMRef("crypto-asset", alg.Name, alg.KeySize, alg.Mode)

	algProps := &cdxAlgorithmProps{
		Primitive:            mapToCDXPrimitive(alg.Primitive),
		AlgorithmFamily:      extractFamily(alg.Name),
		ExecutionEnvironment: "software",
	}

	if alg.KeySize > 0 {
		algProps.ParameterSetIdentifier = fmt.Sprintf("%d", alg.KeySize)
	}
	if alg.Mode != "" {
		algProps.Mode = strings.ToLower(alg.Mode)
	}
	if alg.Curve != "" {
		algProps.Curve = alg.Curve
	}

	// Build OQS custom properties
	var props []cdxProperty
	props = append(props, cdxProperty{Name: "oqs:confidence", Value: string(f.Confidence)})
	props = append(props, cdxProperty{Name: "oqs:source", Value: strings.Join(sources, "+")})
	props = append(props, cdxProperty{Name: "oqs:reachable", Value: string(f.Reachable)})

	if f.QuantumRisk != "" {
		props = append(props, cdxProperty{Name: "oqs:policyVerdict", Value: string(f.QuantumRisk)})
	}
	if f.Severity != "" {
		props = append(props, cdxProperty{Name: "oqs:severity", Value: string(f.Severity)})
	}
	if f.Recommendation != "" {
		props = append(props, cdxProperty{Name: "oqs:recommendation", Value: f.Recommendation})
	}
	if f.HNDLRisk != "" {
		props = append(props, cdxProperty{Name: "oqs:hndlRisk", Value: f.HNDLRisk})
	}
	if f.MigrationEffort != "" {
		props = append(props, cdxProperty{Name: "oqs:migrationEffort", Value: f.MigrationEffort})
	}
	if f.Location.ArtifactType != "" {
		props = append(props, cdxProperty{Name: "oqs:artifactType", Value: f.Location.ArtifactType})
		props = append(props, cdxProperty{Name: "oqs:detectionMethod", Value: "binary-analysis"})
	}
	if f.SourceEngine == "config-scanner" {
		props = append(props, cdxProperty{Name: "oqs:sourceType", Value: "config"})
	}

	if len(f.DataFlowPath) > 0 {
		dfpJSON, err := json.Marshal(f.DataFlowPath)
		if err == nil {
			props = append(props, cdxProperty{Name: "oqs:dataFlowPath", Value: string(dfpJSON)})
		}
		props = append(props, cdxProperty{
			Name:  "oqs:dataFlowEntry",
			Value: fmt.Sprintf("%s:%d", f.DataFlowPath[0].File, f.DataFlowPath[0].Line),
		})
	}

	// Add impact properties when an ImpactZone is available for this finding.
	if zone != nil {
		props = append(props,
			cdxProperty{Name: "oqs:impact:blastRadiusScore", Value: fmt.Sprintf("%d", zone.BlastRadiusScore)},
			cdxProperty{Name: "oqs:impact:blastRadiusGrade", Value: zone.BlastRadiusGrade},
			cdxProperty{Name: "oqs:impact:forwardHopCount", Value: fmt.Sprintf("%d", zone.ForwardHopCount)},
			cdxProperty{Name: "oqs:impact:brokenConstraints", Value: fmt.Sprintf("%d", len(zone.BrokenConstraints))},
			cdxProperty{Name: "oqs:impact:violatedProtocols", Value: fmt.Sprintf("%d", len(zone.ViolatedProtocols))},
			cdxProperty{Name: "oqs:impact:sizeRatio", Value: fmt.Sprintf("%.2f", zone.SizeRatio)},
		)
		if zone.ToAlgorithm != "" {
			props = append(props, cdxProperty{Name: "oqs:impact:migrationTarget", Value: zone.ToAlgorithm})
		}
	}

	return cdxComponent{
		Type:   "cryptographic-asset",
		BOMRef: bomRef,
		Name:   buildComponentName(alg),
		CryptoProperties: &cdxCryptoProps{
			AssetType:           "algorithm",
			AlgorithmProperties: algProps,
		},
		Evidence: &cdxEvidence{
			Occurrences: occurrences,
		},
		Properties: props,
	}
}

// buildDependencyComponent creates a CycloneDX component for a library dependency.
func buildDependencyComponent(f findings.UnifiedFinding, scanTarget string) cdxComponent {
	dep := f.Dependency
	bomRef := generateBOMRef("lib", dep.Library, 0, "")

	var props []cdxProperty
	props = append(props, cdxProperty{Name: "oqs:confidence", Value: string(f.Confidence)})
	props = append(props, cdxProperty{Name: "oqs:source", Value: f.SourceEngine})
	props = append(props, cdxProperty{Name: "oqs:reachable", Value: string(f.Reachable)})
	if f.QuantumRisk != "" {
		props = append(props, cdxProperty{Name: "oqs:policyVerdict", Value: string(f.QuantumRisk)})
	}
	if f.Severity != "" {
		props = append(props, cdxProperty{Name: "oqs:severity", Value: string(f.Severity)})
	}
	if f.Recommendation != "" {
		props = append(props, cdxProperty{Name: "oqs:recommendation", Value: f.Recommendation})
	}
	if f.HNDLRisk != "" {
		props = append(props, cdxProperty{Name: "oqs:hndlRisk", Value: f.HNDLRisk})
	}
	if f.MigrationEffort != "" {
		props = append(props, cdxProperty{Name: "oqs:migrationEffort", Value: f.MigrationEffort})
	}
	if f.SourceEngine == "config-scanner" {
		props = append(props, cdxProperty{Name: "oqs:sourceType", Value: "config"})
	}

	occ := cdxOccurrence{
		Location: relativePath(f.Location.File, scanTarget),
		Line:     f.Location.Line,
	}

	return cdxComponent{
		Type:   "cryptographic-asset",
		BOMRef: bomRef,
		Name:   dep.Library,
		CryptoProperties: &cdxCryptoProps{
			AssetType: "library",
		},
		Evidence: &cdxEvidence{
			Occurrences: []cdxOccurrence{occ},
		},
		Properties: props,
	}
}

// buildCBOMDependencies creates the dependency graph linking repo root to crypto libraries.
func buildCBOMDependencies(result ScanResult) []cdxDependency {
	var depRefs []string
	for _, f := range result.Findings {
		if f.Dependency != nil {
			ref := generateBOMRef("lib", f.Dependency.Library, 0, "")
			if !containsStr(depRefs, ref) {
				depRefs = append(depRefs, ref)
			}
		}
	}

	if len(depRefs) == 0 {
		return nil
	}

	sort.Strings(depRefs)
	return []cdxDependency{
		{
			Ref:       "repo-root",
			DependsOn: depRefs,
		},
	}
}

// buildComponentName creates a canonical component name.
// E.g., "AES-256-GCM", "RSA-2048", "SHA-256"
func buildComponentName(alg *findings.Algorithm) string {
	name := alg.Name
	// If the name already contains key size and mode info, use as-is
	if alg.KeySize > 0 && !strings.Contains(name, fmt.Sprintf("%d", alg.KeySize)) {
		name = fmt.Sprintf("%s-%d", name, alg.KeySize)
	}
	if alg.Mode != "" && !strings.Contains(strings.ToUpper(name), strings.ToUpper(alg.Mode)) {
		name = fmt.Sprintf("%s-%s", name, alg.Mode)
	}
	return name
}

// algorithmGroupKey creates a grouping key for merging occurrences of the same algorithm.
func algorithmGroupKey(f findings.UnifiedFinding) string {
	if f.Algorithm == nil {
		return ""
	}
	a := f.Algorithm
	return fmt.Sprintf("%s|%d|%s|%s", a.Name, a.KeySize, a.Mode, a.Curve)
}

// mapToCDXPrimitive maps our primitive names to CycloneDX 1.7 primitive taxonomy.
func mapToCDXPrimitive(primitive string) string {
	switch strings.ToLower(primitive) {
	case "symmetric", "block-cipher":
		return "block-cipher"
	case "stream-cipher":
		return "stream-cipher"
	case "ae", "aead":
		return "ae"
	case "asymmetric", "pke", "public-key":
		return "pke"
	case "signature", "sign":
		return "signature"
	case "hash", "digest":
		return "hash"
	case "mac", "hmac":
		return "mac"
	case "kdf", "key-derivation":
		return "kdf"
	case "key-exchange", "key-agree", "keyexchange":
		return "key-agree"
	case "kem", "key-encapsulation":
		return "kem"
	case "xof":
		return "xof"
	case "rng", "random", "prng", "csprng":
		return "other"
	default:
		return primitive
	}
}

// extractFamily returns the algorithm family from a full algorithm name.
func extractFamily(name string) string {
	families := []string{
		"ML-KEM", "ML-DSA", "SLH-DSA", "XMSS", "LMS",
		"AES", "ChaCha20", "Camellia", "ARIA", "SEED", "LEA", "Ascon",
		"RSA", "ECDSA", "ECDH", "EdDSA", "Ed25519", "Ed448", "X25519", "X448",
		"SHA-3", "SHA-2", "SHA-1", "BLAKE2", "BLAKE3",
		"HMAC", "HKDF", "PBKDF2", "Argon2", "scrypt", "bcrypt",
		"DES", "3DES", "MD5",
	}
	upper := strings.ToUpper(name)
	for _, f := range families {
		if strings.HasPrefix(upper, strings.ToUpper(f)) {
			return f
		}
	}
	// Fallback: first part before '-'
	parts := strings.SplitN(name, "-", 2)
	return parts[0]
}

// generateSerialNumber creates a deterministic URN:UUID from content hash.
func generateSerialNumber(components []cdxComponent) string {
	h := sha256.New()
	for _, c := range components {
		h.Write([]byte(c.Name))
		h.Write([]byte(c.BOMRef))
		h.Write([]byte(c.Type))
	}
	sum := h.Sum(nil)
	// Set RFC 4122 version 5 (SHA-based) and variant bits.
	sum[6] = (sum[6] & 0x0f) | 0x50 // version 5
	sum[8] = (sum[8] & 0x3f) | 0x80 // variant 10xx
	return fmt.Sprintf("urn:uuid:%08x-%04x-%04x-%04x-%012x",
		sum[0:4], sum[4:6], sum[6:8], sum[8:10], sum[10:16])
}

// generateBOMRef creates a stable bom-ref identifier.
func generateBOMRef(prefix, name string, keySize int, mode string) string {
	h := sha256.New()
	h.Write([]byte(prefix))
	h.Write([]byte(name))
	if keySize > 0 {
		h.Write([]byte(fmt.Sprintf("%d", keySize)))
	}
	if mode != "" {
		h.Write([]byte(mode))
	}
	sum := h.Sum(nil)
	return fmt.Sprintf("%s-%x", prefix, sum[:8])
}

func relativePath(filePath, base string) string {
	if rel, err := filepath.Rel(base, filePath); err == nil {
		return filepath.ToSlash(rel)
	}
	return filePath
}

func containsStr(ss []string, s string) bool {
	for _, v := range ss {
		if v == s {
			return true
		}
	}
	return false
}
