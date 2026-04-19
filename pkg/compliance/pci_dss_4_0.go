package compliance

// pciDSS40Framework implements Framework for PCI DSS 4.0 cryptographic inventory
// requirements (Requirement 12.3.3).
//
// Source: PCI Security Standards Council, PCI DSS v4.0 (March 2022), Requirement 12.3.3:
// "All cryptographic algorithms in use are reviewed, and documented, at least once every
// 12 months, including an algorithm agility roadmap."
// https://www.pcisecuritystandards.org/document_library/
//
// PCI DSS 4.0 Req 12.3.3 differs fundamentally from algorithm-approval frameworks:
//   - It does NOT mandate specific approved algorithms (no CNSA-style approval list).
//   - It DOES require a documented cryptographic inventory with risk assessment.
//   - It DOES require evidence of a PQC migration plan (demonstrated by risk-classified findings).
//
// Compliance logic:
//   - PASS: The scan produced at least one finding with a quantum risk classification,
//     providing evidence that cryptographic inventory and risk assessment are in progress.
//   - FAIL: No risk-classified findings exist, meaning there is no evidence of a
//     cryptographic inventory meeting the Req 12.3.3 annual review requirement.

import (
	"github.com/jimbo111/open-quantum-secure/pkg/findings"
)

const (
	pciDSS40RequirementDate = "2025-03-31" // annual review due — assess at next cycle
	pciDSS40MigrationDate   = "2030-12-31" // PQC migration plan should cover this horizon
)

type pciDSS40Framework struct{}

func (pciDSS40Framework) ID() string          { return "pci-dss-4.0" }
func (pciDSS40Framework) Name() string        { return "PCI DSS 4.0" }
func (pciDSS40Framework) Description() string { return "PCI DSS v4.0 Req 12.3.3 — Cryptographic Inventory (PCI SSC, 2022)" }

func (pciDSS40Framework) ApprovedAlgos() []ApprovedAlgoRef {
	// PCI DSS 4.0 Req 12.3.3 does not define an approved-algorithm list.
	// It requires inventory and an agility roadmap, not specific algorithm choices.
	return []ApprovedAlgoRef{
		{"Inventory Evidence", "Any NIST-standardised PQC algorithm (FIPS 203/204/205)", "NIST PQC standards"},
		{"Migration Roadmap", "Document quantum-vulnerable algorithms and migration plans", "PCI DSS v4.0 Req 12.3.3"},
	}
}

func (pciDSS40Framework) Deadlines() []DeadlineRef {
	return []DeadlineRef{
		{pciDSS40RequirementDate, "Annual cryptographic algorithm review required (Req 12.3.3)"},
		{pciDSS40MigrationDate, "PQC migration roadmap should target this horizon for quantum risk"},
	}
}

// Evaluate implements the PCI DSS 4.0 Req 12.3.3 check.
//
// Unlike algorithm-approval frameworks, PCI DSS compliance here is determined by
// whether the scan produced risk-classified findings (evidence of inventory). If the
// scan finds no classified algorithms, the entity cannot demonstrate the required
// annual cryptographic review and algorithm agility assessment.
func (pciDSS40Framework) Evaluate(ff []findings.UnifiedFinding) []Violation {
	classifiedCount := 0
	for i := range ff {
		if ff[i].QuantumRisk != "" && ff[i].QuantumRisk != findings.QRUnknown {
			classifiedCount++
		}
	}

	// PASS: at least one risk-classified finding provides inventory evidence.
	if classifiedCount > 0 {
		return nil
	}

	// FAIL: no risk-classified findings — cannot demonstrate inventory or migration planning.
	msg := "No cryptographic algorithm risk classifications found in scan output"
	if len(ff) == 0 {
		msg = "No findings produced; scan must include cryptographic inventory to satisfy PCI DSS 4.0 Req 12.3.3"
	} else {
		msg = "Findings exist but none carry quantum risk classifications; " +
			"risk assessment is required for PCI DSS 4.0 Req 12.3.3 inventory evidence"
	}

	return []Violation{
		{
			Algorithm:   "",
			Rule:        "pci-no-inventory-evidence",
			Message:     msg,
			Deadline:    pciDSS40RequirementDate,
			Remediation: "Ensure scanner engines produce quantum risk classifications for all cryptographic algorithms in scope; document the inventory and create a PQC migration plan per PCI DSS v4.0 Req 12.3.3",
		},
	}
}

func init() {
	Register(pciDSS40Framework{})
}
