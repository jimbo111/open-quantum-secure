package output

import (
	"encoding/csv"
	"io"
	"strconv"

	"github.com/jimbo111/open-quantum-secure/pkg/findings"
)

// WriteCSV writes findings as RFC 4180 CSV to w.
// The header row is always emitted, even when Findings is empty.
// encoding/csv handles all quoting (commas, quotes, newlines in fields).
func WriteCSV(w io.Writer, result ScanResult) error {
	cw := csv.NewWriter(w)

	header := []string{
		"severity", "confidence", "algorithm", "primitive", "keySize", "risk",
		"pqcPresent", "pqcMaturity", "negotiatedGroupName", "handshakeVolumeClass",
		"handshakeBytes", "file", "line", "sourceEngine", "reachable",
		"partialInventory", "partialInventoryReason", "dedupeKey",
	}
	if err := cw.Write(header); err != nil {
		return err
	}

	for _, f := range result.Findings {
		if err := cw.Write(findingToCSVRecord(f)); err != nil {
			return err
		}
	}

	cw.Flush()
	return cw.Error()
}

func findingToCSVRecord(f findings.UnifiedFinding) []string {
	algName := ""
	primitive := ""
	keySize := ""
	if f.Algorithm != nil {
		algName = f.Algorithm.Name
		primitive = f.Algorithm.Primitive
		if f.Algorithm.KeySize > 0 {
			keySize = strconv.Itoa(f.Algorithm.KeySize)
		}
	}

	handshakeBytes := ""
	if f.HandshakeBytes > 0 {
		handshakeBytes = strconv.FormatInt(f.HandshakeBytes, 10)
	}

	return []string{
		string(f.Severity),
		string(f.Confidence),
		algName,
		primitive,
		keySize,
		string(f.QuantumRisk),
		strconv.FormatBool(f.PQCPresent),
		f.PQCMaturity,
		f.NegotiatedGroupName,
		f.HandshakeVolumeClass,
		handshakeBytes,
		f.Location.File,
		strconv.Itoa(f.Location.Line),
		f.SourceEngine,
		string(f.Reachable),
		strconv.FormatBool(f.PartialInventory),
		f.PartialInventoryReason,
		f.DedupeKey(),
	}
}
