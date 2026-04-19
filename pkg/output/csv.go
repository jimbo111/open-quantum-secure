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
	cw.UseCRLF = true // RFC 4180 §2 requires CRLF line endings

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

	nf := neutralizeFormula
	return []string{
		nf(string(f.Severity)),
		nf(string(f.Confidence)),
		nf(algName),
		nf(primitive),
		keySize,
		nf(string(f.QuantumRisk)),
		strconv.FormatBool(f.PQCPresent),
		nf(f.PQCMaturity),
		nf(f.NegotiatedGroupName),
		nf(f.HandshakeVolumeClass),
		handshakeBytes,
		nf(f.Location.File),
		strconv.Itoa(f.Location.Line),
		nf(f.SourceEngine),
		nf(string(f.Reachable)),
		strconv.FormatBool(f.PartialInventory),
		nf(f.PartialInventoryReason),
		nf(f.DedupeKey()),
	}
}

// neutralizeFormula prepends a single quote to fields whose first character
// could trigger formula execution in spreadsheet applications (Excel DDE,
// Google Sheets WEBSERVICE, etc.). The OWASP CSV injection defence.
func neutralizeFormula(s string) string {
	if len(s) == 0 {
		return s
	}
	switch s[0] {
	case '=', '+', '-', '@', '\t', '\r':
		return "'" + s
	}
	return s
}
