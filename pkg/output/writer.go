package output

import (
	"fmt"
	"io"
	"sort"
)

// Writer renders a ScanResult to an io.Writer in a particular format.
//
// All package-level Write* functions (WriteJSON, WriteSARIF, WriteCBOM, …)
// satisfy this interface via the WriterFunc adapter. A Writer must not
// retain w after Write returns. Implementations are expected to flush before
// returning so that disk-full or short-write errors are surfaced.
type Writer interface {
	Write(w io.Writer, result ScanResult) error
}

// WriterFunc is a function type that implements Writer.
type WriterFunc func(w io.Writer, result ScanResult) error

// Write satisfies Writer.
func (f WriterFunc) Write(w io.Writer, result ScanResult) error { return f(w, result) }

// writerRegistry maps format names (and aliases) to a Writer.
// "cyclonedx" is an alias for "cbom" — both produce CycloneDX 1.7 CBOM.
var writerRegistry = map[string]Writer{
	"json":      WriterFunc(WriteJSON),
	"table":     WriterFunc(WriteTable),
	"sarif":     WriterFunc(WriteSARIF),
	"cbom":      WriterFunc(WriteCBOM),
	"cyclonedx": WriterFunc(WriteCBOM),
	"html":      WriterFunc(WriteHTML),
	"csv":       WriterFunc(WriteCSV),
}

// LookupWriter returns the Writer registered for format. The boolean is
// false when format is not registered. Format matching is case-sensitive
// to keep error messages crisp — callers normalise upstream if needed.
func LookupWriter(format string) (Writer, bool) {
	w, ok := writerRegistry[format]
	return w, ok
}

// RegisterWriter associates a Writer with a format name. Useful for tests
// or out-of-tree formats. Re-registering an existing format replaces the
// previous Writer.
func RegisterWriter(format string, w Writer) {
	writerRegistry[format] = w
}

// SupportedFormats returns the registered format names sorted alphabetically.
// Used to build user-facing error messages and --help output. Aliases are
// included.
func SupportedFormats() []string {
	out := make([]string, 0, len(writerRegistry))
	for k := range writerRegistry {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// WriteFormat renders result to w in the requested format. Returns an
// error wrapping the unknown-format case when format is not registered.
func WriteFormat(format string, w io.Writer, result ScanResult) error {
	wr, ok := LookupWriter(format)
	if !ok {
		return fmt.Errorf("unknown format: %s (supported: %v)", format, SupportedFormats())
	}
	return wr.Write(w, result)
}
