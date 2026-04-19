package suricatalog

import (
	"context"
	"fmt"
	"io"
	"os"

	"github.com/jimbo111/open-quantum-secure/pkg/engines"
	"github.com/jimbo111/open-quantum-secure/pkg/findings"
)

// Engine reads Suricata eve.json to produce passive TLS PQC findings.
// It is always available (pure Go, file-based) and never dials the network.
type Engine struct{}

// New returns a new suricata-log Engine.
func New() *Engine { return &Engine{} }

func (e *Engine) Name() string                 { return engineName }
func (e *Engine) Tier() engines.Tier           { return engines.Tier5Network }
func (e *Engine) SupportedLanguages() []string { return nil }
func (e *Engine) Available() bool              { return true }
func (e *Engine) Version() string              { return "embedded" }

// Scan reads opts.SuricataEvePath and returns PQC findings from TLS events.
// Returns nil immediately when the path is empty.
// NoNetwork does NOT gate this engine — it reads files, not sockets.
func (e *Engine) Scan(ctx context.Context, opts engines.ScanOptions) ([]findings.UnifiedFinding, error) {
	if opts.SuricataEvePath == "" {
		return nil, nil
	}

	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}

	recs, err := readEveJSON(ctx, opts.SuricataEvePath)
	if err != nil {
		return nil, fmt.Errorf("suricata-log: eve.json: %w", err)
	}

	var all []findings.UnifiedFinding
	for _, rec := range recs {
		all = append(all, tlsRecordToFindings(rec)...)
	}
	fmt.Fprintf(os.Stderr, "Suricata log: eve.json processed — %d unique TLS records\n", len(recs))
	return all, nil
}

// openLogFile opens path for reading with symlink/non-regular-file rejection and
// transparent gzip decompression. The returned ReadCloser is always size-capped
// at maxDecompressedBytes. Caller must call Close() on the returned value.
func openLogFile(path string) (io.ReadCloser, error) {
	fi, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if fi.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("suricata-log: refuses to follow symlink: %s", path)
	}
	if !fi.Mode().IsRegular() {
		return nil, fmt.Errorf("suricata-log: not a regular file: %s", path)
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	r, err := openMaybeGzip(f, path)
	if err != nil {
		f.Close()
		return nil, err
	}
	return r, nil
}

// readEveJSON opens the file at path (with transparent gzip) and parses eve.json.
func readEveJSON(ctx context.Context, path string) ([]TLSRecord, error) {
	r, err := openLogFile(path)
	if err != nil {
		return nil, err
	}
	defer r.Close()
	return parseEveJSON(ctx, r, path)
}
