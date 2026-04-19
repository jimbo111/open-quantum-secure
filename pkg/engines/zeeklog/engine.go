// Package zeeklog implements a passive Zeek log ingestion engine (Sprint 5).
// It reads ssl.log and x509.log produced by Zeek network monitoring and
// extracts PQC inventory signals without any live network probing.
package zeeklog

import (
	"context"
	"fmt"
	"io"
	"os"

	"github.com/jimbo111/open-quantum-secure/pkg/engines"
	"github.com/jimbo111/open-quantum-secure/pkg/findings"
)

// maxZeekRecords caps dedup map growth to prevent unbounded memory use on
// adversarially large or pathological log files.
const maxZeekRecords = 500_000

// Engine reads Zeek ssl.log and x509.log to produce passive TLS PQC findings.
// It is always available (pure Go, file-based) and never dials the network.
type Engine struct{}

// New returns a new zeek-log Engine.
func New() *Engine { return &Engine{} }

func (e *Engine) Name() string                 { return engineName }
func (e *Engine) Tier() engines.Tier           { return engines.Tier5Network }
func (e *Engine) SupportedLanguages() []string { return nil }
func (e *Engine) Available() bool              { return true }
func (e *Engine) Version() string              { return "embedded" }

// Scan reads opts.ZeekSSLPath and opts.ZeekX509Path and returns PQC findings.
// Returns nil immediately when both paths are empty.
// NoNetwork does NOT gate this engine — it reads files, not sockets.
func (e *Engine) Scan(ctx context.Context, opts engines.ScanOptions) ([]findings.UnifiedFinding, error) {
	if opts.ZeekSSLPath == "" && opts.ZeekX509Path == "" {
		return nil, nil
	}

	var all []findings.UnifiedFinding

	if opts.ZeekSSLPath != "" {
		select {
		case <-ctx.Done():
			return all, ctx.Err()
		default:
		}
		recs, err := readSSLLog(ctx, opts.ZeekSSLPath)
		if err != nil {
			return nil, fmt.Errorf("zeek-log: ssl.log: %w", err)
		}
		for _, rec := range recs {
			all = append(all, sslRecordToFindings(rec)...)
		}
		fmt.Fprintf(os.Stderr, "Zeek log: ssl.log processed — %d unique records\n", len(recs))
	}

	if opts.ZeekX509Path != "" {
		select {
		case <-ctx.Done():
			return all, ctx.Err()
		default:
		}
		recs, err := readX509Log(ctx, opts.ZeekX509Path)
		if err != nil {
			return nil, fmt.Errorf("zeek-log: x509.log: %w", err)
		}
		for _, rec := range recs {
			all = append(all, x509RecordToFindings(rec)...)
		}
		fmt.Fprintf(os.Stderr, "Zeek log: x509.log processed — %d unique records\n", len(recs))
	}

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
		return nil, fmt.Errorf("zeeklog: refuses to follow symlink: %s", path)
	}
	if !fi.Mode().IsRegular() {
		return nil, fmt.Errorf("zeeklog: not a regular file: %s", path)
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

// readSSLLog opens the file at path (with transparent gzip) and parses ssl.log.
func readSSLLog(ctx context.Context, path string) ([]SSLRecord, error) {
	r, err := openLogFile(path)
	if err != nil {
		return nil, err
	}
	defer r.Close()
	return parseSSLLog(ctx, r)
}

// readX509Log opens the file at path (with transparent gzip) and parses x509.log.
func readX509Log(ctx context.Context, path string) ([]X509Record, error) {
	r, err := openLogFile(path)
	if err != nil {
		return nil, err
	}
	defer r.Close()
	return parseX509Log(ctx, r)
}
