package zeeklog

import (
	"compress/gzip"
	"fmt"
	"io"
	"strings"
)

// maxDecompressedBytes caps the amount of decompressed data read from a single
// Zeek log. 100 MB is generous for most deployments; prevents zip-bomb DoS.
const maxDecompressedBytes = 100 * 1024 * 1024

// openMaybeGzip returns an io.ReadCloser for the given reader. If compressed
// is true (path ends with .gz), wraps with a gzip.Reader limited to
// maxDecompressedBytes. The caller must close the returned ReadCloser.
func openMaybeGzip(r io.ReadCloser, path string) (io.ReadCloser, error) {
	if !strings.HasSuffix(strings.ToLower(path), ".gz") {
		return r, nil
	}
	gz, err := gzip.NewReader(r)
	if err != nil {
		return nil, fmt.Errorf("zeek-log: gzip open %s: %w", path, err)
	}
	return &limitedReadCloser{
		Reader: io.LimitReader(gz, maxDecompressedBytes+1),
		inner:  gz,
		outer:  r,
		limit:  maxDecompressedBytes,
		path:   path,
	}, nil
}

type limitedReadCloser struct {
	io.Reader
	inner io.Closer
	outer io.Closer
	limit int64
	read  int64
	path  string
}

func (l *limitedReadCloser) Read(p []byte) (int, error) {
	n, err := l.Reader.Read(p)
	l.read += int64(n)
	if l.read > l.limit {
		return n, fmt.Errorf("zeek-log: decompressed %s exceeds %d MB cap", l.path, l.limit/(1024*1024))
	}
	return n, err
}

func (l *limitedReadCloser) Close() error {
	err1 := l.inner.Close()
	err2 := l.outer.Close()
	if err1 != nil {
		return err1
	}
	return err2
}
