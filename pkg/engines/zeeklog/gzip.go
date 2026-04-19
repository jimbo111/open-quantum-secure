package zeeklog

import (
	"compress/gzip"
	"fmt"
	"io"
	"strings"
)

// maxDecompressedBytes caps the amount of data read from a single Zeek log.
// 100 MB is generous for most deployments; prevents DoS via huge or
// decompressed-zip-bomb files.
const maxDecompressedBytes = 100 * 1024 * 1024

// openMaybeGzip returns a size-capped io.ReadCloser for r.
// For .gz paths, wraps with a gzip.Reader limited to maxDecompressedBytes.
// For plain files, applies the same byte cap directly.
// The returned ReadCloser closes r when closed — callers must not close r separately.
func openMaybeGzip(r io.ReadCloser, path string) (io.ReadCloser, error) {
	if !strings.HasSuffix(strings.ToLower(path), ".gz") {
		return &limitedReadCloser{
			Reader: io.LimitReader(r, maxDecompressedBytes+1),
			inner:  nil,
			outer:  r,
			limit:  maxDecompressedBytes,
			path:   path,
		}, nil
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
	inner io.Closer // gzip.Reader (nil for plain files)
	outer io.Closer // underlying os.File
	limit int64
	read  int64
	path  string
}

func (l *limitedReadCloser) Read(p []byte) (int, error) {
	n, err := l.Reader.Read(p)
	l.read += int64(n)
	if l.read > l.limit {
		return n, fmt.Errorf("zeek-log: %s exceeds %d MB cap", l.path, l.limit/(1024*1024))
	}
	return n, err
}

func (l *limitedReadCloser) Close() error {
	var err1 error
	if l.inner != nil {
		err1 = l.inner.Close()
	}
	err2 := l.outer.Close()
	if err1 != nil {
		return err1
	}
	return err2
}
