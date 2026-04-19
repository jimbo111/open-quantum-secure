package zeeklog

import (
	"bytes"
	"io"
)

type logFormat int

const (
	formatTSV  logFormat = iota // Zeek native TSV (#separator \t header)
	formatJSON                  // NDJSON (one object per line)
	formatUnknown
)

// detectFormat reads the first 128 bytes from r (without consuming them) and
// returns the detected format. The reader is rewound via a bytes.Reader so
// callers see the full stream after return.
//
// Detection rules:
//   - starts with '#' → TSV (Zeek native log header)
//   - starts with '{' → JSON / NDJSON
//   - fallback → unknown (callers try JSON first, then TSV)
func detectFormat(peek []byte) logFormat {
	for _, b := range peek {
		if b == ' ' || b == '\t' || b == '\r' || b == '\n' {
			continue
		}
		if b == '#' {
			return formatTSV
		}
		if b == '{' {
			return formatJSON
		}
		break
	}
	return formatUnknown
}

// sniffFormat reads up to sniffBytes from r without consuming the stream.
// Returns (peeked bytes, detected format). The caller must prepend peeked
// to r before further reads (use io.MultiReader).
const sniffBytes = 128

func sniffFormat(r io.Reader) ([]byte, logFormat, error) {
	buf := make([]byte, sniffBytes)
	n, err := io.ReadAtLeast(r, buf, 1)
	if err != nil && err != io.ErrUnexpectedEOF {
		return nil, formatUnknown, err
	}
	peeked := buf[:n]
	return peeked, detectFormat(peeked), nil
}

// multiReader concatenates peeked bytes with the rest of the stream.
func multiReader(peeked []byte, r io.Reader) io.Reader {
	return io.MultiReader(bytes.NewReader(peeked), r)
}
