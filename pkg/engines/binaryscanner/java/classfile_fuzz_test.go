package java

import (
	"bytes"
	"testing"
)

func FuzzParseClassFile(f *testing.F) {
	// Valid class file header: CAFEBABE, version 52.0, cp_count=1 (no entries)
	f.Add([]byte{0xCA, 0xFE, 0xBA, 0xBE, 0x00, 0x00, 0x00, 0x34, 0x00, 0x01})
	// Empty input
	f.Add([]byte{})
	// Wrong magic bytes
	f.Add([]byte{0x00, 0x00, 0x00, 0x00})
	// Truncated magic
	f.Add([]byte{0xCA, 0xFE})
	// Valid magic, truncated after
	f.Add([]byte{0xCA, 0xFE, 0xBA, 0xBE, 0x00})

	f.Fuzz(func(t *testing.T, data []byte) {
		// ParseClassFile must never panic regardless of input.
		_, _ = ParseClassFile(bytes.NewReader(data))
	})
}
