package native

import (
	"testing"
)

// makeBuffer embeds the given pattern inside a block of filler bytes so that
// ScanConstants can find the pattern at a known offset.
func makeBuffer(prefix int, pattern []byte) []byte {
	buf := make([]byte, prefix+len(pattern)+16)
	// Fill with a byte value that won't accidentally create a match.
	for i := range buf {
		buf[i] = 0xAA
	}
	copy(buf[prefix:], pattern)
	return buf
}

func TestScanConstants_EachPatternFound(t *testing.T) {
	tests := []struct {
		name      string
		pattern   []byte
		wantAlg   string
		wantPrim  string
	}{
		{
			name:     "AES S-box",
			pattern:  cryptoConstants[0].pattern,
			wantAlg:  "AES",
			wantPrim: "symmetric",
		},
		{
			name:     "AES Inverse S-box",
			pattern:  cryptoConstants[1].pattern,
			wantAlg:  "AES",
			wantPrim: "symmetric",
		},
		{
			name:     "AES RCON",
			pattern:  cryptoConstants[2].pattern,
			wantAlg:  "AES",
			wantPrim: "symmetric",
		},
		{
			name:     "SHA-256 initial H big-endian",
			pattern:  cryptoConstants[3].pattern,
			wantAlg:  "SHA-256",
			wantPrim: "hash",
		},
		{
			name:     "SHA-256 initial H little-endian",
			pattern:  cryptoConstants[4].pattern,
			wantAlg:  "SHA-256",
			wantPrim: "hash",
		},
		{
			name:     "SHA-512 initial H big-endian",
			pattern:  cryptoConstants[5].pattern,
			wantAlg:  "SHA-512",
			wantPrim: "hash",
		},
		{
			name:     "SHA-1 initial H",
			pattern:  cryptoConstants[6].pattern,
			wantAlg:  "SHA-1",
			wantPrim: "hash",
		},
		{
			name:     "MD5 T-table",
			pattern:  cryptoConstants[7].pattern,
			wantAlg:  "MD5",
			wantPrim: "hash",
		},
		{
			name:     "ChaCha20 constant string",
			pattern:  cryptoConstants[8].pattern,
			wantAlg:  "ChaCha20",
			wantPrim: "symmetric",
		},
		{
			name:     "Blowfish P-array",
			pattern:  cryptoConstants[9].pattern,
			wantAlg:  "Blowfish",
			wantPrim: "symmetric",
		},
		{
			name:     "DES initial permutation table",
			pattern:  cryptoConstants[10].pattern,
			wantAlg:  "DES",
			wantPrim: "symmetric",
		},
		{
			name:     "Poly1305 clamp mask",
			pattern:  cryptoConstants[11].pattern,
			wantAlg:  "Poly1305",
			wantPrim: "mac",
		},
		{
			name:     "Curve25519 prime P",
			pattern:  cryptoConstants[12].pattern,
			wantAlg:  "Curve25519",
			wantPrim: "key-exchange",
		},
		{
			name:     "SM4 S-box",
			pattern:  cryptoConstants[13].pattern,
			wantAlg:  "SM4",
			wantPrim: "symmetric",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			buf := makeBuffer(32, tc.pattern)
			matches := ScanConstants(buf)

			found := false
			for _, m := range matches {
				if m.Algorithm == tc.wantAlg {
					found = true
					if m.Primitive != tc.wantPrim {
						t.Errorf("Algorithm %q: got primitive %q, want %q", tc.wantAlg, m.Primitive, tc.wantPrim)
					}
					if m.Offset != 32 {
						t.Errorf("Algorithm %q: got offset %d, want 32", tc.wantAlg, m.Offset)
					}
					break
				}
			}
			if !found {
				t.Errorf("Algorithm %q not found in scan results (got %v)", tc.wantAlg, matches)
			}
		})
	}
}

func TestScanConstants_NoMatchInRandomData(t *testing.T) {
	// A buffer of 0xAA bytes will not contain any crypto constant.
	buf := make([]byte, 1024)
	for i := range buf {
		buf[i] = 0xAA
	}
	matches := ScanConstants(buf)
	if len(matches) != 0 {
		t.Errorf("expected no matches in filler data, got %d: %v", len(matches), matches)
	}
}

func TestScanConstants_Deduplication_AES(t *testing.T) {
	// Embed both AES S-box and AES Inverse S-box: should collapse to one AES finding.
	sbox := cryptoConstants[0].pattern    // AES S-box
	invSbox := cryptoConstants[1].pattern // AES Inverse S-box

	// Build a buffer: filler | sbox | filler | invSbox | filler
	buf := make([]byte, 0, 64+len(sbox)+64+len(invSbox)+16)
	buf = appendFiller(buf, 64)
	buf = append(buf, sbox...)
	buf = appendFiller(buf, 64)
	buf = append(buf, invSbox...)
	buf = appendFiller(buf, 16)

	matches := ScanConstants(buf)

	aesCnt := 0
	for _, m := range matches {
		if m.Algorithm == "AES" {
			aesCnt++
		}
	}
	if aesCnt != 1 {
		t.Errorf("expected exactly 1 AES match after dedup, got %d (all matches: %v)", aesCnt, matches)
	}
}

func TestScanConstants_EmptyData(t *testing.T) {
	matches := ScanConstants(nil)
	if len(matches) != 0 {
		t.Errorf("expected no matches for nil data, got %d", len(matches))
	}

	matches = ScanConstants([]byte{})
	if len(matches) != 0 {
		t.Errorf("expected no matches for empty data, got %d", len(matches))
	}
}

func TestScanConstants_PatternAtStart(t *testing.T) {
	// Pattern located at offset 0.
	pattern := cryptoConstants[8].pattern // ChaCha20
	buf := make([]byte, len(pattern)+64)
	copy(buf, pattern)
	for i := len(pattern); i < len(buf); i++ {
		buf[i] = 0xBB
	}

	matches := ScanConstants(buf)
	found := false
	for _, m := range matches {
		if m.Algorithm == "ChaCha20" {
			found = true
			if m.Offset != 0 {
				t.Errorf("expected offset 0, got %d", m.Offset)
			}
		}
	}
	if !found {
		t.Error("ChaCha20 pattern not found at offset 0")
	}
}

func TestScanConstants_PatternAtEnd(t *testing.T) {
	// Pattern located at the very end of the buffer.
	pattern := cryptoConstants[11].pattern // Poly1305
	buf := make([]byte, 128+len(pattern))
	for i := 0; i < 128; i++ {
		buf[i] = 0xCC
	}
	copy(buf[128:], pattern)

	matches := ScanConstants(buf)
	found := false
	for _, m := range matches {
		if m.Algorithm == "Poly1305" {
			found = true
			if m.Offset != 128 {
				t.Errorf("expected offset 128, got %d", m.Offset)
			}
		}
	}
	if !found {
		t.Error("Poly1305 pattern not found at end of buffer")
	}
}

func TestScanConstants_AllPatternsPresent(t *testing.T) {
	// Total number of distinct patterns defined.
	if len(cryptoConstants) != 14 {
		t.Errorf("expected 14 crypto constants, got %d", len(cryptoConstants))
	}
}

// appendFiller appends n bytes of 0xAA to dst and returns the result.
func appendFiller(dst []byte, n int) []byte {
	for i := 0; i < n; i++ {
		dst = append(dst, 0xAA)
	}
	return dst
}
