package native

import "bytes"

// cryptoConstant describes a known byte sequence found in binary implementations
// of cryptographic algorithms.
type cryptoConstant struct {
	name      string // human-readable name (e.g. "AES S-box")
	algorithm string // canonical algorithm name (e.g. "AES")
	primitive string // primitive class (e.g. "symmetric")
	pattern   []byte
}

// ConstantMatch records a found crypto constant in scanned data.
type ConstantMatch struct {
	// Algorithm is the canonical algorithm name (e.g. "AES").
	Algorithm string
	// Primitive is the primitive class (e.g. "symmetric").
	Primitive string
	// Offset is the byte offset within the scanned data.
	Offset int
	// PatternName is the human-readable description of the matched pattern.
	PatternName string
}

// cryptoConstants is the catalogue of known binary crypto constants.
// Each entry carries enough bytes to be unambiguous (minimum 11 bytes).
var cryptoConstants = []cryptoConstant{
	{
		name:      "AES S-box",
		algorithm: "AES",
		primitive: "symmetric",
		pattern: []byte{
			0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5,
			0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
			0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0,
			0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
		},
	},
	{
		name:      "AES Inverse S-box",
		algorithm: "AES",
		primitive: "symmetric",
		pattern: []byte{
			0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38,
			0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB,
			0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87,
			0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB,
		},
	},
	{
		name:      "AES RCON",
		algorithm: "AES",
		primitive: "symmetric",
		pattern: []byte{
			0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36, 0x6C,
		},
	},
	{
		// SHA-256 initial hash values H0..H7 in big-endian layout.
		// H0=0x6a09e667  H1=0xbb67ae85  H2=0x3c6ef372  H3=0xa54ff53a
		// H4=0x510e527f  H5=0x9b05688c  H6=0x1f83d9ab  H7=0x5be0cd19
		name:      "SHA-256 initial H (big-endian)",
		algorithm: "SHA-256",
		primitive: "hash",
		pattern: []byte{
			0x6a, 0x09, 0xe6, 0x67, // H0
			0xbb, 0x67, 0xae, 0x85, // H1
			0x3c, 0x6e, 0xf3, 0x72, // H2
			0xa5, 0x4f, 0xf5, 0x3a, // H3
			0x51, 0x0e, 0x52, 0x7f, // H4
			0x9b, 0x05, 0x68, 0x8c, // H5
			0x1f, 0x83, 0xd9, 0xab, // H6
			0x5b, 0xe0, 0xcd, 0x19, // H7
		},
	},
	{
		// SHA-256 initial hash values H0..H7 in little-endian layout
		// (each 32-bit word stored least-significant byte first).
		name:      "SHA-256 initial H (little-endian)",
		algorithm: "SHA-256",
		primitive: "hash",
		pattern: []byte{
			0x67, 0xe6, 0x09, 0x6a, // H0 LE
			0x85, 0xae, 0x67, 0xbb, // H1 LE
			0x72, 0xf3, 0x6e, 0x3c, // H2 LE
			0x3a, 0xf5, 0x4f, 0xa5, // H3 LE
			0x7f, 0x52, 0x0e, 0x51, // H4 LE
			0x8c, 0x68, 0x05, 0x9b, // H5 LE
			0xab, 0xd9, 0x83, 0x1f, // H6 LE
			0x19, 0xcd, 0xe0, 0x5b, // H7 LE
		},
	},
	{
		// SHA-512 initial hash values H0..H3 in big-endian layout.
		// H0=0x6a09e667f3bcc908  H1=0xbb67ae8584caa73b
		// H2=0x3c6ef372fe94f82b  H3=0xa54ff53a5f1d36f1
		name:      "SHA-512 initial H (big-endian, first 32 bytes)",
		algorithm: "SHA-512",
		primitive: "hash",
		pattern: []byte{
			0x6a, 0x09, 0xe6, 0x67, 0xf3, 0xbc, 0xc9, 0x08, // H0
			0xbb, 0x67, 0xae, 0x85, 0x84, 0xca, 0xa7, 0x3b, // H1
			0x3c, 0x6e, 0xf3, 0x72, 0xfe, 0x94, 0xf8, 0x2b, // H2
			0xa5, 0x4f, 0xf5, 0x3a, 0x5f, 0x1d, 0x36, 0xf1, // H3
		},
	},
	{
		// SHA-1 initial hash values H0..H4 in big-endian layout.
		// H0=0x67452301  H1=0xEFCDAB89  H2=0x98BADCFE
		// H3=0x10325476  H4=0xC3D2E1F0
		name:      "SHA-1 initial H (big-endian)",
		algorithm: "SHA-1",
		primitive: "hash",
		pattern: []byte{
			0x67, 0x45, 0x23, 0x01, // H0
			0xEF, 0xCD, 0xAB, 0x89, // H1
			0x98, 0xBA, 0xDC, 0xFE, // H2
			0x10, 0x32, 0x54, 0x76, // H3
			0xC3, 0xD2, 0xE1, 0xF0, // H4
		},
	},
	{
		// MD5 T-table: first four sine-based constants (big-endian uint32).
		// T[1]=0xd76aa478  T[2]=0xe8c7b756  T[3]=0x242070db  T[4]=0xc1bdceee
		name:      "MD5 T-table (first 16 bytes)",
		algorithm: "MD5",
		primitive: "hash",
		pattern: []byte{
			0xd7, 0x6a, 0xa4, 0x78,
			0xe8, 0xc7, 0xb7, 0x56,
			0x24, 0x20, 0x70, 0xdb,
			0xc1, 0xbd, 0xce, 0xee,
		},
	},
	{
		// ChaCha20 constant string "expand 32-byte k" as ASCII bytes.
		name:      `ChaCha20 "expand 32-byte k"`,
		algorithm: "ChaCha20",
		primitive: "symmetric",
		pattern: []byte{
			0x65, 0x78, 0x70, 0x61, 0x6E, 0x64, 0x20, 0x33,
			0x32, 0x2D, 0x62, 0x79, 0x74, 0x65, 0x20, 0x6B,
		},
	},
	{
		// Blowfish P-array words 0-3 in big-endian (pi digits).
		// P0=0x243f6a88  P1=0x85a308d3  P2=0x13198a2e  P3=0x03707344
		name:      "Blowfish P-array (first 16 bytes)",
		algorithm: "Blowfish",
		primitive: "symmetric",
		pattern: []byte{
			0x24, 0x3f, 0x6a, 0x88,
			0x85, 0xa3, 0x08, 0xd3,
			0x13, 0x19, 0x8a, 0x2e,
			0x03, 0x70, 0x73, 0x44,
		},
	},
	{
		// DES initial permutation table (IP), first 16 entries as bytes.
		name:      "DES initial permutation table",
		algorithm: "DES",
		primitive: "symmetric",
		pattern: []byte{
			58, 50, 42, 34, 26, 18, 10, 2,
			60, 52, 44, 36, 28, 20, 12, 4,
		},
	},
	{
		// Poly1305 clamp mask applied to the one-time key r.
		name:      "Poly1305 clamp mask",
		algorithm: "Poly1305",
		primitive: "mac",
		pattern: []byte{
			0x0f, 0xff, 0xff, 0xfc, 0x0f, 0xff, 0xff, 0xfc,
			0x0f, 0xff, 0xff, 0xfc, 0x0f, 0xff, 0xff, 0xfc,
		},
	},
	{
		// Curve25519 prime p = 2^255 - 19 in little-endian 32-byte form.
		// -19 in LE = 0xed followed by 0xff×30 followed by 0x7f
		name:      "Curve25519 prime P (little-endian)",
		algorithm: "Curve25519",
		primitive: "key-exchange",
		pattern: []byte{
			0xed, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
			0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
			0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
			0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f,
		},
	},
	{
		// SM4 S-box (first 32 bytes).
		name:      "SM4 S-box",
		algorithm: "SM4",
		primitive: "symmetric",
		pattern: []byte{
			0xD6, 0x90, 0xE9, 0xFE, 0xCC, 0xE1, 0x3D, 0xB7,
			0x16, 0xB6, 0x14, 0xC2, 0x28, 0xFB, 0x2C, 0x05,
			0x2B, 0x67, 0x9A, 0x76, 0x2A, 0xBE, 0x04, 0xC3,
			0xAA, 0x44, 0x13, 0x26, 0x49, 0x86, 0x06, 0x99,
		},
	},
}

// ScanConstants searches data for known cryptographic byte constant patterns.
// It returns one ConstantMatch per unique occurrence found.
func ScanConstants(data []byte) []ConstantMatch {
	if len(data) == 0 {
		return nil
	}

	var matches []ConstantMatch
	for _, cc := range cryptoConstants {
		offset := 0
		for {
			idx := bytes.Index(data[offset:], cc.pattern)
			if idx < 0 {
				break
			}
			matches = append(matches, ConstantMatch{
				Algorithm:   cc.algorithm,
				Primitive:   cc.primitive,
				Offset:      offset + idx,
				PatternName: cc.name,
			})
			// Advance past this match to find additional occurrences.
			offset += idx + len(cc.pattern)
			if offset >= len(data) {
				break
			}
		}
	}

	return deduplicateMatches(matches)
}

// deduplicateMatches collapses multiple matches for the same algorithm into
// a single entry. The entry with the lowest offset is kept.
func deduplicateMatches(matches []ConstantMatch) []ConstantMatch {
	if len(matches) == 0 {
		return nil
	}

	// Track which algorithms have already been emitted.
	seen := make(map[string]struct{}, len(matches))
	out := make([]ConstantMatch, 0, len(matches))

	for _, m := range matches {
		if _, ok := seen[m.Algorithm]; ok {
			continue
		}
		seen[m.Algorithm] = struct{}{}
		out = append(out, m)
	}

	return out
}
