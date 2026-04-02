package constraints

import "testing"

func TestCalculateEncodedSize(t *testing.T) {
	tests := []struct {
		name     string
		rawBytes int
		encoding string
		want     int
	}{
		// base64: ((n+2)/3)*4
		{"base64/0", 0, "base64", 0},
		{"base64/1", 1, "base64", 4},
		{"base64/2", 2, "base64", 4},
		{"base64/3", 3, "base64", 4},
		{"base64/4", 4, "base64", 8},
		{"base64/100", 100, "base64", 136},
		{"base64/1312", 1312, "base64", 1752}, // ML-DSA-44 public key: ((1312+2)/3)*4=1752

		// hex: n*2
		{"hex/0", 0, "hex", 0},
		{"hex/1", 1, "hex", 2},
		{"hex/32", 32, "hex", 64},
		{"hex/100", 100, "hex", 200},

		// pem: base64 + ceil(base64/64) + 52
		// 100 raw → 136 b64 → ceil(136/64)=3 newlines → 136+3+52=191
		{"pem/100", 100, "pem", 191},
		// 3 raw → 4 b64 → ceil(4/64)=1 newline → 4+1+52=57
		{"pem/3", 3, "pem", 57},
		// 192 raw → 256 b64 → ceil(256/64)=4 → 256+4+52=312
		{"pem/192", 192, "pem", 312},

		// der: n+8
		{"der/0", 0, "der", 8},
		{"der/100", 100, "der", 108},
		{"der/1312", 1312, "der", 1320},

		// raw / empty — identity
		{"raw/100", 100, "raw", 100},
		{"empty/100", 100, "", 100},
		{"unknown/100", 100, "unknown", 100},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := CalculateEncodedSize(tc.rawBytes, tc.encoding)
			if got != tc.want {
				t.Errorf("CalculateEncodedSize(%d, %q)=%d want %d", tc.rawBytes, tc.encoding, got, tc.want)
			}
		})
	}
}
