package tlsprobe

import (
	"testing"
)

func TestClassifyHandshakeVolume(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name       string
		totalBytes int64
		wantClass  HandshakeVolumeClass
		wantStr    string
	}{
		// VolumeClassical: < 7000
		{"zero", 0, VolumeClassical, "classical"},
		{"small classical", 1000, VolumeClassical, "classical"},
		{"x25519 typical", 3500, VolumeClassical, "classical"},
		{"just below hybrid min", 6999, VolumeClassical, "classical"},

		// VolumeHybridKEM: 7000..11999
		{"at hybrid min", 7000, VolumeHybridKEM, "hybrid-kem"},
		{"x25519mlkem768 typical", 9000, VolumeHybridKEM, "hybrid-kem"},
		{"just below hybrid max", 11999, VolumeHybridKEM, "hybrid-kem"},

		// VolumeUnknown: 12000..20000
		{"at hybrid max", 12000, VolumeUnknown, "unknown"},
		{"gap midpoint", 16000, VolumeUnknown, "unknown"},
		{"at full pqc threshold", 20000, VolumeUnknown, "unknown"},

		// VolumeFullPQC: > 20000
		{"just above full pqc", 20001, VolumeFullPQC, "full-pqc"},
		{"full pqc typical", 45000, VolumeFullPQC, "full-pqc"},
		{"very large", 200000, VolumeFullPQC, "full-pqc"},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := ClassifyHandshakeVolume(tt.totalBytes)
			if got != tt.wantClass {
				t.Errorf("ClassifyHandshakeVolume(%d) = %v, want %v", tt.totalBytes, got, tt.wantClass)
			}
			if got.String() != tt.wantStr {
				t.Errorf("HandshakeVolumeClass.String() for %d = %q, want %q", tt.totalBytes, got.String(), tt.wantStr)
			}
		})
	}
}

func TestHandshakeVolumeClass_String_AllValues(t *testing.T) {
	t.Parallel()
	cases := []struct {
		class HandshakeVolumeClass
		want  string
	}{
		{VolumeClassical, "classical"},
		{VolumeHybridKEM, "hybrid-kem"},
		{VolumeUnknown, "unknown"},
		{VolumeFullPQC, "full-pqc"},
		// Sentinel for unknown enum value (HandshakeVolumeClass is int).
		{HandshakeVolumeClass(99), "unknown"},
	}
	for _, c := range cases {
		if got := c.class.String(); got != c.want {
			t.Errorf("HandshakeVolumeClass(%d).String() = %q, want %q", c.class, got, c.want)
		}
	}
}

// TestClassifyHandshakeVolume_NegativeSafe verifies that a negative totalBytes
// (which should never occur from countingConn but could from a test stub) is
// treated as classical without panicking.
func TestClassifyHandshakeVolume_NegativeSafe(t *testing.T) {
	t.Parallel()
	got := ClassifyHandshakeVolume(-1)
	if got != VolumeClassical {
		t.Errorf("ClassifyHandshakeVolume(-1) = %v, want VolumeClassical", got)
	}
}
