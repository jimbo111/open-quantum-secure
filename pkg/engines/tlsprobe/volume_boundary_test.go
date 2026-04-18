package tlsprobe

// volume_boundary_test.go — Bucket 4: boundary and edge-case tests for
// ClassifyHandshakeVolume.
//
// Focuses on:
//   - Exact threshold boundaries (6999/7000/7001, 11999/12000/12001,
//     19999/20000/20001) — each boundary is tested with the value just below,
//     at, and just above to catch inclusive/exclusive confusion.
//   - Negative input (-1) must not panic and is expected to return VolumeClassical
//     (negative < 7000 → VolumeClassical per the < thresholdHybridMin branch).
//   - VolumeUnknown.String() must return "unknown" (not empty string, not "Unknown").

import "testing"

// TestClassifyHandshakeVolume_ExactBoundaries exercises all threshold values
// with {value-1, value, value+1} to pin the inclusive/exclusive semantics.
func TestClassifyHandshakeVolume_ExactBoundaries(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name       string
		bytes      int64
		wantClass  HandshakeVolumeClass
		wantString string
	}{
		// ── Hybrid lower boundary: 7000 (inclusive) ──────────────────────────────
		// totalBytes < 7000 → VolumeClassical
		{"hybrid_lower_minus1 (6999)", 6999, VolumeClassical, "classical"},
		// totalBytes == 7000 → VolumeHybridKEM (first value in [7000, 12000))
		{"hybrid_lower_at (7000)", 7000, VolumeHybridKEM, "hybrid-kem"},
		// totalBytes == 7001 → VolumeHybridKEM
		{"hybrid_lower_plus1 (7001)", 7001, VolumeHybridKEM, "hybrid-kem"},

		// ── Hybrid upper boundary: 12000 (exclusive of HybridKEM, inclusive of Unknown) ─
		// totalBytes == 11999 → VolumeHybridKEM (still < 12000)
		{"hybrid_upper_minus1 (11999)", 11999, VolumeHybridKEM, "hybrid-kem"},
		// totalBytes == 12000 → VolumeUnknown (12000 ≤ bytes ≤ 20000: default branch)
		{"hybrid_upper_at (12000)", 12000, VolumeUnknown, "unknown"},
		// totalBytes == 12001 → VolumeUnknown
		{"hybrid_upper_plus1 (12001)", 12001, VolumeUnknown, "unknown"},

		// ── FullPQC lower boundary: 20000 (exclusive of FullPQC, inclusive of Unknown) ─
		// totalBytes == 19999 → VolumeUnknown
		{"fullpqc_lower_minus1 (19999)", 19999, VolumeUnknown, "unknown"},
		// totalBytes == 20000 → VolumeUnknown (> 20000 is required for FullPQC)
		{"fullpqc_lower_at (20000)", 20000, VolumeUnknown, "unknown"},
		// totalBytes == 20001 → VolumeFullPQC (strictly > 20000)
		{"fullpqc_lower_plus1 (20001)", 20001, VolumeFullPQC, "full-pqc"},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := ClassifyHandshakeVolume(tt.bytes)
			if got != tt.wantClass {
				t.Errorf("ClassifyHandshakeVolume(%d) = %v (%q), want %v (%q)",
					tt.bytes, got, got.String(), tt.wantClass, tt.wantString)
			}
			if got.String() != tt.wantString {
				t.Errorf("ClassifyHandshakeVolume(%d).String() = %q, want %q",
					tt.bytes, got.String(), tt.wantString)
			}
		})
	}
}

// TestClassifyHandshakeVolume_NegativeNoPanic verifies that a negative input
// does not panic and returns VolumeClassical (negative < 7000).
func TestClassifyHandshakeVolume_NegativeNoPanic(t *testing.T) {
	t.Parallel()
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("ClassifyHandshakeVolume(-1) panicked: %v", r)
		}
	}()
	got := ClassifyHandshakeVolume(-1)
	if got != VolumeClassical {
		t.Errorf("ClassifyHandshakeVolume(-1) = %v, want VolumeClassical", got)
	}
}

// TestVolumeUnknown_StringNotEmpty verifies that VolumeUnknown.String() returns
// "unknown" and not an empty string.  An empty String() would silently drop the
// transitional-gap signal from JSON / SARIF output.
func TestVolumeUnknown_StringNotEmpty(t *testing.T) {
	t.Parallel()
	got := VolumeUnknown.String()
	if got == "" {
		t.Error("VolumeUnknown.String() returned empty string; expected \"unknown\"")
	}
	if got != "unknown" {
		t.Errorf("VolumeUnknown.String() = %q, want \"unknown\"", got)
	}
}

// TestHandshakeVolumeClass_SentinelStrings verifies String() for all four named
// constants plus an out-of-range sentinel value.
func TestHandshakeVolumeClass_SentinelStrings(t *testing.T) {
	t.Parallel()
	cases := []struct {
		class HandshakeVolumeClass
		want  string
	}{
		{VolumeClassical, "classical"},
		{VolumeHybridKEM, "hybrid-kem"},
		{VolumeUnknown, "unknown"},
		{VolumeFullPQC, "full-pqc"},
		// Out-of-range sentinel: must return "unknown" (the default branch).
		{HandshakeVolumeClass(42), "unknown"},
		{HandshakeVolumeClass(-5), "unknown"},
	}
	for _, c := range cases {
		if got := c.class.String(); got != c.want {
			t.Errorf("HandshakeVolumeClass(%d).String() = %q, want %q", int(c.class), got, c.want)
		}
	}
}

// TestClassifyHandshakeVolume_ZeroIsClassical verifies that 0 bytes (possible
// from a failed probe) maps to VolumeClassical without panic.
func TestClassifyHandshakeVolume_ZeroIsClassical(t *testing.T) {
	t.Parallel()
	got := ClassifyHandshakeVolume(0)
	if got != VolumeClassical {
		t.Errorf("ClassifyHandshakeVolume(0) = %v, want VolumeClassical", got)
	}
}

// TestClassifyHandshakeVolume_MaxInt64 verifies that a very large input value
// (int64 max) does not panic and returns VolumeFullPQC.
func TestClassifyHandshakeVolume_MaxInt64(t *testing.T) {
	t.Parallel()
	const maxInt64 = int64(^uint64(0) >> 1)
	got := ClassifyHandshakeVolume(maxInt64)
	if got != VolumeFullPQC {
		t.Errorf("ClassifyHandshakeVolume(MaxInt64) = %v, want VolumeFullPQC", got)
	}
}
