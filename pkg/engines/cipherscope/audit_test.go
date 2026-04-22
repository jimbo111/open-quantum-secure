package cipherscope

// AUDIT: adversarial fixtures authored for the 2026-04-20 Tier-1 scanner audit.
// See docs/audits/2026-04-20-scanner-layer-audit/01-t1-source.md for the report.

import (
	"encoding/json"
	"math"
	"testing"
)

// -----------------------------------------------------------------------------
// F-CIPHERSCOPE-1 — parseAlgorithm misinterprets PQC parameter-set suffixes
// (ML-KEM-512, Kyber-768, X25519-MLKEM-768) as key-size values because any
// numeric segment >=64 becomes KeySize.  This is a real-world hit because
// cipherscope is expected to surface PQC identifiers in CBOM output and the
// KeySize=768 for a hybrid KEM is nonsensical downstream.
// -----------------------------------------------------------------------------

func TestAudit_ParseAlgorithm_PQCParamSetsMislabeledAsKeySize(t *testing.T) {
	// 2026-04-21: expectations flipped after fix. Numeric suffixes of PQC
	// parameter-set names must NOT be reported as KeySize.
	cases := []struct {
		id      string
		wantKey int
		comment string
	}{
		{"ML-KEM-512", 0, "512 is PQC parameter set, not key-bit count"},
		{"ML-KEM-768", 0, "param set, not key size"},
		{"ML-KEM-1024", 0, "param set, not key size"},
		{"Kyber-768", 0, "Kyber param set"},
		{"X25519-MLKEM-768", 0, "hybrid KEM; 768 is PQC parameter"},
		{"ML-DSA-44", 0, "44 < 64 threshold and PQC"},
		{"ML-DSA-65", 0, "PQC signature — param set not key size"},
		{"ML-DSA-87", 0, "PQC signature — param set not key size"},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.id, func(t *testing.T) {
			got := parseAlgorithm(tc.id)
			if got.KeySize != tc.wantKey {
				t.Errorf("parseAlgorithm(%q).KeySize = %d, want %d (%s)",
					tc.id, got.KeySize, tc.wantKey, tc.comment)
			}
		})
	}
}

// -----------------------------------------------------------------------------
// F-CIPHERSCOPE-2 — parseAlgorithm lets a later numeric segment overwrite a
// legitimate key-size segment.  "AES-128-CBC-256" yields KeySize=256 even
// though the "128" is the authoritative key length.
// -----------------------------------------------------------------------------

func TestAudit_ParseAlgorithm_LastNumericWinsOverwritesKeySize(t *testing.T) {
	cases := []struct {
		id      string
		wantKey int
	}{
		// 2026-04-21: flipped after fix — first authoritative numeric wins.
		{"AES-128-CBC-256", 128}, // 256 is a MAC/tag length, not the AES key
		{"RSA-2048-4096", 2048},  // first numeric is the key size
		{"AES-256-GCM-96", 256},  // 96 is the GCM IV length
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.id, func(t *testing.T) {
			got := parseAlgorithm(tc.id)
			if got.KeySize != tc.wantKey {
				t.Errorf("parseAlgorithm(%q).KeySize = %d, want %d",
					tc.id, got.KeySize, tc.wantKey)
			}
		})
	}
}

// -----------------------------------------------------------------------------
// F-CIPHERSCOPE-3 — parseKeySize string branch silently accepts embedded
// garbage because it uses strconv.Atoi which rejects the whole string, but
// the current code never reports parse errors.  Adversarial: whitespace,
// sign, hex, scientific notation.
// -----------------------------------------------------------------------------

func TestAudit_ParseKeySize_StringAdversarial(t *testing.T) {
	cases := []struct {
		in   interface{}
		want int
	}{
		{"256 ", 0},     // trailing space defeats strconv.Atoi
		{" 256", 0},     // leading space
		{"+256", 256},   // explicit plus — Atoi accepts
		{"-256", 0},     // negative clamped to 0
		{"0x100", 0},    // hex literal rejected by Atoi
		{"2.5e2", 0},    // scientific form rejected by Atoi
		{"2048\n", 0},   // embedded newline
		{"4_096", 0},    // Go-style underscore separator rejected
	}
	for _, tc := range cases {
		tc := tc
		t.Run(fallbackName(tc.in), func(t *testing.T) {
			got := parseKeySize(tc.in)
			if got != tc.want {
				t.Errorf("parseKeySize(%v) = %d, want %d", tc.in, got, tc.want)
			}
		})
	}
}

// -----------------------------------------------------------------------------
// F-CIPHERSCOPE-4 — parseKeySize float64 overflow edge.  Int conversion of
// a float outside int range is implementation-defined in Go; the explicit
// `ks > 1<<31-1` cap uses int-sized max rather than int64, which means on
// 64-bit platforms values above 2^31-1 are rejected even though they would
// fit in `int`.  Low severity: only affects key sizes >2GB which no algorithm
// uses, but it *does* inconsistently reject legitimate math.MaxInt32+1.
// -----------------------------------------------------------------------------

func TestAudit_ParseKeySize_Float64OverflowBoundary(t *testing.T) {
	cases := []struct {
		in   float64
		want int
	}{
		{math.MaxInt32, int(math.MaxInt32)}, // 2^31-1 accepted
		{math.MaxInt32 + 1, 0},              // 2^31 rejected (uses int32 cap)
		{math.Inf(1), 0},                    // +Inf rejected
		{math.Inf(-1), 0},                   // -Inf rejected (< 0)
		{math.NaN(), 0},                     // NaN rejected
		{-1, 0},                             // negative rejected
		{0, 0},                              // zero
		{256.0, 256},                        // integral float ok
		{256.5, 0},                          // non-integer rejected
	}
	for _, tc := range cases {
		tc := tc
		t.Run(fallbackName(tc.in), func(t *testing.T) {
			got := parseKeySize(tc.in)
			if got != tc.want {
				t.Errorf("parseKeySize(%v) = %d, want %d", tc.in, got, tc.want)
			}
		})
	}
}

// -----------------------------------------------------------------------------
// F-CIPHERSCOPE-5 — parseAlgorithm's mode table is case-folded on input but
// the output key preserves the upper-cased token.  The CLAUDE.md convention
// says hybrid PQC names use underscores for variable names and hyphens for
// algorithm names, but cipherscope silently parses underscore-separated
// identifiers as a single-token Name (no split happens at all).
// -----------------------------------------------------------------------------

func TestAudit_ParseAlgorithm_UnderscoreVariantNotSplit(t *testing.T) {
	// X25519_MLKEM_768 — CLAUDE.md calls this a variable-name form.  cipherscope
	// does not split it, so KeySize=0 (good) but Name stays as-is (good).
	got := parseAlgorithm("X25519_MLKEM_768")
	if got.Name != "X25519_MLKEM_768" {
		t.Errorf("Name: got %q, want %q", got.Name, "X25519_MLKEM_768")
	}
	if got.KeySize != 0 {
		t.Errorf("KeySize: got %d, want 0 (no split occurred)", got.KeySize)
	}
	if got.Mode != "" || got.Curve != "" {
		t.Errorf("Mode/Curve should be empty for unsplit identifier, got mode=%q curve=%q", got.Mode, got.Curve)
	}
}

// -----------------------------------------------------------------------------
// F-CIPHERSCOPE-6 — normalize drops algorithm info when parseKeySize returns
// zero from a negative-integer metadata value.  A pathological emitter
// sending {"keysize": -256} results in a finding with KeySize=0, silently
// downgrading the original parsed value (which came from identifier parsing).
// -----------------------------------------------------------------------------

func TestAudit_Normalize_NegativeMetadataKeysizeSilentlyDowngrades(t *testing.T) {
	raw := rawFinding{
		AssetType:  "algorithm",
		Identifier: "AES-256-GCM", // parseAlgorithm gives KeySize=256
		Path:       "src/foo.go",
		Evidence:   rawEvidence{Line: 1, Column: 1},
		Metadata:   json.RawMessage(`{"keysize": -256}`),
	}
	uf := normalize(raw)
	if uf.Algorithm == nil {
		t.Fatal("expected Algorithm to be set")
	}
	// The comment in cipherscope.go says metadata overlays the parsed values.
	// parseKeySize(-256) returns 0; the code only overlays `if ks > 0`.
	// So the identifier-parsed KeySize=256 is preserved.  Expected 256 — test
	// confirms the overlay gate works as designed.
	if uf.Algorithm.KeySize != 256 {
		t.Errorf("KeySize was clobbered by negative metadata: got %d, want 256", uf.Algorithm.KeySize)
	}
}

// -----------------------------------------------------------------------------
// F-CIPHERSCOPE-7 — normalize emits a library finding whose Dependency.Library
// is the empty string when the raw Identifier is empty.  The current Scan
// loop has no guard for this, so we get phantom findings.
// -----------------------------------------------------------------------------

func TestAudit_Normalize_LibraryEmptyIdentifierPhantomFinding(t *testing.T) {
	raw := rawFinding{
		AssetType:  "library",
		Identifier: "",
		Path:       "src/foo.go",
	}
	uf := normalize(raw)
	if uf.Dependency == nil {
		t.Fatal("expected Dependency to be non-nil for library finding")
	}
	if uf.Dependency.Library != "" {
		t.Errorf("Library: got %q, want empty (reproducing current behaviour)", uf.Dependency.Library)
	}
	// This phantom finding propagates into output channels — the bug is that
	// cipherscope.Scan does not filter these out before emitting.
}

// -----------------------------------------------------------------------------
// F-CIPHERSCOPE-8 — parseAlgorithm handles "AES--GCM" (empty middle segment)
// without error.  The empty segment coerces to neither an integer nor a known
// mode; it is ignored.  Documents benign behaviour.
// -----------------------------------------------------------------------------

func TestAudit_ParseAlgorithm_EmptyMiddleSegment(t *testing.T) {
	got := parseAlgorithm("AES--GCM")
	if got.Mode != "GCM" {
		t.Errorf("Mode: got %q, want %q", got.Mode, "GCM")
	}
	if got.KeySize != 0 {
		t.Errorf("KeySize: got %d, want 0", got.KeySize)
	}
}

func fallbackName(v interface{}) string {
	switch x := v.(type) {
	case string:
		return "string:" + x
	case float64:
		if math.IsNaN(x) {
			return "NaN"
		}
		if math.IsInf(x, 1) {
			return "+Inf"
		}
		if math.IsInf(x, -1) {
			return "-Inf"
		}
		return "f64"
	case int:
		return "int"
	}
	return "unknown"
}
