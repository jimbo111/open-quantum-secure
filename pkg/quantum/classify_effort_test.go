package quantum

import "testing"

// TestClassifyEffort verifies migration effort derivation across all rule
// combinations (primitive × source type × risk).
func TestClassifyEffort(t *testing.T) {
	tests := []struct {
		name      string
		c         Classification
		primitive string
		isConfig  bool
		want      string
	}{
		// --- safe / resistant / unknown → no effort ---
		{"safe algo", Classification{Risk: RiskSafe}, "kem", false, ""},
		{"resistant algo", Classification{Risk: RiskResistant}, "symmetric", false, ""},
		{"unknown algo", Classification{Risk: RiskUnknown}, "", false, ""},

		// --- deprecated → simple (just remove) ---
		{"deprecated DES", Classification{Risk: RiskDeprecated}, "symmetric", false, "simple"},
		{"deprecated RC4", Classification{Risk: RiskDeprecated}, "stream-cipher", false, "simple"},
		{"deprecated MD5", Classification{Risk: RiskDeprecated}, "hash", false, "simple"},
		{"deprecated in config", Classification{Risk: RiskDeprecated}, "symmetric", true, "simple"},

		// --- weakened hash → simple regardless of source type ---
		{"weakened hash source", Classification{Risk: RiskWeakened}, "hash", false, "simple"},
		{"weakened hash config", Classification{Risk: RiskWeakened}, "hash", true, "simple"},
		{"weakened mac", Classification{Risk: RiskWeakened}, "mac", false, "simple"},
		{"weakened kdf", Classification{Risk: RiskWeakened}, "kdf", false, "simple"},
		{"weakened xof", Classification{Risk: RiskWeakened}, "xof", false, "simple"},

		// --- weakened symmetric: config → simple, source → moderate ---
		{"weakened symmetric config (AES-128 in cipher suite)", Classification{Risk: RiskWeakened}, "symmetric", true, "simple"},
		{"weakened symmetric source", Classification{Risk: RiskWeakened}, "symmetric", false, "moderate"},
		{"weakened block-cipher source", Classification{Risk: RiskWeakened}, "block-cipher", false, "moderate"},
		{"weakened ae config", Classification{Risk: RiskWeakened}, "ae", true, "simple"},
		{"weakened ae source", Classification{Risk: RiskWeakened}, "ae", false, "moderate"},

		// --- vulnerable signature → moderate (replace API calls, not protocol) ---
		{"vulnerable signature source", Classification{Risk: RiskVulnerable}, "signature", false, "moderate"},
		{"vulnerable signature config", Classification{Risk: RiskVulnerable}, "signature", true, "moderate"},

		// --- vulnerable key exchange: source → complex, config → moderate ---
		{"vulnerable key-agree source", Classification{Risk: RiskVulnerable}, "key-agree", false, "complex"},
		{"vulnerable key-agree config", Classification{Risk: RiskVulnerable}, "key-agree", true, "moderate"},
		{"vulnerable key-exchange source", Classification{Risk: RiskVulnerable}, "key-exchange", false, "complex"},
		{"vulnerable kem source", Classification{Risk: RiskVulnerable}, "kem", false, "complex"},
		{"vulnerable kem config", Classification{Risk: RiskVulnerable}, "kem", true, "moderate"},
		{"vulnerable pke source", Classification{Risk: RiskVulnerable}, "pke", false, "complex"},

		// --- vulnerable unknown primitive → complex (conservative) ---
		{"vulnerable unknown primitive", Classification{Risk: RiskVulnerable}, "", false, "complex"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ClassifyEffort(tt.c, tt.primitive, tt.isConfig)
			if got != tt.want {
				t.Errorf("ClassifyEffort(%q, %q, isConfig=%v) = %q, want %q",
					tt.c.Risk, tt.primitive, tt.isConfig, got, tt.want)
			}
		})
	}
}

// TestUpgradeEffort verifies the blast-radius effort escalation ladder.
func TestUpgradeEffort(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"simple", "moderate"},
		{"moderate", "complex"},
		{"complex", "complex"}, // already at max — no change
		{"", ""},               // empty — unchanged
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := UpgradeEffort(tt.input)
			if got != tt.want {
				t.Errorf("UpgradeEffort(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

// TestClassifyAlgorithm_Effort verifies that ClassifyAlgorithm populates
// MigrationEffort on full end-to-end paths where effort is expected to be empty
// (safe, resistant, unknown) — the effort is set by the orchestrator via
// ClassifyEffort after we know the source type.
// This test validates the four documented scenarios from the spec.
func TestClassifyAlgorithm_Effort_ViaClassifyEffort(t *testing.T) {
	tests := []struct {
		name      string
		algName   string
		primitive string
		keySize   int
		isConfig  bool
		wantRisk  Risk
		wantEffort string
	}{
		// Symmetric config → simple
		{
			name:       "AES-128 config",
			algName:    "AES-128",
			primitive:  "symmetric",
			keySize:    128,
			isConfig:   true,
			wantRisk:   RiskWeakened,
			wantEffort: "simple",
		},
		// Symmetric source → moderate
		{
			name:       "AES-128 source",
			algName:    "AES-128",
			primitive:  "symmetric",
			keySize:    128,
			isConfig:   false,
			wantRisk:   RiskWeakened,
			wantEffort: "moderate",
		},
		// Asymmetric signature → moderate
		{
			name:       "ECDSA source",
			algName:    "ECDSA",
			primitive:  "signature",
			keySize:    0,
			isConfig:   false,
			wantRisk:   RiskVulnerable,
			wantEffort: "moderate",
		},
		// Key exchange source → complex
		{
			name:       "ECDH key-agree source",
			algName:    "ECDH",
			primitive:  "key-agree",
			keySize:    0,
			isConfig:   false,
			wantRisk:   RiskVulnerable,
			wantEffort: "complex",
		},
		// RSA default (no primitive) → complex (unknown primitive, vulnerable)
		{
			name:       "RSA no primitive",
			algName:    "RSA",
			primitive:  "",
			keySize:    0,
			isConfig:   false,
			wantRisk:   RiskVulnerable,
			wantEffort: "complex",
		},
		// ML-KEM (PQC-safe) → no effort
		{
			name:       "ML-KEM-768 safe",
			algName:    "ML-KEM-768",
			primitive:  "kem",
			keySize:    0,
			isConfig:   false,
			wantRisk:   RiskSafe,
			wantEffort: "",
		},
		// SHA-1 deprecated → simple
		{
			name:       "SHA-1 deprecated",
			algName:    "SHA-1",
			primitive:  "hash",
			keySize:    0,
			isConfig:   false,
			wantRisk:   RiskDeprecated,
			wantEffort: "simple",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := ClassifyAlgorithm(tt.algName, tt.primitive, tt.keySize)
			if c.Risk != tt.wantRisk {
				t.Errorf("ClassifyAlgorithm(%q).Risk = %q, want %q", tt.algName, c.Risk, tt.wantRisk)
			}
			got := ClassifyEffort(c, tt.primitive, tt.isConfig)
			if got != tt.wantEffort {
				t.Errorf("ClassifyEffort for %q (isConfig=%v) = %q, want %q",
					tt.algName, tt.isConfig, got, tt.wantEffort)
			}
		})
	}
}

// TestBlastRadiusEffortUpgrade verifies that high blast radius (> 70) upgrades
// the base effort by one level. This exercises the UpgradeEffort helper.
func TestBlastRadiusEffortUpgrade(t *testing.T) {
	tests := []struct {
		name         string
		baseEffort   string
		blastRadius  int
		wantEffort   string
	}{
		{"simple + blast > 70 → moderate", "simple", 75, "moderate"},
		{"simple + blast = 70 → no upgrade", "simple", 70, "simple"},
		{"simple + blast < 70 → no upgrade", "simple", 50, "simple"},
		{"moderate + blast > 70 → complex", "moderate", 80, "complex"},
		{"complex + blast > 70 → stays complex", "complex", 90, "complex"},
		{"empty + blast > 70 → stays empty", "", 80, ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			effort := tt.baseEffort
			if tt.blastRadius > 70 {
				effort = UpgradeEffort(effort)
			}
			if effort != tt.wantEffort {
				t.Errorf("UpgradeEffort(%q) with blastRadius=%d = %q, want %q",
					tt.baseEffort, tt.blastRadius, effort, tt.wantEffort)
			}
		})
	}
}
