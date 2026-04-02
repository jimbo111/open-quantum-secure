package registry

import (
	"testing"
)

// --------------------------------------------------------------------------
// 1. Load registry and normalize well-known algorithm names.
// --------------------------------------------------------------------------

func TestNormalize_AES256GCM_ExactMatch(t *testing.T) {
	reg := Load()
	result := reg.Normalize("AES-256-GCM", 0, "")

	if result.MatchType != MatchExact {
		t.Errorf("MatchType = %q, want %q", result.MatchType, MatchExact)
	}
	if result.Family != "AES" {
		t.Errorf("Family = %q, want AES", result.Family)
	}
	if result.CanonicalName == "" {
		t.Error("CanonicalName must not be empty for an exact match")
	}
	if result.Confidence != "high" {
		t.Errorf("Confidence = %q, want high", result.Confidence)
	}
}

func TestNormalize_AES_GCM_256_UnderscoreNormalization(t *testing.T) {
	// "aes_gcm_256" → cleanInput → "aes-gcm-256"
	// That pattern does not exist in the registry (AES-256-GCM is the canonical order).
	// The normalizer must fall through to a prefix match on the "AES" family.
	reg := Load()
	result := reg.Normalize("aes_gcm_256", 256, "GCM")

	if result.Family != "AES" {
		t.Errorf("Family = %q, want AES (prefix match after underscore normalisation)", result.Family)
	}
	// Prefix match or exact — either way the family must be resolved.
	if result.MatchType == MatchNone {
		t.Errorf("MatchType = %q, did not expect MatchNone for an AES-prefixed name", result.MatchType)
	}
}

func TestNormalize_RSA2048_ExactMatch(t *testing.T) {
	reg := Load()
	result := reg.Normalize("RSA-2048", 0, "")

	if result.MatchType != MatchExact {
		t.Errorf("MatchType = %q, want %q", result.MatchType, MatchExact)
	}
	if result.Family != "RSA" {
		t.Errorf("Family = %q, want RSA", result.Family)
	}
	if result.Confidence != "high" {
		t.Errorf("Confidence = %q, want high", result.Confidence)
	}
}

func TestNormalize_RSASSA_PKCS1_v1_5_UnderscorePreserved(t *testing.T) {
	// "RSASSA-PKCS1-v1_5" is in the registry verbatim.
	// cleanInput converts '_' → '-', giving "RSASSA-PKCS1-v1-5", which does NOT match.
	// However, Normalize() also tries the trimmed original string as a fallback candidate,
	// so the exact pattern match on "RSASSA-PKCS1-v1_5" must still succeed.
	reg := Load()
	result := reg.Normalize("RSASSA-PKCS1-v1_5", 0, "")

	if result.MatchType != MatchExact {
		t.Errorf("MatchType = %q, want %q — underscore in v1_5 must be preserved via original-string fallback", result.MatchType, MatchExact)
	}
	if result.Family != "RSA" {
		t.Errorf("Family = %q, want RSA", result.Family)
	}
	if result.Confidence != "high" {
		t.Errorf("Confidence = %q, want high", result.Confidence)
	}
}

// --------------------------------------------------------------------------
// 2. cleanInput: underscores → hyphens, whitespace trimmed.
// --------------------------------------------------------------------------

func TestCleanInput(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"AES-256-GCM", "AES-256-GCM"},                  // no change
		{"aes_256_gcm", "aes-256-gcm"},                   // underscores replaced
		{"  RSA-2048  ", "RSA-2048"},                     // leading/trailing whitespace
		{"  ml_kem_768  ", "ml-kem-768"},                 // both whitespace and underscores
		{"SHA_256", "SHA-256"},                            // single underscore
		{"", ""},                                          // empty string
		{"RSASSA-PKCS1-v1_5", "RSASSA-PKCS1-v1-5"},       // underscore becomes hyphen
		{"   ", ""},                                       // whitespace only
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := cleanInput(tt.input)
			if got != tt.want {
				t.Errorf("cleanInput(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

// --------------------------------------------------------------------------
// 3. buildCanonical: family + keySize + mode combinations.
// --------------------------------------------------------------------------

func TestBuildCanonical(t *testing.T) {
	tests := []struct {
		family  string
		keySize int
		mode    string
		want    string
	}{
		{"AES", 256, "GCM", "AES-256-GCM"},
		{"AES", 128, "CBC", "AES-128-CBC"},
		{"AES", 256, "", "AES-256"},
		{"AES", 0, "GCM", "AES-GCM"},
		{"RSA", 0, "", "RSA"},
		{"ML-KEM", 768, "", "ML-KEM-768"},
		{"SHA-2", 0, "", "SHA-2"},
		{"AES", 128, "gcm", "AES-128-GCM"}, // mode uppercased
		{"AES", 192, "ctr", "AES-192-CTR"}, // mode uppercased
		{"DH", 2048, "", "DH-2048"},
	}

	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			got := buildCanonical(tt.family, tt.keySize, tt.mode)
			if got != tt.want {
				t.Errorf("buildCanonical(%q, %d, %q) = %q, want %q",
					tt.family, tt.keySize, tt.mode, got, tt.want)
			}
		})
	}
}

// --------------------------------------------------------------------------
// 4. extractFamily: returns the first hyphen-or-underscore-delimited token.
// --------------------------------------------------------------------------

func TestExtractFamily(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"AES-256-GCM", "AES"},
		{"RSA-2048", "RSA"},
		{"ML-KEM-768", "ML"},         // splits on first hyphen
		{"SHA256", "SHA256"},         // no delimiter → entire string
		{"aes_gcm_256", "aes"},       // underscore delimiter
		{"", ""},                     // empty
		{"ChaCha20-Poly1305", "ChaCha20"},
		{"HMAC-SHA256", "HMAC"},
		{"Ed25519", "Ed25519"},       // no delimiter
		{"SLH-DSA-SHA2-128s", "SLH"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := extractFamily(tt.input)
			if got != tt.want {
				t.Errorf("extractFamily(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

// --------------------------------------------------------------------------
// 5. Normalize with keySize and mode hints — prefix match uses them.
// --------------------------------------------------------------------------

func TestNormalize_WithKeySizeAndModeHints(t *testing.T) {
	reg := Load()

	tests := []struct {
		raw           string
		keySize       int
		mode          string
		wantFamily    string
		wantCanonical string
	}{
		// Exact match ignores hints — canonical comes from the registry pattern.
		{"AES-256-GCM", 256, "GCM", "AES", "AES-256-GCM"},
		{"AES-128-CBC", 128, "CBC", "AES", "AES-128-CBC"},
		// Prefix match uses hints to construct canonical.
		// "AES-XYZ" is not an exact pattern but starts with "AES".
		{"AES-XYZ", 128, "GCM", "AES", "AES-128-GCM"},
	}

	for _, tt := range tests {
		t.Run(tt.raw, func(t *testing.T) {
			result := reg.Normalize(tt.raw, tt.keySize, tt.mode)
			if result.Family != tt.wantFamily {
				t.Errorf("Family = %q, want %q", result.Family, tt.wantFamily)
			}
			if result.CanonicalName != tt.wantCanonical {
				t.Errorf("CanonicalName = %q, want %q", result.CanonicalName, tt.wantCanonical)
			}
		})
	}
}

// --------------------------------------------------------------------------
// 6. MatchType verification: MatchExact, MatchPrefix, MatchNone.
// --------------------------------------------------------------------------

func TestNormalize_MatchTypes(t *testing.T) {
	reg := Load()

	tests := []struct {
		name      string
		raw       string
		keySize   int
		mode      string
		wantMatch MatchType
	}{
		// Exact matches from the registry patterns.
		{"exact_AES256GCM", "AES-256-GCM", 0, "", MatchExact},
		{"exact_MLKEM768", "ML-KEM-768", 0, "", MatchExact},
		{"exact_SHA256", "SHA-256", 0, "", MatchExact},
		{"exact_RSA2048", "RSA-2048", 0, "", MatchExact},
		{"exact_MLDSA65", "ML-DSA-65", 0, "", MatchExact},
		{"exact_ChaCha20Poly1305", "ChaCha20-Poly1305", 0, "", MatchExact},
		// Prefix matches — known family prefix but no exact pattern.
		{"prefix_AES_unknown_variant", "AES-XYZ", 0, "", MatchPrefix},
		{"prefix_RSA_unknown_keysize", "RSA-8192", 0, "", MatchPrefix},
		{"prefix_SHA2_unknown_variant", "SHA-2-512-999", 0, "", MatchPrefix},
		// No match — completely unknown algorithm.
		{"none_unknown", "TotallyUnknownAlgorithm", 0, "", MatchNone},
		{"none_gibberish", "XYZZY-1234", 0, "", MatchNone},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := reg.Normalize(tt.raw, tt.keySize, tt.mode)
			if result.MatchType != tt.wantMatch {
				t.Errorf("Normalize(%q).MatchType = %q, want %q",
					tt.raw, result.MatchType, tt.wantMatch)
			}
		})
	}
}

func TestNormalize_MatchNone_FallbackRetainsRawName(t *testing.T) {
	reg := Load()
	raw := "CompletelyFictionalCipher-9999"
	result := reg.Normalize(raw, 0, "")

	if result.MatchType != MatchNone {
		t.Errorf("MatchType = %q, want none", result.MatchType)
	}
	if result.CanonicalName != raw {
		t.Errorf("CanonicalName = %q, want raw input %q for no-match fallback", result.CanonicalName, raw)
	}
	if result.Confidence != "low" {
		t.Errorf("Confidence = %q, want low", result.Confidence)
	}
}

// --------------------------------------------------------------------------
// 7. ResolveCurve: canonical name, alias, OID, not found.
// --------------------------------------------------------------------------

func TestResolveCurve_AllResolutionPaths(t *testing.T) {
	reg := Load()

	tests := []struct {
		name      string
		input     string
		wantOK    bool
		wantName  string
	}{
		// Canonical short name.
		{"canonical_P256", "P-256", true, "P-256"},
		{"canonical_P384", "P-384", true, "P-384"},
		{"canonical_P521", "P-521", true, "P-521"},
		// Canonical family/name form.
		{"canonical_nist_P256", "nist/P-256", true, "P-256"},
		// Alias resolution.
		{"alias_secp256r1", "secp256r1", true, "P-256"},
		{"alias_secp384r1", "secp384r1", true, "P-384"},
		{"alias_secp521r1", "secp521r1", true, "P-521"},
		{"alias_prime256v1", "prime256v1", true, "P-256"},
		// Alias resolution is case-insensitive.
		{"alias_SECP256R1_upper", "SECP256R1", true, "P-256"},
		{"alias_Prime256V1_mixed", "Prime256V1", true, "P-256"},
		// OID resolution.
		{"oid_P256", "1.2.840.10045.3.1.7", true, "P-256"},
		{"oid_P384", "1.3.132.0.34", true, "P-384"},
		{"oid_P521", "1.3.132.0.35", true, "P-521"},
		// DJB curves.
		{"canonical_Curve25519", "Curve25519", true, "Curve25519"},
		{"alias_X25519", "X25519", true, "Curve25519"},
		{"oid_Curve25519", "1.3.101.110", true, "Curve25519"},
		// Not found.
		{"notfound_fake", "nonexistent-curve-xyz", false, ""},
		{"notfound_empty", "", false, ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, ok := reg.ResolveCurve(tt.input)
			if ok != tt.wantOK {
				t.Errorf("ResolveCurve(%q) ok = %v, want %v", tt.input, ok, tt.wantOK)
				return
			}
			if tt.wantOK && result.Name != tt.wantName {
				t.Errorf("ResolveCurve(%q).Name = %q, want %q", tt.input, result.Name, tt.wantName)
			}
		})
	}
}

func TestResolveCurve_ResultFields(t *testing.T) {
	reg := Load()

	// P-256 has a known OID and Weierstrass form — verify all fields populate.
	result, ok := reg.ResolveCurve("P-256")
	if !ok {
		t.Fatal("ResolveCurve(P-256) returned false")
	}
	if result.Name != "P-256" {
		t.Errorf("Name = %q, want P-256", result.Name)
	}
	if result.OID != "1.2.840.10045.3.1.7" {
		t.Errorf("OID = %q, want 1.2.840.10045.3.1.7", result.OID)
	}
	if result.Form != "Weierstrass" {
		t.Errorf("Form = %q, want Weierstrass", result.Form)
	}
}

func TestResolveCurve_secp256k1(t *testing.T) {
	// secp256k1 lives in the secg family, has no NIST alias.
	reg := Load()
	result, ok := reg.ResolveCurve("secp256k1")
	if !ok {
		t.Fatal("ResolveCurve(secp256k1) returned false")
	}
	if result.Name != "secp256k1" {
		t.Errorf("Name = %q, want secp256k1", result.Name)
	}
}

// --------------------------------------------------------------------------
// 8. itoa: zero, positive, negative, and edge cases.
// --------------------------------------------------------------------------

func TestItoa(t *testing.T) {
	tests := []struct {
		n    int
		want string
	}{
		{0, "0"},
		{1, "1"},
		{9, "9"},
		{10, "10"},
		{128, "128"},
		{256, "256"},
		{1024, "1024"},
		{-1, "-1"},
		{-128, "-128"},
		{-1024, "-1024"},
		{2147483647, "2147483647"},   // MaxInt32
		{-2147483648, "-2147483648"}, // MinInt32
	}

	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			got := itoa(tt.n)
			if got != tt.want {
				t.Errorf("itoa(%d) = %q, want %q", tt.n, got, tt.want)
			}
		})
	}
}

// --------------------------------------------------------------------------
// Supplementary: Normalize is case-insensitive for exact pattern matches.
// --------------------------------------------------------------------------

func TestNormalize_CaseInsensitive(t *testing.T) {
	reg := Load()

	variants := []string{
		"AES-256-GCM",
		"aes-256-gcm",
		"Aes-256-Gcm",
		"AES-256-gcm",
	}

	var canonicalBase string
	for i, v := range variants {
		result := reg.Normalize(v, 0, "")
		if result.MatchType != MatchExact {
			t.Errorf("Normalize(%q) MatchType = %q, want exact", v, result.MatchType)
		}
		if i == 0 {
			canonicalBase = result.CanonicalName
		} else if result.CanonicalName != canonicalBase {
			t.Errorf("Normalize(%q).CanonicalName = %q, want %q (same as AES-256-GCM)",
				v, result.CanonicalName, canonicalBase)
		}
	}
}

// --------------------------------------------------------------------------
// Supplementary: Normalize returns non-empty family for all known families
// when given the exact canonical pattern name.
// --------------------------------------------------------------------------

func TestNormalize_KnownFamilies_ExactPatterns(t *testing.T) {
	reg := Load()

	knownPatterns := []struct {
		raw    string
		family string
	}{
		{"AES-256-GCM", "AES"},
		{"AES-128-CBC", "AES"},
		{"RSA-2048", "RSA"},
		{"RSASSA-PKCS1-v1_5", "RSA"},
		{"ECDSA-P256", "ECDSA"},
		{"ML-KEM-768", "ML-KEM"},
		{"ML-DSA-65", "ML-DSA"},
		{"SLH-DSA-SHA2-128s", "SLH-DSA"},
		{"SHA-256", "SHA-2"},
		{"SHA-512", "SHA-2"},
		{"SHA3-256", "SHA-3"},
		{"ChaCha20-Poly1305", "ChaCha20"},
		{"HMAC-SHA256", "HMAC"},
		{"Ed25519", "EdDSA"},
		{"X25519", "X25519"},
		{"MD5", "MD5"},
		{"SHA-1", "SHA-1"},
		{"ARIA-256-GCM", "ARIA"},
		{"SEED-128-CBC", "SEED"},
		{"LEA-256", "LEA"},
		{"SMAUG-T-128", "SMAUG-T"},
		{"HAETAE-2", "HAETAE"},
		{"AIMer-128f", "AIMer"},
	}

	for _, tt := range knownPatterns {
		t.Run(tt.raw, func(t *testing.T) {
			result := reg.Normalize(tt.raw, 0, "")
			if result.MatchType != MatchExact {
				t.Errorf("Normalize(%q) MatchType = %q, want exact", tt.raw, result.MatchType)
			}
			if result.Family != tt.family {
				t.Errorf("Normalize(%q) Family = %q, want %q", tt.raw, result.Family, tt.family)
			}
		})
	}
}
