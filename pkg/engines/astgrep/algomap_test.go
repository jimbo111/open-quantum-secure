package astgrep

import "testing"

func TestParseCryptoIdentifier(t *testing.T) {
	tests := []struct {
		in       string
		wantName string
		wantBits int
		wantMode string
	}{
		{"EVP_aes_128_cbc()", "AES", 128, "CBC"},
		{"EVP_aes_256_gcm()", "AES", 256, "GCM"},
		{"EVP_des_ede3_cbc()", "3DES", 0, "CBC"},
		{"EVP_sha256()", "SHA-256", 0, ""},
		{"EVP_sha1", "SHA-1", 0, ""},
		{"EVP_sha3_256()", "SHA3-256", 0, ""},
		{"EVP_md5()", "MD5", 0, ""},
		{"EVP_rc4()", "RC4", 0, ""},
		{"AES-128-CBC", "AES", 128, "CBC"},   // EVP_CIPHER_fetch name form
		{"sha256.New", "SHA-256", 0, ""},     // Go hash constructor value
		{"TLS_client_method()", "TLS", 0, ""},
		{"TLS_method()", "TLS", 0, ""},
		{"SSLv23_method()", "TLS", 0, ""}, // version-flexible, not SSLv2/v3
		{"SSLv3_method()", "SSLv3", 0, ""},
		{"TLSv1_2_client_method()", "TLSv1.2", 0, ""},
		{"TLSv1_1_method()", "TLSv1.1", 0, ""},
		{"TLSv1_method()", "TLSv1.0", 0, ""},
		{"cipher", "", 0, ""},   // variable name — unrecognized
		{"ctx", "", 0, ""},      // variable name
		{"", "", 0, ""},
		{"EVP_aes_128_cbc(x)", "", 0, ""}, // call with args is not a selector
	}
	for _, tc := range tests {
		t.Run(tc.in, func(t *testing.T) {
			name, bits, mode := parseCryptoIdentifier(tc.in)
			if name != tc.wantName || bits != tc.wantBits || mode != tc.wantMode {
				t.Errorf("parseCryptoIdentifier(%q) = (%q, %d, %q), want (%q, %d, %q)",
					tc.in, name, bits, mode, tc.wantName, tc.wantBits, tc.wantMode)
			}
		})
	}
}

func TestCanonicalAlgoName(t *testing.T) {
	tests := []struct {
		in   string
		want string
	}{
		{"rsa", "RSA"},
		{"RSA", "RSA"},
		{"ec", "ECDSA"},
		{"ed25519", "Ed25519"},
		{"md5", "MD5"},
		{"sha1", "SHA-1"},
		{"sha256", "SHA-256"},
		{"RS256", "RSA"},
		{"PS384", "RSA"},
		{"ES256", "ECDSA"},
		{"HS256", "HMAC-SHA256"},
		{"EdDSA", "Ed25519"},
		{"SHA256withRSA", "RSA"},
		{"SHA1withDSA", "DSA"},
		{"HmacSHA256", "HMAC-SHA256"},
		{"AES/CBC/PKCS5Padding", ""}, // not a token — caller keeps the literal
		{"transform", ""},            // variable name — unrecognized
		{"", ""},
	}
	for _, tc := range tests {
		t.Run(tc.in, func(t *testing.T) {
			if got := canonicalAlgoName(tc.in); got != tc.want {
				t.Errorf("canonicalAlgoName(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

func TestInferAlgorithmFromRuleID(t *testing.T) {
	tests := []struct {
		ruleID string
		want   string
	}{
		{"custom-rsa-keygen", "RSA"},
		{"custom-md5-usage", "MD5"},
		{"my-org-ecdh-check", "ECDH"},
		{"tls-version-check", "TLS"},
		// No algorithm token: must return "" — never "NEW"/"CONFIG"/"CHECK".
		{"custom-thing-new", ""},
		{"some-config", ""},
		{"", ""},
		// Hybrid ids resolve to the full hybrid, not the classical component.
		{"crypto-x25519-mlkem768", "X25519MLKEM768"},
		{"crypto-x25519-mlkem-768", "X25519MLKEM768"},
	}
	for _, tc := range tests {
		t.Run(tc.ruleID, func(t *testing.T) {
			if got := inferAlgorithmFromRuleID(tc.ruleID); got != tc.want {
				t.Errorf("inferAlgorithmFromRuleID(%q) = %q, want %q", tc.ruleID, got, tc.want)
			}
		})
	}
}

func TestExtractCurve(t *testing.T) {
	tests := []struct {
		text string
		want string
	}{
		{"elliptic.P256()", "P-256"},
		{"ec.SECP384R1()", "P-384"},
		{"'secp256k1'", "secp256k1"}, // contains "p256" — must not map to P-256
		{"'prime256v1'", "P-256"},
		{"curveVar", ""},
	}
	for _, tc := range tests {
		t.Run(tc.text, func(t *testing.T) {
			m := rawMatch{MetaVars: rawMetaVars{"CURVE": {Text: tc.text}}}
			if got := extractCurve(m); got != tc.want {
				t.Errorf("extractCurve(%q) = %q, want %q", tc.text, got, tc.want)
			}
		})
	}
}

// TestExtractAlgorithmDetails_HMACRefinement pins HMAC + captured hash
// combination for Go's hmac.New and OpenSSL's HMAC_Init_ex.
func TestExtractAlgorithmDetails_HMACRefinement(t *testing.T) {
	goMatch := rawMatch{
		RuleID:   "crypto-go-hmac-new",
		MetaVars: rawMetaVars{"HASH": {Text: "sha256.New"}, "KEY": {Text: "key"}},
	}
	if name, _, _ := extractAlgorithmDetails(goMatch, nil); name != "HMAC-SHA256" {
		t.Errorf("go hmac.New: got %q, want HMAC-SHA256", name)
	}

	osslMatch := rawMatch{
		RuleID:   "crypto-openssl-hmac-init-ex",
		MetaVars: rawMetaVars{"MD": {Text: "EVP_sha512()"}},
	}
	if name, _, _ := extractAlgorithmDetails(osslMatch, nil); name != "HMAC-SHA512" {
		t.Errorf("openssl HMAC_Init_ex: got %q, want HMAC-SHA512", name)
	}

	// Unresolvable hash capture keeps the bare HMAC name.
	bare := rawMatch{
		RuleID:   "crypto-go-hmac-new",
		MetaVars: rawMetaVars{"HASH": {Text: "hashFn"}},
	}
	if name, _, _ := extractAlgorithmDetails(bare, nil); name != "HMAC" {
		t.Errorf("unresolvable hash capture: got %q, want HMAC", name)
	}
}
