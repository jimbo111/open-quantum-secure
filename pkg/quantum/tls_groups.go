package quantum

// GroupInfo describes a TLS SupportedGroup (named group / key-share) codepoint.
// Sources: IANA TLS Parameters registry + NETWORK_ENGINE_PLAN.md §9.
type GroupInfo struct {
	Name       string // canonical human-readable name, e.g. "X25519MLKEM768"
	PQCPresent bool   // true when at least one ML-KEM component is present
	Maturity   string // "final" (FIPS/IETF standard), "draft" (deprecated), "" (classical)
	RiskLevel  Risk   // quantum risk characterisation for the group
}

// tlsGroupRegistry maps IANA TLS SupportedGroup codepoints → GroupInfo.
//
// Hybrid codepoints (0x11EB–0x11EE) are assigned in IETF
// draft-ietf-tls-hybrid-design and reference ML-KEM (FIPS 203).
// Pure ML-KEM codepoints (0x0200–0x0202) are from the same draft.
// Draft Kyber codepoints (0x6399, 0x636D) were used before FIPS 203
// was finalised; they are deprecated and should not appear in new deployments.
var tlsGroupRegistry = map[uint16]GroupInfo{
	// ── Hybrid KEMs: classical ECDH + ML-KEM ────────────────────────────────
	// IETF draft-ietf-tls-hybrid-design, codepoints from IANA provisional registry.
	0x11EB: {Name: "SecP256r1MLKEM768", PQCPresent: true, Maturity: "final", RiskLevel: RiskSafe},
	0x11EC: {Name: "X25519MLKEM768", PQCPresent: true, Maturity: "final", RiskLevel: RiskSafe},
	0x11ED: {Name: "SecP384r1MLKEM1024", PQCPresent: true, Maturity: "final", RiskLevel: RiskSafe},
	0x11EE: {Name: "curveSM2MLKEM768", PQCPresent: true, Maturity: "final", RiskLevel: RiskSafe},

	// ── Pure ML-KEM (FIPS 203) ──────────────────────────────────────────────
	0x0200: {Name: "MLKEM512", PQCPresent: true, Maturity: "final", RiskLevel: RiskSafe},
	0x0201: {Name: "MLKEM768", PQCPresent: true, Maturity: "final", RiskLevel: RiskSafe},
	0x0202: {Name: "MLKEM1024", PQCPresent: true, Maturity: "final", RiskLevel: RiskSafe},

	// ── Deprecated draft Kyber (pre-FIPS 203) ───────────────────────────────
	// PQCPresent=true because a PQ component is present, but Maturity="draft"
	// and RiskLevel=RiskDeprecated signals that these codepoints must not be
	// used in new deployments (they were finalised as X25519MLKEM768 / 0x11EC).
	0x6399: {Name: "X25519Kyber768Draft00", PQCPresent: true, Maturity: "draft", RiskLevel: RiskDeprecated},
	0x636D: {Name: "X25519Kyber768Draft00", PQCPresent: true, Maturity: "draft", RiskLevel: RiskDeprecated},

	// ── Classical ECDH / FFDH groups ────────────────────────────────────────
	// All broken by Shor's algorithm; PQCPresent=false.
	0x0017: {Name: "secp256r1", PQCPresent: false, Maturity: "", RiskLevel: RiskVulnerable},
	0x0018: {Name: "secp384r1", PQCPresent: false, Maturity: "", RiskLevel: RiskVulnerable},
	0x0019: {Name: "secp521r1", PQCPresent: false, Maturity: "", RiskLevel: RiskVulnerable},
	0x001d: {Name: "X25519", PQCPresent: false, Maturity: "", RiskLevel: RiskVulnerable},
	0x001e: {Name: "X448", PQCPresent: false, Maturity: "", RiskLevel: RiskVulnerable},
	0x0100: {Name: "ffdhe2048", PQCPresent: false, Maturity: "", RiskLevel: RiskVulnerable},
	0x0101: {Name: "ffdhe3072", PQCPresent: false, Maturity: "", RiskLevel: RiskVulnerable},
	0x0102: {Name: "ffdhe4096", PQCPresent: false, Maturity: "", RiskLevel: RiskVulnerable},
	0x0103: {Name: "ffdhe6144", PQCPresent: false, Maturity: "", RiskLevel: RiskVulnerable},
	0x0104: {Name: "ffdhe8192", PQCPresent: false, Maturity: "", RiskLevel: RiskVulnerable},
}

// ClassifyTLSGroup looks up a TLS SupportedGroup codepoint in the registry.
// Returns (GroupInfo, true) for known codepoints, (GroupInfo{}, false) for
// unknown ones. Callers must treat unknown codepoints as PQCPresent=false.
func ClassifyTLSGroup(id uint16) (GroupInfo, bool) {
	info, ok := tlsGroupRegistry[id]
	return info, ok
}
