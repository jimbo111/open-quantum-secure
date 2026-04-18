package sshprobe

import "strings"

// kexInfo describes the PQC status of a SSH KEX method.
type kexInfo struct {
	pqcPresent bool
	maturity   string // "final", "draft", or "" (classical)
}

// kexTable maps SSH KEX algorithm names to their PQC classification.
// Sources: RFC 4253, OpenSSH release notes, IETF draft-ssh-pqc-* documents.
var kexTable = map[string]kexInfo{
	// IETF-standardised hybrid KEM (ML-KEM-768 + X25519, SHA-256).
	// Adopted as the OpenSSH 10.0 default (released 2025).
	// Ref: draft-ietf-crypto-sshpq-kem (expected RFC).
	"mlkem768x25519-sha256": {pqcPresent: true, maturity: "final"},

	// OpenSSH's pre-standard hybrid (sntrup761 + X25519, SHA-512).
	// Default in OpenSSH 8.5–9.9; superseded by mlkem768x25519-sha256 in 10.0.
	"sntrup761x25519-sha512@openssh.com": {pqcPresent: true, maturity: "draft"},

	// Draft Kyber variants published before ML-KEM standardisation.
	// These use the pre-FIPS-203 Kyber round-3 spec — deprecated per CNSA 2.0.
	"kyber-512-sha256@pqc.ssh":             {pqcPresent: true, maturity: "draft"},
	"kyber-768-sha256@pqc.ssh":             {pqcPresent: true, maturity: "draft"},
	"kyber-1024-sha256@pqc.ssh":            {pqcPresent: true, maturity: "draft"},
	"x25519-kyber-512-sha256@ietf.org":     {pqcPresent: true, maturity: "draft"},
	"x25519-kyber-768-sha256@ietf.org":     {pqcPresent: true, maturity: "draft"},

	// NTRUPrime variants (pre-sntrup761 era; rare in production).
	"ntruprime-ntrulpr761x25519-sha512@openssh.com": {pqcPresent: true, maturity: "draft"},
	"ntruprime-sntrup761x25519-sha512@openssh.com":  {pqcPresent: true, maturity: "draft"},

	// Classical KEX methods — quantum-vulnerable (Shor's algorithm).
	"diffie-hellman-group14-sha1":                    {pqcPresent: false},
	"diffie-hellman-group14-sha256":                  {pqcPresent: false},
	"diffie-hellman-group16-sha512":                  {pqcPresent: false},
	"diffie-hellman-group18-sha512":                  {pqcPresent: false},
	"diffie-hellman-group-exchange-sha1":             {pqcPresent: false},
	"diffie-hellman-group-exchange-sha256":           {pqcPresent: false},
	"diffie-hellman-group1-sha1":                     {pqcPresent: false},
	"ecdh-sha2-nistp256":                             {pqcPresent: false},
	"ecdh-sha2-nistp384":                             {pqcPresent: false},
	"ecdh-sha2-nistp521":                             {pqcPresent: false},
	"curve25519-sha256":                              {pqcPresent: false},
	"curve25519-sha256@libssh.org":                   {pqcPresent: false},
	"curve448-sha512":                                {pqcPresent: false},
}

// pqcHeuristics lists substrings that suggest a PQC KEX not yet in kexTable.
// Used to return a more informative label for unknown-but-PQC-looking methods.
// B6: "ntru" removed — "sntrup" and "ntruprime" substrings already cover real
// PQC implementations; bare "ntru" risks false positives on unrelated algorithm names.
var pqcHeuristics = []string{"mlkem", "kyber", "sntrup", "frodo", "ntruprime", "bike", "hqc", "mceliece"}

// classifyKex returns the kexInfo for a KEX method name.
// For names not in kexTable, it applies a heuristic based on pqcHeuristics.
func classifyKex(method string) kexInfo {
	if info, ok := kexTable[method]; ok {
		return info
	}
	lower := strings.ToLower(method)
	for _, hint := range pqcHeuristics {
		if strings.Contains(lower, hint) {
			// Unrecognised but looks PQC — report as draft so it surfaces in findings.
			return kexInfo{pqcPresent: true, maturity: "draft"}
		}
	}
	return kexInfo{pqcPresent: false}
}
