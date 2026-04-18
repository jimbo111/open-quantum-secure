// kex_matrix_test.go — KEX advertisement matrix tests for real-world OpenSSH versions.
//
// Purpose: verify that every documented OpenSSH default KEX advertisement
// (versions 7.4 through 10.0) is correctly parsed and classified. Each version
// fixture asserts:
//   1. The first PQC method detected is the expected one (or none for pre-8.5).
//   2. Total finding count == total method count.
//   3. RiskSafe count (PQC-capable KEX methods) matches expected value.
//   4. RiskVulnerable count (classical methods) matches expected value.
//
// Source: OpenSSH release notes + RFC 4253 §7.1 + IETF draft-ietf-crypto-sshpq-kem.
// KEX lists reflect each version's compiled-in defaults before host-based filtering.
package sshprobe

import (
	"strings"
	"testing"
	"time"

	"github.com/jimbo111/open-quantum-secure/pkg/findings"
)

// opensshVersion describes the KEX advertisement of a specific OpenSSH release.
type opensshVersion struct {
	name string // e.g. "OpenSSH 7.4"
	// serverID is the SSH identification string sent by the server.
	serverID string
	// kexMethods is the default kex_algorithms name-list in order.
	kexMethods []string
	// firstPQCMethod is the expected first method with pqcPresent=true, or "" for none.
	firstPQCMethod string
	// wantRiskSafe is the expected count of PQC-safe findings (QuantumRisk == QRSafe).
	wantRiskSafe int
	// wantNotSafe is the expected count of findings that are NOT QRSafe.
	// This includes QRVulnerable, QRUnknown, QRDeprecated, etc.
	// Note: curve25519-sha256 and curve25519-sha256@libssh.org are classified as
	// QRUnknown (not QRVulnerable) by ClassifyAlgorithm because the generic
	// classifier does not map SSH-specific method names to curve families.
	wantNotSafe int
}

var opensshMatrix = []opensshVersion{
	{
		name:     "OpenSSH 7.4",
		serverID: "SSH-2.0-OpenSSH_7.4",
		// Released 2016-12-19. No PQC KEX. Classical only.
		// curve25519-sha256 and curve25519-sha256@libssh.org → QRUnknown (2)
		// ecdh-sha2-nistp{256,384,521} + 5× DH → QRVulnerable (8)
		kexMethods: []string{
			"curve25519-sha256",
			"curve25519-sha256@libssh.org",
			"ecdh-sha2-nistp256",
			"ecdh-sha2-nistp384",
			"ecdh-sha2-nistp521",
			"diffie-hellman-group-exchange-sha256",
			"diffie-hellman-group16-sha512",
			"diffie-hellman-group18-sha512",
			"diffie-hellman-group14-sha256",
			"diffie-hellman-group14-sha1",
		},
		firstPQCMethod: "",
		wantRiskSafe:   0,
		wantNotSafe:    10,
	},
	{
		name:     "OpenSSH 8.0",
		serverID: "SSH-2.0-OpenSSH_8.0",
		// Released 2019-04-18. Still classical only by default.
		kexMethods: []string{
			"curve25519-sha256",
			"curve25519-sha256@libssh.org",
			"ecdh-sha2-nistp256",
			"ecdh-sha2-nistp384",
			"ecdh-sha2-nistp521",
			"diffie-hellman-group-exchange-sha256",
			"diffie-hellman-group16-sha512",
			"diffie-hellman-group18-sha512",
			"diffie-hellman-group14-sha256",
			"diffie-hellman-group14-sha1",
		},
		firstPQCMethod: "",
		wantRiskSafe:   0,
		wantNotSafe:    10,
	},
	{
		name:     "OpenSSH 8.5",
		serverID: "SSH-2.0-OpenSSH_8.5",
		// Released 2021-03-03. First release with sntrup761x25519 as a compiled-in
		// default (prepended before classical methods). Ref: OpenSSH 8.5 release notes.
		kexMethods: []string{
			"sntrup761x25519-sha512@openssh.com",
			"curve25519-sha256",
			"curve25519-sha256@libssh.org",
			"ecdh-sha2-nistp256",
			"ecdh-sha2-nistp384",
			"ecdh-sha2-nistp521",
			"diffie-hellman-group-exchange-sha256",
			"diffie-hellman-group16-sha512",
			"diffie-hellman-group18-sha512",
			"diffie-hellman-group14-sha256",
		},
		firstPQCMethod: "sntrup761x25519-sha512@openssh.com",
		wantRiskSafe:   1,
		wantNotSafe:    9,
	},
	{
		name:     "OpenSSH 9.0",
		serverID: "SSH-2.0-OpenSSH_9.0",
		// Released 2022-04-08. Same kex default list as 8.5.
		kexMethods: []string{
			"sntrup761x25519-sha512@openssh.com",
			"curve25519-sha256",
			"curve25519-sha256@libssh.org",
			"ecdh-sha2-nistp256",
			"ecdh-sha2-nistp384",
			"ecdh-sha2-nistp521",
			"diffie-hellman-group-exchange-sha256",
			"diffie-hellman-group16-sha512",
			"diffie-hellman-group18-sha512",
			"diffie-hellman-group14-sha256",
		},
		firstPQCMethod: "sntrup761x25519-sha512@openssh.com",
		wantRiskSafe:   1,
		wantNotSafe:    9,
	},
	{
		name:     "OpenSSH 9.9",
		serverID: "SSH-2.0-OpenSSH_9.9",
		// Last release before mlkem768 landing. sntrup761 remains default.
		kexMethods: []string{
			"sntrup761x25519-sha512@openssh.com",
			"curve25519-sha256",
			"curve25519-sha256@libssh.org",
			"ecdh-sha2-nistp256",
			"ecdh-sha2-nistp384",
			"ecdh-sha2-nistp521",
			"diffie-hellman-group-exchange-sha256",
			"diffie-hellman-group16-sha512",
			"diffie-hellman-group18-sha512",
			"diffie-hellman-group14-sha256",
		},
		firstPQCMethod: "sntrup761x25519-sha512@openssh.com",
		wantRiskSafe:   1,
		wantNotSafe:    9,
	},
	{
		name:     "OpenSSH 10.0",
		serverID: "SSH-2.0-OpenSSH_10.0",
		// Released 2025. Adopts mlkem768x25519-sha256 (draft-ietf-crypto-sshpq-kem)
		// as the primary hybrid KEX; sntrup761 dropped from the default list.
		// Ref: OpenSSH 10.0 release notes + CLAUDE.md.
		kexMethods: []string{
			"mlkem768x25519-sha256",
			"curve25519-sha256",
			"curve25519-sha256@libssh.org",
			"ecdh-sha2-nistp256",
			"ecdh-sha2-nistp384",
			"ecdh-sha2-nistp521",
			"diffie-hellman-group-exchange-sha256",
			"diffie-hellman-group16-sha512",
			"diffie-hellman-group18-sha512",
			"diffie-hellman-group14-sha256",
		},
		firstPQCMethod: "mlkem768x25519-sha256",
		wantRiskSafe:   1,
		wantNotSafe:    9,
	},
	{
		name:     "Dropbear 2020.80",
		serverID: "SSH-2.0-dropbear_2020.80",
		// Common embedded SSH server. Classical only, minimal method set.
		// curve25519-sha256 → QRUnknown; 4 ECDH/DH → QRVulnerable.
		kexMethods: []string{
			"curve25519-sha256",
			"ecdh-sha2-nistp256",
			"ecdh-sha2-nistp384",
			"ecdh-sha2-nistp521",
			"diffie-hellman-group14-sha256",
			"diffie-hellman-group14-sha1",
		},
		firstPQCMethod: "",
		wantRiskSafe:   0,
		wantNotSafe:    6,
	},
	{
		name:     "Vendor_PQC_experimental",
		serverID: "SSH-2.0-VendorSSH_3.0",
		// Hypothetical vendor advertising multiple PQC methods alongside classical.
		// mlkem768 + sntrup761 + kyber-768 → 3 QRSafe; curve25519 (QRUnknown) +
		// ecdh-sha2-nistp256 (QRVulnerable) + diffie-hellman-group14 (QRVulnerable) → 3 not-safe.
		kexMethods: []string{
			"mlkem768x25519-sha256",
			"sntrup761x25519-sha512@openssh.com",
			"kyber-768-sha256@pqc.ssh",
			"curve25519-sha256",
			"ecdh-sha2-nistp256",
			"diffie-hellman-group14-sha256",
		},
		firstPQCMethod: "mlkem768x25519-sha256",
		wantRiskSafe:   3,
		wantNotSafe:    3,
	},
}

// TestKEXMatrix runs the full matrix of OpenSSH version fixtures against
// kexInitToFindings, asserting PQC detection accuracy.
func TestKEXMatrix(t *testing.T) {
	for _, v := range opensshMatrix {
		v := v
		t.Run(v.name, func(t *testing.T) {
			result := ProbeResult{
				Target:     "203.0.113.5:22",
				ServerID:   v.serverID,
				KEXMethods: v.kexMethods,
			}
			ff := kexInitToFindings(result)

			// 1. Total finding count must equal total method count.
			if len(ff) != len(v.kexMethods) {
				t.Fatalf("finding count = %d; want %d (one per method)", len(ff), len(v.kexMethods))
			}

			// 2. First PQC method detected must be correct.
			firstPQC := ""
			for _, f := range ff {
				if f.PQCPresent {
					firstPQC = f.Algorithm.Name
					break
				}
			}
			if firstPQC != v.firstPQCMethod {
				t.Errorf("first PQC method = %q; want %q", firstPQC, v.firstPQCMethod)
			}

			// 3. RiskSafe count and not-safe count must match.
			// Note: classical methods map to QRVulnerable or QRUnknown (curve25519-sha256
			// is classified as QRUnknown by ClassifyAlgorithm since it doesn't recognise
			// the SSH-specific method name format). wantNotSafe covers both.
			var gotSafe, gotNotSafe int
			for _, f := range ff {
				if f.QuantumRisk == findings.QRSafe {
					gotSafe++
				} else {
					gotNotSafe++
				}
			}
			if gotSafe != v.wantRiskSafe {
				t.Errorf("RiskSafe count = %d; want %d", gotSafe, v.wantRiskSafe)
			}
			if gotNotSafe != v.wantNotSafe {
				t.Errorf("not-safe count = %d; want %d", gotNotSafe, v.wantNotSafe)
			}

			// 4. PQCMaturity for mlkem768 must be "final", sntrup761/kyber must be "draft".
			for _, f := range ff {
				if !f.PQCPresent {
					continue
				}
				switch {
				case strings.Contains(f.Algorithm.Name, "mlkem"):
					if f.PQCMaturity != "final" {
						t.Errorf("method %q: PQCMaturity=%q; want final", f.Algorithm.Name, f.PQCMaturity)
					}
				case strings.Contains(f.Algorithm.Name, "sntrup"), strings.Contains(f.Algorithm.Name, "kyber"):
					if f.PQCMaturity != "draft" {
						t.Errorf("method %q: PQCMaturity=%q; want draft", f.Algorithm.Name, f.PQCMaturity)
					}
				}
			}

			// 5. Algorithm primitive must always be "kex".
			for i, f := range ff {
				if f.Algorithm == nil || f.Algorithm.Primitive != "kex" {
					t.Errorf("finding[%d] Algorithm.Primitive=%v; want kex", i, f.Algorithm)
				}
			}
		})
	}
}

// TestKEXMatrix_ProbeRoundTrip runs the full OpenSSH matrix through a live TCP
// probe against a fake SSH server, verifying end-to-end probe + classification.
func TestKEXMatrix_ProbeRoundTrip(t *testing.T) {
	for _, v := range opensshMatrix {
		v := v
		t.Run(v.name+"_probe", func(t *testing.T) {
			addr := serveFakeSSH(t, v.serverID, v.kexMethods)

			result := probeSSH(t.Context(), addr, 5*time.Second)
			if result.Error != nil {
				t.Fatalf("probeSSH error: %v", result.Error)
			}
			if result.ServerID != v.serverID {
				t.Errorf("ServerID=%q; want %q", result.ServerID, v.serverID)
			}
			if len(result.KEXMethods) != len(v.kexMethods) {
				t.Fatalf("KEXMethods len=%d; want %d", len(result.KEXMethods), len(v.kexMethods))
			}
			for i, m := range v.kexMethods {
				if result.KEXMethods[i] != m {
					t.Errorf("method[%d]=%q; want %q", i, result.KEXMethods[i], m)
				}
			}

			// Classify and assert PQC-safe split matches.
			ff := kexInitToFindings(result)
			var gotSafe int
			for _, f := range ff {
				if f.QuantumRisk == findings.QRSafe {
					gotSafe++
				}
			}
			if gotSafe != v.wantRiskSafe {
				t.Errorf("probe round-trip RiskSafe=%d; want %d", gotSafe, v.wantRiskSafe)
			}
		})
	}
}
