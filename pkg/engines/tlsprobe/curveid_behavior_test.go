package tlsprobe

import (
	"crypto/tls"
	"strings"
	"testing"
)

// curveid_behavior_test.go — table-driven tests for observationToFindings across
// the full TLS version × CurveID space that the probe function can produce.
//
// Tests are parameterized to cover:
//   - TLS 1.3 with final PQC hybrid group   (0x11EC — X25519MLKEM768)
//   - TLS 1.3 with deprecated draft Kyber   (0x6399 — X25519Kyber768Draft00)
//   - TLS 1.3 with classical ECDH group     (0x001d — X25519)
//   - TLS 1.3 with CurveID == 0             (shouldn't happen, must not crash)
//   - TLS 1.3 with unknown codepoint        (0x9999 — must not panic)
//   - TLS 1.2 with classical ECDHE group    (0x001d from ECDHE handshake)
//   - TLS 1.2 with CurveID == 0             (RSA KEM — no named group)
//
// Additionally verifies Algorithm.Name for the TLS-1.3 synthetic kex finding,
// encoding the implementer's design decision: PQC hybrid/draft groups use the
// group name (e.g., "X25519MLKEM768"), classical/unknown groups fall back to
// the generic "ECDHE" label.

type curveIDBehaviorCase struct {
	name string

	tlsVersion  uint16
	curveID     uint16
	cipherSuite uint16
	leafKeyAlgo string
	leafKeySize int

	// expected session-level PQC metadata on every finding
	wantPQCPresent bool
	wantMaturity   string // "" means expect empty
	wantGroupName  string // "" means expect empty

	// wantKexName is the expected Algorithm.Name for the TLS-1.3 synthetic kex
	// finding (rawID prefix "kex:"). Empty string means no synthetic kex expected
	// (i.e., TLS 1.2 sessions).
	wantKexName string
}

var curveIDBehaviorCases = []curveIDBehaviorCase{
	{
		name:           "TLS13_PQCFinal_X25519MLKEM768",
		tlsVersion:     tls.VersionTLS13,
		curveID:        0x11EC,
		cipherSuite:    tls.TLS_AES_256_GCM_SHA384,
		leafKeyAlgo:    "RSA",
		leafKeySize:    2048,
		wantPQCPresent: true,
		wantMaturity:   "final",
		wantGroupName:  "X25519MLKEM768",
		wantKexName:    "X25519MLKEM768",
	},
	{
		name:           "TLS13_DraftKyber_0x6399",
		tlsVersion:     tls.VersionTLS13,
		curveID:        0x6399,
		cipherSuite:    tls.TLS_AES_256_GCM_SHA384,
		leafKeyAlgo:    "RSA",
		leafKeySize:    2048,
		wantPQCPresent: true,
		wantMaturity:   "draft",
		wantGroupName:  "X25519Kyber768Draft00",
		// PQCPresent=true but PQCMaturity="draft" → still uses group name, not "ECDHE".
		wantKexName: "X25519Kyber768Draft00",
	},
	{
		name:           "TLS13_Classical_X25519",
		tlsVersion:     tls.VersionTLS13,
		curveID:        0x001d,
		cipherSuite:    tls.TLS_AES_128_GCM_SHA256,
		leafKeyAlgo:    "ECDSA",
		leafKeySize:    256,
		wantPQCPresent: false,
		wantMaturity:   "",
		wantGroupName:  "X25519",
		wantKexName:    "ECDHE",
	},
	{
		// CurveID=0 in TLS 1.3 shouldn't occur (TLS 1.3 always negotiates a key
		// share), but the code must not panic and must not claim PQC presence.
		name:           "TLS13_ZeroCurveID",
		tlsVersion:     tls.VersionTLS13,
		curveID:        0,
		cipherSuite:    tls.TLS_AES_128_GCM_SHA256,
		leafKeyAlgo:    "RSA",
		leafKeySize:    2048,
		wantPQCPresent: false,
		wantMaturity:   "",
		wantGroupName:  "",
		wantKexName:    "ECDHE",
	},
	{
		// Unknown codepoint — must not panic and must not claim PQC presence.
		name:           "TLS13_UnknownCurveID_0x9999",
		tlsVersion:     tls.VersionTLS13,
		curveID:        0x9999,
		cipherSuite:    tls.TLS_AES_256_GCM_SHA384,
		leafKeyAlgo:    "ECDSA",
		leafKeySize:    256,
		wantPQCPresent: false,
		wantMaturity:   "",
		wantGroupName:  "",
		wantKexName:    "ECDHE",
	},
	{
		// TLS 1.2 ECDHE — CurveID is set; no TLS-1.3 synthetic kex emitted.
		name:           "TLS12_ECDHE_X25519",
		tlsVersion:     tls.VersionTLS12,
		curveID:        0x001d,
		cipherSuite:    tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
		leafKeyAlgo:    "RSA",
		leafKeySize:    2048,
		wantPQCPresent: false,
		wantMaturity:   "",
		wantGroupName:  "X25519",
		wantKexName:    "", // no TLS-1.3 synthetic kex for TLS 1.2
	},
	{
		// TLS 1.2 RSA KEM — no ECDHE, no named group, CurveID=0.
		name:           "TLS12_RSA_KEM_ZeroCurveID",
		tlsVersion:     tls.VersionTLS12,
		curveID:        0,
		cipherSuite:    tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
		leafKeyAlgo:    "RSA",
		leafKeySize:    2048,
		wantPQCPresent: false,
		wantMaturity:   "",
		wantGroupName:  "",
		wantKexName:    "", // no TLS-1.3 synthetic kex for TLS 1.2
	},
}

func TestCurveIDBehavior_AllCases(t *testing.T) {
	for _, tc := range curveIDBehaviorCases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			result := ProbeResult{
				Target:            "test.example.com:443",
				TLSVersion:        tc.tlsVersion,
				CipherSuiteID:     tc.cipherSuite,
				CipherSuiteName:   tls.CipherSuiteName(tc.cipherSuite),
				NegotiatedGroupID: tc.curveID,
				LeafCertKeyAlgo:   tc.leafKeyAlgo,
				LeafCertKeySize:   tc.leafKeySize,
			}

			// observationToFindings must never panic on any valid ProbeResult.
			func() {
				defer func() {
					if r := recover(); r != nil {
						t.Fatalf("observationToFindings panicked: %v", r)
					}
				}()
				findings := observationToFindings(result)
				if len(findings) == 0 {
					t.Fatal("expected at least one finding, got none")
				}

				// Every finding in the session must carry the same session-level metadata.
				for i, f := range findings {
					if f.PQCPresent != tc.wantPQCPresent {
						t.Errorf("finding[%d] %q: PQCPresent=%v, want %v",
							i, f.RawIdentifier, f.PQCPresent, tc.wantPQCPresent)
					}
					if f.PQCMaturity != tc.wantMaturity {
						t.Errorf("finding[%d] %q: PQCMaturity=%q, want %q",
							i, f.RawIdentifier, f.PQCMaturity, tc.wantMaturity)
					}
					if f.NegotiatedGroupName != tc.wantGroupName {
						t.Errorf("finding[%d] %q: NegotiatedGroupName=%q, want %q",
							i, f.RawIdentifier, f.NegotiatedGroupName, tc.wantGroupName)
					}
				}

				// Locate the TLS-1.3 synthetic kex finding (rawID prefix "kex:").
				var syntheticKexName string
				var foundSyntheticKex bool
				for _, f := range findings {
					if strings.HasPrefix(f.RawIdentifier, "kex:") {
						syntheticKexName = ""
						if f.Algorithm != nil {
							syntheticKexName = f.Algorithm.Name
						}
						foundSyntheticKex = true
					}
				}

				if tc.wantKexName != "" {
					if !foundSyntheticKex {
						t.Errorf("expected TLS-1.3 synthetic kex finding (rawID prefix 'kex:'), not found")
					} else if syntheticKexName != tc.wantKexName {
						t.Errorf("TLS-1.3 kex Algorithm.Name=%q, want %q",
							syntheticKexName, tc.wantKexName)
					}
				} else if foundSyntheticKex {
					t.Errorf("unexpected TLS-1.3 synthetic kex finding for TLS 1.2 session (rawID prefix 'kex:')")
				}
			}()
		})
	}
}

// TestCurveIDBehavior_PQCGroupNamePropagatesUniformly verifies that when a PQC
// hybrid group is negotiated, every finding in the session (symmetric, hash,
// cert, kex) carries the same NegotiatedGroupName. A missing field on any single
// finding would silently hide PQC negotiation from downstream consumers.
func TestCurveIDBehavior_PQCGroupNamePropagatesUniformly(t *testing.T) {
	const groupID = uint16(0x11EC) // X25519MLKEM768

	result := ProbeResult{
		Target:            "uniform.example.com:443",
		TLSVersion:        tls.VersionTLS13,
		CipherSuiteID:     tls.TLS_AES_256_GCM_SHA384,
		CipherSuiteName:   "TLS_AES_256_GCM_SHA384",
		NegotiatedGroupID: groupID,
		LeafCertKeyAlgo:   "ECDSA",
		LeafCertKeySize:   256,
	}

	ff := observationToFindings(result)
	if len(ff) == 0 {
		t.Fatal("expected findings, got none")
	}

	for _, f := range ff {
		if f.NegotiatedGroup != groupID {
			t.Errorf("finding %q: NegotiatedGroup=0x%04x, want 0x%04x",
				f.RawIdentifier, f.NegotiatedGroup, groupID)
		}
		if f.NegotiatedGroupName != "X25519MLKEM768" {
			t.Errorf("finding %q: NegotiatedGroupName=%q, want X25519MLKEM768",
				f.RawIdentifier, f.NegotiatedGroupName)
		}
		if !f.PQCPresent {
			t.Errorf("finding %q: PQCPresent=false, want true", f.RawIdentifier)
		}
	}
}

// TestCurveIDBehavior_DraftKyberBothCodepoints verifies both deprecated Kyber
// codepoints (0x6399 and 0x636D) produce PQCPresent=true, PQCMaturity="draft".
func TestCurveIDBehavior_DraftKyberBothCodepoints(t *testing.T) {
	for _, curveID := range []uint16{0x6399, 0x636D} {
		curveID := curveID
		t.Run("0x"+uint16HexStr(curveID), func(t *testing.T) {
			result := ProbeResult{
				Target:            "kyber.example.com:443",
				TLSVersion:        tls.VersionTLS13,
				CipherSuiteID:     tls.TLS_AES_256_GCM_SHA384,
				CipherSuiteName:   "TLS_AES_256_GCM_SHA384",
				NegotiatedGroupID: curveID,
				LeafCertKeyAlgo:   "ECDSA",
				LeafCertKeySize:   256,
			}
			ff := observationToFindings(result)
			for _, f := range ff {
				if !f.PQCPresent {
					t.Errorf("0x%04x finding %q: PQCPresent=false, want true",
						curveID, f.RawIdentifier)
				}
				if f.PQCMaturity != "draft" {
					t.Errorf("0x%04x finding %q: PQCMaturity=%q, want draft",
						curveID, f.RawIdentifier, f.PQCMaturity)
				}
				if f.NegotiatedGroupName == "" {
					t.Errorf("0x%04x finding %q: NegotiatedGroupName empty for known codepoint",
						curveID, f.RawIdentifier)
				}
			}
		})
	}
}

// uint16HexStr returns a 4-digit uppercase hex string for v.
func uint16HexStr(v uint16) string {
	const hex = "0123456789ABCDEF"
	return string([]byte{
		hex[(v>>12)&0xF], hex[(v>>8)&0xF],
		hex[(v>>4)&0xF], hex[v&0xF],
	})
}
