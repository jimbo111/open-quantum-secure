// Codepoints in this file are TLS SignatureScheme values (RFC 8446 §4.2.3),
// NOT TLS SupportedGroup codepoints (see tls_groups.go). Both are uint16;
// the namespaces are entirely distinct — a codepoint value means different
// things in each registry. Do not mix TLSSignatureSchemeName with GroupName.

package tlsprobe

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/jimbo111/open-quantum-secure/pkg/engines/tlsprobe/rawhello"
)

// fullSigAlgList is the comprehensive list of TLS 1.3 SignatureScheme codepoints
// probed during --enumerate-sigalgs. Covers ML-DSA (FIPS 204 / draft-tls-mldsa),
// RSA-PSS, ECDSA, EdDSA, and legacy RSA-PKCS1 per IANA TLS SignatureScheme registry.
//
// ML-DSA codepoints (0x0904–0x0906) are from draft-ietf-tls-mldsa. Servers that
// support post-quantum signatures will accept these; classical servers will Alert.
//
// TODO(sprint-8-followup): after a successful full handshake, inspect
// cert.SignatureAlgorithm (via crypto/x509) for a definitive server sigalg signal.
// Our current raw probe can only infer acceptance from the presence or absence of
// an Alert — it cannot read CertificateVerify because TLS 1.3 encrypts it.
var fullSigAlgList = []uint16{
	// ML-DSA (FIPS 204, draft-ietf-tls-mldsa) — PQ signature algorithms.
	// Accept/reject signal is weaker than group enumeration: we cannot decrypt
	// CertificateVerify to confirm the server actually used the scheme.
	0x0904, // mldsa44 (ML-DSA security level 2)
	0x0905, // mldsa65 (ML-DSA security level 3)
	0x0906, // mldsa87 (ML-DSA security level 5)
	// RSA-PSS with rsaEncryption key (modern, recommended).
	0x0804, // rsa_pss_rsae_sha256
	0x0805, // rsa_pss_rsae_sha384
	0x0806, // rsa_pss_rsae_sha512
	// ECDSA.
	0x0403, // ecdsa_secp256r1_sha256
	0x0503, // ecdsa_secp384r1_sha384
	0x0603, // ecdsa_secp521r1_sha512
	// EdDSA.
	0x0807, // ed25519
	0x0808, // ed448
	// RSA-PKCS1v1.5 (legacy; TLS 1.3 implementations may accept for cert auth).
	0x0401, // rsa_pkcs1_sha256
	0x0501, // rsa_pkcs1_sha384
	0x0601, // rsa_pkcs1_sha512
	// RSA-PSS with rsassaPss key.
	0x0809, // rsa_pss_pss_sha256
	0x080a, // rsa_pss_pss_sha384
	0x080b, // rsa_pss_pss_sha512
}

// SigAlgEnumResult holds the outcome of a signature algorithm enumeration pass
// for one target.
type SigAlgEnumResult struct {
	// AcceptedSigAlgs lists TLS SignatureScheme codepoints for which the server
	// sent a ServerHello without an immediate post-SH Alert. "Provisional" — TLS
	// 1.3 encrypts CertificateVerify, so we cannot confirm cert signing compatibility.
	AcceptedSigAlgs []uint16
	// RejectedSigAlgs lists codepoints for which the server sent an Alert before
	// or immediately after the ServerHello.
	RejectedSigAlgs []uint16
}

// enumerateSigAlgs probes addr for each scheme in fullSigAlgList and classifies
// acceptance vs rejection. addr must be a pre-resolved "ip:port" string.
// Each probe uses X25519 (0x001d) as the key share so that group negotiation
// succeeds independently of the sig alg under test.
// ctx bounds total time; timeout bounds each individual probe.
func enumerateSigAlgs(ctx context.Context, addr, sni string, timeout time.Duration) (SigAlgEnumResult, error) {
	if timeout == 0 {
		timeout = 10 * time.Second
	}
	// Defence-in-depth SSRF check.
	if h, _, err := net.SplitHostPort(addr); err != nil || net.ParseIP(h) == nil {
		return SigAlgEnumResult{}, fmt.Errorf("enumerateSigAlgs: addr %q must be a pre-resolved IP:port, not a hostname", addr)
	}

	var result SigAlgEnumResult
	var lastErr error

	for _, sigAlg := range fullSigAlgList {
		if ctx.Err() != nil {
			return result, ctx.Err()
		}
		accepted, err := probeSigAlg(ctx, addr, sni, timeout, sigAlg)
		if err != nil {
			// Transport errors are not classified — skip the scheme, record the error
			// so the caller knows the probe was incomplete.
			lastErr = err
			continue
		}
		if accepted {
			result.AcceptedSigAlgs = append(result.AcceptedSigAlgs, sigAlg)
		} else {
			result.RejectedSigAlgs = append(result.RejectedSigAlgs, sigAlg)
		}
	}
	return result, lastErr
}

// probeSigAlg tests a single TLS SignatureScheme codepoint against addr.
// Returns true when the server sent a ServerHello without an immediate Alert.
//
// Probe strategy (TLS 1.3):
//  1. Send a ClientHello with sig_algs = [sigAlg] and a known-good X25519 key share.
//  2. Read the server's first handshake message via ParseServerResponse.
//  3. If Alert before ServerHello → rejected.
//  4. If ServerHello received → read the next TLS record to catch an immediate
//     post-SH Alert (emitted by some servers when sig alg is incompatible).
//  5. No Alert after ServerHello → provisionally accepted.
//
// Limitation: CertificateVerify is encrypted in TLS 1.3 so we cannot observe
// whether the server ultimately signed with the requested scheme. Servers that
// can satisfy the restriction at the signing level are counted as accepted.
func probeSigAlg(ctx context.Context, addr, sni string, timeout time.Duration, sigAlg uint16) (bool, error) {
	if timeout == 0 {
		timeout = 10 * time.Second
	}

	dialCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	conn, err := (&net.Dialer{}).DialContext(dialCtx, "tcp", addr)
	if err != nil {
		return false, fmt.Errorf("probeSigAlg 0x%04x: dial %s: %w", sigAlg, addr, err)
	}
	defer conn.Close()

	// Set a single deadline on the conn for all I/O in this probe.
	if dl, ok := dialCtx.Deadline(); ok {
		conn.SetDeadline(dl) //nolint:errcheck
	}

	ks, err := rawhello.ProbeKeyShare(0x001d) // X25519 — always succeeds
	if err != nil {
		return false, err
	}
	ch, err := rawhello.BuildClientHello(rawhello.ClientHelloOpts{
		SNI:             sni,
		SupportedGroups: []uint16{0x001d},
		KeyShares:       []rawhello.KeyShareEntry{ks},
		SigAlgs:         []uint16{sigAlg},
	})
	if err != nil {
		return false, fmt.Errorf("probeSigAlg 0x%04x: BuildClientHello: %w", sigAlg, err)
	}

	if _, err := conn.Write(ch); err != nil {
		return false, fmt.Errorf("probeSigAlg 0x%04x: write: %w", sigAlg, err)
	}

	parsed, err := rawhello.ParseServerResponse(dialCtx, conn)
	if err != nil {
		// Transport/protocol error — route as error so enumerateSigAlgs skips classification.
		return false, err
	}
	if parsed.IsAlert {
		// Explicit rejection before ServerHello.
		return false, nil
	}
	if parsed.IsHRR {
		// HRR requests a retry with a different key_share group — not a sig-alg
		// signal. We don't retry inside a single probe; treat as indeterminate/rejected.
		return false, nil
	}

	// ServerHello received. Read one more record to catch an immediate post-SH Alert.
	// ReadRecord honours dialCtx deadline internally.
	next, recErr := rawhello.ReadRecord(dialCtx, conn)
	if recErr == nil && next.Type == rawhello.RecordTypeAlert && len(next.Payload) >= 2 {
		// Alert immediately after ServerHello — sig alg rejected post-SH.
		return false, nil
	}
	// Timeout, EOF, or non-Alert record → provisionally accepted.
	return true, nil
}

// TLSSignatureSchemeName returns the IANA name for a TLS SignatureScheme codepoint.
// Returns a hex string for unknown codepoints.
func TLSSignatureSchemeName(scheme uint16) string {
	names := map[uint16]string{
		0x0904: "mldsa44",
		0x0905: "mldsa65",
		0x0906: "mldsa87",
		0x0804: "rsa_pss_rsae_sha256",
		0x0805: "rsa_pss_rsae_sha384",
		0x0806: "rsa_pss_rsae_sha512",
		0x0403: "ecdsa_secp256r1_sha256",
		0x0503: "ecdsa_secp384r1_sha384",
		0x0603: "ecdsa_secp521r1_sha512",
		0x0807: "ed25519",
		0x0808: "ed448",
		0x0401: "rsa_pkcs1_sha256",
		0x0501: "rsa_pkcs1_sha384",
		0x0601: "rsa_pkcs1_sha512",
		0x0809: "rsa_pss_pss_sha256",
		0x080a: "rsa_pss_pss_sha384",
		0x080b: "rsa_pss_pss_sha512",
		0x0201: "rsa_pkcs1_sha1",
		0x0203: "ecdsa_sha1",
	}
	if name, ok := names[scheme]; ok {
		return name
	}
	return fmt.Sprintf("0x%04x", scheme)
}
