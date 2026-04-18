package tlsprobe

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"os"
	"strconv"
	"time"
)

// ProbeResult captures the TLS handshake data from a single endpoint.
type ProbeResult struct {
	Target            string // original host:port
	ResolvedIP        string // IP used for connection (DNS-pinned)
	TLSVersion        uint16
	CipherSuiteID     uint16
	CipherSuiteName   string
	NegotiatedGroupID uint16 // IANA SupportedGroup codepoint from ConnectionState().CurveID; 0 = none/unknown
	LeafCertKeyAlgo   string // "RSA", "ECDSA", "Ed25519"
	LeafCertKeySize   int    // bits
	LeafCertSigAlgo   string // e.g. "SHA256-RSA"
	Verified          bool   // true if manual cert verification passed
	VerifyError       string // non-empty if verification failed
	Error             error  // non-nil means handshake failed entirely
	Duration          time.Duration

	// Size-based passive detection fields (Sprint 2, S2.1–S2.3).
	// Diagnostic: surfaced in JSON output via /dashboard only; not consumed by classifier.
	IncomingSegments    int64  // approximate number of incoming TCP segments during handshake
	// Diagnostic: surfaced in JSON output via /dashboard only; not consumed by classifier.
	OutgoingSegments    int64  // approximate number of outgoing TCP segments during handshake
	BytesIn             int64  // total bytes received during handshake (authoritative volume signal)
	BytesOut            int64  // total bytes sent during handshake (authoritative volume signal)
	HandshakeVolumeClass string // "classical", "hybrid-kem", "full-pqc", or "unknown" (S2.3)

	// ECH detection fields (Sprint 2, S2.4).
	ECHDetected bool   // true when Encrypted Client Hello is detected
	// Diagnostic: surfaced in JSON output via /dashboard only; not consumed by classifier.
	ECHSource   string // "dns-https-rr", "tls-ext", or "" when not detected

	// Deep-probe fields (Sprint 7, S7.4).
	// DeepProbeAcceptedGroups lists IANA SupportedGroup codepoints for which the
	// server returned a ServerHello (not HRR, not Alert) during the raw probe pass.
	// Only populated when --deep-probe is enabled.
	DeepProbeAcceptedGroups []uint16
}

// ProbeOpts configures a single TLS probe.
type ProbeOpts struct {
	Insecure    bool
	DenyPrivate bool
	Timeout     time.Duration
	CACertPath  string
}

// probe connects to a TLS endpoint, captures handshake data, and optionally
// verifies the certificate chain. It always uses InsecureSkipVerify=true at
// the TLS layer to ensure VerifyPeerCertificate fires even for invalid certs
// (Go aborts the callback chain if normal verification fails first).
// Manual verification is performed in application code afterward.
func probe(ctx context.Context, target string, opts ProbeOpts) ProbeResult {
	start := time.Now()
	result := ProbeResult{Target: target}

	host, port, err := parseHostPort(target)
	if err != nil {
		result.Error = err
		result.Duration = time.Since(start)
		return result
	}

	// DNS resolution with pinning.
	resolvedIP, err := resolveAndValidate(ctx, host, opts.DenyPrivate)
	if err != nil {
		result.Error = err
		result.Duration = time.Since(start)
		return result
	}
	result.ResolvedIP = resolvedIP

	timeout := opts.Timeout
	if timeout == 0 {
		timeout = 10 * time.Second
	}

	// Dial TCP to the resolved IP (DNS pinning prevents rebinding).
	dialCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	dialer := &net.Dialer{}
	rawConn, err := dialer.DialContext(dialCtx, "tcp", net.JoinHostPort(resolvedIP, port))
	if err != nil {
		result.Error = fmt.Errorf("TCP dial to %s (%s): %w", target, resolvedIP, err)
		result.Duration = time.Since(start)
		return result
	}

	// Wrap the raw connection in a countingConn to observe handshake byte volumes
	// and segment counts. This is the S2.1 instrumentation layer.
	counting := newCountingConn(rawConn)

	// Capture certs via callback. Always use InsecureSkipVerify=true so the
	// callback fires even for expired/self-signed certs (Round 3 critical finding).
	var capturedCerts []*x509.Certificate
	tlsCfg := &tls.Config{
		ServerName:         host,
		InsecureSkipVerify: true, //nolint:gosec // intentional: capture certs before manual verify
		VerifyPeerCertificate: func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
			for _, raw := range rawCerts {
				cert, parseErr := x509.ParseCertificate(raw)
				if parseErr == nil {
					capturedCerts = append(capturedCerts, cert)
				}
			}
			return nil
		},
	}

	// Load custom CA if provided.
	if opts.CACertPath != "" {
		pool, poolErr := loadCACert(opts.CACertPath)
		if poolErr != nil {
			result.Error = fmt.Errorf("load CA cert: %w", poolErr)
			rawConn.Close()
			result.Duration = time.Since(start)
			return result
		}
		tlsCfg.RootCAs = pool
	}

	tlsConn := tls.Client(counting, tlsCfg)
	defer tlsConn.Close()

	if err := tlsConn.HandshakeContext(dialCtx); err != nil {
		result.Error = fmt.Errorf("TLS handshake with %s: %w", target, err)
		result.Duration = time.Since(start)
		return result
	}

	state := tlsConn.ConnectionState()
	result.TLSVersion = state.Version
	result.CipherSuiteID = state.CipherSuite
	result.CipherSuiteName = tls.CipherSuiteName(state.CipherSuite)
	// CurveID carries the IANA SupportedGroup codepoint negotiated during the
	// handshake (e.g., 0x11EC for X25519MLKEM768, 0x001d for X25519). It is 0
	// for TLS 1.2 sessions that used an RSA KEM (no ECDHE, no named group).
	// tls.CurveID is a uint16 alias, so the conversion is always safe.
	result.NegotiatedGroupID = uint16(state.CurveID)

	// Populate S2.1 size-based observability fields from countingConn.
	result.IncomingSegments = counting.ReadCalls()
	result.OutgoingSegments = counting.WriteCalls()
	result.BytesIn = counting.BytesIn()
	result.BytesOut = counting.BytesOut()
	result.HandshakeVolumeClass = ClassifyHandshakeVolume(result.BytesIn + result.BytesOut).String()

	// Detect ECH (S2.4) after handshake data is available.
	// Pass DenyPrivate so that --tls-strict prevents DNS queries to private resolvers.
	echDetected, echSource := detectECH(ctx, host, opts.Timeout, opts.DenyPrivate)
	result.ECHDetected = echDetected
	result.ECHSource = echSource

	// Extract leaf cert info.
	if len(capturedCerts) > 0 {
		leaf := capturedCerts[0]
		result.LeafCertKeyAlgo, result.LeafCertKeySize = extractKeyInfo(leaf)
		result.LeafCertSigAlgo = leaf.SignatureAlgorithm.String()
	}

	// Manual certificate verification (unless --tls-insecure).
	if !opts.Insecure && len(capturedCerts) > 0 {
		verifyOpts := x509.VerifyOptions{
			DNSName: host,
		}
		if tlsCfg.RootCAs != nil {
			verifyOpts.Roots = tlsCfg.RootCAs
		}
		// Build intermediates from captured chain.
		if len(capturedCerts) > 1 {
			intermediates := x509.NewCertPool()
			for _, c := range capturedCerts[1:] {
				intermediates.AddCert(c)
			}
			verifyOpts.Intermediates = intermediates
		}
		if _, verifyErr := capturedCerts[0].Verify(verifyOpts); verifyErr != nil {
			result.Verified = false
			result.VerifyError = verifyErr.Error()
		} else {
			result.Verified = true
		}
	} else if opts.Insecure {
		result.Verified = false
		result.VerifyError = "verification skipped (--tls-insecure)"
	}

	result.Duration = time.Since(start)
	return result
}

// extractKeyInfo returns the key algorithm name and size from a certificate.
func extractKeyInfo(cert *x509.Certificate) (string, int) {
	switch pub := cert.PublicKey.(type) {
	case *rsa.PublicKey:
		return "RSA", pub.N.BitLen()
	case *ecdsa.PublicKey:
		if params := pub.Params(); params != nil {
			return "ECDSA", params.BitSize
		}
		return "ECDSA", 0
	case ed25519.PublicKey:
		return "Ed25519", 256
	default:
		return cert.PublicKeyAlgorithm.String(), 0
	}
}

// parseHostPort splits a target into host and port, defaulting to 443.
func parseHostPort(target string) (string, string, error) {
	host, port, err := net.SplitHostPort(target)
	if err != nil {
		// Try adding default port.
		host, port, err = net.SplitHostPort(target + ":443")
		if err != nil {
			return "", "", fmt.Errorf("invalid target %q: %w", target, err)
		}
	}
	if host == "" {
		return "", "", fmt.Errorf("empty host in target %q", target)
	}
	// Validate port is in valid range.
	portNum, err := strconv.Atoi(port)
	if err != nil || portNum < 1 || portNum > 65535 {
		return "", "", fmt.Errorf("invalid port %q in target %q (must be 1-65535)", port, target)
	}
	return host, port, nil
}

// loadCACert reads a PEM file and returns a certificate pool.
func loadCACert(path string) (*x509.CertPool, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(data) {
		return nil, fmt.Errorf("no valid certificates found in %s", path)
	}
	return pool, nil
}
