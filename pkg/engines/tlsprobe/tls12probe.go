package tlsprobe

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"time"
)

// tls12probeFn is the underlying TLS 1.2 probe function. Package-level variable
// so tests can inject a stub without making real network connections.
var tls12probeFn = probeTLS12

// TLS12ProbeResult holds the result of a TLS 1.2 fallback probe.
type TLS12ProbeResult struct {
	AcceptedTLS12   bool
	CipherSuiteID   uint16
	CipherSuiteName string
	Error           error
}

// probeTLS12 attempts a TLS 1.2-only handshake to the given already-resolved
// addr (IP:port). sni is the original hostname used for SNI. denyPrivate causes
// private/loopback IPs in addr to be rejected before dialing.
//
// InsecureSkipVerify is intentional: this probe only cares about whether the
// server accepts TLS 1.2, not about certificate validity.
func probeTLS12(ctx context.Context, addr, sni string, timeout time.Duration, denyPrivate bool) (TLS12ProbeResult, error) {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return TLS12ProbeResult{}, fmt.Errorf("probeTLS12: invalid addr %q: %w", addr, err)
	}

	// Honour DenyPrivate: reject addresses that resolve to private/loopback ranges.
	// addr is already a resolved IP:port (not a hostname), so we check it directly.
	if denyPrivate {
		ip := net.ParseIP(host)
		if ip != nil && isPrivateIP(ip) {
			return TLS12ProbeResult{}, fmt.Errorf("probeTLS12: private IP rejected: %s", host)
		}
	}

	if timeout == 0 {
		timeout = 10 * time.Second
	}

	dialCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	dialer := &net.Dialer{}
	rawConn, err := dialer.DialContext(dialCtx, "tcp", addr)
	if err != nil {
		return TLS12ProbeResult{Error: fmt.Errorf("probeTLS12 TCP dial %s: %w", addr, err)},
			fmt.Errorf("probeTLS12 TCP dial %s: %w", addr, err)
	}

	tlsCfg := &tls.Config{
		ServerName:         sni,
		InsecureSkipVerify: true, //nolint:gosec // intentional: downgrade detection only
		MinVersion:         tls.VersionTLS12,
		MaxVersion:         tls.VersionTLS12,
	}

	tlsConn := tls.Client(rawConn, tlsCfg)
	defer tlsConn.Close()

	if err := tlsConn.HandshakeContext(dialCtx); err != nil {
		return TLS12ProbeResult{Error: err}, err
	}

	state := tlsConn.ConnectionState()
	return TLS12ProbeResult{
		AcceptedTLS12:   true,
		CipherSuiteID:   state.CipherSuite,
		CipherSuiteName: tls.CipherSuiteName(state.CipherSuite),
	}, nil
}
