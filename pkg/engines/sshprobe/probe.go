package sshprobe

import (
	"context"
	"fmt"
	"io"
	"net"
	"strings"
	"time"

	"github.com/jimbo111/open-quantum-secure/pkg/engines/netutil"
)

const (
	// clientBanner is sent immediately after connection. We identify as the scanner
	// so server logs are unambiguous. RFC 4253 §4.2 allows any compliant string.
	clientBanner = "SSH-2.0-OQS-Scanner_1.0\r\n"

	// defaultTimeout caps the dial + banner + KEXINIT read per target.
	defaultTimeout = 10 * time.Second

	// kexinitCookieLen is the fixed 16-byte random cookie in SSH_MSG_KEXINIT.
	kexinitCookieLen = 16

	// kexinitNameListCount is the number of name-list fields before first_kex_packet_follows.
	// RFC 4253 §7.1: kex, host-key, enc-c2s, enc-s2c, mac-c2s, mac-s2c, comp-c2s, comp-s2c, lang-c2s, lang-s2c.
	kexinitNameListCount = 10

	// A1: preamble limits per RFC 4253 §4.2 (servers MAY send lines before the SSH- banner).
	maxBannerLines   = 10
	maxPreambleBytes = 8 * 1024
)

// ProbeResult captures the SSH KEXINIT data from a single endpoint.
type ProbeResult struct {
	Target     string // host:port as provided by caller
	ServerID   string // SSH identification string, e.g. "SSH-2.0-OpenSSH_9.0"
	KEXMethods []string
	Error      error
}

// probeFn is the underlying per-endpoint probe function. Package-level variable
// so tests can inject a stub without real network connections (mirrors tlsprobe pattern).
var probeFn = probeSSH

// probeSSH connects to host:port, exchanges banners, reads SSH_MSG_KEXINIT,
// and extracts the kex_algorithms name-list. It does NOT negotiate a session.
func probeSSH(ctx context.Context, target string, timeout time.Duration, denyPrivate bool) ProbeResult {
	// A2: Parse host and port for DNS validation and pinned dialing.
	host, port, err := sshParseTarget(target)
	if err != nil {
		return ProbeResult{Target: target, Error: err}
	}

	// A2: Resolve and validate — blocks RFC 1918 / loopback IPs when denyPrivate is set.
	resolvedIP, err := netutil.ResolveAndValidate(ctx, host, denyPrivate)
	if err != nil {
		return ProbeResult{Target: target, Error: err}
	}

	dialer := net.Dialer{Timeout: timeout}
	conn, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(resolvedIP, port))
	if err != nil {
		return ProbeResult{Target: target, Error: fmt.Errorf("dial: %w", err)}
	}
	defer conn.Close()

	// A3: Context watchdog — closes the connection when ctx is cancelled so that
	// blocked reads return promptly. conn.SetDeadline is decoupled from ctx; without
	// this goroutine, orchestrator cancellations have up to timeout×ceil(n/5) lag.
	ctxDone := make(chan struct{})
	defer close(ctxDone)
	go func() {
		select {
		case <-ctx.Done():
			conn.Close()
		case <-ctxDone:
		}
	}()

	deadline := time.Now().Add(timeout)
	if err := conn.SetDeadline(deadline); err != nil {
		return ProbeResult{Target: target, Error: fmt.Errorf("set deadline: %w", err)}
	}

	// Step 1: Read server identification banner (A1: tolerates RFC 4253 preamble lines).
	serverID, err := readBannerWithPreamble(conn)
	if err != nil {
		return ProbeResult{Target: target, Error: fmt.Errorf("read server banner: %w", err)}
	}

	// B4: Reject SSH-1.x; only SSH-2.0 and SSH-1.99 are RFC 4253-compliant.
	if !strings.HasPrefix(serverID, "SSH-2.0-") && !strings.HasPrefix(serverID, "SSH-1.99-") {
		return ProbeResult{Target: target, Error: fmt.Errorf("unsupported SSH version in banner %q (only SSH-2.0 and SSH-1.99 accepted)", serverID)}
	}

	// Step 2: Send client identification banner.
	if _, err := conn.Write([]byte(clientBanner)); err != nil {
		return ProbeResult{Target: target, Error: fmt.Errorf("send client banner: %w", err)}
	}

	// Step 3: Read server's SSH_MSG_KEXINIT packet.
	// RFC 4253 §7.1: servers MUST send KEXINIT immediately after the banner.
	// Some implementations (e.g. dropbear) send version-probe lines first;
	// we skip any non-KEXINIT payloads up to a small limit.
	kexMethods, err := readKEXInit(conn)
	if err != nil {
		return ProbeResult{Target: target, Error: err}
	}

	return ProbeResult{
		Target:     target,
		ServerID:   serverID,
		KEXMethods: kexMethods,
	}
}

// readBannerWithPreamble reads lines until an SSH-prefixed identification string
// is found, skipping up to maxBannerLines–1 RFC 4253 preamble lines first.
// Total preamble bytes are bounded by maxPreambleBytes to prevent amplification.
// The returned banner is validated for printable US-ASCII (B1: RFC 4253 §4.2).
func readBannerWithPreamble(r io.Reader) (string, error) {
	var totalBytes int
	for i := 0; i < maxBannerLines; i++ {
		line, err := readBanner(r)
		if err != nil {
			return "", err
		}
		totalBytes += len(line) + 2 // +2 for \r\n stripped by readBanner
		if totalBytes > maxPreambleBytes {
			return "", fmt.Errorf("banner preamble exceeded %d bytes", maxPreambleBytes)
		}
		if !strings.HasPrefix(line, "SSH-") {
			continue // preamble line — skip and read the next one
		}
		// B1: Validate banner contains only printable US-ASCII [0x20, 0x7E].
		for j := 0; j < len(line); j++ {
			b := line[j]
			if b < 0x20 || b > 0x7E {
				return "", fmt.Errorf("ssh banner contains non-printable byte 0x%02x at offset %d", b, j)
			}
		}
		return line, nil
	}
	return "", fmt.Errorf("no SSH banner found after %d preamble lines", maxBannerLines)
}

// readKEXInit reads SSH binary packets until it finds SSH_MSG_KEXINIT (type=20),
// then parses and returns the kex_algorithms name-list.
// B3: maxSkip reduced to 2 (real servers send KEXINIT first per RFC 4253 §7.1).
// B3: Cumulative skipped bytes capped at 64 KB to prevent attacker amplification.
func readKEXInit(conn net.Conn) ([]string, error) {
	const (
		maxSkip      = 2          // B3: real SSH servers send KEXINIT first
		maxSkipBytes = 64 * 1024  // B3: per-connection amplification cap
	)
	var totalSkipped int
	for skip := 0; skip < maxSkip; skip++ {
		payload, err := readPacket(conn)
		if err != nil {
			return nil, fmt.Errorf("read packet: %w", err)
		}
		if len(payload) == 0 {
			continue
		}
		if payload[0] != sshMsgKexInit {
			totalSkipped += len(payload) + 8 // +8 approximates packet framing overhead
			if totalSkipped > maxSkipBytes {
				return nil, fmt.Errorf("exceeded %d byte limit waiting for KEXINIT", maxSkipBytes)
			}
			continue // skip non-KEXINIT packet
		}
		return parseKEXInitPayload(payload)
	}
	return nil, fmt.Errorf("no SSH_MSG_KEXINIT received in first %d packets", maxSkip)
}

// parseKEXInitPayload extracts the kex_algorithms name-list from a KEXINIT payload.
// Payload layout (RFC 4253 §7.1):
//
//	[0]     byte SSH_MSG_KEXINIT (20)
//	[1..16] byte[16] cookie (random)
//	[17..]  name-list kex_algorithms (uint32 len + bytes)
//	        ... 9 more name-lists (host-key, enc×2, mac×2, comp×2, lang×2)
//	        boolean first_kex_packet_follows
//	        uint32 reserved (0)
func parseKEXInitPayload(payload []byte) ([]string, error) {
	// Skip: type byte (1) + cookie (16).
	offset := 1 + kexinitCookieLen
	if offset > len(payload) {
		return nil, fmt.Errorf("KEXINIT payload too short (%d bytes)", len(payload))
	}

	kexMethods, _, err := parseNameList(payload, offset)
	if err != nil {
		return nil, fmt.Errorf("parse kex_algorithms: %w", err)
	}
	return kexMethods, nil
}

// sshParseTarget splits a "host:port" target into its components.
// Defaults to port 22 when no port is specified.
func sshParseTarget(target string) (host, port string, err error) {
	h, p, e := net.SplitHostPort(target)
	if e != nil {
		// Try adding default SSH port.
		h, p, e = net.SplitHostPort(target + ":22")
		if e != nil {
			return "", "", fmt.Errorf("invalid SSH target %q: %w", target, e)
		}
	}
	if h == "" {
		return "", "", fmt.Errorf("empty host in SSH target %q", target)
	}
	return h, p, nil
}
