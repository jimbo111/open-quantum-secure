package sshprobe

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"
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
func probeSSH(ctx context.Context, target string, timeout time.Duration) ProbeResult {
	dialer := net.Dialer{Timeout: timeout}
	conn, err := dialer.DialContext(ctx, "tcp", target)
	if err != nil {
		return ProbeResult{Target: target, Error: fmt.Errorf("dial: %w", err)}
	}
	defer conn.Close()

	deadline := time.Now().Add(timeout)
	if err := conn.SetDeadline(deadline); err != nil {
		return ProbeResult{Target: target, Error: fmt.Errorf("set deadline: %w", err)}
	}

	// Step 1: Read server identification banner.
	serverID, err := readBanner(conn)
	if err != nil {
		return ProbeResult{Target: target, Error: fmt.Errorf("read server banner: %w", err)}
	}
	if !strings.HasPrefix(serverID, "SSH-") {
		return ProbeResult{Target: target, Error: fmt.Errorf("unexpected server banner (not SSH): %q", serverID)}
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

// readKEXInit reads SSH binary packets until it finds SSH_MSG_KEXINIT (type=20),
// then parses and returns the kex_algorithms name-list.
// Skips up to 5 non-KEXINIT packets to tolerate implementations that send
// informational packets before KEXINIT.
func readKEXInit(conn net.Conn) ([]string, error) {
	const maxSkip = 5
	for skip := 0; skip < maxSkip; skip++ {
		payload, err := readPacket(conn)
		if err != nil {
			return nil, fmt.Errorf("read packet: %w", err)
		}
		if len(payload) == 0 {
			continue
		}
		if payload[0] != sshMsgKexInit {
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
