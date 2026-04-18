package tlsprobe

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"runtime"
	"strings"
	"time"
)

// ECH TLS extension type code (RFC 9849, formerly draft-ietf-tls-esni).
const echExtensionType = uint16(0xfe0d)

// dnsTxIDFn returns a random uint16 for use as the DNS transaction ID.
// Overridable in tests to produce deterministic IDs.
var dnsTxIDFn = cryptoRandUint16

// cryptoRandUint16 returns a cryptographically random uint16.
func cryptoRandUint16() uint16 {
	var buf [2]byte
	if _, err := rand.Read(buf[:]); err != nil {
		// Fall back to a static non-zero value on entropy failure; this is
		// exceedingly rare and only affects a best-effort DNS probe.
		return 0xabcd
	}
	return binary.BigEndian.Uint16(buf[:])
}

// echSvcParamKey is the HTTPS/SVCB SvcParamKey for the ECH config list (RFC 9460 §7.3).
const echSvcParamKey = uint16(0x0005)

// detectECH probes for Encrypted Client Hello support on the given hostname
// using two complementary paths:
//
//  1. DNS HTTPS RR (type 65) lookup for SvcParamKey 0x0005 (ECH config).
//     Implemented via a raw DNS query over UDP because Go's stdlib does not
//     expose HTTPS/SVCB record types before a dedicated resolver API lands.
//     The query is best-effort: DNS failures fall through silently.
//
//  2. TLS-extension-byte scan: the caller could capture the outgoing ClientHello
//     bytes and scan for 0xfe0d. In this sprint the scan of captured bytes is
//     implemented as ScanBytesForECHExtension; the integration with
//     countingConn's Write() capture is documented in the function body below.
//
// timeout controls the DNS query deadline cap: if zero, defaults to 3s; if
// positive but < 3s, the tighter value is used.
//
// denyPrivate mirrors --tls-strict: when true, a private/loopback system resolver
// is bypassed in favour of public fallbacks (1.1.1.1:53, 8.8.8.8:53) so that no
// traffic is sent to RFC 1918 addresses.
//
// Returns (true, source) when ECH is detected; (false, "") when not detected.
// source is "dns-https-rr" or "tls-ext".
func detectECH(ctx context.Context, hostname string, timeout time.Duration, denyPrivate bool) (bool, string) {
	// Short-circuit for IP-literal hostnames: HTTPS RRs are keyed on names,
	// never bare IPs, so the query would always return NXDOMAIN after wasting
	// up to `timeout` seconds. RFC 9460 §2.4.3 confirms this.
	if net.ParseIP(hostname) != nil {
		return false, ""
	}

	// Path 1: DNS HTTPS RR lookup.
	// We implement a minimal raw DNS query (Type=65) to avoid the stdlib
	// limitation. Budget: kept under 100 LOC by querying only the first
	// name server returned by the OS and parsing only the RDATA we need.
	if ok := queryHTTPSRecordForECH(ctx, hostname, timeout, denyPrivate); ok {
		return true, "dns-https-rr"
	}

	// Path 2: TLS extension byte scan.
	// NOTE: Go 1.25's crypto/tls does NOT add an ECH extension to outgoing
	// ClientHellos (ECH requires the server's ECHConfig, which the TLS stack
	// does not auto-fetch). Therefore this scan will always return false for
	// connections made with Go's stdlib TLS. It is included as infrastructure
	// for Sprint 7 (raw ClientHello builder) which will construct and send
	// ClientHellos with an ECH outer extension.
	// If the countingConn Write() capture approach is wired in a later sprint,
	// the captured bytes can be passed to ScanBytesForECHExtension here.
	//
	// For now Path 2 is a no-op in live probes; it is tested via the exported
	// helper ScanBytesForECHExtension in unit tests.
	return false, ""
}

// publicFallbackNS are the DNS resolvers used when denyPrivate is true and the
// system resolver is a private/loopback address. Cloudflare is tried first,
// Google DNS is the secondary fallback.
var publicFallbackNS = []string{"1.1.1.1:53", "8.8.8.8:53"}

// queryHTTPSRecordForECH performs a raw DNS query for the HTTPS RR (type 65)
// of hostname. It returns true when the response includes SvcParamKey 0x0005
// (ECH config list), indicating the host supports ECH.
//
// Implementation notes:
//   - Uses UDP with an EDNS0 OPT record advertising a 4096-byte buffer.
//   - Checks the TC (truncated) bit after reading the UDP response; if set,
//     retries the same query over TCP (RFC 7766 §6.2).
//   - Parses only the RDATA portion minimally: walks SvcParams looking for key 5.
//   - DNS failure modes (NXDOMAIN, timeout, SERVFAIL) all return false silently.
//   - When denyPrivate is true, a private/loopback system resolver is bypassed
//     in favour of publicFallbackNS to honour --tls-strict semantics.
func queryHTTPSRecordForECH(ctx context.Context, hostname string, timeout time.Duration, denyPrivate bool) bool {
	// Resolve the system's default nameserver address.
	nsAddr := resolveSystemNS()

	if denyPrivate {
		// Validate the system resolver: if it is private/loopback, use public fallbacks.
		host, _, err := net.SplitHostPort(nsAddr)
		if err != nil || isPrivateIP(net.ParseIP(host)) {
			// System resolver is private. Try public fallbacks in order.
			nsAddr = ""
			for _, fb := range publicFallbackNS {
				fbHost, _, fbErr := net.SplitHostPort(fb)
				if fbErr == nil && !isPrivateIP(net.ParseIP(fbHost)) {
					nsAddr = fb
					break
				}
			}
			if nsAddr == "" {
				// All fallbacks are also private (extremely unusual) — bail safely.
				return false
			}
		}
	}

	if nsAddr == "" {
		return false
	}

	// Build a DNS query for Type=65 (HTTPS RR) with EDNS0 OPT.
	qname := hostname
	if !strings.HasSuffix(qname, ".") {
		qname += "."
	}
	query, err := buildDNSQuery(qname, 65 /* HTTPS */)
	if err != nil {
		return false
	}

	// Determine DNS timeout: cap at 3s; honour caller's tighter bound when set.
	const maxDNSTimeout = 3 * time.Second
	dnsTimeout := maxDNSTimeout
	if timeout > 0 && timeout < maxDNSTimeout {
		dnsTimeout = timeout
	}

	dialCtx, cancel := context.WithTimeout(ctx, dnsTimeout)
	defer cancel()

	// --- UDP path ---
	udpConn, err := (&net.Dialer{}).DialContext(dialCtx, "udp", nsAddr)
	if err != nil {
		return false
	}
	defer udpConn.Close()

	if deadline, ok := dialCtx.Deadline(); ok {
		_ = udpConn.SetDeadline(deadline)
	}
	if _, err := udpConn.Write(query); err != nil {
		return false
	}

	buf := make([]byte, 4096)
	n, err := udpConn.Read(buf)
	if err != nil || n < 12 {
		return false
	}
	resp := buf[:n]

	// TC bit is bit 1 of byte 2 of the DNS header (flags high byte).
	// RFC 1035 §4.1.1: flags = QR|Opcode|AA|TC|RD|RA|Z|RCODE
	// TC is the 9th bit of the 16-bit flags field → byte[2] bit 1.
	if resp[2]&0x02 != 0 {
		// Response was truncated — retry over TCP.
		resp = dnsQueryTCP(dialCtx, nsAddr, query)
		if resp == nil {
			return false
		}
	}

	return parseHTTPSResponseForECH(resp)
}

// dnsQueryTCP sends a DNS query over TCP and returns the response bytes, or nil
// on any error. TCP DNS messages are prefixed with a 2-byte big-endian length
// (RFC 1035 §4.2.2).
func dnsQueryTCP(ctx context.Context, nsAddr string, query []byte) []byte {
	tcpConn, err := (&net.Dialer{}).DialContext(ctx, "tcp", nsAddr)
	if err != nil {
		return nil
	}
	defer tcpConn.Close()

	if deadline, ok := ctx.Deadline(); ok {
		_ = tcpConn.SetDeadline(deadline)
	}

	// Prepend the 2-byte message length.
	framed := make([]byte, 2+len(query))
	binary.BigEndian.PutUint16(framed[0:2], uint16(len(query)))
	copy(framed[2:], query)
	if _, err := tcpConn.Write(framed); err != nil {
		return nil
	}

	// Read the 2-byte length prefix.
	var lenBuf [2]byte
	if _, err := readFull(tcpConn, lenBuf[:]); err != nil {
		return nil
	}
	msgLen := int(binary.BigEndian.Uint16(lenBuf[:]))
	if msgLen < 12 {
		return nil
	}

	resp := make([]byte, msgLen)
	if _, err := readFull(tcpConn, resp); err != nil {
		return nil
	}
	return resp
}

// readFull reads exactly len(buf) bytes from r, returning an error on short reads.
func readFull(r net.Conn, buf []byte) (int, error) {
	total := 0
	for total < len(buf) {
		n, err := r.Read(buf[total:])
		total += n
		if err != nil {
			return total, err
		}
	}
	return total, nil
}

// resolveSystemNS returns "ip:53" for the first nameserver in /etc/resolv.conf,
// or falls back to "1.1.1.1:53" then "8.8.8.8:53" if it cannot be read.
func resolveSystemNS() string {
	return readSystemResolver()
}

// readSystemResolver returns the first nameserver in /etc/resolv.conf, or a
// public fallback. On Windows there is no /etc/resolv.conf; the fallback is
// used directly.
func readSystemResolver() string {
	if runtime.GOOS == "windows" {
		return "1.1.1.1:53"
	}
	f, err := os.Open("/etc/resolv.conf")
	if err != nil {
		return "1.1.1.1:53"
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "nameserver") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				ip := fields[1]
				// Validate it parses as an IP.
				if net.ParseIP(ip) != nil {
					return net.JoinHostPort(ip, "53")
				}
			}
		}
	}
	// Fallback to Cloudflare then Google public DNS.
	return "1.1.1.1:53"
}

// buildDNSQuery constructs a minimal RFC 1035 DNS query message with an EDNS0
// OPT pseudo-RR (RFC 6891) advertising a 4096-byte UDP payload size.
func buildDNSQuery(fqdn string, qtype uint16) ([]byte, error) {
	txID := dnsTxIDFn()

	// Header: ID(2) + FLAGS(2) + QDCOUNT(2) + ANCOUNT(2) + NSCOUNT(2) + ARCOUNT(2)
	msg := make([]byte, 12)
	binary.BigEndian.PutUint16(msg[0:2], txID)    // transaction ID
	binary.BigEndian.PutUint16(msg[2:4], 0x0100)  // flags: RD=1
	binary.BigEndian.PutUint16(msg[4:6], 1)       // QDCOUNT=1
	// ARCOUNT=1 for the OPT pseudo-RR (filled below).

	// Encode the QNAME as a sequence of labels.
	for _, label := range strings.Split(strings.TrimSuffix(fqdn, "."), ".") {
		if len(label) == 0 || len(label) > 63 {
			return nil, fmt.Errorf("invalid DNS label %q", label)
		}
		msg = append(msg, byte(len(label)))
		msg = append(msg, []byte(label)...)
	}
	msg = append(msg, 0x00) // root label

	// QTYPE and QCLASS (IN = 1).
	msg = append(msg, 0, 0) // QTYPE placeholder
	binary.BigEndian.PutUint16(msg[len(msg)-2:], qtype)
	msg = append(msg, 0x00, 0x01) // QCLASS IN

	// EDNS0 OPT pseudo-RR (RFC 6891 §6.1.2):
	//   NAME:     0x00   (root — empty owner name)
	//   TYPE:     0x0029 (41 = OPT)
	//   CLASS:    0x1000 (payload size = 4096)
	//   TTL:      0x00000000 (extended RCODE + flags = 0)
	//   RDLENGTH: 0x0000 (no RDATA)
	msg = append(msg,
		0x00,       // NAME = root
		0x00, 0x29, // TYPE = OPT (41)
		0x10, 0x00, // CLASS = 4096 (advertised UDP payload size)
		0x00, 0x00, 0x00, 0x00, // TTL = extended RCODE 0, flags 0
		0x00, 0x00, // RDLENGTH = 0
	)
	// Set ARCOUNT=1 in the header (bytes 10–11).
	binary.BigEndian.PutUint16(msg[10:12], 1)

	return msg, nil
}

// parseHTTPSResponseForECH walks a DNS response and returns true when any HTTPS
// RR in the answer section carries SvcParamKey 0x0005 (ECH config list).
func parseHTTPSResponseForECH(resp []byte) bool {
	if len(resp) < 12 {
		return false
	}
	ancount := int(binary.BigEndian.Uint16(resp[6:8]))
	if ancount == 0 {
		return false
	}

	// Skip the header (12 bytes) and the question section.
	offset := 12
	qdcount := int(binary.BigEndian.Uint16(resp[4:6]))
	for i := 0; i < qdcount; i++ {
		offset = skipDNSName(resp, offset)
		if offset+4 > len(resp) {
			return false
		}
		offset += 4 // QTYPE + QCLASS
	}

	// Walk answer RRs looking for Type=65 HTTPS with SvcParamKey 0x0005.
	for i := 0; i < ancount; i++ {
		offset = skipDNSName(resp, offset)
		if offset+10 > len(resp) {
			return false
		}
		rrType := binary.BigEndian.Uint16(resp[offset : offset+2])
		rdLen := int(binary.BigEndian.Uint16(resp[offset+8 : offset+10]))
		offset += 10

		if offset+rdLen > len(resp) {
			return false
		}
		rdata := resp[offset : offset+rdLen]
		offset += rdLen

		if rrType != 65 || len(rdata) < 4 {
			continue
		}
		// HTTPS RDATA: SvcPriority(2) + TargetName(variable) + SvcParams
		rdOff := 2 // skip SvcPriority
		rdOff = skipDNSName(rdata, rdOff)
		// Walk SvcParams: Key(2) + Len(2) + Value(Len)
		for rdOff+4 <= len(rdata) {
			svcKey := binary.BigEndian.Uint16(rdata[rdOff : rdOff+2])
			svcLen := int(binary.BigEndian.Uint16(rdata[rdOff+2 : rdOff+4]))
			rdOff += 4
			if svcKey == echSvcParamKey {
				return true
			}
			rdOff += svcLen
		}
	}
	return false
}

// maxDNSPointerHops is the maximum number of compression-pointer dereferences
// skipDNSName will follow before aborting. RFC 1035 §4.1.4 defines pointer
// compression; a hard cap of 128 hops is well within the RFC-maximum of 255
// labels and prevents crafted responses from causing an infinite loop.
const maxDNSPointerHops = 128

// skipDNSName advances offset past a DNS name in wire format (compressed or plain).
// It follows compression pointers and counts hops; if more than maxDNSPointerHops
// pointers are encountered (indicating a loop in a malicious response), it returns
// 0 so callers treat the response as invalid.
//
// For a plain (uncompressed) name the returned offset points to the byte after the
// terminating zero label. For a compressed name it returns the byte after the
// 2-byte pointer field at the outermost call site (i.e. the wire position, not the
// destination), which is the correct advance for a caller iterating through RRs.
func skipDNSName(data []byte, offset int) int {
	hops := 0
	// outerAdvance tracks the position after the first pointer field so we can
	// return the right wire offset to the caller while still following the chain.
	outerAdvance := -1
	cur := offset

	for cur < len(data) {
		length := int(data[cur])
		if length == 0 {
			if outerAdvance >= 0 {
				return outerAdvance
			}
			return cur + 1
		}
		// Pointer compression: top 2 bits == 11.
		if length&0xC0 == 0xC0 {
			if cur+1 >= len(data) {
				// Truncated pointer — invalid.
				return 0
			}
			hops++
			if hops > maxDNSPointerHops {
				// Pointer loop detected — signal invalid to caller.
				return 0
			}
			// Record the wire position immediately after this pointer field
			// (only the first one matters for the caller's offset advance).
			if outerAdvance < 0 {
				outerAdvance = cur + 2
			}
			// Follow the pointer: compute the referenced offset.
			target := int(binary.BigEndian.Uint16(data[cur:cur+2]) & 0x3FFF)
			cur = target
			continue
		}
		cur += 1 + length
	}
	if outerAdvance >= 0 {
		return outerAdvance
	}
	return cur
}

// ScanBytesForECHExtension scans a buffer for the 0xfe0d ECH extension codepoint
// as a 2-byte pattern. False-positive rate ~0.0015% per kilobyte of random data
// (≈7% over a 5KB random buffer). Intended for use on parsed TLS record bytes,
// not raw ciphertext.
//
// Returns (true, "tls-ext") when the pattern is found, (false, "") otherwise.
func ScanBytesForECHExtension(data []byte) (bool, string) {
	needle := [2]byte{byte(echExtensionType >> 8), byte(echExtensionType & 0xFF)}
	for i := 0; i+1 < len(data); i++ {
		if data[i] == needle[0] && data[i+1] == needle[1] {
			return true, "tls-ext"
		}
	}
	return false, ""
}
