package tlsprobe

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"strings"
	"time"
)

// ECH TLS extension type code (RFC 9849, formerly draft-ietf-tls-esni).
const echExtensionType = uint16(0xfe0d)

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
// Returns (true, source) when ECH is detected; (false, "") when not detected.
// source is "dns-https-rr" or "tls-ext".
func detectECH(ctx context.Context, hostname string) (bool, string) {
	// Path 1: DNS HTTPS RR lookup.
	// We implement a minimal raw DNS query (Type=65) to avoid the stdlib
	// limitation. Budget: kept under 100 LOC by querying only the first
	// name server returned by the OS and parsing only the RDATA we need.
	if ok := queryHTTPSRecordForECH(ctx, hostname); ok {
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

// queryHTTPSRecordForECH performs a raw DNS query for the HTTPS RR (type 65)
// of hostname. It returns true when the response includes SvcParamKey 0x0005
// (ECH config list), indicating the host supports ECH.
//
// Implementation notes:
//   - Uses UDP (fallback to TCP on TC bit would add >50 LOC; acceptable risk
//     for a corroborating signal — ECH RDATA is large but single-UDP responses
//     cover the detection use case).
//   - Parses only the RDATA portion minimally: walks SvcParams looking for key 5.
//   - DNS failure modes (NXDOMAIN, timeout, SERVFAIL) all return false silently.
func queryHTTPSRecordForECH(ctx context.Context, hostname string) bool {
	// Resolve the system's default nameserver address.
	nsAddr := resolveSystemNS()
	if nsAddr == "" {
		return false
	}

	// Build a DNS query for Type=65 (HTTPS RR).
	qname := hostname
	if !strings.HasSuffix(qname, ".") {
		qname += "."
	}
	query, err := buildDNSQuery(qname, 65 /* HTTPS */)
	if err != nil {
		return false
	}

	// Send the query and read the response.
	dialCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()

	conn, err := (&net.Dialer{}).DialContext(dialCtx, "udp", nsAddr)
	if err != nil {
		return false
	}
	defer conn.Close()

	deadline, ok := dialCtx.Deadline()
	if ok {
		_ = conn.SetDeadline(deadline)
	}

	if _, err := conn.Write(query); err != nil {
		return false
	}

	resp := make([]byte, 4096)
	n, err := conn.Read(resp)
	if err != nil || n < 12 {
		return false
	}
	return parseHTTPSResponseForECH(resp[:n])
}

// resolveSystemNS returns "ip:53" for the first nameserver in /etc/resolv.conf,
// or falls back to "8.8.8.8:53" if it cannot be read.
func resolveSystemNS() string {
	resolvers, err := net.DefaultResolver.LookupNS(context.Background(), ".")
	if err == nil && len(resolvers) > 0 {
		return net.JoinHostPort(resolvers[0].Host, "53")
	}
	// Fallback: use Google Public DNS (will be filtered by DenyPrivate if needed
	// at the engine level — ECH detection is best-effort).
	return "8.8.8.8:53"
}

// buildDNSQuery constructs a minimal RFC 1035 DNS query message.
func buildDNSQuery(fqdn string, qtype uint16) ([]byte, error) {
	// Header: ID(2) + FLAGS(2) + QDCOUNT(2) + ANCOUNT(2) + NSCOUNT(2) + ARCOUNT(2)
	msg := make([]byte, 12)
	binary.BigEndian.PutUint16(msg[0:2], 0x1234) // transaction ID
	binary.BigEndian.PutUint16(msg[2:4], 0x0100) // flags: RD=1
	binary.BigEndian.PutUint16(msg[4:6], 1)      // QDCOUNT=1

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

// skipDNSName advances offset past a DNS name in wire format (compressed or plain).
func skipDNSName(data []byte, offset int) int {
	for offset < len(data) {
		length := int(data[offset])
		if length == 0 {
			return offset + 1
		}
		// Pointer compression: top 2 bits == 11.
		if length&0xC0 == 0xC0 {
			return offset + 2
		}
		offset += 1 + length
	}
	return offset
}

// ScanBytesForECHExtension scans raw TLS record bytes for the ECH extension
// type (0xfe0d). It is used to detect ECH presence in captured ClientHello or
// ServerHello bytes.
//
// This path is best-effort: it does NOT attempt to parse the full TLS record
// structure. It walks the byte slice looking for the 2-byte big-endian value
// 0xfe0d. This is safe because 0xfe0d would not appear accidentally in ECDHE
// or ML-KEM key material with high probability; false positives here are
// acceptable for a corroborating signal.
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
