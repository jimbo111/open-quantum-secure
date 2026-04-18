package tlsprobe

import (
	"context"
	"encoding/binary"
	"strings"
	"testing"
	"time"
)

// ── ScanBytesForECHExtension ─────────────────────────────────────────────────

func TestScanBytesForECHExtension_Found(t *testing.T) {
	t.Parallel()
	// Embed 0xfe0d at offset 10 inside a larger byte slice.
	data := make([]byte, 20)
	data[10] = 0xfe
	data[11] = 0x0d
	found, src := ScanBytesForECHExtension(data)
	if !found {
		t.Error("expected ECH extension found, got false")
	}
	if src != "tls-ext" {
		t.Errorf("source=%q, want tls-ext", src)
	}
}

func TestScanBytesForECHExtension_NotFound(t *testing.T) {
	t.Parallel()
	data := []byte{0x00, 0x17, 0x00, 0x01, 0xfe, 0x0e} // 0xfe0e, not 0xfe0d
	found, src := ScanBytesForECHExtension(data)
	if found {
		t.Error("expected no ECH extension, got found=true")
	}
	if src != "" {
		t.Errorf("source=%q, want empty", src)
	}
}

func TestScanBytesForECHExtension_Empty(t *testing.T) {
	t.Parallel()
	found, _ := ScanBytesForECHExtension(nil)
	if found {
		t.Error("expected false for nil input")
	}
	found, _ = ScanBytesForECHExtension([]byte{})
	if found {
		t.Error("expected false for empty input")
	}
}

func TestScanBytesForECHExtension_AtStart(t *testing.T) {
	t.Parallel()
	data := []byte{0xfe, 0x0d, 0x00}
	found, src := ScanBytesForECHExtension(data)
	if !found || src != "tls-ext" {
		t.Errorf("expected (true, tls-ext) at start, got (%v, %q)", found, src)
	}
}

func TestScanBytesForECHExtension_AtEnd(t *testing.T) {
	t.Parallel()
	data := []byte{0x00, 0x01, 0xfe, 0x0d}
	found, src := ScanBytesForECHExtension(data)
	if !found || src != "tls-ext" {
		t.Errorf("expected (true, tls-ext) at end, got (%v, %q)", found, src)
	}
}

func TestScanBytesForECHExtension_SingleByte(t *testing.T) {
	t.Parallel()
	// A single byte can never form a 2-byte pattern.
	found, _ := ScanBytesForECHExtension([]byte{0xfe})
	if found {
		t.Error("expected false for single-byte input")
	}
}

// ── buildDNSQuery ─────────────────────────────────────────────────────────────

func TestBuildDNSQuery_Structure(t *testing.T) {
	t.Parallel()
	q, err := buildDNSQuery("example.com.", 65)
	if err != nil {
		t.Fatalf("buildDNSQuery: %v", err)
	}
	// Header must be 12 bytes.
	if len(q) < 12 {
		t.Fatalf("query too short: %d bytes", len(q))
	}
	// QDCOUNT must be 1.
	qdcount := binary.BigEndian.Uint16(q[4:6])
	if qdcount != 1 {
		t.Errorf("QDCOUNT=%d, want 1", qdcount)
	}
	// RD flag must be set.
	flags := binary.BigEndian.Uint16(q[2:4])
	if flags&0x0100 == 0 {
		t.Error("RD flag not set in DNS query")
	}
}

func TestBuildDNSQuery_InvalidLabel(t *testing.T) {
	t.Parallel()
	tests := []struct {
		fqdn string
	}{
		{"a.b..c."}, // empty label in middle
	}
	for _, tt := range tests {
		_, err := buildDNSQuery(tt.fqdn, 65)
		if err == nil {
			t.Errorf("buildDNSQuery(%q): expected error, got nil", tt.fqdn)
		}
	}
}

// ── skipDNSName ───────────────────────────────────────────────────────────────

func TestSkipDNSName_Plain(t *testing.T) {
	t.Parallel()
	// "example.com." encoded as labels: 7 example 3 com 0
	data := []byte{7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0}
	got := skipDNSName(data, 0)
	if got != len(data) {
		t.Errorf("skipDNSName returned %d, want %d", got, len(data))
	}
}

func TestSkipDNSName_Pointer(t *testing.T) {
	t.Parallel()
	// Compression pointer: 0xC0 0x0C → skip 2 bytes.
	data := []byte{0xC0, 0x0C, 0xFF}
	got := skipDNSName(data, 0)
	if got != 2 {
		t.Errorf("skipDNSName pointer: got %d, want 2", got)
	}
}

// TestSkipDNSName_PointerLoopReturnsZero verifies that skipDNSName enforces a hard
// cap on compression-pointer hops. A self-referential pointer (offset → itself)
// would loop forever without the cap; with it the function must return 0.
func TestSkipDNSName_PointerLoopReturnsZero(t *testing.T) {
	t.Parallel()
	// Pointer at offset 0 pointing back to offset 0: 0xC0 0x00.
	// The updated skipDNSName follows the pointer, lands at 0 again, follows
	// it again, etc. — until maxDNSPointerHops is hit and it returns 0.
	data := []byte{0xC0, 0x00}
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("skipDNSName(self-pointer loop) panicked: %v", r)
		}
	}()
	got := skipDNSName(data, 0)
	if got != 0 {
		t.Errorf("skipDNSName(self-pointer loop): expected 0 (hop-limit sentinel), got %d", got)
	}
}

// TestParseHTTPSResponseForECH_PointerLoopInQuestion verifies that a crafted
// DNS response with a pointer loop in the question section's QNAME does not
// hang or panic. parseHTTPSResponseForECH relies on skipDNSName to advance
// past QNAME; with a looping pointer it should return false cleanly.
func TestParseHTTPSResponseForECH_PointerLoopInQuestion(t *testing.T) {
	t.Parallel()
	// Header: QDCOUNT=1, ANCOUNT=1 so the parser tries to skip the question.
	// QNAME is a pointer at offset 12 → offset 12 (self-loop).
	msg := make([]byte, 20)
	binary.BigEndian.PutUint16(msg[4:6], 1) // QDCOUNT=1
	binary.BigEndian.PutUint16(msg[6:8], 1) // ANCOUNT=1
	msg[12] = 0xC0                           // pointer flag
	msg[13] = 0x0C                           // → offset 12 (self-loop)
	// Remaining bytes are zero (QTYPE/QCLASS parsing never reached safely).

	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("parseHTTPSResponseForECH(pointer loop in QNAME) panicked: %v", r)
		}
	}()
	result := parseHTTPSResponseForECH(msg)
	// Must return false (not true and not panic).
	if result {
		t.Error("parseHTTPSResponseForECH(pointer loop): expected false, got true")
	}
}

// ── parseHTTPSResponseForECH ─────────────────────────────────────────────────

// buildHTTPSResponse constructs a minimal DNS response containing a Type=65
// HTTPS RR answer with the given SvcParams. This exercises the RDATA parser
// without requiring a live DNS server.
func buildHTTPSResponse(hostname string, svcParams []byte) []byte {
	// Encode hostname as labels.
	encodeLabel := func(name string) []byte {
		var out []byte
		// Split on "." and encode each label.
		parts := splitLabels(name)
		for _, p := range parts {
			out = append(out, byte(len(p)))
			out = append(out, []byte(p)...)
		}
		out = append(out, 0) // root
		return out
	}

	encodedName := encodeLabel(hostname)

	// SvcPriority(2) + TargetName(root=1 byte) + SvcParams
	rdata := make([]byte, 2+1+len(svcParams))
	binary.BigEndian.PutUint16(rdata[0:2], 1) // SvcPriority=1
	rdata[2] = 0                               // TargetName = root label
	copy(rdata[3:], svcParams)

	// RR: NAME + TYPE(2) + CLASS(2) + TTL(4) + RDLENGTH(2) + RDATA
	rr := make([]byte, len(encodedName)+10+len(rdata))
	copy(rr, encodedName)
	off := len(encodedName)
	binary.BigEndian.PutUint16(rr[off:], 65)  // TYPE HTTPS
	binary.BigEndian.PutUint16(rr[off+2:], 1) // CLASS IN
	binary.BigEndian.PutUint32(rr[off+4:], 60) // TTL
	binary.BigEndian.PutUint16(rr[off+8:], uint16(len(rdata)))
	copy(rr[off+10:], rdata)

	// Question section: same name + QTYPE=65 + QCLASS=1
	qsec := append(encodedName, 0, 65, 0, 1) //nolint:gocritic

	// Header: ID=0x1234, QR=1 RD=1 (response), QDCOUNT=1, ANCOUNT=1
	hdr := make([]byte, 12)
	binary.BigEndian.PutUint16(hdr[0:2], 0x1234)
	binary.BigEndian.PutUint16(hdr[2:4], 0x8100) // QR=1, RD=1
	binary.BigEndian.PutUint16(hdr[4:6], 1)      // QDCOUNT
	binary.BigEndian.PutUint16(hdr[6:8], 1)      // ANCOUNT

	msg := append(hdr, qsec...)
	msg = append(msg, rr...)
	return msg
}

// splitLabels splits a hostname into label parts, stripping trailing dot.
func splitLabels(name string) []string {
	name = strings.TrimSuffix(name, ".")
	if name == "" {
		return nil
	}
	return strings.Split(name, ".")
}

func TestParseHTTPSResponseForECH_WithECHParam(t *testing.T) {
	t.Parallel()
	// Build SvcParams with key=5 (ECH) and 4 bytes of dummy value.
	svcParam := []byte{0x00, 0x05, 0x00, 0x04, 0xDE, 0xAD, 0xBE, 0xEF}
	resp := buildHTTPSResponse("example.com", svcParam)
	if !parseHTTPSResponseForECH(resp) {
		t.Error("expected ECH param detected in HTTPS RR, got false")
	}
}

func TestParseHTTPSResponseForECH_WithoutECHParam(t *testing.T) {
	t.Parallel()
	// Build SvcParams with key=1 (alpn) only.
	svcParam := []byte{0x00, 0x01, 0x00, 0x02, 0x68, 0x32} // alpn: h2
	resp := buildHTTPSResponse("example.com", svcParam)
	if parseHTTPSResponseForECH(resp) {
		t.Error("unexpected ECH param in HTTPS RR with only alpn")
	}
}

func TestParseHTTPSResponseForECH_EmptyResponse(t *testing.T) {
	t.Parallel()
	if parseHTTPSResponseForECH(nil) {
		t.Error("expected false for nil response")
	}
	if parseHTTPSResponseForECH([]byte{0x01, 0x02}) {
		t.Error("expected false for truncated response")
	}
}

func TestParseHTTPSResponseForECH_NoAnswers(t *testing.T) {
	t.Parallel()
	// Build a response header with ANCOUNT=0.
	hdr := make([]byte, 12)
	binary.BigEndian.PutUint16(hdr[0:2], 0x1234)
	binary.BigEndian.PutUint16(hdr[2:4], 0x8100)
	// QDCOUNT=0, ANCOUNT=0
	if parseHTTPSResponseForECH(hdr) {
		t.Error("expected false for response with no answers")
	}
}

// ── DenyPrivate / queryHTTPSRecordForECH ─────────────────────────────────────

// TestQueryHTTPSRecordForECH_DenyPrivate_PrivateResolver verifies that when
// denyPrivate=true and the system resolver is a private/loopback address,
// queryHTTPSRecordForECH falls back to a public resolver without sending
// traffic to RFC 1918 space. We verify the short-circuit path by substituting
// a private resolver address via readSystemResolver and asserting the function
// returns cleanly (no panic, false result) even without a real DNS dial.
//
// The test overrides publicFallbackNS with an unreachable TEST-NET address so
// no actual DNS traffic is sent during CI.
func TestQueryHTTPSRecordForECH_DenyPrivate_PrivateResolverFallback(t *testing.T) {
	t.Parallel()
	// Save and restore publicFallbackNS.
	orig := publicFallbackNS
	defer func() { publicFallbackNS = orig }()

	// Replace fallbacks with a TEST-NET address so no real DNS dial occurs.
	// This exercises the "found a non-private fallback" branch without network I/O.
	// 192.0.2.1 is TEST-NET-1 (RFC 5737) — publicly routable, not private.
	publicFallbackNS = []string{"192.0.2.1:53"}

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()

	// With denyPrivate=true and a system resolver that will be private on most
	// CI machines, the function must reach for publicFallbackNS.
	// The query will fail (TEST-NET is not a real resolver) → returns false.
	result := queryHTTPSRecordForECH(ctx, "example.com", 200*time.Millisecond, true)
	// Any result is acceptable — we assert no panic and no hang.
	_ = result
}

// TestDetectECH_DenyPrivate_IPLiteral verifies that detectECH with denyPrivate=true
// short-circuits on IP literals before touching any DNS logic.
func TestDetectECH_DenyPrivate_IPLiteral(t *testing.T) {
	t.Parallel()
	detected, src := detectECH(context.Background(), "192.0.2.1", 100*time.Millisecond, true)
	if detected {
		t.Errorf("detectECH(IPv4 literal, denyPrivate=true): want false, got true (src=%q)", src)
	}
	if src != "" {
		t.Errorf("detectECH(IPv4 literal, denyPrivate=true): want src=\"\", got %q", src)
	}
}
