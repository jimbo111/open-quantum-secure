package tlsprobe

import (
	"encoding/binary"
	"strings"
	"testing"
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
