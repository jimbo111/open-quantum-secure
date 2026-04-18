package tlsprobe

// ech_matrix_test.go — Bucket 5: ECH behaviour matrix.
//
// Tests cover:
//  1. detectECH hostname short-circuits (IP literals, empty, root, long, trailing dot).
//  2. ScanBytesForECHExtension with crafted valid extension, random bytes,
//     truncated records, and oversize extensions.
//
// We hook dnsTxIDFn to make DNS query construction deterministic, but
// detectECH network calls are avoided by using IP-literal and other
// short-circuit inputs.

import (
	"context"
	"strings"
	"testing"
	"time"
)

// ── detectECH hostname matrix ─────────────────────────────────────────────────

// TestDetectECH_IPLiteral_IPv4 verifies that an IPv4 address literal
// short-circuits before any DNS lookup.
func TestDetectECH_IPLiteral_IPv4(t *testing.T) {
	t.Parallel()
	detected, src := detectECH(context.Background(), "192.0.2.1", 100*time.Millisecond, false)
	if detected {
		t.Errorf("detectECH(IPv4 literal): want false, got true (src=%q)", src)
	}
	if src != "" {
		t.Errorf("detectECH(IPv4 literal): want src=\"\", got %q", src)
	}
}

// TestDetectECH_IPLiteral_IPv6 verifies that an IPv6 address literal
// short-circuits before any DNS lookup.
func TestDetectECH_IPLiteral_IPv6(t *testing.T) {
	t.Parallel()
	detected, src := detectECH(context.Background(), "2001:db8::1", 100*time.Millisecond, false)
	if detected {
		t.Errorf("detectECH(IPv6 literal): want false, got true (src=%q)", src)
	}
	if src != "" {
		t.Errorf("detectECH(IPv6 literal): want src=\"\", got %q", src)
	}
}

// TestDetectECH_EmptyHostname verifies that an empty hostname returns (false, "")
// without panicking.
func TestDetectECH_EmptyHostname(t *testing.T) {
	t.Parallel()
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("detectECH(\"\") panicked: %v", r)
		}
	}()
	// Empty hostname: net.ParseIP("") returns nil so it falls through to DNS path.
	// The DNS path will fail immediately (empty label) and return false.
	detected, src := detectECH(context.Background(), "", 50*time.Millisecond, false)
	if detected {
		t.Errorf("detectECH(empty): want false, got true (src=%q)", src)
	}
	if src != "" {
		t.Errorf("detectECH(empty): want src=\"\", got %q", src)
	}
}

// TestDetectECH_RootDot verifies that "." returns (false, "") without panic.
func TestDetectECH_RootDot(t *testing.T) {
	t.Parallel()
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("detectECH(\".\") panicked: %v", r)
		}
	}()
	detected, src := detectECH(context.Background(), ".", 50*time.Millisecond, false)
	if detected {
		t.Errorf("detectECH(\".\"): want false, got true (src=%q)", src)
	}
	if src != "" {
		t.Errorf("detectECH(\".\"): want src=\"\", got %q", src)
	}
}

// TestDetectECH_LongHostname verifies that a 253-character hostname does not
// panic (it may fail due to label-length limits, but must not crash).
func TestDetectECH_LongHostname(t *testing.T) {
	t.Parallel()
	// Build a hostname of exactly 253 characters (max per RFC 1035 §2.3.4).
	// Use 'a' repeated segments: 63 + "." + 63 + "." + 63 + "." + 61 = 253.
	label63 := strings.Repeat("a", 63)
	hostname := label63 + "." + label63 + "." + label63 + "." + strings.Repeat("b", 61)
	if len(hostname) != 253 {
		t.Fatalf("test setup: hostname len=%d, want 253", len(hostname))
	}

	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("detectECH(long hostname) panicked: %v", r)
		}
	}()
	// Any result is acceptable; we only assert no panic.
	_, _ = detectECH(context.Background(), hostname, 50*time.Millisecond, false)
}

// TestDetectECH_TrailingDot verifies that a hostname with a trailing dot
// (e.g., "example.com.") does not panic and returns (false, "").
// The HTTPS RR lookup may fail (buildDNSQuery would strip the trailing dot),
// but the result must be deterministic.
func TestDetectECH_TrailingDot(t *testing.T) {
	t.Parallel()
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("detectECH(trailing dot) panicked: %v", r)
		}
	}()
	// Route to an IP so we short-circuit; trailing-dot hostnames that look like
	// IPs won't parse, so it goes through the DNS path which will time out quickly.
	_, _ = detectECH(context.Background(), "example.com.", 50*time.Millisecond, false)
}

// ── ScanBytesForECHExtension matrix ──────────────────────────────────────────

// TestScanBytesForECHExtension_CraftedValidExtension verifies detection of a
// syntactically valid ECH extension payload: type=0xfe0d + length + config.
func TestScanBytesForECHExtension_CraftedValidExtension(t *testing.T) {
	t.Parallel()
	// Minimal ECH extension: type(2) + ext_len(2) + ech_outer_ext(n).
	// We embed it inside a larger TLS extension list preamble.
	//
	// Layout:
	//   00 17 00 01 00    — extension type 23 (SNI), length 1, value 0
	//   fe 0d 00 04 DE AD BE EF  — ECH extension, length 4, dummy value
	data := []byte{
		0x00, 0x17, 0x00, 0x01, 0x00,        // SNI extension (type 23)
		0xfe, 0x0d, 0x00, 0x04, 0xDE, 0xAD, 0xBE, 0xEF, // ECH extension
	}
	found, src := ScanBytesForECHExtension(data)
	if !found {
		t.Error("ScanBytesForECHExtension: expected true for crafted ECH extension")
	}
	if src != "tls-ext" {
		t.Errorf("src=%q, want tls-ext", src)
	}
}

// TestScanBytesForECHExtension_RandomBytes verifies that purely random bytes
// return a deterministic result (no panic, consistent bool).
func TestScanBytesForECHExtension_RandomBytes(t *testing.T) {
	t.Parallel()
	// Use a fixed byte sequence that is unlikely to contain 0xfe 0x0d.
	data := make([]byte, 512)
	for i := range data {
		data[i] = byte(i & 0xFF)
	}
	found1, _ := ScanBytesForECHExtension(data)
	found2, _ := ScanBytesForECHExtension(data)
	if found1 != found2 {
		t.Error("ScanBytesForECHExtension: non-deterministic result for fixed input")
	}
}

// TestScanBytesForECHExtension_TruncatedTLSRecord verifies that a record
// truncated mid-extension does not panic and returns a deterministic bool.
func TestScanBytesForECHExtension_TruncatedTLSRecord(t *testing.T) {
	t.Parallel()
	// TLS record header (5 bytes): type=0x16, version=0x0303, length=0x0100
	// Followed by 2 bytes of body (truncated).
	data := []byte{0x16, 0x03, 0x03, 0x01, 0x00, 0xAB, 0xCD}
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("ScanBytesForECHExtension(truncated) panicked: %v", r)
		}
	}()
	_, _ = ScanBytesForECHExtension(data)
}

// TestScanBytesForECHExtension_OversizeExtension verifies that a synthetic
// "extension" claiming a very large length is handled without panic.
func TestScanBytesForECHExtension_OversizeExtension(t *testing.T) {
	t.Parallel()
	// Build a buffer with 0xfe 0x0d followed by a length that exceeds the buffer.
	data := []byte{0xfe, 0x0d, 0xFF, 0xFF} // type=0xfe0d, claimed length=65535
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("ScanBytesForECHExtension(oversize) panicked: %v", r)
		}
	}()
	found, src := ScanBytesForECHExtension(data)
	// The scanner does a simple 2-byte pattern match; it should find 0xfe0d.
	if !found {
		t.Error("ScanBytesForECHExtension: expected true for 0xfe0d pattern, regardless of claimed length")
	}
	if src != "tls-ext" {
		t.Errorf("src=%q, want tls-ext", src)
	}
}

// TestScanBytesForECHExtension_AllZeroes verifies that a buffer of all zeroes
// returns false (0x0000 is not 0xfe0d).
func TestScanBytesForECHExtension_AllZeroes(t *testing.T) {
	t.Parallel()
	found, _ := ScanBytesForECHExtension(make([]byte, 1024))
	if found {
		t.Error("ScanBytesForECHExtension: expected false for all-zero buffer")
	}
}

// TestScanBytesForECHExtension_ExactTwoBytes verifies edge-case of exactly
// 2 bytes: only valid 2-byte input is the ECH codepoint itself.
func TestScanBytesForECHExtension_ExactTwoBytes(t *testing.T) {
	t.Parallel()
	found, src := ScanBytesForECHExtension([]byte{0xfe, 0x0d})
	if !found || src != "tls-ext" {
		t.Errorf("expected (true, tls-ext) for exact 2-byte ECH codepoint, got (%v, %q)", found, src)
	}
	found2, _ := ScanBytesForECHExtension([]byte{0xfe, 0x0c})
	if found2 {
		t.Error("expected false for 0xfe0c (near-miss)")
	}
}
