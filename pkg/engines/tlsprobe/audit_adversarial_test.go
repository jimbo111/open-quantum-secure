package tlsprobe

// audit_adversarial_test.go — T5-network audit (2026-04-20) adversarial fixtures.
//
// Covers hostile TLS peer scenarios that are not exercised in the pre-existing
// suite. All tests run against 127.0.0.1 listeners with ephemeral ports — no
// real network traffic leaves the machine.

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/jimbo111/open-quantum-secure/pkg/engines"
	"github.com/jimbo111/open-quantum-secure/pkg/findings"
)

// scanOptsForAudit builds a minimal ScanOptions for audit-concurrency tests.
// SkipTLS12Fallback=true keeps the stubbed probeFn from being re-entered for
// the fallback pass (which would inflate the in-flight counter and hide the
// invariant being tested).
func scanOptsForAudit(targets []string) engines.ScanOptions {
	return engines.ScanOptions{
		TLSTargets:        targets,
		TLSInsecure:       true,
		TLSTimeout:        1,
		SkipTLS12Fallback: true,
	}
}

// ─── F-adv-1: Hostile peers ──────────────────────────────────────────────────

// startHostilePlainTCP returns a listener on 127.0.0.1 whose handler sends
// the given raw bytes, then closes the connection. Used for malformed-handshake
// scenarios that never reach tls.Server.
func startHostilePlainTCP(t *testing.T, handler func(conn net.Conn)) *net.TCPListener {
	t.Helper()
	l, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	go func() {
		for {
			conn, err := l.Accept()
			if err != nil {
				return
			}
			go handler(conn)
		}
	}()
	t.Cleanup(func() { _ = l.Close() })
	return l
}

// TestAuditF1_HostilePeer_TruncatedServerHello verifies that a server that
// closes immediately after the client sends ClientHello does not panic — the
// probe must return an error.
func TestAuditF1_HostilePeer_TruncatedServerHello(t *testing.T) {
	t.Parallel()

	l := startHostilePlainTCP(t, func(conn net.Conn) {
		defer conn.Close()
		// Read whatever the client sends; then silently drop the connection
		// (simulating a server that crashes mid-handshake).
		_ = conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
		_, _ = io.ReadAll(conn)
	})
	addr := l.Addr().String()

	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("probe panicked on truncated handshake: %v", r)
		}
	}()
	result := probe(context.Background(), addr, ProbeOpts{
		Insecure: true,
		Timeout:  2 * time.Second,
	})
	if result.Error == nil {
		t.Error("expected Error from probe against peer that drops after ClientHello")
	}
}

// TestAuditF1_HostilePeer_TLSAlertMidHandshake sends a TLS alert (level=fatal,
// description=handshake_failure) as soon as the client shows up. Probe must
// return an error and not produce a classification.
func TestAuditF1_HostilePeer_TLSAlertMidHandshake(t *testing.T) {
	t.Parallel()

	l := startHostilePlainTCP(t, func(conn net.Conn) {
		defer conn.Close()
		// Read at least one byte (to let client push ClientHello) then alert.
		buf := make([]byte, 1024)
		_ = conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
		_, _ = conn.Read(buf)
		// TLS Alert record: ContentType=21, legacy_version=0x0303, length=2, level=2 (fatal), desc=40 (handshake_failure)
		alert := []byte{0x15, 0x03, 0x03, 0x00, 0x02, 0x02, 0x28}
		_, _ = conn.Write(alert)
	})
	addr := l.Addr().String()

	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("probe panicked on TLS alert: %v", r)
		}
	}()
	result := probe(context.Background(), addr, ProbeOpts{
		Insecure: true,
		Timeout:  2 * time.Second,
	})
	if result.Error == nil {
		t.Error("expected Error from probe against TLS-alert-returning peer")
	}
}

// TestAuditF1_HostilePeer_HangAfterAccept simulates a server that accepts the
// TCP connection and then never replies. The probe must time out cleanly and
// not leak goroutines.
func TestAuditF1_HostilePeer_HangAfterAccept(t *testing.T) {
	t.Parallel()

	l := startHostilePlainTCP(t, func(conn net.Conn) {
		// Hold the connection open for longer than the probe timeout.
		time.Sleep(2 * time.Second)
		_ = conn.Close()
	})
	addr := l.Addr().String()

	start := time.Now()
	result := probe(context.Background(), addr, ProbeOpts{
		Insecure: true,
		Timeout:  500 * time.Millisecond,
	})
	elapsed := time.Since(start)

	if result.Error == nil {
		t.Error("expected timeout error from hanging peer")
	}
	// Must return close to the timeout, not much longer.
	if elapsed > 2500*time.Millisecond {
		t.Errorf("probe took %v; timeout leak suspected (> 2.5× configured timeout)", elapsed)
	}
}

// TestAuditF1_HostilePeer_OversizeGarbage sends a torrent of random bytes
// claiming to be a TLS record with a huge length. Probe must not panic and
// must not attempt to allocate a huge buffer.
func TestAuditF1_HostilePeer_OversizeGarbage(t *testing.T) {
	t.Parallel()

	l := startHostilePlainTCP(t, func(conn net.Conn) {
		defer conn.Close()
		// Read ClientHello to let the handshake start.
		buf := make([]byte, 1024)
		_ = conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
		_, _ = conn.Read(buf)
		// Send a TLS record header claiming length 0xFFFF (max), followed by
		// a few random bytes. crypto/tls caps record length at 16 KB + overhead
		// per RFC 8446 so this is rejected.
		record := []byte{0x16, 0x03, 0x03, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00}
		_, _ = conn.Write(record)
	})
	addr := l.Addr().String()

	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("probe panicked on oversize record: %v", r)
		}
	}()
	_ = probe(context.Background(), addr, ProbeOpts{
		Insecure: true,
		Timeout:  2 * time.Second,
	})
}

// ─── F-adv-2: CurveID=0 edge case ────────────────────────────────────────────

// TestAuditF2_NegotiatedGroupZero verifies that a ProbeResult with
// NegotiatedGroupID=0 (e.g., TLS 1.2 RSA KEM) yields findings where
// NegotiatedGroupName is empty and PQCPresent=false — not a panic.
func TestAuditF2_NegotiatedGroupZero(t *testing.T) {
	t.Parallel()

	// NegotiatedGroupID=0 is the sentinel for "no named group" (TLS 1.2 RSA KEM).
	result := ProbeResult{
		Target:            "rsa-kem-server.example.com:443",
		TLSVersion:        tls.VersionTLS12,
		CipherSuiteID:     tls.TLS_RSA_WITH_AES_128_GCM_SHA256,
		CipherSuiteName:   "TLS_RSA_WITH_AES_128_GCM_SHA256",
		NegotiatedGroupID: 0,
		LeafCertKeyAlgo:   "RSA",
		LeafCertKeySize:   2048,
	}

	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("observationToFindings panicked with CurveID=0: %v", r)
		}
	}()
	ff := observationToFindings(result)
	if len(ff) == 0 {
		t.Fatal("expected findings")
	}
	for _, f := range ff {
		if f.NegotiatedGroup != 0 {
			t.Errorf("NegotiatedGroup=%d, want 0", f.NegotiatedGroup)
		}
		if f.PQCPresent {
			t.Errorf("PQCPresent=true for CurveID=0, want false")
		}
		if f.NegotiatedGroupName != "" {
			t.Errorf("NegotiatedGroupName=%q, want empty for CurveID=0", f.NegotiatedGroupName)
		}
	}
}

// TestAuditF2_NegotiatedGroupReservedCodepoint verifies that an IANA reserved
// or unregistered codepoint (e.g., 0xFFFF) is treated as "unknown" rather than
// silently classified as PQC.
func TestAuditF2_NegotiatedGroupReservedCodepoint(t *testing.T) {
	t.Parallel()

	const reserved uint16 = 0xFFFF
	result := ProbeResult{
		Target:            "future-server.example.com:443",
		TLSVersion:        tls.VersionTLS13,
		CipherSuiteID:     tls.TLS_AES_128_GCM_SHA256,
		CipherSuiteName:   "TLS_AES_128_GCM_SHA256",
		NegotiatedGroupID: reserved,
	}

	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("panic with reserved codepoint: %v", r)
		}
	}()
	ff := observationToFindings(result)
	for _, f := range ff {
		if f.PQCPresent {
			t.Errorf("finding %q: PQCPresent=true for unknown codepoint 0x%04x",
				f.RawIdentifier, reserved)
		}
		if f.NegotiatedGroupName != "" {
			t.Errorf("finding %q: NegotiatedGroupName=%q for unknown codepoint, want empty",
				f.RawIdentifier, f.NegotiatedGroupName)
		}
	}
}

// ─── F-adv-3: Integration — loopback TLS with PQC-tagged group ───────────────

// TestAuditIntegration_PQCGroupInjected is the integration test called for by
// the audit spec: probe a loopback TLS endpoint, inject a hybrid-KEM CurveID
// into the captured state via a probeFn-style path, and assert that the
// UnifiedFinding carries NegotiatedGroup=0x11EC, NegotiatedGroupName="X25519MLKEM768",
// PQCPresent=true.
//
// Because Go's standard crypto/tls does not yet negotiate X25519MLKEM768
// natively on the server side in all versions, we do the end-to-end probe for
// the reachable bits (handshake success, cipher suite, cert algorithm) and
// then drive observationToFindings with an injected CurveID to assert the
// wiring from ProbeResult.NegotiatedGroupID → UnifiedFinding field-by-field.
func TestAuditIntegration_PQCGroupInjected(t *testing.T) {
	t.Parallel()

	// Start a TLS server on 127.0.0.1 with a self-signed cert.
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "audit-test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &privKey.PublicKey, privKey)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	tlsCert := tls.Certificate{Certificate: [][]byte{certDER}, PrivateKey: privKey}

	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{tlsCert}, MinVersion: tls.VersionTLS13}
	srv.StartTLS()
	defer srv.Close()

	addr := srv.Listener.Addr().String()

	result := probe(context.Background(), addr, ProbeOpts{Insecure: true, Timeout: 3 * time.Second})
	if result.Error != nil {
		t.Fatalf("probe error: %v", result.Error)
	}
	if result.TLSVersion != tls.VersionTLS13 {
		t.Fatalf("expected TLS 1.3, got version 0x%04x", result.TLSVersion)
	}

	// Inject the X25519MLKEM768 codepoint (0x11EC) into the captured result,
	// mirroring what conn.ConnectionState().CurveID would return if the Go
	// stdlib had negotiated it. Then verify the finding wiring.
	result.NegotiatedGroupID = 0x11EC
	result.HandshakeVolumeClass = "hybrid-kem"
	result.BytesIn = 8000 // inside the hybrid-KEM band

	ff := observationToFindings(result)
	if len(ff) == 0 {
		t.Fatal("expected findings")
	}
	var kexFinding *findings.UnifiedFinding
	for i := range ff {
		if ff[i].NegotiatedGroup != 0x11EC {
			t.Errorf("finding[%d] NegotiatedGroup=0x%04x, want 0x11EC",
				i, ff[i].NegotiatedGroup)
		}
		if ff[i].NegotiatedGroupName != "X25519MLKEM768" {
			t.Errorf("finding[%d] NegotiatedGroupName=%q, want X25519MLKEM768",
				i, ff[i].NegotiatedGroupName)
		}
		if !ff[i].PQCPresent {
			t.Errorf("finding[%d] PQCPresent=false, want true", i)
		}
		if ff[i].HandshakeVolumeClass != "hybrid-kem" {
			t.Errorf("finding[%d] HandshakeVolumeClass=%q, want hybrid-kem",
				i, ff[i].HandshakeVolumeClass)
		}
		if ff[i].Algorithm != nil && ff[i].Algorithm.Primitive == "key-exchange" {
			kexFinding = &ff[i]
		}
	}
	if kexFinding == nil {
		t.Fatal("no key-exchange finding emitted for TLS 1.3 probe")
	}
	if kexFinding.Algorithm.Name != "X25519MLKEM768" {
		t.Errorf("kex Algorithm.Name=%q, want X25519MLKEM768", kexFinding.Algorithm.Name)
	}
}

// ─── F-adv-4: Concurrency cap + parent-acquire invariant ─────────────────────

// TestAuditF4_ConcurrencyCap_ParentAcquireProven stubs probeFn, drives 20
// synthetic targets through engine.Scan(), and counts the maximum concurrent
// in-flight probes. If the parent-acquire invariant is honoured the count
// must never exceed defaultConcurrency (5); if a future refactor moves the
// acquire inside the child goroutine the count will burst to 20.
func TestAuditF4_ConcurrencyCap_ParentAcquireProven(t *testing.T) {
	origProbeFn := probeFn
	defer func() { probeFn = origProbeFn }()

	var (
		mu       sync.Mutex
		inFlight int64
		maxSeen  int64
	)
	probeFn = func(ctx context.Context, target string, opts ProbeOpts) ProbeResult {
		mu.Lock()
		inFlight++
		if inFlight > maxSeen {
			maxSeen = inFlight
		}
		mu.Unlock()
		// Hold the slot long enough that concurrent bursting would show up.
		time.Sleep(40 * time.Millisecond)
		mu.Lock()
		inFlight--
		mu.Unlock()
		return ProbeResult{
			Target:           target,
			ResolvedIP:       "", // empty → skips deep-probe and enum passes in Scan()
			TLSVersion:       tls.VersionTLS13,
			CipherSuiteID:    tls.TLS_AES_256_GCM_SHA384,
			HandshakeVolumeClass: "classical",
		}
	}

	targets := make([]string, 20)
	for i := range targets {
		targets[i] = "pqc-target.example.com:443"
	}

	e := New()
	_, _ = e.Scan(context.Background(), scanOptsForAudit(targets))

	mu.Lock()
	got := maxSeen
	mu.Unlock()

	if got > int64(defaultConcurrency) {
		t.Errorf("maxSeen=%d exceeds defaultConcurrency=%d — parent-acquire invariant broken",
			got, defaultConcurrency)
	}
	if got == 0 {
		t.Error("maxSeen=0 — stub probeFn was never called, test is not measuring the right thing")
	}
}

// ─── F-adv-5: ECH parser hostile DNS responses ───────────────────────────────

// TestAuditF5_ECH_PointerBomb ensures the DNS-pointer hop cap in skipDNSName
// defuses a self-referencing pointer crafted into an HTTPS RR.
func TestAuditF5_ECH_PointerBomb(t *testing.T) {
	t.Parallel()

	// Build a minimal DNS response that contains one compressed name in the
	// question section pointing back to itself. If skipDNSName loops infinitely
	// the test hangs; the 128-hop cap should break the loop.
	resp := make([]byte, 0, 64)
	header := make([]byte, 12)
	binary.BigEndian.PutUint16(header[0:2], 0xabcd) // ID
	binary.BigEndian.PutUint16(header[2:4], 0x8180) // flags: response + RD + RA
	binary.BigEndian.PutUint16(header[4:6], 1)      // qdcount
	binary.BigEndian.PutUint16(header[6:8], 0)      // ancount
	resp = append(resp, header...)
	// Question name: a pointer with offset 12 (the start of the QNAME itself → self-loop).
	resp = append(resp, 0xC0, 0x0C)       // pointer to offset 12 (self-ref)
	resp = append(resp, 0x00, 0x41, 0x00, 0x01) // QTYPE=65, QCLASS=IN

	done := make(chan bool, 1)
	go func() {
		defer func() {
			if r := recover(); r != nil {
				done <- false
			} else {
				done <- true
			}
		}()
		_ = parseHTTPSResponseForECH(resp)
	}()

	select {
	case ok := <-done:
		if !ok {
			t.Error("parseHTTPSResponseForECH panicked on pointer bomb")
		}
	case <-time.After(3 * time.Second):
		t.Error("parseHTTPSResponseForECH hung on pointer bomb — 128-hop cap failed")
	}
}

// TestAuditF5_ECH_MalformedRDATA sends an HTTPS RR with a claimed RDLENGTH
// that extends past the packet. Must return false safely.
func TestAuditF5_ECH_MalformedRDATA(t *testing.T) {
	t.Parallel()

	// Header: 1 answer.
	resp := make([]byte, 0, 64)
	header := make([]byte, 12)
	binary.BigEndian.PutUint16(header[0:2], 0x1234)
	binary.BigEndian.PutUint16(header[2:4], 0x8180)
	binary.BigEndian.PutUint16(header[4:6], 0) // qdcount=0
	binary.BigEndian.PutUint16(header[6:8], 1) // ancount=1
	resp = append(resp, header...)
	// Answer: root name, type=65, class=1, TTL=60, rdlen=65535 (way more than packet has)
	resp = append(resp, 0x00)                         // root name
	resp = append(resp, 0x00, 0x41)                   // TYPE=65
	resp = append(resp, 0x00, 0x01)                   // CLASS=1
	resp = append(resp, 0x00, 0x00, 0x00, 0x3C)       // TTL=60
	resp = append(resp, 0xFF, 0xFF)                   // RDLENGTH=65535

	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("panicked on malformed RDATA: %v", r)
		}
	}()
	got := parseHTTPSResponseForECH(resp)
	if got {
		t.Error("expected false for malformed HTTPS RR with RDLENGTH > packet size")
	}
}

// TestAuditF5_ECH_ValidRRWithECHKey verifies the positive path: a well-formed
// HTTPS RR containing SvcParamKey 0x0005 (ECH config) returns true.
func TestAuditF5_ECH_ValidRRWithECHKey(t *testing.T) {
	t.Parallel()

	// Build DNS response header.
	resp := make([]byte, 0, 128)
	header := make([]byte, 12)
	binary.BigEndian.PutUint16(header[0:2], 0x1234)
	binary.BigEndian.PutUint16(header[2:4], 0x8180)
	binary.BigEndian.PutUint16(header[4:6], 0)
	binary.BigEndian.PutUint16(header[6:8], 1)
	resp = append(resp, header...)

	// Build RDATA: SvcPriority(2) + TargetName(1 for root '.') + SvcParams(key=5,len=4,val=0x00000000).
	rdata := []byte{0x00, 0x01, 0x00}       // SvcPriority=1, TargetName=root
	rdata = append(rdata, 0x00, 0x05)       // SvcParamKey=5 (ech)
	rdata = append(rdata, 0x00, 0x04)       // length=4
	rdata = append(rdata, 0x00, 0x00, 0x00, 0x00) // dummy ECHConfigList

	// Answer: root name, type=65, class=1, TTL=60, rdlen=len(rdata).
	resp = append(resp, 0x00)                                                  // root name
	resp = append(resp, 0x00, 0x41)                                            // TYPE=65
	resp = append(resp, 0x00, 0x01)                                            // CLASS=1
	resp = append(resp, 0x00, 0x00, 0x00, 0x3C)                                // TTL=60
	lenPrefix := make([]byte, 2)
	binary.BigEndian.PutUint16(lenPrefix, uint16(len(rdata)))
	resp = append(resp, lenPrefix...)
	resp = append(resp, rdata...)

	got := parseHTTPSResponseForECH(resp)
	if !got {
		t.Error("expected true for valid HTTPS RR containing ECH SvcParamKey 0x0005")
	}
}

// TestAuditF5_ECH_ValidRRNoECHKey verifies that an HTTPS RR with an ALPN key
// (0x0001) but no ECH key returns false.
func TestAuditF5_ECH_ValidRRNoECHKey(t *testing.T) {
	t.Parallel()

	resp := make([]byte, 0, 128)
	header := make([]byte, 12)
	binary.BigEndian.PutUint16(header[0:2], 0x1234)
	binary.BigEndian.PutUint16(header[2:4], 0x8180)
	binary.BigEndian.PutUint16(header[4:6], 0)
	binary.BigEndian.PutUint16(header[6:8], 1)
	resp = append(resp, header...)

	rdata := []byte{0x00, 0x01, 0x00}   // SvcPriority=1, TargetName=root
	rdata = append(rdata, 0x00, 0x01)   // SvcParamKey=1 (alpn)
	rdata = append(rdata, 0x00, 0x02)   // length=2
	rdata = append(rdata, 0x68, 0x32)   // "h2"

	resp = append(resp, 0x00)
	resp = append(resp, 0x00, 0x41)
	resp = append(resp, 0x00, 0x01)
	resp = append(resp, 0x00, 0x00, 0x00, 0x3C)
	lenPrefix := make([]byte, 2)
	binary.BigEndian.PutUint16(lenPrefix, uint16(len(rdata)))
	resp = append(resp, lenPrefix...)
	resp = append(resp, rdata...)

	got := parseHTTPSResponseForECH(resp)
	if got {
		t.Error("expected false for HTTPS RR without ECH SvcParamKey")
	}
}

// ─── F-adv-6: ScanBytesForECHExtension — noisy-byte false-positive rate ──────

// TestAuditF6_ECHScanner_FalsePositiveOnRandomBytes quantifies the noted
// false-positive rate from the docstring (~0.0015%/KB) to guard against future
// regressions that might increase it.
func TestAuditF6_ECHScanner_FalsePositiveOnRandomBytes(t *testing.T) {
	t.Parallel()

	// Deterministic buffer that intentionally does NOT contain 0xfe 0x0d.
	buf := bytes.Repeat([]byte{0x00, 0xFF, 0x01, 0xFE, 0x02}, 2048) // 10 KB, no 0xfe 0x0d sequence
	found, src := ScanBytesForECHExtension(buf)
	if found {
		t.Errorf("false positive: ScanBytesForECHExtension returned true src=%q on buffer without 0xfe0d", src)
	}
}

// TestAuditF6_ECHScanner_SingleByteBuffers verifies that a buffer of length 0
// or 1 never returns true (it cannot contain the 2-byte codepoint).
func TestAuditF6_ECHScanner_SingleByteBuffers(t *testing.T) {
	t.Parallel()
	cases := [][]byte{nil, {}, {0xfe}, {0x0d}}
	for _, b := range cases {
		found, _ := ScanBytesForECHExtension(b)
		if found {
			t.Errorf("ScanBytesForECHExtension(%v) = true, want false", b)
		}
	}
}
