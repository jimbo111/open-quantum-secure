// sshprobe_integration_test.go — orchestrator integration tests for the SSH probe engine.
//
// Purpose: verify that the ssh-probe engine integrates correctly with the
// orchestrator's scan pipeline — findings flow through classification,
// deduplication, and output stages without errors. Tests use a real local TCP
// listener to avoid mocking the network layer.
//
// Seam note: the orchestrator excludes Tier5Network engines by default when
// ScanType="" (source scan). To include ssh-probe, tests use ScanType="all".
// This is the same mechanism used by users who pass `--scan-type=all` on the CLI.
// Flag for implementer: consider adding SSHTargets to the Tier5Network inclusion
// condition in orchestrator.go (alongside TLSTargets/CTLookupTargets) so that
// setting --ssh-targets automatically activates the ssh-probe without requiring
// --scan-type=all.
package orchestrator

import (
	"context"
	"encoding/binary"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/jimbo111/open-quantum-secure/pkg/engines"
	"github.com/jimbo111/open-quantum-secure/pkg/engines/sshprobe"
	"github.com/jimbo111/open-quantum-secure/pkg/findings"
)

// startFakeSSH starts a minimal SSH server that serves the given KEX methods.
// Returns the TCP address (host:port) of the listener.
func startFakeSSH(t *testing.T, serverID string, kexMethods []string) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	addr := ln.Addr().String()

	go func() {
		defer ln.Close()
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(5 * time.Second))

		// Send banner.
		_, _ = conn.Write([]byte(serverID + "\r\n"))

		// Read (and discard) client banner.
		buf := make([]byte, 512)
		for {
			n, err := conn.Read(buf)
			if err != nil || n == 0 {
				break
			}
			if strings.Contains(string(buf[:n]), "\n") {
				break
			}
		}

		// Send KEXINIT packet.
		pkt := buildSSHTestPacket(kexMethods)
		_, _ = conn.Write(pkt)
	}()

	return addr
}

// buildSSHTestPacket builds a minimal SSH binary packet containing a KEXINIT
// payload for the given KEX methods. Replicates the encoding from probe_test.go
// without creating a cross-package dependency.
func buildSSHTestPacket(kexMethods []string) []byte {
	const sshMsgKexInit = 20
	const kexinitCookieLen = 16
	const kexinitNameListCount = 10

	// Build payload.
	payload := []byte{sshMsgKexInit}
	payload = append(payload, make([]byte, kexinitCookieLen)...)

	// Encode kex_algorithms.
	joined := strings.Join(kexMethods, ",")
	lenBuf := make([]byte, 4)
	binary.BigEndian.PutUint32(lenBuf, uint32(len(joined)))
	payload = append(payload, lenBuf...)
	payload = append(payload, []byte(joined)...)

	// 9 remaining empty name-lists.
	emptyList := make([]byte, 4) // uint32 length = 0
	for i := 0; i < kexinitNameListCount-1; i++ {
		payload = append(payload, emptyList...)
	}
	// first_kex_packet_follows + reserved.
	payload = append(payload, 0, 0, 0, 0, 0)

	// Wrap in SSH binary packet frame.
	padding := 8 - (len(payload)+5)%8
	if padding < 4 {
		padding += 8
	}
	pktLen := uint32(1 + len(payload) + padding)
	pkt := make([]byte, 4+1+len(payload)+padding)
	binary.BigEndian.PutUint32(pkt[0:4], pktLen)
	pkt[4] = byte(padding)
	copy(pkt[5:], payload)
	return pkt
}

// ─── Integration tests ────────────────────────────────────────────────────────

// TestSSHProbeOrchestrator_ClassicalServer verifies that the orchestrator correctly
// processes ssh-probe findings from a server advertising only classical KEX methods.
func TestSSHProbeOrchestrator_ClassicalServer(t *testing.T) {
	methods := []string{
		"curve25519-sha256",
		"diffie-hellman-group14-sha256",
		"ecdh-sha2-nistp256",
	}
	addr := startFakeSSH(t, "SSH-2.0-OpenSSH_7.4", methods)

	o := New(sshprobe.New())
	ff, err := o.Scan(context.Background(), engines.ScanOptions{
		SSHTargets: []string{addr},
		ScanType:   "all", // required to include Tier5Network engines
	})
	if err != nil {
		t.Fatalf("Scan error: %v", err)
	}
	if len(ff) != len(methods) {
		t.Errorf("findings = %d; want %d (one per method)", len(ff), len(methods))
	}
	for _, f := range ff {
		if f.PQCPresent {
			t.Errorf("classical method %q flagged as PQCPresent=true", f.Algorithm.Name)
		}
		if f.QuantumRisk == findings.QRSafe {
			t.Errorf("classical method %q has QuantumRisk=QRSafe", f.Algorithm.Name)
		}
		if f.SourceEngine != "ssh-probe" {
			t.Errorf("finding SourceEngine=%q; want ssh-probe", f.SourceEngine)
		}
	}
}

// TestSSHProbeOrchestrator_PQCServer verifies that a server advertising a PQC
// KEX method yields a finding with PQCPresent=true and QuantumRisk=QRSafe.
func TestSSHProbeOrchestrator_PQCServer(t *testing.T) {
	methods := []string{
		"mlkem768x25519-sha256",
		"curve25519-sha256",
		"diffie-hellman-group14-sha256",
	}
	addr := startFakeSSH(t, "SSH-2.0-OpenSSH_10.0", methods)

	o := New(sshprobe.New())
	ff, err := o.Scan(context.Background(), engines.ScanOptions{
		SSHTargets: []string{addr},
		ScanType:   "all",
	})
	if err != nil {
		t.Fatalf("Scan error: %v", err)
	}
	if len(ff) != 3 {
		t.Fatalf("findings = %d; want 3", len(ff))
	}

	// Find the mlkem768 finding.
	var pqcFound bool
	for _, f := range ff {
		if f.Algorithm.Name == "mlkem768x25519-sha256" {
			pqcFound = true
			if !f.PQCPresent {
				t.Error("mlkem768x25519-sha256: PQCPresent=false, want true")
			}
			if f.QuantumRisk != findings.QRSafe {
				t.Errorf("mlkem768x25519-sha256: QuantumRisk=%q, want QRSafe", f.QuantumRisk)
			}
			if f.PQCMaturity != "final" {
				t.Errorf("mlkem768x25519-sha256: PQCMaturity=%q, want final", f.PQCMaturity)
			}
		}
	}
	if !pqcFound {
		t.Error("mlkem768x25519-sha256 finding not returned by orchestrator")
	}
}

// TestSSHProbeOrchestrator_MultiTarget verifies multiple SSH targets in one scan.
func TestSSHProbeOrchestrator_MultiTarget(t *testing.T) {
	methodsA := []string{"mlkem768x25519-sha256", "curve25519-sha256"}
	methodsB := []string{"diffie-hellman-group14-sha256", "ecdh-sha2-nistp256"}

	addrA := startFakeSSH(t, "SSH-2.0-OpenSSH_10.0", methodsA)
	addrB := startFakeSSH(t, "SSH-2.0-OpenSSH_7.4", methodsB)

	o := New(sshprobe.New())
	ff, err := o.Scan(context.Background(), engines.ScanOptions{
		SSHTargets: []string{addrA, addrB},
		ScanType:   "all",
	})
	if err != nil {
		t.Fatalf("Scan error: %v", err)
	}

	// Total findings = 2 + 2 = 4
	if len(ff) != 4 {
		t.Errorf("findings = %d; want 4 (2 per target)", len(ff))
	}

	var pqcCount int
	for _, f := range ff {
		if f.PQCPresent {
			pqcCount++
		}
	}
	if pqcCount != 1 {
		t.Errorf("PQC findings = %d; want 1 (only mlkem768x25519-sha256)", pqcCount)
	}
}

// TestSSHProbeOrchestrator_NoNetwork verifies that NoNetwork=true prevents the
// orchestrator from probing even when SSHTargets is set.
func TestSSHProbeOrchestrator_NoNetwork(t *testing.T) {
	o := New(sshprobe.New())
	ff, err := o.Scan(context.Background(), engines.ScanOptions{
		SSHTargets: []string{"192.0.2.1:22"},
		ScanType:   "all",
		NoNetwork:  true,
	})
	if err != nil {
		t.Fatalf("expected no error with NoNetwork=true, got: %v", err)
	}
	if len(ff) != 0 {
		t.Errorf("expected no findings with NoNetwork=true, got %d", len(ff))
	}
}

// TestSSHProbeOrchestrator_ContextCancellation verifies that cancelling the
// context aborts the orchestrator scan cleanly.
func TestSSHProbeOrchestrator_ContextCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel before scan starts

	o := New(sshprobe.New())
	// Cancelled context: scan may return error or empty findings — either is fine.
	// What matters: no hang, no panic.
	done := make(chan struct{})
	go func() {
		defer close(done)
		_, _ = o.Scan(ctx, engines.ScanOptions{
			SSHTargets: []string{"192.0.2.1:22"},
			ScanType:   "all",
		})
	}()

	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("Scan did not return within 3s with pre-cancelled context")
	}
}
