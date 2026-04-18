package tlsprobe

import (
	"bytes"
	"net"
	"testing"
	"time"
)

// pipeConn adapts a net.Pipe end to satisfy net.Conn deadlines (net.Pipe already
// does, but we use it here explicitly to keep tests self-contained).
type pipeConn = net.Conn

func TestCountingConn_ReadWriteCounts(t *testing.T) {
	t.Parallel()
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	cc := newCountingConn(client)

	// Write 10 bytes through the counting side.
	payload := []byte("0123456789")
	done := make(chan struct{})
	go func() {
		defer close(done)
		buf := make([]byte, len(payload))
		_, _ = server.Read(buf)
	}()

	n, err := cc.Write(payload)
	if err != nil {
		t.Fatalf("Write: %v", err)
	}
	if n != len(payload) {
		t.Errorf("Write returned n=%d, want %d", n, len(payload))
	}
	<-done

	if got := cc.WriteCalls(); got != 1 {
		t.Errorf("WriteCalls=%d, want 1", got)
	}
	if got := cc.BytesOut(); got != int64(len(payload)) {
		t.Errorf("BytesOut=%d, want %d", got, len(payload))
	}

	// Send data from server → client and read via counting conn.
	send := []byte("hello")
	go func() {
		_, _ = server.Write(send)
	}()
	buf := make([]byte, len(send))
	n, err = cc.Read(buf)
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if !bytes.Equal(buf[:n], send) {
		t.Errorf("Read got %q, want %q", buf[:n], send)
	}

	if got := cc.ReadCalls(); got != 1 {
		t.Errorf("ReadCalls=%d, want 1", got)
	}
	if got := cc.BytesIn(); got != int64(len(send)) {
		t.Errorf("BytesIn=%d, want %d", got, len(send))
	}
}

func TestCountingConn_MultipleWrites(t *testing.T) {
	t.Parallel()
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	cc := newCountingConn(client)

	chunks := [][]byte{
		[]byte("abc"),
		[]byte("de"),
		[]byte("fghij"),
	}
	totalBytes := 0
	for _, c := range chunks {
		totalBytes += len(c)
	}

	go func() {
		buf := make([]byte, totalBytes)
		remaining := totalBytes
		for remaining > 0 {
			n, _ := server.Read(buf)
			remaining -= n
		}
	}()

	for _, c := range chunks {
		if _, err := cc.Write(c); err != nil {
			t.Fatalf("Write: %v", err)
		}
	}

	if got := cc.WriteCalls(); got != int64(len(chunks)) {
		t.Errorf("WriteCalls=%d, want %d", got, len(chunks))
	}
	if got := cc.BytesOut(); got != int64(totalBytes) {
		t.Errorf("BytesOut=%d, want %d", got, totalBytes)
	}
}

func TestCountingConn_ZeroCountWhenNoTraffic(t *testing.T) {
	t.Parallel()
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	_ = server // suppress unused warning

	cc := newCountingConn(client)
	if got := cc.ReadCalls(); got != 0 {
		t.Errorf("ReadCalls=%d before any read, want 0", got)
	}
	if got := cc.WriteCalls(); got != 0 {
		t.Errorf("WriteCalls=%d before any write, want 0", got)
	}
	if got := cc.BytesIn(); got != 0 {
		t.Errorf("BytesIn=%d before any read, want 0", got)
	}
	if got := cc.BytesOut(); got != 0 {
		t.Errorf("BytesOut=%d before any write, want 0", got)
	}
}

func TestCountingConn_SetDeadlines(t *testing.T) {
	t.Parallel()
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	_ = server

	cc := newCountingConn(client)
	// These must not panic or error on a fresh pipe.
	if err := cc.SetDeadline(time.Now().Add(time.Second)); err != nil {
		t.Errorf("SetDeadline: %v", err)
	}
	if err := cc.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Errorf("SetReadDeadline: %v", err)
	}
	if err := cc.SetWriteDeadline(time.Now().Add(time.Second)); err != nil {
		t.Errorf("SetWriteDeadline: %v", err)
	}
}

func TestCountingConn_ImplementsNetConn(t *testing.T) {
	t.Parallel()
	// Compile-time check that *countingConn satisfies net.Conn.
	var _ net.Conn = (*countingConn)(nil)
}
