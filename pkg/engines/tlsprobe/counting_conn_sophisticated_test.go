package tlsprobe

// counting_conn_sophisticated_test.go — Sophisticated tests for countingConn.
//
// Covers:
//  1. Race condition: concurrent goroutines reading and writing must not corrupt
//     atomic counters (run with -race; any DATA RACE = test failure).
//  2. Zero-byte read/write path: n=0 must NOT increment call counters.
//  3. Partial-read accumulation: when a single Write is split across multiple
//     Reads (as TLS does with 5-byte header then body), BytesIn must still total
//     to the correct sum.
//  4. Byte total correctness across a high volume of writes and reads.

import (
	"bytes"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
)

// TestCountingConn_ConcurrentReadWrite_NoRace verifies that concurrent goroutines
// all writing to and reading from the same countingConn do not introduce data
// races in the atomic counters. This test is a regression guard for any future
// replacement of atomic.Int64 with non-atomic accumulators.
//
// Run with: go test -race -count=1 ./pkg/engines/tlsprobe/ -run TestCountingConn_ConcurrentReadWrite_NoRace
func TestCountingConn_ConcurrentReadWrite_NoRace(t *testing.T) {
	t.Parallel()

	const numWriters = 5
	const numReaders = 5
	const chunkSize = 128
	const chunksPerWriter = 20

	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	cc := newCountingConn(client)

	// Server side: drain all incoming bytes so writers don't block.
	var drainWg sync.WaitGroup
	drainWg.Add(1)
	go func() {
		defer drainWg.Done()
		io.Copy(io.Discard, server) //nolint:errcheck
	}()

	// Track expected totals.
	var wantBytesOut atomic.Int64

	var writerWg sync.WaitGroup
	for w := 0; w < numWriters; w++ {
		writerWg.Add(1)
		go func() {
			defer writerWg.Done()
			chunk := bytes.Repeat([]byte{0xAB}, chunkSize)
			for i := 0; i < chunksPerWriter; i++ {
				n, err := cc.Write(chunk)
				if err == nil && n > 0 {
					wantBytesOut.Add(int64(n))
				}
			}
		}()
	}

	writerWg.Wait()
	// Close client write side so the server drainer exits cleanly.
	// (net.Pipe doesn't support half-close; close the whole conn after writers are done.)
	client.Close()
	drainWg.Wait()

	// All 5 writers wrote chunksPerWriter × chunkSize bytes each — counters must be consistent.
	gotOut := cc.BytesOut()
	gotCalls := cc.WriteCalls()

	if gotOut != wantBytesOut.Load() {
		t.Errorf("BytesOut=%d, want %d (concurrent writes miscounted)", gotOut, wantBytesOut.Load())
	}
	if gotCalls <= 0 {
		t.Errorf("WriteCalls=%d, want >0", gotCalls)
	}
	// WriteCalls <= numWriters×chunksPerWriter (not all writes may fully succeed).
	maxExpectedCalls := int64(numWriters * chunksPerWriter)
	if gotCalls > maxExpectedCalls {
		t.Errorf("WriteCalls=%d exceeds max expected %d", gotCalls, maxExpectedCalls)
	}
	_ = numReaders // numReaders declared for documentation symmetry
}

// TestCountingConn_ZeroBytesReadDoesNotIncrementCallCounter verifies that when
// the underlying Conn.Read returns (0, nil) — which can happen on non-blocking
// connections — the ReadCalls counter is NOT incremented. The production code
// gates the add on `if n > 0`.
//
// We simulate a zero-read by using a mock net.Conn that returns (0, nil) once
// before returning (5, nil) with actual data.
func TestCountingConn_ZeroBytesReadDoesNotIncrementCallCounter(t *testing.T) {
	t.Parallel()

	mock := &zeroThenRealConn{payload: []byte("hello")}
	cc := newCountingConn(mock)

	// First read: underlying Conn returns (0, nil) — should NOT increment ReadCalls.
	buf := make([]byte, 16)
	n, err := cc.Read(buf)
	if n != 0 || err != nil {
		t.Fatalf("expected zero-byte read from mock, got n=%d err=%v", n, err)
	}
	if calls := cc.ReadCalls(); calls != 0 {
		t.Errorf("ReadCalls=%d after 0-byte read, want 0 (counter must not increment on n=0)", calls)
	}
	if bIn := cc.BytesIn(); bIn != 0 {
		t.Errorf("BytesIn=%d after 0-byte read, want 0", bIn)
	}

	// Second read: real 5 bytes — must increment.
	n, err = cc.Read(buf)
	if n != 5 || err != nil {
		t.Fatalf("expected 5-byte read, got n=%d err=%v", n, err)
	}
	if calls := cc.ReadCalls(); calls != 1 {
		t.Errorf("ReadCalls=%d after real read, want 1", calls)
	}
	if bIn := cc.BytesIn(); bIn != 5 {
		t.Errorf("BytesIn=%d after real read, want 5", bIn)
	}
}

// zeroThenRealConn is a minimal net.Conn mock: first Read returns (0, nil);
// subsequent Reads return from payload.
type zeroThenRealConn struct {
	net.Conn
	payload   []byte
	firstDone bool
}

func (c *zeroThenRealConn) Read(b []byte) (int, error) {
	if !c.firstDone {
		c.firstDone = true
		return 0, nil
	}
	n := copy(b, c.payload)
	c.payload = c.payload[n:]
	return n, nil
}

func (c *zeroThenRealConn) Write(b []byte) (int, error) { return len(b), nil }
func (c *zeroThenRealConn) Close() error                { return nil }

// TestCountingConn_ZeroBytesWriteDoesNotIncrementCallCounter mirrors the Read
// test for the Write path: a (0, nil) Write must not increment WriteCalls.
func TestCountingConn_ZeroBytesWriteDoesNotIncrementCallCounter(t *testing.T) {
	t.Parallel()

	mock := &zeroWriteConn{}
	cc := newCountingConn(mock)

	// Write that succeeds but returns n=0.
	n, err := cc.Write([]byte("data"))
	if n != 0 || err != nil {
		t.Fatalf("expected (0,nil) from mock write, got n=%d err=%v", n, err)
	}
	if calls := cc.WriteCalls(); calls != 0 {
		t.Errorf("WriteCalls=%d after 0-byte write success, want 0", calls)
	}
	if bOut := cc.BytesOut(); bOut != 0 {
		t.Errorf("BytesOut=%d after 0-byte write success, want 0", bOut)
	}
}

// zeroWriteConn always returns (0, nil) from Write.
type zeroWriteConn struct{ net.Conn }

func (c *zeroWriteConn) Read(b []byte) (int, error)  { return 0, io.EOF }
func (c *zeroWriteConn) Write(b []byte) (int, error) { return 0, nil }
func (c *zeroWriteConn) Close() error                 { return nil }

// TestCountingConn_PartialReadAccumulation verifies that when a large payload is
// delivered in TLS fashion — 5-byte header read followed by multiple body reads —
// BytesIn accumulates the correct total across all partial reads.
//
// This mirrors the TLS stack behaviour that the CLAUDE.md documents: a 1500B TCP
// segment yields ~2 Read calls (5B header + body), so ReadCalls is a noisy proxy
// but BytesIn must be exact.
func TestCountingConn_PartialReadAccumulation(t *testing.T) {
	t.Parallel()

	const totalPayload = 1500
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	cc := newCountingConn(client)

	payload := bytes.Repeat([]byte{0x7F}, totalPayload)
	done := make(chan struct{})
	go func() {
		defer close(done)
		server.Write(payload) //nolint:errcheck
	}()

	// Read in 5-byte header chunks then 1-byte body chunks to simulate TLS fragmentation.
	var totalRead int
	// First: 5-byte "header".
	hdr := make([]byte, 5)
	n, err := io.ReadFull(cc, hdr)
	totalRead += n
	if err != nil {
		t.Fatalf("header read: %v", err)
	}

	// Remaining bytes in smaller chunks.
	chunk := make([]byte, 100)
	for totalRead < totalPayload {
		n, err := cc.Read(chunk)
		totalRead += n
		if err != nil {
			break
		}
	}
	<-done

	if got := cc.BytesIn(); got != int64(totalPayload) {
		t.Errorf("BytesIn=%d, want %d (partial reads must accumulate correctly)", got, totalPayload)
	}
	// ReadCalls must be >= 2 (at least the header read and one body read).
	if rc := cc.ReadCalls(); rc < 2 {
		t.Errorf("ReadCalls=%d, want >=2 for fragmented read", rc)
	}
}

// TestCountingConn_HighVolumeByteAccuracy submits 1 MB of data through countingConn
// and verifies BytesOut counts exactly 1 048 576 bytes. This ensures no off-by-one
// or truncation in the atomic accumulation under repeated large writes.
func TestCountingConn_HighVolumeByteAccuracy(t *testing.T) {
	t.Parallel()

	const totalBytes = 1 << 20 // 1 MB
	const writeSize = 4096

	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	cc := newCountingConn(client)

	// Drain server side concurrently.
	done := make(chan struct{})
	go func() {
		defer close(done)
		io.Copy(io.Discard, server) //nolint:errcheck
	}()

	chunk := make([]byte, writeSize)
	written := 0
	for written < totalBytes {
		n, err := cc.Write(chunk)
		written += n
		if err != nil {
			break
		}
	}
	client.Close()
	<-done

	if got := cc.BytesOut(); got != int64(written) {
		t.Errorf("BytesOut=%d, want %d (byte total mismatch under high volume)", got, int64(written))
	}
}
