package tlsprobe

// tcp_segments_stress_test.go — Bucket 3: goroutine-parallel stress tests for
// countingConn under the -race detector.
//
// Two scenarios:
//  1. 1-second saturation: many goroutines read and write concurrently; counters
//     must strictly increase (monotonically non-decreasing) and converge to the
//     correct total.
//  2. 8-goroutine exact-match: 8 goroutines each write 1 KB and read 1 KB via
//     net.Pipe; final counters must equal the sum across all goroutines.

import (
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// TestCountingConn_ParallelStress_MonotonicCounters runs concurrent Writes on
// a countingConn for ~200ms and verifies that BytesOut never decreases between
// successive snapshots taken by a monitor goroutine (monotonically non-decreasing).
//
// BytesIn is not exercised here because net.Pipe requires a symmetric
// reader-on-the-other-end for every write; exercising bidirectional concurrent
// I/O reliably is done in TestCountingConn_EightGoroutines_ExactMatch below.
func TestCountingConn_ParallelStress_MonotonicCounters(t *testing.T) {
	t.Parallel()

	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	cc := newCountingConn(clientConn)

	const (
		chunkSize    = 128
		numWriters   = 4
		testDuration = 200 * time.Millisecond
	)

	deadline := time.Now().Add(testDuration)
	_ = cc.SetDeadline(deadline)
	_ = serverConn.SetDeadline(deadline)

	var (
		wg         sync.WaitGroup
		monitorErr atomic.Value // stores first string error message
	)

	// Monitor goroutine: samples BytesOut every 5ms and asserts monotonicity.
	monitorDone := make(chan struct{})
	wg.Add(1)
	go func() {
		defer wg.Done()
		defer close(monitorDone)
		var prevOut int64
		for {
			if time.Now().After(deadline) {
				return
			}
			curOut := cc.BytesOut()
			if curOut < prevOut {
				monitorErr.Store("BytesOut decreased")
			}
			prevOut = curOut
			time.Sleep(5 * time.Millisecond)
		}
	}()

	// Drain goroutine: reads everything the writers send (required by net.Pipe).
	wg.Add(1)
	go func() {
		defer wg.Done()
		buf := make([]byte, chunkSize*numWriters)
		for {
			serverConn.SetReadDeadline(deadline) //nolint:errcheck
			_, err := serverConn.Read(buf)
			if err != nil {
				return
			}
		}
	}()

	// Writer goroutines: write via cc (client side) until deadline.
	for i := 0; i < numWriters; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			buf := make([]byte, chunkSize)
			for {
				_, err := cc.Write(buf)
				if err != nil || time.Now().After(deadline) {
					return
				}
			}
		}()
	}

	wg.Wait()

	if msg := monitorErr.Load(); msg != nil {
		t.Error(msg.(string))
	}
	if gotOut := cc.BytesOut(); gotOut <= 0 {
		t.Errorf("BytesOut=%d after stress test, expected > 0", gotOut)
	}
}

// TestCountingConn_EightGoroutines_ExactMatch spawns 8 goroutines each writing
// exactly 1 KB through countingConn and reading exactly 1 KB back via net.Pipe.
// The final BytesOut must equal 8*1024 and BytesIn must equal 8*1024.
func TestCountingConn_EightGoroutines_ExactMatch(t *testing.T) {
	t.Parallel()

	const (
		numGoroutines = 8
		chunkSize     = 1024
		totalBytes    = numGoroutines * chunkSize
	)

	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	cc := newCountingConn(clientConn)

	// Server goroutine: drains numGoroutines*chunkSize bytes (client→server),
	// then echoes them back (server→client).  This is sequential to avoid
	// interleaving issues with the echo direction.
	serverDone := make(chan error, 1)
	go func() {
		buf := make([]byte, totalBytes)
		total := 0
		for total < totalBytes {
			n, err := serverConn.Read(buf[total:])
			total += n
			if err != nil {
				serverDone <- err
				return
			}
		}
		// Echo back the same number of bytes to satisfy cc.Read calls.
		written := 0
		for written < totalBytes {
			n, err := serverConn.Write(buf[written:])
			written += n
			if err != nil {
				serverDone <- err
				return
			}
		}
		serverDone <- nil
	}()

	// 8 goroutines each write chunkSize bytes.
	var wg sync.WaitGroup
	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			payload := make([]byte, chunkSize)
			remaining := chunkSize
			for remaining > 0 {
				n, err := cc.Write(payload[chunkSize-remaining:])
				remaining -= n
				if err != nil {
					t.Errorf("Write error: %v", err)
					return
				}
			}
		}()
	}
	wg.Wait()

	// 8 goroutines each read chunkSize bytes (echoed back by server goroutine).
	var wg2 sync.WaitGroup
	for i := 0; i < numGoroutines; i++ {
		wg2.Add(1)
		go func() {
			defer wg2.Done()
			buf := make([]byte, chunkSize)
			remaining := chunkSize
			for remaining > 0 {
				n, err := cc.Read(buf[chunkSize-remaining:])
				remaining -= n
				if err != nil {
					t.Errorf("Read error: %v", err)
					return
				}
			}
		}()
	}
	wg2.Wait()

	if err := <-serverDone; err != nil {
		t.Fatalf("server goroutine error: %v", err)
	}

	if got := cc.BytesOut(); got != int64(totalBytes) {
		t.Errorf("BytesOut=%d, want %d", got, totalBytes)
	}
	if got := cc.BytesIn(); got != int64(totalBytes) {
		t.Errorf("BytesIn=%d, want %d", got, totalBytes)
	}
}

// TestCountingConn_WriteCalls_Atomic verifies that WriteCalls and ReadCalls
// values are consistent under concurrent access (the race detector will flag
// any non-atomic access).
func TestCountingConn_WriteCalls_Atomic(t *testing.T) {
	t.Parallel()

	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	cc := newCountingConn(clientConn)

	const calls = 50
	var wg sync.WaitGroup

	// Sink goroutine to drain server side.
	wg.Add(1)
	go func() {
		defer wg.Done()
		buf := make([]byte, 1)
		for i := 0; i < calls; i++ {
			_, _ = serverConn.Read(buf)
		}
	}()

	// Concurrent writers.
	for i := 0; i < calls; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _ = cc.Write([]byte{0x42})
		}()
	}

	wg.Wait()

	if got := cc.WriteCalls(); got != int64(calls) {
		t.Errorf("WriteCalls=%d, want %d", got, calls)
	}
	if got := cc.BytesOut(); got != int64(calls) {
		t.Errorf("BytesOut=%d, want %d (1 byte per call)", got, calls)
	}
}
