package tlsprobe

import (
	"net"
	"sync/atomic"
	"time"
)

// countingConn wraps a net.Conn and atomically tracks Read/Write call counts
// and byte totals.
//
// Read() calls are a noisy proxy for TCP segment boundaries: crypto/tls issues
// a 5-byte header read followed by a full-record-body read, so a single 1500-byte
// segment typically yields 2 Read() calls rather than 1. As a result
// IncomingSegments (= ReadCalls) and OutgoingSegments (= WriteCalls) are
// diagnostic-only and must not be used for classification decisions.
//
// BytesIn and BytesOut are the authoritative volume signal: they count raw bytes
// transferred regardless of how the TLS layer fragments records across syscalls.
type countingConn struct {
	net.Conn

	readCalls  atomic.Int64
	writeCalls atomic.Int64
	bytesIn    atomic.Int64
	bytesOut   atomic.Int64
}

// newCountingConn wraps c in a countingConn.
func newCountingConn(c net.Conn) *countingConn {
	return &countingConn{Conn: c}
}

// Read delegates to the underlying Conn and atomically accumulates byte counts
// and call counts.
func (cc *countingConn) Read(b []byte) (int, error) {
	n, err := cc.Conn.Read(b)
	if n > 0 {
		cc.bytesIn.Add(int64(n))
		cc.readCalls.Add(1)
	}
	return n, err
}

// Write delegates to the underlying Conn and atomically accumulates byte counts
// and call counts.
func (cc *countingConn) Write(b []byte) (int, error) {
	n, err := cc.Conn.Write(b)
	if n > 0 {
		cc.bytesOut.Add(int64(n))
		cc.writeCalls.Add(1)
	}
	return n, err
}

// SetDeadline delegates to the underlying Conn.
func (cc *countingConn) SetDeadline(t time.Time) error {
	return cc.Conn.SetDeadline(t)
}

// SetReadDeadline delegates to the underlying Conn.
func (cc *countingConn) SetReadDeadline(t time.Time) error {
	return cc.Conn.SetReadDeadline(t)
}

// SetWriteDeadline delegates to the underlying Conn.
func (cc *countingConn) SetWriteDeadline(t time.Time) error {
	return cc.Conn.SetWriteDeadline(t)
}

// ReadCalls returns the number of Read calls that transferred ≥1 byte.
func (cc *countingConn) ReadCalls() int64 { return cc.readCalls.Load() }

// WriteCalls returns the number of Write calls that transferred ≥1 byte.
func (cc *countingConn) WriteCalls() int64 { return cc.writeCalls.Load() }

// BytesIn returns the total bytes received.
func (cc *countingConn) BytesIn() int64 { return cc.bytesIn.Load() }

// BytesOut returns the total bytes sent.
func (cc *countingConn) BytesOut() int64 { return cc.bytesOut.Load() }
