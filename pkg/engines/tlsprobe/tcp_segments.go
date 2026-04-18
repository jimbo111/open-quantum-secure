package tlsprobe

import (
	"net"
	"sync/atomic"
	"time"
)

// countingConn wraps a net.Conn and atomically tracks Read/Write call counts
// and byte totals. Each Read() call is a practical proxy for one incoming TCP
// segment on typical Linux/Darwin because Go's TLS record layer issues a 5-byte
// header read followed by a full-record read; the OS delivers whatever the NIC
// received, so a single Read() call generally corresponds to one segment boundary.
// Pre-PQ ClientHellos (~220-380 B) always fit in one segment; hybrid PQ
// ClientHellos (~1450 B) span ≥2 segments, producing ≥2 Read() calls on the
// server side / ≥2 Write() calls on the client side.
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
