package trojan

import (
	"net"
	"sync/atomic"
	"time"
)

// handshakeTimeout bounds how long a client may take, from the moment its
// connection reaches the Trojan layer, to send the request header (password
// key, command, address and the CRLFs). Without it a client that connects and
// sends nothing, or trickles bytes, holds a goroutine forever before it is
// authenticated.
//
// Xray-core uses policy timeouts.handshake (4s by default) for the same window
// (proxy/trojan). The value here is more generous, for slow mobile links (and
// the lazy TLS handshake, done on the first read on the tls listener). The
// deadline is cleared once the header is read, so an idle session after that
// is never affected; it also covers the header of every mux stream. Atomic
// only so that tests can shorten it while listener goroutines of an earlier
// test still read it.
var handshakeTimeout = newDuration(15 * time.Second)

// maxMuxStreams caps the streams one Trojan mux (smux) session may have open
// at once; a stream beyond it is closed as soon as it is accepted. Every
// stream costs a goroutine, so without a cap one authenticated client could
// open streams until the process runs out of memory. 1024 is far above what
// one client multiplexes (a phone with a few hundred connections). A variable
// only so that tests can lower it.
var maxMuxStreams = 1024

// setHandshakeDeadline arms the pre-authentication read deadline. Every conn
// that reaches the Trojan layer supports it: TCP, TLS, REALITY, ShadowTLS,
// ResTLS, JLS, ws (wrapped in N.NewDeadlineConn) and gun (whose deadline
// closes the conn when it fires).
func setHandshakeDeadline(conn net.Conn) {
	_ = conn.SetReadDeadline(time.Now().Add(handshakeTimeout.Load()))
}

// clearHandshakeDeadline lifts the deadline set by setHandshakeDeadline.
func clearHandshakeDeadline(conn net.Conn) {
	_ = conn.SetReadDeadline(time.Time{})
}

// duration is a time.Duration safe for concurrent use.
type duration struct{ v atomic.Int64 }

func newDuration(d time.Duration) *duration {
	x := &duration{}
	x.Store(d)
	return x
}

func (d *duration) Load() time.Duration   { return time.Duration(d.v.Load()) }
func (d *duration) Store(v time.Duration) { d.v.Store(int64(v)) }
