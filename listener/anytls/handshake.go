package anytls

import (
	"net"
	"sync/atomic"
	"time"
)

// handshakeTimeout bounds how long a client may take, from the moment its
// connection reaches the AnyTLS layer, to send the authentication prelude
// (password hash and padding). Without it a client that connects and sends
// nothing holds a goroutine forever before it is authenticated. The deadline
// is cleared once the prelude is read, so an idle session after that is never
// affected (the session has its own idle handling). It also bounds how long
// a stream may take to send its destination. The value matches the VLESS and
// Trojan listeners. Atomic only so that tests can shorten it while listener
// goroutines of an earlier test still read it.
var handshakeTimeout = newDuration(15 * time.Second)

func setHandshakeDeadline(conn net.Conn) {
	_ = conn.SetReadDeadline(time.Now().Add(handshakeTimeout.Load()))
}

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
