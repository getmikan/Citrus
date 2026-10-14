package sing_vless

import (
	"context"
	"net"
	"sync/atomic"
	"time"
)

type onAuthenticatedKey struct{}

// withOnAuthenticated records a function NewConnection calls once the user is
// authenticated.
func withOnAuthenticated(ctx context.Context, fn func()) context.Context {
	return context.WithValue(ctx, onAuthenticatedKey{}, fn)
}

func onAuthenticatedFrom(ctx context.Context) func() {
	fn, _ := ctx.Value(onAuthenticatedKey{}).(func())
	return fn
}

// handshakeTimeout bounds how long a client may take, from the moment its
// connection reaches the VLESS layer, to finish the VLESS Encryption handshake
// and to send the request header (version, UUID, addons, command, address).
// Without it a client that connects and sends nothing, or trickles bytes,
// holds a goroutine and its buffers forever before it is authenticated.
//
// Xray-core uses policy timeouts.handshake (4s by default) for the same window
// (proxy/vless/inbound). The constant here is more generous, so that slow
// mobile links (and the first read of a lazy TLS handshake on the tls
// listener) are not cut; it is still far below any idle timeout, and the
// deadline is cleared once the user is authenticated, so an idle session after
// that is never affected. Atomic only so that tests can shorten it while
// listener goroutines of an earlier test still read it.
var handshakeTimeout = newDuration(15 * time.Second)

// duration is a time.Duration safe for concurrent use.
type duration struct{ v atomic.Int64 }

func newDuration(d time.Duration) *duration {
	x := &duration{}
	x.Store(d)
	return x
}

func (d *duration) Load() time.Duration   { return time.Duration(d.v.Load()) }
func (d *duration) Store(v time.Duration) { d.v.Store(int64(v)) }

// setHandshakeDeadline arms the pre-authentication read deadline. Every conn
// that reaches the VLESS layer supports it: TCP, TLS, REALITY, ShadowTLS,
// ResTLS, JLS, ws (wrapped in N.NewDeadlineConn), and gun and xhttp (whose
// deadlines close the conn when they fire).
func setHandshakeDeadline(conn net.Conn) {
	_ = conn.SetReadDeadline(time.Now().Add(handshakeTimeout.Load()))
}

// clearHandshakeDeadline lifts the deadline set by setHandshakeDeadline.
func clearHandshakeDeadline(conn net.Conn) {
	_ = conn.SetReadDeadline(time.Time{})
}
