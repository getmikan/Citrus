package auth

import (
	"net"
	"time"
)

// HandshakeTimeout bounds how long a client of the HTTP, SOCKS and mixed
// listeners may take to send its greeting, credentials and request. Without
// it a client that connects and sends nothing, or trickles bytes, holds a
// goroutine and its buffers forever before it is authenticated. The value
// matches the VLESS and Trojan listeners: generous for slow links (and the
// first read of a lazy TLS handshake on a tls listener), far below any idle
// timeout. The deadline is cleared once the request has been parsed, so a
// long-lived CONNECT tunnel or UDP association is never cut by it. A variable
// only so that tests can shorten it.
var HandshakeTimeout = 15 * time.Second

// SetHandshakeDeadline arms the pre-request read deadline on conn.
func SetHandshakeDeadline(conn net.Conn) {
	_ = conn.SetReadDeadline(time.Now().Add(HandshakeTimeout))
}

// ClearHandshakeDeadline lifts the deadline set by SetHandshakeDeadline.
func ClearHandshakeDeadline(conn net.Conn) {
	_ = conn.SetReadDeadline(time.Time{})
}
