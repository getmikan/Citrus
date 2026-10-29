// Package accept holds the Accept call shared by the inbound accept loops.
package accept

import (
	"errors"
	"net"
	"time"

	"github.com/metacubex/mihomo/log"
)

const (
	minDelay = 5 * time.Millisecond
	maxDelay = time.Second
)

// Next returns the next connection of l. It returns an error only once l is
// closed, either net.ErrClosed or closed() reporting true, and the caller then
// ends its loop. Any other error is waited out with the back-off net/http
// uses, so the loop neither spins on it nor stops serving. Temporary() is not
// enough to tell the two apart: on Windows WSAEMFILE and WSAENOBUFS do not
// report Temporary, and a failed handshake listener keeps returning its own
// error, even after Close, hence closed.
func Next(l net.Listener, closed func() bool) (net.Conn, error) {
	var delay time.Duration
	for {
		c, err := l.Accept()
		if err == nil {
			return c, nil
		}
		if errors.Is(err, net.ErrClosed) || closed() {
			return nil, err
		}
		if delay == 0 {
			delay = minDelay
			log.Warnln("accept on %s: %v", l.Addr(), err)
		} else if delay *= 2; delay > maxDelay {
			delay = maxDelay
		}
		time.Sleep(delay)
	}
}
