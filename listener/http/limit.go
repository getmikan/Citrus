package http

import (
	"errors"
	"net"
)

// MaxHeaderBytes bounds the request line and header of a proxy request, read
// before the client is authenticated. It is the size of the header itself;
// the reader is given a little more, as net/http does, for the bytes its
// buffer reads ahead.
const MaxHeaderBytes = 64 << 10

const readAheadSlack = 4096

var errHeaderTooLarge = errors.New("http: request header too large")

// headerLimitConn caps the bytes read from the client while a request header
// is parsed; outside that it is transparent. It is only touched by the
// goroutine that holds the request loop's read lock, and by the relay after
// the connection is hijacked.
type headerLimitConn struct {
	net.Conn
	remain  int
	limited bool
	hit     bool
}

func (c *headerLimitConn) limit(n int) {
	c.remain = n + readAheadSlack
	c.limited = true
	c.hit = false
}

// unlimit lifts the cap and reports whether it was reached.
func (c *headerLimitConn) unlimit() bool {
	c.limited = false
	return c.hit
}

func (c *headerLimitConn) Read(p []byte) (int, error) {
	if !c.limited {
		return c.Conn.Read(p)
	}
	if c.remain <= 0 {
		c.hit = true
		return 0, errHeaderTooLarge
	}
	if len(p) > c.remain {
		p = p[:c.remain]
	}
	n, err := c.Conn.Read(p)
	c.remain -= n
	return n, err
}

// Upstream lets the relay of a CONNECT tunnel reach the client connection.
func (c *headerLimitConn) Upstream() any { return c.Conn }

func (c *headerLimitConn) ReaderReplaceable() bool { return !c.limited }

func (c *headerLimitConn) WriterReplaceable() bool { return true }
