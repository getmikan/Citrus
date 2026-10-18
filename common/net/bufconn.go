package net

import (
	"bufio"
	"net"

	"github.com/metacubex/mihomo/common/buf"
)

var _ ExtendedConn = (*BufferedConn)(nil)

// BufferedConn is a connection with a bufio.Reader in front of its reads.
//
// The reader (and its 4 KiB buffer) is made on the first call that needs
// it: the core wraps every inbound connection in a BufferedConn, and most of
// them are only ever relayed with ReadBuffer/ReadCached, which work without
// one.
type BufferedConn struct {
	r *bufio.Reader
	ExtendedConn
	peeked bool
}

func NewBufferedConn(c net.Conn) *BufferedConn {
	if bc, ok := c.(*BufferedConn); ok {
		return bc
	}
	return &BufferedConn{nil, NewExtendedConn(c), false}
}

// NewBufferedConnSize is NewBufferedConn with a reader of size bytes, made
// at once: for a protocol that parses a short header with it.
func NewBufferedConnSize(c net.Conn, size int) *BufferedConn {
	if bc, ok := c.(*BufferedConn); ok {
		return bc
	}
	ec := NewExtendedConn(c)
	return &BufferedConn{bufio.NewReaderSize(ec, size), ec, false}
}

// reader returns the bufio.Reader, made on first use.
func (c *BufferedConn) reader() *bufio.Reader {
	if c.r == nil {
		c.r = bufio.NewReader(c.ExtendedConn)
	}
	return c.r
}

func WarpConnWithBioReader(c net.Conn, br *bufio.Reader) net.Conn {
	if br != nil && br.Buffered() > 0 {
		if bc, ok := c.(*BufferedConn); ok && bc.r == br {
			return bc
		}
		return &BufferedConn{br, NewExtendedConn(c), true}
	}
	return c
}

// Reader returns the internal bufio.Reader.
func (c *BufferedConn) Reader() *bufio.Reader {
	return c.reader()
}

func (c *BufferedConn) ResetPeeked() {
	c.peeked = false
}

func (c *BufferedConn) Peeked() bool {
	return c.peeked
}

// Peek returns the next n bytes without advancing the reader.
func (c *BufferedConn) Peek(n int) ([]byte, error) {
	c.peeked = true
	return c.reader().Peek(n)
}

func (c *BufferedConn) Discard(n int) (discarded int, err error) {
	return c.reader().Discard(n)
}

func (c *BufferedConn) Read(p []byte) (int, error) {
	if c.r == nil {
		// nothing is buffered without a reader: no need to make one
		return c.ExtendedConn.Read(p)
	}
	return c.r.Read(p)
}

func (c *BufferedConn) ReadByte() (byte, error) {
	return c.reader().ReadByte()
}

func (c *BufferedConn) UnreadByte() error {
	return c.reader().UnreadByte()
}

func (c *BufferedConn) Buffered() int {
	if c.r == nil {
		return 0
	}
	return c.r.Buffered()
}

func (c *BufferedConn) ReadBuffer(buffer *buf.Buffer) (err error) {
	if c.r != nil && c.r.Buffered() > 0 {
		_, err = buffer.ReadOnceFrom(c.r)
		return
	}
	return c.ExtendedConn.ReadBuffer(buffer)
}

func (c *BufferedConn) ReadCached() *buf.Buffer { // call in sing/common/bufio.Copy
	if c.r != nil && c.r.Buffered() > 0 {
		length := c.r.Buffered()
		b, _ := c.r.Peek(length)
		_, _ = c.r.Discard(length)
		return buf.As(b)
	}
	c.r = nil // drop bufio.Reader to let gc can clean up its internal buf
	return nil
}

func (c *BufferedConn) Upstream() any {
	return c.ExtendedConn
}

// ReaderReplaceable lets the copy read the upstream conn directly once the
// reader is drained, and drops the reader then. The copy asks this before it
// looks for cached data (ReadCached), so without the drop a conn that was
// peeked (sniffing, an outbound with a lazy handshake) kept its 4 KiB reader
// for as long as it was relayed.
func (c *BufferedConn) ReaderReplaceable() bool {
	if c.r != nil && c.r.Buffered() > 0 {
		return false
	}
	c.r = nil
	return true
}

func (c *BufferedConn) WriterReplaceable() bool {
	return true
}
