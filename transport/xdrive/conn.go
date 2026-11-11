package xdrive

import (
	"context"
	"net"
	"os"
	"sync"
	"time"

	"github.com/metacubex/mihomo/common/net/deadline"
)

var placeholderAddr = &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)}

type Conn struct {
	cancel                      context.CancelFunc
	writer                      *walWriter
	reader                      *walReader
	onClose                     func()
	readBuf                     []byte
	readMu                      sync.Mutex
	readDeadline, writeDeadline deadline.PipeDeadline
	done                        chan struct{}
	closeOnce                   sync.Once
	closeErr                    error
}

func newConn(ctx context.Context, storage Storage, writePrefix, readPrefix string, p params, onClose func()) *Conn {
	ctx, cancel := context.WithCancel(ctx)
	c := &Conn{cancel: cancel, onClose: onClose, readDeadline: deadline.MakePipeDeadline(), writeDeadline: deadline.MakePipeDeadline(), done: make(chan struct{})}
	c.writer = newWALWriter(ctx, storage, writePrefix, p, &c.writeDeadline)
	c.reader = newWALReader(ctx, storage, readPrefix, p)
	return c
}
func (c *Conn) Read(b []byte) (int, error) {
	c.readMu.Lock()
	defer c.readMu.Unlock()
	if len(b) == 0 {
		return 0, nil
	}
	if len(c.readBuf) == 0 {
		select {
		case <-c.done:
			return 0, net.ErrClosed
		case <-c.readDeadline.Wait():
			return 0, os.ErrDeadlineExceeded
		case data, ok := <-c.reader.ch:
			if !ok {
				return 0, c.reader.Err()
			}
			c.readBuf = data
		}
	}
	n := copy(b, c.readBuf)
	c.readBuf = c.readBuf[n:]
	return n, nil
}
func (c *Conn) Write(b []byte) (int, error) {
	select {
	case <-c.done:
		return 0, net.ErrClosed
	default:
	}
	n, err := c.writer.Write(b)
	if n > 0 {
		c.reader.Wake()
	}
	return n, err
}
func (c *Conn) Close() error {
	c.closeOnce.Do(func() {
		close(c.done)
		finished := make(chan error, 1)
		go func() { finished <- c.writer.Close() }()
		timer := time.NewTimer(5 * time.Second)
		defer timer.Stop()
		select {
		case c.closeErr = <-finished:
		case <-timer.C:
			c.closeErr = os.ErrDeadlineExceeded
		}
		c.cancel()
		c.readDeadline.Set(time.Time{})
		c.writeDeadline.Set(time.Time{})
		if c.onClose != nil {
			c.onClose()
		}
	})
	return c.closeErr
}
func (c *Conn) LocalAddr() net.Addr  { return placeholderAddr }
func (c *Conn) RemoteAddr() net.Addr { return placeholderAddr }
func (c *Conn) SetDeadline(t time.Time) error {
	c.readDeadline.Set(t)
	c.writeDeadline.Set(t)
	return nil
}
func (c *Conn) SetReadDeadline(t time.Time) error  { c.readDeadline.Set(t); return nil }
func (c *Conn) SetWriteDeadline(t time.Time) error { c.writeDeadline.Set(t); return nil }
