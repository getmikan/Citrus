package xhttp

import (
	"errors"
	"io"
	"os"
	"sync"
	"time"

	"github.com/metacubex/mihomo/common/httputils"
)

type Conn struct {
	writer  io.WriteCloser
	reader  io.ReadCloser
	onClose func()
	httputils.NetAddr

	closeOnce sync.Once
	closeErr  error

	// deadlines
	readDeadline  opDeadline
	writeDeadline opDeadline
}

func (c *Conn) Write(b []byte) (int, error) {
	if !c.writeDeadline.begin() {
		return 0, os.ErrDeadlineExceeded
	}
	n, err := c.writer.Write(b)
	return n, c.writeDeadline.end(err)
}

func (c *Conn) Read(b []byte) (int, error) {
	if !c.readDeadline.begin() {
		return 0, os.ErrDeadlineExceeded
	}
	n, err := c.reader.Read(b)
	return n, c.readDeadline.end(err)
}

func (c *Conn) Close() error {
	c.closeOnce.Do(func() {
		c.readDeadline.stop()
		c.writeDeadline.stop()
		err := c.writer.Close()
		err2 := c.reader.Close()
		if c.onClose != nil {
			c.onClose()
		}
		c.closeErr = errors.Join(err, err2)
	})
	return c.closeErr
}

func (c *Conn) SetReadDeadline(t time.Time) error {
	c.readDeadline.set(t, c.abort)
	return nil
}

func (c *Conn) SetWriteDeadline(t time.Time) error {
	c.writeDeadline.set(t, c.abort)
	return nil
}

func (c *Conn) SetDeadline(t time.Time) error {
	c.readDeadline.set(t, c.abort)
	c.writeDeadline.set(t, c.abort)
	return nil
}

func (c *Conn) abort() { _ = c.Close() }

// opDeadline is one direction's deadline over a reader or writer that cannot be interrupted.
// An operation that starts after the deadline fails at once with os.ErrDeadlineExceeded, and
// one still blocked when the deadline passes is ended by closing the conn, the only way to
// unblock it. A conn with no operation in progress is left open: a write deadline that
// yamux keeps extending ahead of its writes must not tear down an idle session.
type opDeadline struct {
	mu      sync.Mutex
	timer   *time.Timer
	expired bool
	pending int
}

func (d *opDeadline) set(t time.Time, abort func()) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.timer != nil {
		d.timer.Stop()
		d.timer = nil
	}
	d.expired = false
	if t.IsZero() {
		return
	}
	dur := time.Until(t)
	if dur <= 0 {
		d.expired = true
		if d.pending > 0 {
			go abort()
		}
		return
	}
	var timer *time.Timer
	timer = time.AfterFunc(dur, func() {
		d.mu.Lock()
		if d.timer != timer { // reset or stopped meanwhile
			d.mu.Unlock()
			return
		}
		d.timer = nil
		d.expired = true
		blocked := d.pending > 0
		d.mu.Unlock()
		if blocked {
			abort()
		}
	})
	d.timer = timer
}

func (d *opDeadline) stop() {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.timer != nil {
		d.timer.Stop()
		d.timer = nil
	}
}

// begin reports whether an operation may start, and counts it as in progress if so.
func (d *opDeadline) begin() bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.expired {
		return false
	}
	d.pending++
	return true
}

// end finishes an operation started by begin, reporting a failure past the deadline as a timeout.
func (d *opDeadline) end(err error) error {
	d.mu.Lock()
	d.pending--
	expired := d.expired
	d.mu.Unlock()
	if err != nil && expired {
		return os.ErrDeadlineExceeded
	}
	return err
}
