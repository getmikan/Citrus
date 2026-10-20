package net

import (
	"context"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

const (
	defaultHandshakeLimit   = 256
	defaultHandshakeTimeout = 15 * time.Second
)

type handleContextListener struct {
	net.Listener
	ctx                       context.Context
	cancel                    context.CancelFunc
	conns                     chan net.Conn
	done                      chan struct{}
	once, stopOnce, closeOnce sync.Once
	mu                        sync.Mutex
	err, closeErr             error
	pending                   map[*handshakeConn]struct{}
	slots                     chan struct{}
	timeout                   time.Duration
	handle                    func(context.Context, net.Conn) (net.Conn, error)
	panicLog                  func(any)
}

// A classified fallback releases its handshake slot, but remains tracked while
// its handler runs so listener shutdown can close its sockets.
type handshakeConn struct {
	net.Conn
	listener    *handleContextListener
	cancel      context.CancelFunc
	timer       *time.Timer
	state       atomic.Int32 // 0: pending, 1: classified, 2: expired / closing
	releaseOnce sync.Once
}

func (c *handshakeConn) Upstream() any { return c.Conn }
func (c *handshakeConn) Close() error  { c.cancel(); return c.Conn.Close() }
func (c *handshakeConn) CloseWrite() error {
	if conn, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return conn.CloseWrite()
	}
	return c.Close()
}
func (c *handshakeConn) CloseRead() error {
	if conn, ok := c.Conn.(interface{ CloseRead() error }); ok {
		return conn.CloseRead()
	}
	return c.Close()
}
func (c *handshakeConn) release() { c.releaseOnce.Do(func() { <-c.listener.slots }) }
func (c *handshakeConn) HandshakeComplete() {
	if c.state.CompareAndSwap(0, 1) {
		c.timer.Stop()
		_ = c.Conn.SetDeadline(time.Time{})
		c.release()
	}
}
func (c *handshakeConn) expire() {
	if c.state.CompareAndSwap(0, 2) {
		c.cancel()
		_ = c.Conn.Close()
	}
}
func (c *handshakeConn) abort() {
	c.state.CompareAndSwap(0, 2)
	c.timer.Stop()
	c.cancel()
	_ = c.Conn.Close()
}

// HandshakeComplete is called before a transport enters fallback. Successful
// ordinary handshakes complete automatically when the handler returns.
func HandshakeComplete(conn net.Conn) {
	if c, ok := FindUpstream(conn, func(c *handshakeConn) bool { return true }); ok {
		c.HandshakeComplete()
	}
}

func (l *handleContextListener) shutdown(err error) {
	l.stopOnce.Do(func() {
		l.mu.Lock()
		l.err = err
		conns := make([]*handshakeConn, 0, len(l.pending))
		for c := range l.pending {
			conns = append(conns, c)
		}
		l.mu.Unlock()
		l.cancel()
		close(l.done)
		for _, c := range conns {
			c.abort()
		}
	})
}
func (l *handleContextListener) init() {
	go func() {
		for {
			raw, err := l.Listener.Accept()
			if err != nil {
				l.shutdown(err)
				return
			}
			select {
			case l.slots <- struct{}{}:
			default:
				raw.Close()
				continue
			}
			ctx, cancel := context.WithCancel(l.ctx)
			c := &handshakeConn{Conn: raw, listener: l, cancel: cancel}
			_ = raw.SetDeadline(time.Now().Add(l.timeout))
			c.timer = time.AfterFunc(l.timeout, c.expire)
			l.mu.Lock()
			if l.ctx.Err() != nil {
				l.mu.Unlock()
				c.abort()
				c.release()
				return
			}
			l.pending[c] = struct{}{}
			l.mu.Unlock()
			go l.serve(ctx, c)
		}
	}()
}
func (l *handleContextListener) serve(ctx context.Context, c *handshakeConn) {
	accepted := false
	defer func() {
		if r := recover(); r != nil {
			c.abort()
			if l.panicLog != nil {
				l.panicLog(r)
			}
		}
		c.timer.Stop()
		if !accepted {
			c.cancel()
		}
		c.release()
		l.mu.Lock()
		delete(l.pending, c)
		l.mu.Unlock()
	}()
	conn, err := l.handle(ctx, c)
	if err != nil || conn == nil || c.state.Load() == 2 {
		c.abort()
		return
	}
	c.HandshakeComplete()
	if c.state.Load() != 1 {
		c.abort()
		_ = conn.Close()
		return
	}
	l.mu.Lock()
	delete(l.pending, c)
	l.mu.Unlock()
	select {
	case l.conns <- conn:
		accepted = true
	case <-l.done:
		conn.Close()
	}
}
func (l *handleContextListener) Accept() (net.Conn, error) {
	l.once.Do(l.init)
	select {
	case c := <-l.conns:
		return c, nil
	case <-l.done:
		l.mu.Lock()
		defer l.mu.Unlock()
		return nil, l.err
	}
}
func (l *handleContextListener) Close() error {
	l.closeOnce.Do(func() { l.shutdown(net.ErrClosed); l.closeErr = l.Listener.Close() })
	return l.closeErr
}
func NewHandleContextListener(ctx context.Context, l net.Listener, handle func(context.Context, net.Conn) (net.Conn, error), panicLog func(any)) net.Listener {
	listenerCtx, cancel := context.WithCancel(ctx)
	w := &handleContextListener{Listener: l, ctx: listenerCtx, cancel: cancel, conns: make(chan net.Conn), done: make(chan struct{}), pending: make(map[*handshakeConn]struct{}), slots: make(chan struct{}, defaultHandshakeLimit), timeout: defaultHandshakeTimeout, handle: handle, panicLog: panicLog}
	go func() { <-listenerCtx.Done(); _ = w.Close() }()
	return w
}
