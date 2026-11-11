// Package fanin joins several UDP sockets into one net.PacketConn, so that a
// single QUIC server can serve a whole port range.
//
// A QUIC server keeps its connections in a table of its transport. A listener
// on a port range used to start one server per port: every port had its own
// transport, so a client that hops ports (hysteria2) lost its connection on
// the first hop, and every idle port cost five goroutines and the batch
// buffers of quic-go. The fan-in conn reads every socket with one goroutine
// and hands the packets to the one server; replies go out of the socket the
// client last sent to.
package fanin

import (
	"errors"
	"net"
	"net/netip"
	"os"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

// BufferSize is the largest datagram the conn delivers whole. quic-go reads
// into buffers of 1452 bytes (protocol.MaxPacketBufferSize) and drops what does
// not fit, so a bigger datagram is useless to it anyway; the headroom covers
// the obfuscation headers. A longer datagram is truncated, as a short buffer
// truncates it on a plain socket.
const BufferSize = 2048

const (
	// routeTTL is how long the socket of a client is remembered after its
	// last packet. It is far longer than the idle timeouts of the QUIC
	// listeners, so a live connection never loses its route.
	routeTTL = 10 * time.Minute
	// maxRoutes bounds the route table against floods of spoofed sources; a
	// client that does not fit gets its replies from the first socket.
	maxRoutes = 1 << 17
	// queueSize is the number of read packets waiting for ReadFrom.
	queueSize = 256
)

type packet struct {
	buf  *[]byte
	n    int
	addr net.Addr
}

type route struct {
	index atomic.Int32
	seen  atomic.Int64 // unix nanoseconds
}

// Conn is the fan-in conn. Reads return the packets of every socket; WriteTo
// sends from the socket the destination last sent to (the first socket for
// an unknown destination), so the reply passes the NAT of the client.
//
// Out-of-band data (ECN, GSO, batched reads) of the sockets is not available
// through it: quic-go treats it as a plain net.PacketConn.
type Conn struct {
	conns []net.PacketConn

	packets chan packet
	done    chan struct{}
	close   sync.Once
	wg      sync.WaitGroup

	deadlineMu sync.Mutex
	deadline   time.Time
	timer      *time.Timer
	expired    chan struct{} // closed when the read deadline passes

	routeMu   sync.RWMutex
	routes    map[netip.AddrPort]*route
	lastSweep time.Time
}

var bufferPool = sync.Pool{New: func() any {
	b := make([]byte, BufferSize)
	return &b
}}

// New joins conns, which it owns from now on: Close closes them. There must
// be at least one. The result has a SyscallConn method when every conn has
// one.
func New(conns []net.PacketConn) net.PacketConn {
	if len(conns) == 0 {
		panic("fanin: no conns")
	}
	c := &Conn{
		conns:     conns,
		packets:   make(chan packet, queueSize),
		done:      make(chan struct{}),
		expired:   make(chan struct{}),
		routes:    make(map[netip.AddrPort]*route),
		lastSweep: time.Now(),
	}
	c.wg.Add(len(conns))
	for i, pc := range conns {
		go c.read(int32(i), pc)
	}
	for _, pc := range conns {
		if _, ok := pc.(syscall.Conn); !ok {
			return c
		}
	}
	return &syscallConn{c}
}

func (c *Conn) read(index int32, pc net.PacketConn) {
	defer c.wg.Done()
	var failures int
	for {
		buf := bufferPool.Get().(*[]byte)
		n, addr, err := pc.ReadFrom(*buf)
		if err != nil {
			bufferPool.Put(buf)
			if c.isClosed() || errors.Is(err, net.ErrClosed) {
				return
			}
			// A transient error (a datagram too long for the buffer on
			// Windows, an ICMP error): keep reading, but do not spin on an
			// error that repeats.
			failures++
			if failures > 1 {
				select {
				case <-time.After(time.Duration(min(failures, 100)) * 10 * time.Millisecond):
				case <-c.done:
					return
				}
			}
			continue
		}
		failures = 0
		c.learn(addr, index)
		select {
		case c.packets <- packet{buf: buf, n: n, addr: addr}:
		case <-c.done:
			bufferPool.Put(buf)
			return
		}
	}
}

func (c *Conn) isClosed() bool {
	select {
	case <-c.done:
		return true
	default:
		return false
	}
}

// learn remembers that addr last sent to the socket index.
func (c *Conn) learn(addr net.Addr, index int32) {
	key, ok := addrPort(addr)
	if !ok {
		return
	}
	now := time.Now()
	c.routeMu.RLock()
	r := c.routes[key]
	c.routeMu.RUnlock()
	if r != nil {
		if r.index.Load() != index {
			r.index.Store(index)
		}
		// a coarse clock is enough for a TTL of minutes
		if now.UnixNano()-r.seen.Load() > int64(time.Second) {
			r.seen.Store(now.UnixNano())
		}
		return
	}
	c.routeMu.Lock()
	defer c.routeMu.Unlock()
	if r = c.routes[key]; r != nil {
		r.index.Store(index)
		r.seen.Store(now.UnixNano())
		return
	}
	if now.Sub(c.lastSweep) > routeTTL/2 || len(c.routes) >= maxRoutes {
		c.sweep(now)
	}
	if len(c.routes) >= maxRoutes {
		return
	}
	r = new(route)
	r.index.Store(index)
	r.seen.Store(now.UnixNano())
	c.routes[key] = r
}

// sweep forgets the routes older than routeTTL; routeMu must be held.
func (c *Conn) sweep(now time.Time) {
	c.lastSweep = now
	oldest := now.Add(-routeTTL).UnixNano()
	for key, r := range c.routes {
		if r.seen.Load() < oldest {
			delete(c.routes, key)
		}
	}
}

func addrPort(addr net.Addr) (netip.AddrPort, bool) {
	switch a := addr.(type) {
	case *net.UDPAddr:
		return a.AddrPort(), true
	default:
		ap, err := netip.ParseAddrPort(addr.String())
		return ap, err == nil
	}
}

// ReadFrom implements net.PacketConn.
func (c *Conn) ReadFrom(p []byte) (int, net.Addr, error) {
	c.deadlineMu.Lock()
	expired := c.expired
	c.deadlineMu.Unlock()
	// a passed deadline wins over queued packets, as on a socket
	select {
	case <-expired:
		return 0, nil, os.ErrDeadlineExceeded
	case <-c.done:
		return 0, nil, net.ErrClosed
	default:
	}
	select {
	case pkt := <-c.packets:
		n := copy(p, (*pkt.buf)[:pkt.n])
		bufferPool.Put(pkt.buf)
		return n, pkt.addr, nil
	case <-expired:
		return 0, nil, os.ErrDeadlineExceeded
	case <-c.done:
		return 0, nil, net.ErrClosed
	}
}

// WriteTo implements net.PacketConn.
func (c *Conn) WriteTo(p []byte, addr net.Addr) (int, error) {
	if c.isClosed() {
		return 0, net.ErrClosed
	}
	return c.conns[c.socketFor(addr)].WriteTo(p, addr)
}

func (c *Conn) socketFor(addr net.Addr) int32 {
	key, ok := addrPort(addr)
	if !ok {
		return 0
	}
	c.routeMu.RLock()
	r := c.routes[key]
	c.routeMu.RUnlock()
	if r == nil {
		return 0
	}
	return r.index.Load()
}

// Close closes every socket and waits for the readers to stop.
func (c *Conn) Close() error {
	var err error
	c.close.Do(func() {
		close(c.done)
		for _, pc := range c.conns {
			if cErr := pc.Close(); cErr != nil && err == nil {
				err = cErr
			}
		}
		c.wg.Wait()
		c.deadlineMu.Lock()
		if c.timer != nil {
			c.timer.Stop()
		}
		c.deadlineMu.Unlock()
		for {
			select {
			case pkt := <-c.packets:
				bufferPool.Put(pkt.buf)
				continue
			default:
			}
			break
		}
	})
	return err
}

// LocalAddr returns the address of the first socket; Addrs has them all.
func (c *Conn) LocalAddr() net.Addr { return c.conns[0].LocalAddr() }

// Addrs returns the addresses of all the sockets.
func (c *Conn) Addrs() []net.Addr {
	addrs := make([]net.Addr, len(c.conns))
	for i, pc := range c.conns {
		addrs[i] = pc.LocalAddr()
	}
	return addrs
}

// SetDeadline implements net.PacketConn.
func (c *Conn) SetDeadline(t time.Time) error {
	if err := c.SetReadDeadline(t); err != nil {
		return err
	}
	return c.SetWriteDeadline(t)
}

// SetReadDeadline implements net.PacketConn. A deadline in the past wakes a
// blocked ReadFrom, which quic-go relies on to stop reading on Close.
func (c *Conn) SetReadDeadline(t time.Time) error {
	if c.isClosed() {
		return net.ErrClosed
	}
	c.deadlineMu.Lock()
	defer c.deadlineMu.Unlock()
	if c.timer != nil && !c.timer.Stop() {
		// the timer fired or is firing: its channel is (about to be)
		// closed, so the next deadline needs a new one
		c.expired = make(chan struct{})
	}
	c.timer = nil
	select {
	case <-c.expired:
		c.expired = make(chan struct{})
	default:
	}
	c.deadline = t
	if t.IsZero() {
		return nil
	}
	expired := c.expired
	if d := time.Until(t); d <= 0 {
		close(expired)
	} else {
		c.timer = time.AfterFunc(d, func() { close(expired) })
	}
	return nil
}

// SetWriteDeadline implements net.PacketConn; it is set on every socket.
func (c *Conn) SetWriteDeadline(t time.Time) error {
	var err error
	for _, pc := range c.conns {
		if wErr := pc.SetWriteDeadline(t); wErr != nil && err == nil {
			err = wErr
		}
	}
	return err
}

// SetReadBuffer sets the receive buffer of every socket that has one.
func (c *Conn) SetReadBuffer(bytes int) error {
	var err error
	for _, pc := range c.conns {
		if s, ok := pc.(interface{ SetReadBuffer(int) error }); ok {
			if sErr := s.SetReadBuffer(bytes); sErr != nil && err == nil {
				err = sErr
			}
		}
	}
	return err
}

// SetWriteBuffer sets the send buffer of every socket that has one.
func (c *Conn) SetWriteBuffer(bytes int) error {
	var err error
	for _, pc := range c.conns {
		if s, ok := pc.(interface{ SetWriteBuffer(int) error }); ok {
			if sErr := s.SetWriteBuffer(bytes); sErr != nil && err == nil {
				err = sErr
			}
		}
	}
	return err
}

// syscallConn is a Conn whose sockets all have a SyscallConn.
type syscallConn struct{ *Conn }

// Unwrap returns the fan-in conn.
func (c *syscallConn) Unwrap() *Conn { return c.Conn }

// SyscallConn returns a raw conn whose Control runs on every socket, so a
// socket option set by quic-go (the DF bit, the buffer sizes) reaches all of
// them. Read and Write act on the first socket.
func (c *syscallConn) SyscallConn() (syscall.RawConn, error) {
	raws := make([]syscall.RawConn, len(c.conns))
	for i, pc := range c.conns {
		raw, err := pc.(syscall.Conn).SyscallConn()
		if err != nil {
			return nil, err
		}
		raws[i] = raw
	}
	return rawConns(raws), nil
}

type rawConns []syscall.RawConn

func (r rawConns) Control(f func(fd uintptr)) error {
	for _, raw := range r {
		if err := raw.Control(f); err != nil {
			return err
		}
	}
	return nil
}

func (r rawConns) Read(f func(fd uintptr) bool) error  { return r[0].Read(f) }
func (r rawConns) Write(f func(fd uintptr) bool) error { return r[0].Write(f) }

// Of returns the fan-in conn behind pc, or nil.
func Of(pc net.PacketConn) *Conn {
	switch c := pc.(type) {
	case *Conn:
		return c
	case *syscallConn:
		return c.Conn
	}
	return nil
}

// LocalAddrs returns the addresses pc listens on: those of every socket of a
// fan-in conn.
func LocalAddrs(pc net.PacketConn) []net.Addr {
	if c := Of(pc); c != nil {
		return c.Addrs()
	}
	return []net.Addr{pc.LocalAddr()}
}
