package fallback

import (
	"net"
	"net/netip"
	"sync"
	"time"
)

// The bounds of the relays a listener's fallback keeps open (Sudoku, and the
// fallbacks of VLESS and Trojan): every one holds two sockets and two copy
// goroutines for a peer that never authenticated.
const (
	MaxRelays    = 256
	MaxPerSource = 64
	IdleTimeout  = 60 * time.Second
)

// Reservation is one relay counted by a Limiter.
type Reservation struct {
	raw, backend net.Conn
	source       netip.Prefix
}

// Limiter caps the open fallback relays of a listener, in all and per source
// (an IPv4 address or an IPv6 /64). Zero caps mean MaxRelays and MaxPerSource.
type Limiter struct {
	MaxTotal, MaxSource int

	mu      sync.Mutex
	closed  bool
	active  map[*Reservation]struct{}
	sources map[netip.Prefix]int
}

// Source is the bucket a Limiter counts a peer at addr in.
func Source(addr net.Addr) netip.Prefix {
	if addr == nil {
		return netip.Prefix{}
	}
	ip, err := netip.ParseAddrPort(addr.String())
	if err != nil {
		// Unknown sources share one bucket rather than bypassing the limit.
		return netip.Prefix{}
	}
	host := ip.Addr().Unmap().WithZone("")
	bits := 32
	if host.Is6() {
		bits = 64
	}
	return netip.PrefixFrom(host, bits).Masked()
}

// Acquire reserves a relay for raw; false when a cap is reached or the
// limiter is closed.
func (l *Limiter) Acquire(raw net.Conn) (*Reservation, bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.active == nil {
		l.active = make(map[*Reservation]struct{})
		l.sources = make(map[netip.Prefix]int)
	}
	total, perSource := l.MaxTotal, l.MaxSource
	if total <= 0 {
		total = MaxRelays
	}
	if perSource <= 0 {
		perSource = MaxPerSource
	}
	source := Source(raw.RemoteAddr())
	if l.closed || len(l.active) >= total || l.sources[source] >= perSource {
		return nil, false
	}
	r := &Reservation{raw: raw, source: source}
	l.active[r] = struct{}{}
	l.sources[source]++
	return r, true
}

// Attach records the backend of r for Close; false, with backend closed, when
// the limiter is closed already.
func (l *Limiter) Attach(r *Reservation, backend net.Conn) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed {
		backend.Close()
		return false
	}
	r.backend = backend
	return true
}

// Release frees r; a second release is a no-op.
func (l *Limiter) Release(r *Reservation) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if _, ok := l.active[r]; !ok {
		return
	}
	delete(l.active, r)
	if l.sources[r.source]--; l.sources[r.source] == 0 {
		delete(l.sources, r.source)
	}
}

// Close closes the sockets of every open relay and refuses new ones.
func (l *Limiter) Close() {
	l.mu.Lock()
	l.closed = true
	var conns []net.Conn
	for r := range l.active {
		conns = append(conns, r.raw)
		if r.backend != nil {
			conns = append(conns, r.backend)
		}
	}
	l.mu.Unlock()
	for _, conn := range conns {
		conn.Close()
	}
}

// IdleGuard closes the conns of a relay once no byte has moved either way for
// its timeout. One activity clock for both directions keeps a download alive
// even when its upload direction is silent. Closing the sockets also
// interrupts blocked writes and wrappers that do not implement deadlines.
type IdleGuard struct {
	mu      sync.Mutex
	timer   *time.Timer
	last    time.Time
	timeout time.Duration
	stopped bool
	conns   []net.Conn
}

// NewIdleGuard starts the clock of conns; the relay copies through Wrap of
// them so that their traffic resets it.
func NewIdleGuard(timeout time.Duration, conns ...net.Conn) *IdleGuard {
	g := &IdleGuard{last: time.Now(), timeout: timeout, conns: conns}
	g.mu.Lock()
	g.timer = time.AfterFunc(timeout, g.expire)
	g.mu.Unlock()
	return g
}

func (g *IdleGuard) expire() {
	g.mu.Lock()
	if g.stopped {
		g.mu.Unlock()
		return
	}
	if remaining := g.timeout - time.Since(g.last); remaining > 0 {
		g.timer.Reset(remaining)
		g.mu.Unlock()
		return
	}
	g.stopped = true
	g.mu.Unlock()
	for _, c := range g.conns {
		c.Close()
	}
}

func (g *IdleGuard) touch(n int) {
	if n <= 0 {
		return
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if !g.stopped {
		g.last = time.Now()
		g.timer.Reset(g.timeout)
	}
}

// Stop stops the clock; the conns stay open.
func (g *IdleGuard) Stop() {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.stopped = true
	g.timer.Stop()
}

// Wrap returns c with its reads and writes counted as activity.
func (g *IdleGuard) Wrap(c net.Conn) net.Conn { return &idleConn{Conn: c, guard: g} }

type idleConn struct {
	net.Conn
	guard *IdleGuard
}

func (c *idleConn) Read(p []byte) (n int, err error) {
	n, err = c.Conn.Read(p)
	c.guard.touch(n)
	return
}

func (c *idleConn) Write(p []byte) (n int, err error) {
	n, err = c.Conn.Write(p)
	c.guard.touch(n)
	return
}
