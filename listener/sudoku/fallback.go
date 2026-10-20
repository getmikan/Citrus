package sudoku

import (
	"net"
	"net/netip"
	"sync"
	"time"

	N "github.com/metacubex/mihomo/common/net"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/listener/inner"
)

const (
	maxFallbackRelays    = 256
	maxFallbackPerSource = 64
	fallbackIdleTimeout  = 60 * time.Second
)

type fallbackReservation struct {
	raw, backend net.Conn
	source       netip.Prefix
}

type fallbackLimiter struct {
	mu                  sync.Mutex
	closed              bool
	maxTotal, maxSource int
	active              map[*fallbackReservation]struct{}
	sources             map[netip.Prefix]int
}

func fallbackSource(addr net.Addr) netip.Prefix {
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

func (l *fallbackLimiter) acquire(raw net.Conn) (*fallbackReservation, bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.active == nil {
		l.active = make(map[*fallbackReservation]struct{})
		l.sources = make(map[netip.Prefix]int)
	}
	total, perSource := l.maxTotal, l.maxSource
	if total <= 0 {
		total = maxFallbackRelays
	}
	if perSource <= 0 {
		perSource = maxFallbackPerSource
	}
	source := fallbackSource(raw.RemoteAddr())
	if l.closed || len(l.active) >= total || l.sources[source] >= perSource {
		return nil, false
	}
	r := &fallbackReservation{raw: raw, source: source}
	l.active[r] = struct{}{}
	l.sources[source]++
	return r, true
}

func (l *fallbackLimiter) attach(r *fallbackReservation, backend net.Conn) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed {
		backend.Close()
		return false
	}
	r.backend = backend
	return true
}

func (l *fallbackLimiter) release(r *fallbackReservation) {
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

func (l *fallbackLimiter) close() {
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

func (l *Listener) relayFallback(wrapper, raw net.Conn, tunnel C.Tunnel, replay bool) {
	defer raw.Close()
	if wrapper != raw {
		defer wrapper.Close()
	}
	r, ok := l.fallbacks.acquire(raw)
	if !ok {
		return
	}
	defer l.fallbacks.release(r)
	backend, err := inner.HandleTcp(tunnel, l.fallback, "")
	if err != nil {
		return
	}
	defer backend.Close()
	if !l.fallbacks.attach(r, backend) {
		return
	}
	_ = raw.SetDeadline(time.Time{})
	_ = backend.SetDeadline(time.Time{})
	idle := newFallbackIdleGuard(fallbackIdleTimeout, raw, backend)
	defer idle.stop()
	if replay {
		relayToFallback(wrapper, idle.wrap(raw), idle.wrap(backend))
	} else {
		N.Relay(idle.wrap(wrapper), idle.wrap(backend))
	}
}

// One activity clock for both directions keeps a download alive even when its
// upload direction is silent. Closing the sockets also interrupts blocked writes
// and wrappers that do not implement deadlines.
type fallbackIdleGuard struct {
	mu      sync.Mutex
	timer   *time.Timer
	last    time.Time
	timeout time.Duration
	stopped bool
	conns   []net.Conn
}

func newFallbackIdleGuard(timeout time.Duration, conns ...net.Conn) *fallbackIdleGuard {
	g := &fallbackIdleGuard{last: time.Now(), timeout: timeout, conns: conns}
	g.mu.Lock()
	g.timer = time.AfterFunc(timeout, g.expire)
	g.mu.Unlock()
	return g
}

func (g *fallbackIdleGuard) expire() {
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

func (g *fallbackIdleGuard) touch(n int) {
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

func (g *fallbackIdleGuard) stop() {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.stopped = true
	g.timer.Stop()
}

func (g *fallbackIdleGuard) wrap(c net.Conn) net.Conn { return &fallbackIdleConn{Conn: c, guard: g} }

type fallbackIdleConn struct {
	net.Conn
	guard *fallbackIdleGuard
}

func (c *fallbackIdleConn) Read(p []byte) (n int, err error) {
	n, err = c.Conn.Read(p)
	c.guard.touch(n)
	return
}

func (c *fallbackIdleConn) Write(p []byte) (n int, err error) {
	n, err = c.Conn.Write(p)
	c.guard.touch(n)
	return
}
