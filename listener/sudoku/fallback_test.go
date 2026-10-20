package sudoku

import (
	"io"
	"net"
	"net/netip"
	"testing"
	"time"

	N "github.com/metacubex/mihomo/common/net"
)

type fallbackSourceConn struct {
	net.Conn
	addr *net.TCPAddr
}

func (c *fallbackSourceConn) RemoteAddr() net.Addr { return c.addr }

func fallbackTestSource(t *testing.T, ip string) net.Conn {
	t.Helper()
	a, b := net.Pipe()
	t.Cleanup(func() { a.Close(); b.Close() })
	return &fallbackSourceConn{Conn: a, addr: net.TCPAddrFromAddrPort(netip.AddrPortFrom(netip.MustParseAddr(ip), 12345))}
}

func TestFallbackCapsSourcesAndGlobalReservations(t *testing.T) {
	l := &fallbackLimiter{maxTotal: 3, maxSource: 2}
	same := fallbackTestSource(t, "192.0.2.1")
	first, ok := l.acquire(same)
	if !ok {
		t.Fatal("first reservation rejected")
	}
	second, ok := l.acquire(same)
	if !ok {
		t.Fatal("second reservation rejected")
	}
	if _, ok := l.acquire(same); ok {
		t.Fatal("source cap bypassed")
	}
	other, ok := l.acquire(fallbackTestSource(t, "192.0.2.2"))
	if !ok {
		t.Fatal("another source rejected before global cap")
	}
	if _, ok := l.acquire(fallbackTestSource(t, "192.0.2.3")); ok {
		t.Fatal("global cap bypassed")
	}
	l.release(first)
	l.release(first)
	replacement, ok := l.acquire(same)
	if !ok {
		t.Fatal("released capacity did not recover")
	}
	if _, ok := l.acquire(same); ok {
		t.Fatal("double release corrupted source accounting")
	}
	for _, r := range []*fallbackReservation{second, other, replacement} {
		l.release(r)
	}
	if len(l.active) != 0 || len(l.sources) != 0 {
		t.Fatal("reservations leaked")
	}
}

func TestFallbackIPv6RotationSharesSourceBudget(t *testing.T) {
	l := &fallbackLimiter{maxTotal: 4, maxSource: 1}
	r, ok := l.acquire(fallbackTestSource(t, "2001:db8:1::1"))
	if !ok {
		t.Fatal("initial IPv6 reservation rejected")
	}
	defer l.release(r)
	if _, ok := l.acquire(fallbackTestSource(t, "2001:db8:1::2")); ok {
		t.Fatal("IPv6 /64 rotation bypassed source cap")
	}
	if fallbackSource(&net.TCPAddr{IP: net.ParseIP("::ffff:192.0.2.1"), Port: 1}) != fallbackSource(&net.TCPAddr{IP: net.ParseIP("192.0.2.1"), Port: 2}) {
		t.Fatal("IPv4-mapped source bypassed cap")
	}
}

func TestFallbackShutdownClosesBothSocketsAndRejectsNewWork(t *testing.T) {
	l := &fallbackLimiter{}
	raw, peer := net.Pipe()
	backend, target := net.Pipe()
	defer peer.Close()
	defer target.Close()
	r, ok := l.acquire(raw)
	if !ok || !l.attach(r, backend) {
		t.Fatal("reservation failed")
	}
	l.close()
	l.close()
	for _, c := range []net.Conn{peer, target} {
		c.SetReadDeadline(time.Now().Add(time.Second))
		if _, err := c.Read(make([]byte, 1)); err != io.EOF {
			t.Fatalf("socket retained: %v", err)
		}
	}
	if _, ok := l.acquire(fallbackTestSource(t, "192.0.2.4")); ok {
		t.Fatal("shutdown accepted new relay")
	}
	l.release(r)
}

func TestFallbackIdleClockTracksEitherDirectionAndClosesStall(t *testing.T) {
	raw, client := net.Pipe()
	backend, target := net.Pipe()
	defer raw.Close()
	defer client.Close()
	defer backend.Close()
	defer target.Close()
	client.SetDeadline(time.Now().Add(3 * time.Second))
	target.SetDeadline(time.Now().Add(3 * time.Second))
	g := newFallbackIdleGuard(100*time.Millisecond, raw, backend)
	defer g.stop()
	done := make(chan struct{})
	go func() { defer close(done); N.Relay(g.wrap(raw), g.wrap(backend)) }()
	// A download stays alive without any upload traffic, for longer than one
	// idle interval; expiry is measured from the last actual byte.
	for n := 0; n < 5; n++ {
		time.Sleep(30 * time.Millisecond)
		written := make(chan error, 1)
		go func() { _, err := target.Write([]byte("x")); written <- err }()
		var p [1]byte
		if _, err := io.ReadFull(client, p[:]); err != nil || p[0] != 'x' {
			t.Fatalf("active download interrupted: %v", err)
		}
		if err := <-written; err != nil {
			t.Fatal(err)
		}
	}
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("idle relay retained its sockets and copy goroutines")
	}
}
