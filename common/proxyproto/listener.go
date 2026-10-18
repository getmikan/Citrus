package proxyproto

import (
	"errors"
	"net"
	"net/netip"
	"runtime/debug"
	"sync"
	"time"

	"github.com/metacubex/mihomo/log"
)

// DefaultTimeout bounds the wait for the header of an accepted connection.
const DefaultTimeout = 5 * time.Second

// Loopback is the default set of peers allowed to send the header.
var Loopback = []netip.Prefix{
	netip.MustParsePrefix("127.0.0.0/8"),
	netip.MustParsePrefix("::1/128"),
}

// Config configures NewListener.
type Config struct {
	// Trusted are the networks whose peers may send the header; a connection
	// from any other peer is closed without being read, since the address in
	// its header could be anything. Empty means Loopback.
	Trusted []netip.Prefix
	// Timeout bounds the wait for the header, DefaultTimeout when zero.
	Timeout time.Duration
}

type listener struct {
	net.Listener
	trusted []netip.Prefix
	timeout time.Duration

	conns     chan net.Conn
	done      chan struct{} // closed by Close
	failed    chan struct{} // closed when the accept loop ends
	err       error         // why, set before failed is closed
	closeOnce sync.Once
}

// NewListener returns a listener whose connections are the ones of l with the
// PROXY protocol header already read: RemoteAddr reports the client address
// from the header (LocalAddr is the real one, so rules on the inbound port
// keep matching), and the stream starts right after the header.
//
// A connection is closed, and never returned by Accept, when its peer is not
// trusted or sends no header, a malformed one or none within the timeout: a
// trusted peer must send the header on every connection, there is no fallback
// to a bare stream. The headers are read in goroutines of their own, so a
// silent peer never holds up the accept loop.
//
// TCP only. UDP has no PROXY protocol header, the datagram listeners keep
// the address of their socket.
func NewListener(l net.Listener, config Config) net.Listener {
	pl := &listener{
		Listener: l,
		trusted:  config.Trusted,
		timeout:  config.Timeout,
		conns:    make(chan net.Conn),
		done:     make(chan struct{}),
		failed:   make(chan struct{}),
	}
	if len(pl.trusted) == 0 {
		pl.trusted = Loopback
	}
	if pl.timeout <= 0 {
		pl.timeout = DefaultTimeout
	}
	go pl.loop()
	return pl
}

func (l *listener) loop() {
	defer close(l.failed)
	var delay time.Duration
	for {
		conn, err := l.Listener.Accept()
		if err != nil {
			var temporary interface{ Temporary() bool }
			if errors.As(err, &temporary) && temporary.Temporary() {
				// out of file descriptors and the like: back off as net/http does
				if delay == 0 {
					delay = 5 * time.Millisecond
				} else if delay *= 2; delay > time.Second {
					delay = time.Second
				}
				select {
				case <-time.After(delay):
					continue
				case <-l.done:
				}
			}
			l.err = err
			return
		}
		delay = 0
		go l.handshake(conn)
	}
}

func (l *listener) handshake(conn net.Conn) {
	defer func() {
		if r := recover(); r != nil {
			log.Errorln("proxy protocol panic: %s\n%s", r, debug.Stack())
			_ = conn.Close()
		}
	}()
	raw := conn
	conn, err := accept(raw, l.trusted, l.timeout)
	if err != nil {
		_ = raw.Close()
		return
	}
	select {
	case l.conns <- conn:
	case <-l.done:
		_ = conn.Close()
	case <-l.failed:
		_ = conn.Close()
	}
}

func (l *listener) Accept() (net.Conn, error) {
	select {
	case conn := <-l.conns:
		return conn, nil
	case <-l.failed:
		return nil, l.err
	}
}

func (l *listener) Close() error {
	l.closeOnce.Do(func() { close(l.done) })
	return l.Listener.Close()
}

func accept(conn net.Conn, trusted []netip.Prefix, timeout time.Duration) (net.Conn, error) {
	peer, ok := peerAddr(conn.RemoteAddr())
	if !ok || !contains(trusted, peer.Addr()) {
		log.Debugln("[ProxyProtocol] %s is not a trusted peer, closing", conn.RemoteAddr())
		return nil, ErrNoHeader
	}
	if err := conn.SetReadDeadline(time.Now().Add(timeout)); err != nil {
		return nil, err
	}
	header, err := Read(conn)
	if err == nil {
		err = conn.SetReadDeadline(time.Time{})
	}
	if err != nil {
		log.Debugln("[ProxyProtocol] %s: %v", conn.RemoteAddr(), err)
		return nil, err
	}
	if header.Local {
		return conn, nil
	}
	return &Conn{
		Conn:   conn,
		remote: net.TCPAddrFromAddrPort(netip.AddrPortFrom(header.Source.Addr().Unmap(), header.Source.Port())),
	}, nil
}

func peerAddr(addr net.Addr) (netip.AddrPort, bool) {
	if tcp, ok := addr.(*net.TCPAddr); ok {
		ap := tcp.AddrPort()
		return netip.AddrPortFrom(ap.Addr().WithZone("").Unmap(), ap.Port()), ap.IsValid()
	}
	if addr == nil {
		return netip.AddrPort{}, false
	}
	ap, err := netip.ParseAddrPort(addr.String())
	return netip.AddrPortFrom(ap.Addr().WithZone("").Unmap(), ap.Port()), err == nil
}

func contains(prefixes []netip.Prefix, addr netip.Addr) bool {
	for _, prefix := range prefixes {
		if prefix.Contains(addr) {
			return true
		}
	}
	return false
}

// Conn is a connection whose RemoteAddr is the client address a PROXY
// protocol header carried.
type Conn struct {
	net.Conn
	remote net.Addr
}

// RemoteAddr returns the client address from the header.
func (c *Conn) RemoteAddr() net.Addr { return c.remote }

// Upstream lets the relay and the half-close find the TCP connection below.
func (c *Conn) Upstream() any { return c.Conn }

func (c *Conn) ReaderReplaceable() bool { return true }

func (c *Conn) WriterReplaceable() bool { return true }
