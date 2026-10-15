package loopback

import (
	"errors"
	"net"
	"net/netip"
	"testing"

	C "github.com/metacubex/mihomo/constant"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type fakeConn struct {
	C.Conn
	local, remote net.Addr
}

func (c *fakeConn) LocalAddr() net.Addr  { return c.local }
func (c *fakeConn) RemoteAddr() net.Addr { return c.remote }
func (c *fakeConn) Close() error         { return nil }

type fakePacketConn struct {
	C.PacketConn
	local net.Addr
}

func (c *fakePacketConn) LocalAddr() net.Addr { return c.local }
func (c *fakePacketConn) Close() error        { return nil }

func tcpAddr(s string) *net.TCPAddr {
	return net.TCPAddrFromAddrPort(netip.MustParseAddrPort(s))
}

func udpAddr(s string) *net.UDPAddr {
	return net.UDPAddrFromAddrPort(netip.MustParseAddrPort(s))
}

// inboundMetadata describes a TCP connection that arrived on a listener at
// in from src, asking for dst (empty when the target is a domain).
func inboundMetadata(src, in, dst string) *C.Metadata {
	m := &C.Metadata{NetWork: C.TCP}
	s := netip.MustParseAddrPort(src)
	m.SrcIP, m.SrcPort = s.Addr(), s.Port()
	i := netip.MustParseAddrPort(in)
	m.InIP, m.InPort = i.Addr(), i.Port()
	if dst != "" {
		d := netip.MustParseAddrPort(dst)
		m.DstIP, m.DstPort = d.Addr(), d.Port()
	} else {
		m.Host, m.DstPort = "example.com", 443
	}
	return m
}

func newTestDetector(t *testing.T) *Detector {
	t.Helper()
	if disableLoopBackDetector {
		t.Skip("loopback detector disabled")
	}
	return NewDetector()
}

// TestDetectorRealLoopRejected: DIRECT dialed the listener's own address, so
// the listener sees DIRECT's local address as the source and itself as the
// destination.
func TestDetectorRealLoopRejected(t *testing.T) {
	l := newTestDetector(t)
	conn := l.NewConn(&fakeConn{local: tcpAddr("127.0.0.1:40000"), remote: tcpAddr("127.0.0.1:7890")})

	err := l.CheckConn(inboundMetadata("127.0.0.1:40000", "127.0.0.1:7890", "127.0.0.1:7890"))
	assert.True(t, errors.Is(err, ErrReject), "a loop through the listener must be rejected, got %v", err)

	// An explicit proxy loop: whatever target the looped request asks for,
	// the listener address is the destination of the looped connection.
	err = l.CheckConn(inboundMetadata("127.0.0.1:40000", "127.0.0.1:7890", "93.184.216.34:443"))
	assert.True(t, errors.Is(err, ErrReject), "a loop through the listener must be rejected, got %v", err)
	err = l.CheckConn(inboundMetadata("127.0.0.1:40000", "127.0.0.1:7890", ""))
	assert.True(t, errors.Is(err, ErrReject), "a loop through the listener must be rejected, got %v", err)

	require.NoError(t, conn.Close())
	assert.NoError(t, l.CheckConn(inboundMetadata("127.0.0.1:40000", "127.0.0.1:7890", "127.0.0.1:7890")),
		"a closed DIRECT connection must not reject anything")
}

// TestDetectorTransparentLoopRejected: a DIRECT connection captured back by
// tun/tproxy keeps its original destination; the inbound address is the
// capturing listener, not DIRECT's remote.
func TestDetectorTransparentLoopRejected(t *testing.T) {
	l := newTestDetector(t)
	l.NewConn(&fakeConn{local: tcpAddr("192.168.1.10:40000"), remote: tcpAddr("93.184.216.34:443")})

	err := l.CheckConn(inboundMetadata("192.168.1.10:40000", "198.18.0.1:7893", "93.184.216.34:443"))
	assert.True(t, errors.Is(err, ErrReject), "a captured DIRECT connection must be rejected, got %v", err)
}

// TestDetectorSharedSourcePortAllowed: the kernel reuses an ephemeral port for
// connections towards different destinations. A local client whose source
// address matches a live DIRECT connection's, but which connects elsewhere,
// is not a loop.
func TestDetectorSharedSourcePortAllowed(t *testing.T) {
	l := newTestDetector(t)
	// DIRECT: 127.0.0.1:40000 -> 127.0.0.1:8080 (some local service).
	l.NewConn(&fakeConn{local: tcpAddr("127.0.0.1:40000"), remote: tcpAddr("127.0.0.1:8080")})

	// Client: 127.0.0.1:40000 -> Citrus listener 127.0.0.1:7890.
	assert.NoError(t, l.CheckConn(inboundMetadata("127.0.0.1:40000", "127.0.0.1:7890", "1.1.1.1:443")))
	assert.NoError(t, l.CheckConn(inboundMetadata("127.0.0.1:40000", "127.0.0.1:7890", "")))
}

func TestDetectorMappedAddresses(t *testing.T) {
	l := newTestDetector(t)
	l.NewConn(&fakeConn{local: tcpAddr("[::ffff:127.0.0.1]:40000"), remote: tcpAddr("[::ffff:127.0.0.1]:7890")})

	m := inboundMetadata("127.0.0.1:40000", "127.0.0.1:7890", "")
	m.InIP = netip.MustParseAddr("::ffff:127.0.0.1")
	assert.True(t, errors.Is(l.CheckConn(m), ErrReject))
}

func TestDetectorPacketConn(t *testing.T) {
	l := newTestDetector(t)
	udpMetadata := func(src string) *C.Metadata {
		m := &C.Metadata{NetWork: C.UDP}
		s := netip.MustParseAddrPort(src)
		m.SrcIP, m.SrcPort = s.Addr(), s.Port()
		return m
	}

	wildcard := l.NewPacketConn(&fakePacketConn{local: udpAddr("[::]:50000")})
	assert.True(t, errors.Is(l.CheckPacketConn(udpMetadata("127.0.0.1:50000")), ErrReject),
		"a wildcard-bound DIRECT socket owns the port on every local address")
	assert.NoError(t, l.CheckPacketConn(udpMetadata("127.0.0.1:50001")))
	require.NoError(t, wildcard.Close())
	assert.NoError(t, l.CheckPacketConn(udpMetadata("127.0.0.1:50000")))

	// Bound to one address: the same port on another local address belongs
	// to another socket.
	l.NewPacketConn(&fakePacketConn{local: udpAddr("127.0.0.2:50002")})
	assert.True(t, errors.Is(l.CheckPacketConn(udpMetadata("127.0.0.2:50002")), ErrReject))
	assert.NoError(t, l.CheckPacketConn(udpMetadata("127.0.0.1:50002")))
}
