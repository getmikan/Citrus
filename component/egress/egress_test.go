package egress

import (
	"errors"
	"net"
	"net/netip"
	"syscall"
	"testing"

	C "github.com/metacubex/mihomo/constant"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// withOptions publishes o for one test and restores the default afterwards.
func withOptions(t *testing.T, o Options) {
	t.Helper()
	old := CurrentOptions()
	SetOptions(o)
	t.Cleanup(func() { SetOptions(old) })
}

func TestForInboundTypes(t *testing.T) {
	withOptions(t, Options{Enable: true})

	for _, typ := range []C.Type{C.SHADOWSOCKS, C.SNELL, C.VLESS, C.TROJAN, C.TUIC, C.HYSTERIA2,
		C.ANYTLS, C.MIERU, C.SUDOKU, C.TRUSTTUNNEL, C.SHADOWQUIC} {
		assert.NotNil(t, For(&C.Metadata{Type: typ}), "%s is a server inbound and must be guarded", typ)
	}
	for _, typ := range []C.Type{C.HTTP, C.HTTPS, C.SOCKS4, C.SOCKS5, C.REDIR, C.TPROXY, C.TUN, C.TUNNEL, C.INNER} {
		assert.Nil(t, For(&C.Metadata{Type: typ}), "%s is a client inbound and must stay unguarded", typ)
	}
}

func TestForListenerOverride(t *testing.T) {
	withOptions(t, Options{Enable: true})
	assert.Nil(t, For(&C.Metadata{Type: C.VLESS, EgressGuard: C.EgressGuardOff}))
	assert.NotNil(t, For(&C.Metadata{Type: C.SOCKS5, EgressGuard: C.EgressGuardOn}))

	// enable: false turns off the default, not an explicit listener choice
	SetOptions(Options{Enable: false})
	assert.Nil(t, For(&C.Metadata{Type: C.VLESS}))
	assert.NotNil(t, For(&C.Metadata{Type: C.SOCKS5, EgressGuard: C.EgressGuardOn}))
}

func TestCheckAddr(t *testing.T) {
	withOptions(t, Options{Enable: true})
	g := For(&C.Metadata{Type: C.VLESS, InName: "vless-in", InUser: "alice"})
	require.NotNil(t, g)

	blocked := []string{
		"127.0.0.1", "127.8.9.10", "::1", "::ffff:127.0.0.1", // loopback, also IPv4-mapped
		"0.0.0.0", "::", // unspecified
		"10.1.2.3", "172.16.0.1", "192.168.1.1", "fd12:3456::1", // private, ULA
		"100.64.0.1",                                  // CGNAT
		"169.254.169.254", "fe80::1", "169.254.170.2", // link-local, AWS/GCP/Azure metadata, ECS
		"fd00:ec2::254",                           // AWS metadata over IPv6
		"100.100.100.200",                         // Alibaba Cloud metadata
		"192.0.0.192",                             // Oracle Cloud metadata
		"224.0.0.1", "239.255.255.250", "ff02::1", // multicast
		"255.255.255.255", "240.0.0.1", // broadcast, reserved
		"64:ff9b::a00:1", // NAT64 of 10.0.0.1
		"2002:7f00:1::1", // 6to4 of 127.0.0.1
		"198.18.0.1",     // benchmarking, the default fake-ip range
	}
	for _, s := range blocked {
		err := g.CheckAddr(netip.MustParseAddr(s))
		if assert.Error(t, err, s) {
			assert.ErrorIs(t, err, ErrBlocked, s)
			var be *BlockedError
			require.True(t, errors.As(err, &be))
			assert.Contains(t, err.Error(), "vless-in (user alice)")
		}
	}

	for _, s := range []string{"1.1.1.1", "93.184.216.34", "2606:4700::1111", "64:ff9b::5db8:d822"} {
		assert.NoError(t, g.CheckAddr(netip.MustParseAddr(s)), s)
	}
}

func TestCheckAddrAllowIPs(t *testing.T) {
	withOptions(t, Options{Enable: true, AllowIPs: []netip.Prefix{
		netip.MustParsePrefix("10.8.0.0/24"),
		netip.MustParsePrefix("fd00:ec2::254/128"),
	}})
	g := For(&C.Metadata{Type: C.TROJAN})
	require.NotNil(t, g)

	assert.NoError(t, g.CheckAddr(netip.MustParseAddr("10.8.0.7")))
	assert.NoError(t, g.CheckAddr(netip.MustParseAddr("::ffff:10.8.0.7")))
	assert.NoError(t, g.CheckAddr(netip.MustParseAddr("fd00:ec2::254")))
	assert.ErrorIs(t, g.CheckAddr(netip.MustParseAddr("10.8.1.7")), ErrBlocked)
	assert.ErrorIs(t, g.CheckAddr(netip.MustParseAddr("169.254.169.254")), ErrBlocked)
}

// A public address that belongs to this host (the controller, the inbounds
// and every other local service listen on it) is refused too.
func TestCheckAddrOwnAddress(t *testing.T) {
	withOptions(t, Options{Enable: true})
	public := netip.MustParseAddr("93.184.216.34") // standing in for the server's public address
	oldIsLocal := isLocalIP
	isLocalIP = func(addr netip.Addr) bool { return addr == public }
	t.Cleanup(func() { isLocalIP = oldIsLocal })

	g := For(&C.Metadata{Type: C.TUIC})
	err := g.CheckAddr(public)
	assert.ErrorIs(t, err, ErrBlocked)
	assert.Contains(t, err.Error(), "address of this host")
	assert.NoError(t, g.CheckAddr(netip.MustParseAddr("1.1.1.1")))
}

// fakePacketConn records the datagrams written to it and hands out queued ones.
type fakePacketConn struct {
	net.PacketConn
	written []net.Addr
	queue   []net.Addr
}

func (c *fakePacketConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	c.written = append(c.written, addr)
	return len(p), nil
}

func (c *fakePacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	if len(c.queue) == 0 {
		return 0, nil, net.ErrClosed
	}
	addr := c.queue[0]
	c.queue = c.queue[1:]
	return copy(p, "x"), addr, nil
}

func (c *fakePacketConn) LocalAddr() net.Addr { return &net.UDPAddr{IP: net.IPv4zero} }

func udpAddr(s string) *net.UDPAddr {
	return net.UDPAddrFromAddrPort(netip.MustParseAddrPort(s))
}

func TestPacketConn(t *testing.T) {
	withOptions(t, Options{Enable: true})
	g := For(&C.Metadata{Type: C.HYSTERIA2})
	raw := &fakePacketConn{queue: []net.Addr{
		udpAddr("192.168.1.1:53"),     // a LAN host answering: dropped
		udpAddr("169.254.169.254:80"), // dropped
		udpAddr("1.1.1.1:53"),
		udpAddr("[fe80::1]:53"), // dropped
		udpAddr("8.8.8.8:53"),
	}}
	pc := NewPacketConn(raw, g)

	n, err := pc.WriteTo([]byte("query"), udpAddr("10.0.0.1:53"))
	assert.NoError(t, err, "a blocked datagram is dropped, not an error that ends the session")
	assert.Equal(t, 5, n)
	_, err = pc.WriteTo([]byte("query"), udpAddr("[::ffff:127.0.0.1]:53"))
	assert.NoError(t, err)
	_, err = pc.WriteTo([]byte("query"), udpAddr("1.1.1.1:53"))
	assert.NoError(t, err)
	assert.Equal(t, []net.Addr{udpAddr("1.1.1.1:53")}, raw.written, "only the public destination may be sent to")

	buf := make([]byte, 16)
	_, from, err := pc.ReadFrom(buf)
	require.NoError(t, err)
	assert.Equal(t, "1.1.1.1:53", from.String())

	epc, ok := pc.(interface {
		WaitReadFrom() ([]byte, func(), net.Addr, error)
	})
	require.True(t, ok)
	_, put, from, err := epc.WaitReadFrom()
	require.NoError(t, err)
	if put != nil {
		put()
	}
	assert.Equal(t, "8.8.8.8:53", from.String())

	_, _, err = pc.ReadFrom(buf)
	assert.ErrorIs(t, err, net.ErrClosed)
}

func TestPacketConnKeepsSyscallConn(t *testing.T) {
	withOptions(t, Options{Enable: true})
	udp, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	require.NoError(t, err)
	defer udp.Close()
	pc := NewPacketConn(udp, For(&C.Metadata{Type: C.VLESS}))
	_, ok := pc.(syscall.Conn)
	assert.True(t, ok, "a guarded UDP socket must still look like a system conn")
}
