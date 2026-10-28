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

// on443 is the address s on port 443.
func on443(s string) netip.AddrPort {
	return netip.AddrPortFrom(netip.MustParseAddr(s), 443)
}

func TestForListenerOverride(t *testing.T) {
	withOptions(t, Options{Enable: true})
	assert.Nil(t, For(&C.Metadata{Type: C.VLESS, EgressGuard: C.EgressGuardOff}))
	assert.NotNil(t, For(&C.Metadata{Type: C.SOCKS5, EgressGuard: C.EgressGuardOn}))

	// enable: false turns off the default, not an explicit listener choice
	SetOptions(Options{Enable: false})
	assert.NoError(t, For(&C.Metadata{Type: C.VLESS}).CheckAddrPort(on443("127.0.0.1")))
	assert.ErrorIs(t, For(&C.Metadata{Type: C.SOCKS5, EgressGuard: C.EgressGuardOn}).CheckAddrPort(on443("127.0.0.1")), ErrBlocked)
}

// A guard reads the config at every check, so a reload reaches the UDP
// sessions already open: a narrowed allow-list or a guard turned back on
// applies to their next datagram.
func TestGuardFollowsReload(t *testing.T) {
	withOptions(t, Options{Enable: true, AllowIPs: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}})
	g := For(&C.Metadata{Type: C.TUIC})
	assert.NoError(t, g.CheckAddrPort(on443("10.1.2.3")))

	SetOptions(Options{Enable: true})
	assert.ErrorIs(t, g.CheckAddrPort(on443("10.1.2.3")), ErrBlocked, "the narrowed allow-list applies")

	SetOptions(Options{Enable: false})
	assert.NoError(t, g.CheckAddrPort(on443("10.1.2.3")), "turned off")
	SetOptions(Options{Enable: true})
	assert.ErrorIs(t, g.CheckAddrPort(on443("10.1.2.3")), ErrBlocked, "turned on again")
}

// An address:port entry exempts that port and nothing else: a website on this
// host's public address stays reachable, its controller port does not.
func TestCheckAddrPortAllowAddrPorts(t *testing.T) {
	public := netip.MustParseAddr("93.184.216.34") // standing in for the server's public address
	oldIsLocal := isLocalIP
	isLocalIP = func(addr netip.Addr) bool { return addr == public }
	t.Cleanup(func() { isLocalIP = oldIsLocal })
	withOptions(t, Options{Enable: true, AllowAddrPorts: []netip.AddrPort{
		netip.AddrPortFrom(public, 443),
		netip.MustParseAddrPort("[::ffff:10.0.0.5]:5432"), // unmapped by SetOptions
	}})
	g := For(&C.Metadata{Type: C.VLESS})

	assert.NoError(t, g.CheckAddrPort(netip.AddrPortFrom(public, 443)))
	assert.ErrorIs(t, g.CheckAddrPort(netip.AddrPortFrom(public, 9090)), ErrBlocked)
	assert.NoError(t, g.CheckAddrPort(netip.MustParseAddrPort("10.0.0.5:5432")))
	assert.ErrorIs(t, g.CheckAddrPort(netip.MustParseAddrPort("10.0.0.5:22")), ErrBlocked)
	assert.ErrorIs(t, g.CheckAddrPort(netip.MustParseAddrPort("10.0.0.6:5432")), ErrBlocked)
}

// fqdnAddr is a net.Addr of a domain, like an M.Socksaddr with an FQDN.
type fqdnAddr string

func (a fqdnAddr) Network() string { return "udp" }
func (a fqdnAddr) String() string  { return string(a) }

// A datagram address the guard cannot check is refused rather than let
// through: a domain, a nil address, an address without an IP (which a socket
// sends to this host).
func TestCheckNetAddrFailsClosed(t *testing.T) {
	withOptions(t, Options{Enable: true})
	g := For(&C.Metadata{Type: C.HYSTERIA2})
	var nilUDP *net.UDPAddr
	for _, addr := range []net.Addr{fqdnAddr("metadata.google.internal:80"), nil, nilUDP, &net.UDPAddr{Port: 53}} {
		assert.ErrorIs(t, g.checkNetAddr(addr), ErrBlocked, "%#v", addr)
	}
	assert.NoError(t, g.checkNetAddr(fqdnAddr("1.1.1.1:53")), "an IP in another net.Addr type is checked")
	assert.ErrorIs(t, g.checkNetAddr(fqdnAddr("[fe80::1%eth0]:53")), ErrBlocked)

	SetOptions(Options{Enable: false})
	assert.NoError(t, g.checkNetAddr(fqdnAddr("metadata.google.internal:80")), "nothing is refused while the guard is off")
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
		err := g.CheckAddrPort(on443(s))
		if assert.Error(t, err, s) {
			assert.ErrorIs(t, err, ErrBlocked, s)
			var be *BlockedError
			require.True(t, errors.As(err, &be))
			assert.Contains(t, err.Error(), "vless-in (user alice)")
		}
	}

	for _, s := range []string{"1.1.1.1", "93.184.216.34", "2606:4700::1111", "64:ff9b::5db8:d822"} {
		assert.NoError(t, g.CheckAddrPort(on443(s)), s)
	}
}

func TestCheckAddrAllowIPs(t *testing.T) {
	withOptions(t, Options{Enable: true, AllowIPs: []netip.Prefix{
		netip.MustParsePrefix("10.8.0.0/24"),
		netip.MustParsePrefix("fd00:ec2::254/128"),
	}})
	g := For(&C.Metadata{Type: C.TROJAN})
	require.NotNil(t, g)

	assert.NoError(t, g.CheckAddrPort(on443("10.8.0.7")))
	assert.NoError(t, g.CheckAddrPort(on443("::ffff:10.8.0.7")))
	assert.NoError(t, g.CheckAddrPort(on443("fd00:ec2::254")))
	assert.ErrorIs(t, g.CheckAddrPort(on443("10.8.1.7")), ErrBlocked)
	assert.ErrorIs(t, g.CheckAddrPort(on443("169.254.169.254")), ErrBlocked)
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
	err := g.CheckAddrPort(netip.AddrPortFrom(public, 443))
	assert.ErrorIs(t, err, ErrBlocked)
	assert.Contains(t, err.Error(), "address of this host")
	assert.NoError(t, g.CheckAddrPort(on443("1.1.1.1")))
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
