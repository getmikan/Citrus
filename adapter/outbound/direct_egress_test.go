package outbound

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/metacubex/mihomo/component/egress"
	"github.com/metacubex/mihomo/component/resolver"
	C "github.com/metacubex/mihomo/constant"

	D "github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// listResolver answers every lookup with the same addresses.
type listResolver struct{ ips []netip.Addr }

func (r *listResolver) LookupIP(context.Context, string) ([]netip.Addr, error) {
	return append([]netip.Addr(nil), r.ips...), nil
}

func (r *listResolver) LookupIPv4(ctx context.Context, host string) ([]netip.Addr, error) {
	return r.LookupIP(ctx, host)
}

func (r *listResolver) LookupIPv6(context.Context, string) ([]netip.Addr, error) {
	return nil, resolver.ErrIPv6Disabled
}

func (r *listResolver) ResolveECH(context.Context, string) ([]byte, error) {
	return nil, errors.New("not supported")
}

func (r *listResolver) ExchangeContext(context.Context, *D.Msg) (*D.Msg, error) {
	return nil, errors.New("not supported")
}

func (r *listResolver) Invalid() bool    { return true }
func (r *listResolver) ClearCache()      {}
func (r *listResolver) ResetConnection() {}

func withEgressOptions(t *testing.T, o egress.Options) {
	t.Helper()
	old := egress.CurrentOptions()
	egress.SetOptions(o)
	t.Cleanup(func() { egress.SetOptions(old) })
}

func withDirectResolver(t *testing.T, r resolver.Resolver) {
	t.Helper()
	oldDefault, oldDirect, oldV6 := resolver.DefaultResolver, resolver.DirectHostResolver, resolver.DisableIPv6
	resolver.DefaultResolver, resolver.DirectHostResolver, resolver.DisableIPv6 = r, r, true
	t.Cleanup(func() {
		resolver.DefaultResolver, resolver.DirectHostResolver, resolver.DisableIPv6 = oldDefault, oldDirect, oldV6
	})
}

func acceptAll(t *testing.T) netip.AddrPort {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			_ = c.Close()
		}
	}()
	return ln.Addr().(*net.TCPAddr).AddrPort()
}

func dialDirect(t *testing.T, metadata *C.Metadata) error {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	c, err := NewDirect().DialContext(ctx, metadata)
	if err == nil {
		_ = c.Close()
	}
	return err
}

func TestDirectEgressGuardTCP(t *testing.T) {
	withEgressOptions(t, egress.Options{Enable: true})
	target := acceptAll(t)
	withDirectResolver(t, &listResolver{ips: []netip.Addr{netip.MustParseAddr("127.0.0.1")}})

	literal := func(typ C.Type) *C.Metadata {
		return &C.Metadata{NetWork: C.TCP, Type: typ, InName: "in", DstIP: target.Addr(), DstPort: target.Port()}
	}
	domain := func(typ C.Type) *C.Metadata {
		return &C.Metadata{NetWork: C.TCP, Type: typ, InName: "in", Host: "rebind.example", DstPort: target.Port()}
	}

	err := dialDirect(t, literal(C.VLESS))
	assert.ErrorIs(t, err, egress.ErrBlocked, "an IP literal of the loopback")
	assert.ErrorIs(t, dialDirect(t, domain(C.TROJAN)), egress.ErrBlocked, "a domain that resolves to the loopback")

	// The rule-checked address is vetted too.
	checked := domain(C.SHADOWSOCKS)
	checked.DstIP, checked.DstIPChecked = target.Addr(), true
	assert.ErrorIs(t, dialDirect(t, checked), egress.ErrBlocked)

	// Client inbounds and the core itself are untouched.
	assert.NoError(t, dialDirect(t, literal(C.SOCKS5)))
	assert.NoError(t, dialDirect(t, domain(C.SOCKS5)))
	for _, typ := range []C.Type{C.HTTP, C.TUN, C.REDIR, C.TPROXY, C.TUNNEL, C.INNER} {
		// not ErrBlocked: a busy host may run out of ephemeral ports here
		assert.NotErrorIs(t, dialDirect(t, literal(typ)), egress.ErrBlocked, typ.String())
		assert.NotErrorIs(t, dialDirect(t, domain(typ)), egress.ErrBlocked, typ.String())
	}

	// The listener's own choice wins over the inbound type.
	off := literal(C.VLESS)
	off.EgressGuard = C.EgressGuardOff
	assert.NoError(t, dialDirect(t, off))
	on := literal(C.SOCKS5)
	on.EgressGuard = C.EgressGuardOn
	assert.ErrorIs(t, dialDirect(t, on), egress.ErrBlocked)
}

// Of the addresses a domain resolves to, the blocked ones are skipped and the
// allowed one is dialed (10.0.0.1 comes first and would not answer).
func TestDirectEgressGuardFiltersResolvedAddrs(t *testing.T) {
	withEgressOptions(t, egress.Options{Enable: true, AllowIPs: []netip.Prefix{netip.MustParsePrefix("127.0.0.1/32")}})
	target := acceptAll(t)
	withDirectResolver(t, &listResolver{ips: []netip.Addr{netip.MustParseAddr("10.0.0.1"), netip.MustParseAddr("127.0.0.1")}})

	assert.NoError(t, dialDirect(t, &C.Metadata{NetWork: C.TCP, Type: C.VLESS, Host: "mixed.example", DstPort: target.Port()}))

	// with the allow-list emptied neither address is reachable
	egress.SetOptions(egress.Options{Enable: true})
	assert.ErrorIs(t, dialDirect(t, &C.Metadata{NetWork: C.TCP, Type: C.VLESS, Host: "mixed.example", DstPort: target.Port()}), egress.ErrBlocked)
}

func TestDirectEgressGuardDisabled(t *testing.T) {
	withEgressOptions(t, egress.Options{Enable: false})
	target := acceptAll(t)
	assert.NoError(t, dialDirect(t, &C.Metadata{NetWork: C.TCP, Type: C.VLESS, DstIP: target.Addr(), DstPort: target.Port()}))
}

// A session whose first datagram goes to a blocked address is not refused:
// like REJECT, the datagram is dropped and the session stays, so a client
// that keeps sending to the LAN (mDNS, SSDP) is not dialed and logged again
// for every packet, and its datagrams to the allowed addresses still go out.
func TestDirectEgressGuardUDPBlockedFirst(t *testing.T) {
	withEgressOptions(t, egress.Options{Enable: true, AllowIPs: []netip.Prefix{netip.MustParsePrefix("127.0.0.1/32")}})
	withDirectResolver(t, &listResolver{ips: []netip.Addr{netip.MustParseAddr("127.0.0.2")}})

	allowed, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	require.NoError(t, err)
	defer allowed.Close()
	blocked, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 2)})
	if err != nil {
		t.Skipf("cannot listen on 127.0.0.2: %v", err)
	}
	defer blocked.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	blockedAddr := blocked.LocalAddr().(*net.UDPAddr).AddrPort()
	for _, metadata := range []*C.Metadata{
		{NetWork: C.UDP, Type: C.TUIC, DstIP: blockedAddr.Addr(), DstPort: blockedAddr.Port()},
		{NetWork: C.UDP, Type: C.HYSTERIA2, Host: "rebind.example", DstPort: blockedAddr.Port()}, // resolves to 127.0.0.2
	} {
		pc, err := NewDirect().ListenPacketContext(ctx, metadata)
		require.NoError(t, err, "%s: the session is opened", metadata.Type)

		_, err = pc.WriteTo([]byte("to-blocked"), blocked.LocalAddr())
		require.NoError(t, err, "dropped like a lost datagram")
		_, err = pc.WriteTo([]byte("to-allowed"), allowed.LocalAddr())
		require.NoError(t, err)

		buf := make([]byte, 64)
		_ = allowed.SetReadDeadline(time.Now().Add(2 * time.Second))
		n, _, err := allowed.ReadFromUDP(buf)
		require.NoError(t, err)
		assert.Equal(t, "to-allowed", string(buf[:n]))
		_ = blocked.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
		_, _, err = blocked.ReadFromUDP(buf)
		assert.Error(t, err, "nothing may reach the blocked address")
		_ = pc.Close()
	}

	pc, err := NewDirect().ListenPacketContext(ctx, &C.Metadata{NetWork: C.UDP, Type: C.SOCKS5, DstIP: blockedAddr.Addr(), DstPort: blockedAddr.Port()})
	require.NoError(t, err, "client inbounds are untouched")
	defer pc.Close()
	_, err = pc.WriteTo([]byte("from-client"), blocked.LocalAddr())
	require.NoError(t, err)
	buf := make([]byte, 64)
	_ = blocked.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, _, err := blocked.ReadFromUDP(buf)
	require.NoError(t, err)
	assert.Equal(t, "from-client", string(buf[:n]))
}

// The later datagrams of a guarded session: a blocked destination is dropped
// and the replies of a blocked source never reach the user.
func TestDirectEgressGuardUDPSession(t *testing.T) {
	withEgressOptions(t, egress.Options{Enable: true, AllowIPs: []netip.Prefix{netip.MustParsePrefix("127.0.0.1/32")}})

	allowed, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	require.NoError(t, err)
	defer allowed.Close()
	blocked, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 2)})
	if err != nil {
		t.Skipf("cannot listen on 127.0.0.2: %v", err)
	}
	defer blocked.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	allowedAddr := allowed.LocalAddr().(*net.UDPAddr).AddrPort()
	pc, err := NewDirect().ListenPacketContext(ctx, &C.Metadata{NetWork: C.UDP, Type: C.VLESS, DstIP: allowedAddr.Addr(), DstPort: allowedAddr.Port()})
	require.NoError(t, err)
	defer pc.Close()

	_, err = pc.WriteTo([]byte("to-blocked"), blocked.LocalAddr())
	require.NoError(t, err, "dropped like a lost datagram")
	_, err = pc.WriteTo([]byte("to-allowed"), allowed.LocalAddr())
	require.NoError(t, err)

	buf := make([]byte, 64)
	_ = allowed.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, from, err := allowed.ReadFromUDP(buf)
	require.NoError(t, err)
	assert.Equal(t, "to-allowed", string(buf[:n]))
	_ = blocked.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
	_, _, err = blocked.ReadFromUDP(buf)
	assert.Error(t, err, "nothing may reach the blocked address")

	// Both answer the session's socket; only the allowed answer comes through.
	session := netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), from.AddrPort().Port())
	_, err = blocked.WriteToUDPAddrPort([]byte("from-blocked"), session)
	require.NoError(t, err)
	_, err = allowed.WriteToUDPAddrPort([]byte("from-allowed"), session)
	require.NoError(t, err)

	_ = pc.SetReadDeadline(time.Now().Add(2 * time.Second))
	data, put, src, err := pc.WaitReadFrom()
	require.NoError(t, err)
	assert.Equal(t, "from-allowed", string(data))
	assert.Equal(t, allowed.LocalAddr().String(), src.String())
	if put != nil {
		put()
	}
}
