package inbound_test

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"testing"
	"time"

	"github.com/metacubex/mihomo/adapter"
	"github.com/metacubex/mihomo/adapter/outbound"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/listener/inbound"
	"github.com/metacubex/mihomo/tunnel"
	"github.com/metacubex/mihomo/tunnel/statistic"

	"github.com/stretchr/testify/require"
)

func startUDPEcho(t *testing.T) netip.AddrPort {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = pc.Close() })
	go func() {
		buf := make([]byte, 2048)
		for {
			n, from, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			_, _ = pc.WriteTo(buf[:n], from)
		}
	}()
	return pc.LocalAddr().(*net.UDPAddr).AddrPort()
}

// udpRoundTrip opens a UDP association through out and echoes one datagram.
func udpRoundTrip(out C.ProxyAdapter, echo netip.AddrPort, timeout time.Duration) (net.PacketConn, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	pc, err := out.ListenPacketContext(ctx, &C.Metadata{NetWork: C.UDP, DstIP: echo.Addr(), DstPort: echo.Port()})
	if err != nil {
		return nil, err
	}
	payload := []byte("citrus-socks-udp")
	_ = pc.SetDeadline(time.Now().Add(timeout))
	if _, err = pc.WriteTo(payload, net.UDPAddrFromAddrPort(echo)); err != nil {
		_ = pc.Close()
		return nil, err
	}
	buf := make([]byte, 1024)
	n, _, err := pc.ReadFrom(buf)
	if err != nil {
		_ = pc.Close()
		return nil, err
	}
	if string(buf[:n]) != string(payload) {
		_ = pc.Close()
		return nil, fmt.Errorf("echo mismatch: %q", buf[:n])
	}
	_ = pc.SetDeadline(time.Time{})
	return pc, nil
}

// UDP relayed through a SOCKS5 UDP ASSOCIATE carries the user that
// authenticated the association, so its flows are counted and limited per
// user. The client is the stock SOCKS5 outbound (it asks for 0.0.0.0:0).
func TestInboundSocksUDPUser(t *testing.T) {
	tunnel.UpdateProxies(map[string]C.Proxy{"DIRECT": adapter.NewProxy(outbound.NewDirect())}, nil)
	tunnel.OnRunning()
	name := fmt.Sprintf("socks-udp-user-%d", time.Now().UnixNano())
	// the UDP relay is on the port of the TCP listener: take a free TCP port
	// and listen on it with both. A free UDP port can fall in a range Windows
	// reserves for TCP, and then the TCP bind is refused.
	var in *inbound.Socks
	var err error
	for i := 0; i < 20; i++ {
		var probe net.Listener
		probe, err = net.Listen("tcp", "127.0.0.1:0")
		require.NoError(t, err)
		port := probe.Addr().(*net.TCPAddr).Port
		_ = probe.Close()
		in, err = inbound.NewSocks(&inbound.SocksOption{
			BaseOption: inbound.BaseOption{NameStr: name, Listen: "127.0.0.1", Port: strconv.Itoa(port)},
			Users:      inbound.AuthUsers{{Username: "alice", Password: "alice-pass"}},
			UDP:        true,
		})
		require.NoError(t, err)
		if err = in.Listen(tunnel.Tunnel); err == nil {
			break
		}
		_ = in.Close()
	}
	require.NoError(t, err)
	t.Cleanup(func() { _ = in.Close() })

	um := statistic.DefaultManager.Users()
	limit := statistic.UserLimit{Inbound: name, User: "alice", MaxConns: 1}
	require.NoError(t, um.SetLimit(limit))
	t.Cleanup(func() { um.DeleteLimit(limit.Key()) })

	addr, err := netip.ParseAddrPort(in.Address())
	require.NoError(t, err)
	out, err := outbound.NewSocks5(outbound.Socks5Option{
		Name: "socks-udp-user", Server: addr.Addr().String(), Port: int(addr.Port()),
		UserName: "alice", Password: "alice-pass", UDP: true,
	})
	require.NoError(t, err)
	echo := startUDPEcho(t)

	first, err := udpRoundTrip(out, echo, 5*time.Second)
	require.NoError(t, err)
	defer first.Close()
	stat, ok := um.Get(statistic.UserKey{Inbound: name, User: "alice"})
	require.True(t, ok, "the UDP flow was not counted for its user")
	require.Equal(t, int64(1), stat.Conns)

	// max-conns 1: a second UDP flow of alice is refused
	second, err := udpRoundTrip(out, echo, time.Second)
	if second != nil {
		_ = second.Close()
	}
	require.Error(t, err)
	stat, _ = um.Get(statistic.UserKey{Inbound: name, User: "alice"})
	require.Equal(t, int64(1), stat.RejectReasons[statistic.RejectMaxConns], strconv.Quote(fmt.Sprint(stat.RejectReasons)))
}
