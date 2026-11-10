package inbound_test

import (
	"context"
	"net"
	"net/netip"
	"strconv"
	"testing"
	"time"

	"github.com/metacubex/mihomo/adapter/outbound"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/listener/inbound"
	"github.com/metacubex/mihomo/transport/socks5"
	"github.com/metacubex/mihomo/transport/trojan"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The additions of a listener are shared by all its connections, and a
// connection appends its user to them: with room for one more entry, every
// connection would write its user into the same slot of the same array.
func TestBaseOptionAdditionsHaveNoSpareCapacity(t *testing.T) {
	on, off := true, false
	for name, guard := range map[string]*bool{"unset": nil, "true": &on, "false": &off} {
		additions := inbound.BaseOption{NameStr: "in", EgressGuard: guard}.Additions()
		assert.Equal(t, len(additions), cap(additions), "egress-guard %s", name)
	}
}

// userTunnel passes the user of every connection and datagram it is handed
// to users.
func userTunnel(users chan<- string) *TestTunnel {
	return &TestTunnel{
		HandleTCPConnFn: func(conn net.Conn, metadata *C.Metadata) {
			users <- metadata.InUser
			_ = conn.Close()
		},
		HandleUDPPacketFn: func(packet C.UDPPacket, metadata *C.Metadata) {
			users <- metadata.InUser
			packet.Drop()
		},
		CloseFn: func() error { return nil },
	}
}

func nextUser(t *testing.T, users <-chan string) string {
	t.Helper()
	select {
	case user := <-users:
		return user
	case <-time.After(5 * time.Second):
		require.FailNow(t, "nothing reached the tunnel")
		return ""
	}
}

// A UDP session keeps its Trojan user after another user authenticated on
// the same listener with egress-guard set: its datagrams went on as the
// other user when the connections shared their additions.
func TestInboundTrojanUserPerSession(t *testing.T) {
	guard := true
	in, err := inbound.NewTrojan(&inbound.TrojanOption{
		BaseOption:    inbound.BaseOption{NameStr: "trojan-users", Listen: "127.0.0.1", Port: "0", EgressGuard: &guard},
		Users:         []inbound.TrojanUser{{Username: "alice", Password: "alice-password"}, {Username: "bob", Password: "bob-password"}},
		AllowInsecure: true, // plain TCP, the protocol by hand
	})
	require.NoError(t, err)
	users := make(chan string, 8)
	require.NoError(t, in.Listen(userTunnel(users)))
	t.Cleanup(func() { _ = in.Close() })

	target := socks5.ParseAddr("1.1.1.1:53")
	dial := func(password string, command trojan.Command) net.Conn {
		conn, err := net.Dial("tcp", in.Address())
		require.NoError(t, err)
		t.Cleanup(func() { _ = conn.Close() })
		require.NoError(t, trojan.WriteHeader(conn, trojan.Key(password), command, target))
		return conn
	}

	alice := dial("alice-password", trojan.CommandUDP)
	_, err = trojan.WritePacket(alice, target, []byte("one"))
	require.NoError(t, err)
	assert.Equal(t, "alice", nextUser(t, users))

	dial("bob-password", trojan.CommandTCP)
	assert.Equal(t, "bob", nextUser(t, users))

	_, err = trojan.WritePacket(alice, target, []byte("two"))
	require.NoError(t, err)
	assert.Equal(t, "alice", nextUser(t, users), "a datagram of alice's session after bob authenticated")
}

// The same for the UDP association of Mieru, over its TCP transport.
func TestInboundMieruUserPerSession(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = l.Close() })
	guard := true
	in, err := inbound.NewMieru(&inbound.MieruOption{
		BaseOption: inbound.BaseOption{
			NameStr:     "mieru-users",
			Listen:      "127.0.0.1",
			Port:        strconv.Itoa(l.Addr().(*net.TCPAddr).Port),
			EgressGuard: &guard,
			ListenConfigForAPI: mieruTestInboundListenConfig{
				ListenFn: func(context.Context, string, string) (net.Listener, error) { return l, nil },
				ListenPacketFn: func(context.Context, string, string) (net.PacketConn, error) {
					panic("should not be called")
				},
			},
		},
		Transport: "TCP",
		Users:     map[string]string{"alice": "alice-password", "bob": "bob-password"},
	})
	require.NoError(t, err)
	users := make(chan string, 8)
	require.NoError(t, in.Listen(userTunnel(users)))
	t.Cleanup(func() { _ = in.Close() })
	addrPort, err := netip.ParseAddrPort(in.Address())
	require.NoError(t, err)

	target := &net.UDPAddr{IP: net.IPv4(1, 1, 1, 1), Port: 53}
	session := func(user string) C.PacketConn {
		out, err := outbound.NewMieru(outbound.MieruOption{
			Name:      "mieru-" + user,
			Server:    addrPort.Addr().String(),
			Port:      int(addrPort.Port()),
			Transport: "TCP",
			UserName:  user,
			Password:  user + "-password",
		})
		require.NoError(t, err)
		t.Cleanup(func() { _ = out.Close() })
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		pc, err := out.ListenPacketContext(ctx, &C.Metadata{NetWork: C.UDP, DstIP: netip.MustParseAddr("1.1.1.1"), DstPort: 53})
		require.NoError(t, err)
		t.Cleanup(func() { _ = pc.Close() })
		return pc
	}

	alice := session("alice")
	_, err = alice.WriteTo([]byte("one"), target)
	require.NoError(t, err)
	assert.Equal(t, "alice", nextUser(t, users))

	bob := session("bob")
	_, err = bob.WriteTo([]byte("one"), target)
	require.NoError(t, err)
	assert.Equal(t, "bob", nextUser(t, users))

	_, err = alice.WriteTo([]byte("two"), target)
	require.NoError(t, err)
	assert.Equal(t, "alice", nextUser(t, users), "a datagram of alice's session after bob's began")
}
