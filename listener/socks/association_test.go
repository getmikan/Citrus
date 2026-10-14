package socks

import (
	"net"
	"testing"
	"time"

	"github.com/metacubex/mihomo/adapter/inbound"
	"github.com/metacubex/mihomo/component/auth"
	C "github.com/metacubex/mihomo/constant"
	authStore "github.com/metacubex/mihomo/listener/auth"
	LC "github.com/metacubex/mihomo/listener/config"
	"github.com/metacubex/mihomo/transport/socks5"

	"github.com/stretchr/testify/require"
)

type udpRecorder struct {
	packets chan *C.Metadata
}

func (t *udpRecorder) HandleTCPConn(conn net.Conn, metadata *C.Metadata) { _ = conn.Close() }

func (t *udpRecorder) HandleUDPPacket(packet C.UDPPacket, metadata *C.Metadata) {
	packet.Drop()
	t.packets <- metadata
}

func (t *udpRecorder) NatTable() C.NatTable { return nil }

func (t *udpRecorder) received(timeout time.Duration) bool {
	select {
	case <-t.packets:
		return true
	case <-time.After(timeout):
		return false
	}
}

func newSocksPair(t *testing.T, store auth.AuthStore) (*Listener, *UDPListener, *udpRecorder) {
	t.Helper()
	tunnel := &udpRecorder{packets: make(chan *C.Metadata, 16)}
	additions := []inbound.Addition{inbound.WithInName("test-socks")}

	// The UDP listener shares the TCP listener's port, as the real inbounds do.
	// Free TCP ports come out sequentially and a run of them can fall inside an
	// excluded UDP range on Windows, so take a free UDP port first and open TCP
	// on it, falling back to the other order.
	newTCP := func(listen string) (*Listener, error) {
		return NewWithConfig(LC.AuthServer{Enable: true, Listen: listen, AuthStore: store}, inbound.NewListenConfig(), tunnel, additions...)
	}
	newUDP := func(listen string) (*UDPListener, error) {
		return NewUDPWithConfig(LC.AuthServer{Enable: true, Listen: listen, AuthStore: store}, inbound.NewListenConfig(), tunnel, additions...)
	}
	var tcp *Listener
	var udp *UDPListener
	var err error
	for i := 0; i < 20; i++ {
		udp, err = newUDP("127.0.0.1:0")
		require.NoError(t, err)
		if tcp, err = newTCP(udp.Address()); err == nil {
			break
		}
		_ = udp.Close()

		tcp, err = newTCP("127.0.0.1:0")
		require.NoError(t, err)
		if udp, err = newUDP(tcp.Address()); err == nil {
			break
		}
		_ = tcp.Close()
	}
	require.NoError(t, err)
	t.Cleanup(func() {
		_ = tcp.Close()
		_ = udp.Close()
	})
	return tcp, udp, tunnel
}

func sendSocksUDP(t *testing.T, client net.PacketConn, to string) {
	t.Helper()
	pkt, err := socks5.EncodeUDPPacket(socks5.ParseAddr("1.1.1.1:53"), []byte("ping"))
	require.NoError(t, err)
	addr, err := net.ResolveUDPAddr("udp", to)
	require.NoError(t, err)
	_, err = client.WriteTo(pkt, addr)
	require.NoError(t, err)
}

func associate(t *testing.T, addr string, user *socks5.User) net.Conn {
	t.Helper()
	conn, err := net.Dial("tcp", addr)
	require.NoError(t, err)
	_, err = socks5.ClientHandshake(conn, socks5.ParseAddr("0.0.0.0:0"), socks5.CmdUDPAssociate, user)
	require.NoError(t, err)
	return conn
}

func waitAssociation(t *testing.T, udp *UDPListener, client net.PacketConn, want bool) {
	t.Helper()
	require.Eventually(t, func() bool {
		return hasAssociation(udp.packetConn.LocalAddr(), client.LocalAddr()) == want
	}, 2*time.Second, 10*time.Millisecond)
}

func TestSocksUDPRequiresAssociationWithAuth(t *testing.T) {
	store := authStore.NewAuthStore(auth.NewAuthenticator([]auth.AuthUser{{User: "u", Pass: "p"}}))
	tcp, udp, tunnel := newSocksPair(t, store)

	client, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)
	defer client.Close()

	// No association: dropped.
	sendSocksUDP(t, client, udp.Address())
	require.False(t, tunnel.received(300*time.Millisecond), "datagram relayed without UDP ASSOCIATE")

	// Wrong credentials: the handshake fails and nothing is associated.
	bad, err := net.Dial("tcp", tcp.Address())
	require.NoError(t, err)
	_, err = socks5.ClientHandshake(bad, socks5.ParseAddr("0.0.0.0:0"), socks5.CmdUDPAssociate, &socks5.User{Username: "u", Password: "wrong"})
	require.Error(t, err)
	_ = bad.Close()
	sendSocksUDP(t, client, udp.Address())
	require.False(t, tunnel.received(300*time.Millisecond), "datagram relayed after a failed handshake")

	// Authenticated association: relayed.
	control := associate(t, tcp.Address(), &socks5.User{Username: "u", Password: "p"})
	waitAssociation(t, udp, client, true)
	sendSocksUDP(t, client, udp.Address())
	require.True(t, tunnel.received(2*time.Second), "datagram not relayed with an open association")

	// Control connection closed: dropped again.
	require.NoError(t, control.Close())
	waitAssociation(t, udp, client, false)
	sendSocksUDP(t, client, udp.Address())
	require.False(t, tunnel.received(300*time.Millisecond), "datagram relayed after the association ended")
}

func TestSocksUDPWithoutAuthNeedsNoAssociation(t *testing.T) {
	_, udp, tunnel := newSocksPair(t, authStore.Nil)

	client, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)
	defer client.Close()

	sendSocksUDP(t, client, udp.Address())
	require.True(t, tunnel.received(2*time.Second), "unauthenticated listener should keep relaying as before")
}

func TestAssociationRefCount(t *testing.T) {
	local := &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1080}
	remote := &net.TCPAddr{IP: net.IPv4(127, 0, 0, 2), Port: 5555}
	udpFrom := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 2), Port: 6000}
	udpLocal := &net.UDPAddr{IP: net.IPv4zero, Port: 1080}

	r1 := addAssociation(local, remote, "", nil)
	r2 := addAssociation(local, remote, "", nil)
	require.True(t, hasAssociation(udpLocal, udpFrom))
	r1()
	r1() // idempotent
	require.True(t, hasAssociation(udpLocal, udpFrom))
	r2()
	require.False(t, hasAssociation(udpLocal, udpFrom))

	// IPv4-mapped addresses match their IPv4 form.
	mapped := &net.TCPAddr{IP: net.ParseIP("::ffff:127.0.0.2"), Port: 5555}
	r3 := addAssociation(local, mapped, "", nil)
	require.True(t, hasAssociation(udpLocal, udpFrom))
	r3()
}

// An association belongs to its user and to one UDP source port of the
// client: the first that claims it, or the one the client named.
func TestAssociationBindsUserAndPort(t *testing.T) {
	local := &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1081}
	remote := &net.TCPAddr{IP: net.IPv4(127, 0, 0, 3), Port: 5555}
	udpLocal := &net.UDPAddr{IP: net.IPv4zero, Port: 1081}
	from := func(port int) *net.UDPAddr { return &net.UDPAddr{IP: net.IPv4(127, 0, 0, 3), Port: port} }

	rAlice := addAssociation(local, remote, "alice", &net.UDPAddr{IP: net.IPv4zero})
	defer rAlice()
	user, ok := lookupAssociation(udpLocal, from(6000))
	require.True(t, ok)
	require.Equal(t, "alice", user)
	user, ok = lookupAssociation(udpLocal, from(6000))
	require.True(t, ok)
	require.Equal(t, "alice", user)
	_, ok = lookupAssociation(udpLocal, from(6001))
	require.False(t, ok, "another port of the same IP rode on alice's association")

	// bob names his own address: only that port is his
	rBob := addAssociation(local, remote, "bob", from(7000))
	_, ok = lookupAssociation(udpLocal, from(6001))
	require.False(t, ok)
	user, ok = lookupAssociation(udpLocal, from(7000))
	require.True(t, ok)
	require.Equal(t, "bob", user)
	rBob()
	_, ok = lookupAssociation(udpLocal, from(7000))
	require.False(t, ok)

	// a freed association no longer answers for its port
	rAlice()
	_, ok = lookupAssociation(udpLocal, from(6000))
	require.False(t, ok)
}

// A datagram is relayed as the user of its association, and a second socket
// of the same client IP does not get in on it.
func TestSocksUDPAssociationUser(t *testing.T) {
	store := authStore.NewAuthStore(auth.NewAuthenticator([]auth.AuthUser{{User: "u", Pass: "p"}}))
	tcp, udp, tunnel := newSocksPair(t, store)

	client, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)
	defer client.Close()
	other, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)
	defer other.Close()

	control := associate(t, tcp.Address(), &socks5.User{Username: "u", Password: "p"})
	defer control.Close()
	waitAssociation(t, udp, client, true)

	sendSocksUDP(t, client, udp.Address())
	select {
	case metadata := <-tunnel.packets:
		require.Equal(t, "u", metadata.InUser)
	case <-time.After(2 * time.Second):
		t.Fatal("datagram not relayed with an open association")
	}

	sendSocksUDP(t, other, udp.Address())
	require.False(t, tunnel.received(300*time.Millisecond), "a datagram from another port rode on the association")
}
