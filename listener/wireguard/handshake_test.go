package wireguard

import (
	"context"
	"io"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	C "github.com/metacubex/mihomo/constant"
	LC "github.com/metacubex/mihomo/listener/config"
	"github.com/metacubex/mihomo/listener/inbounduser"

	"github.com/metacubex/mipstack"
	"github.com/metacubex/wireguard-go/conn"
	"github.com/metacubex/wireguard-go/device"
	"github.com/metacubex/wireguard-go/tun"
)

// echoTunnel is a C.Tunnel that echoes TCP payloads back and records the
// metadata of every connection it is handed.
type echoTunnel struct {
	mu   sync.Mutex
	seen []*C.Metadata
}

var _ C.Tunnel = (*echoTunnel)(nil)

func (e *echoTunnel) HandleTCPConn(conn net.Conn, md *C.Metadata) {
	defer conn.Close()
	e.mu.Lock()
	e.seen = append(e.seen, md)
	e.mu.Unlock()
	_, _ = io.Copy(conn, conn)
}

func (e *echoTunnel) HandleUDPPacket(packet C.UDPPacket, md *C.Metadata) {
	e.mu.Lock()
	e.seen = append(e.seen, md)
	e.mu.Unlock()
	packet.Drop()
}

func (e *echoTunnel) NatTable() C.NatTable { return nil }

func (e *echoTunnel) connections() []*C.Metadata {
	e.mu.Lock()
	defer e.mu.Unlock()
	out := make([]*C.Metadata, len(e.seen))
	copy(out, e.seen)
	return out
}

// testListenConfig is a plain InboundListenConfig: the listener opens its UDP
// socket through it exactly like a node does.
type testListenConfig struct{}

func (testListenConfig) Listen(context.Context, string, string) (net.Listener, error) {
	return nil, errNotSupported
}

func (testListenConfig) ListenPacket(ctx context.Context, network, address string) (net.PacketConn, error) {
	var lc net.ListenConfig
	return lc.ListenPacket(ctx, network, address)
}

var errNotSupported = &net.OpError{Op: "listen", Err: net.ErrClosed}

// client is a userspace WireGuard client of the listener, built from the same
// pieces the node uses, so the test runs a real handshake.
type client struct {
	dev   *device.Device
	stack *mipstack.Stack
}

func (c *client) Close() {
	c.dev.Close()
	_ = c.stack.Close()
}

// dialClient brings up a client for one user and returns it with its inner
// address.
func dialClient(t *testing.T, serverAddr string, serverPublic [32]byte, secret string) (*client, netip.Addr) {
	t.Helper()

	private := privateKey(secret)
	pool, _, err := parsePool("10.66.66.0/24")
	if err != nil {
		t.Fatal(err)
	}
	key, err := UserKey(secret)
	if err != nil {
		t.Fatal(err)
	}
	addr, ok := assignAddresses([][32]byte{key}, poolAddresses(pool))[key]
	if !ok {
		t.Fatal("no client address")
	}

	stack, err := mipstack.New(mipstack.Config{
		LocalAddresses: []netip.Prefix{netip.PrefixFrom(addr, 32)},
		MTU:            defaultMTU,
	})
	if err != nil {
		t.Fatalf("client stack: %v", err)
	}
	if err := stack.Start(); err != nil {
		t.Fatalf("client stack: %v", err)
	}
	tunDev := &stackDevice{stack: stack, events: make(chan tun.Event, 4), mtu: defaultMTU}

	logger := &device.Logger{
		Verbosef: func(string, ...any) {},
		Errorf:   func(string, ...any) {},
	}
	dev := device.NewDevice(tunDev, conn.NewDefaultBind(), logger, 1)

	conf := "private_key=" + hexKey(private) + "\n" +
		"public_key=" + hexKey(serverPublic) + "\n" +
		"endpoint=" + serverAddr + "\n" +
		"allowed_ip=0.0.0.0/0\n" +
		"persistent_keepalive_interval=1\n"
	if err := dev.IpcSet(conf); err != nil {
		dev.Close()
		_ = stack.Close()
		t.Fatalf("client ipc: %v", err)
	}
	if err := dev.Up(); err != nil {
		dev.Close()
		_ = stack.Close()
		t.Fatalf("client up: %v", err)
	}
	return &client{dev: dev, stack: stack}, addr
}

// startListener brings up a listener on a free UDP port.
func startListener(t *testing.T, users map[string]string, tunnel C.Tunnel) *Listener {
	t.Helper()
	serverPrivate := privateKey("node-secret")
	addr := freeUDPAddr(t)
	sl, err := New(LC.WireGuardServer{
		Enable:     true,
		Listen:     addr,
		Users:      users,
		PrivateKey: hexKey(serverPrivate),
		IPv4CIDR:   "10.66.66.0/24",
	}, testListenConfig{}, tunnel)
	if err != nil {
		t.Fatalf("start listener: %v", err)
	}
	t.Cleanup(func() { _ = sl.Close() })
	return sl
}

func freeUDPAddr(t *testing.T) string {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := pc.LocalAddr().String()
	_ = pc.Close()
	return addr
}

func serverPublicOf(t *testing.T, sl *Listener) [32]byte {
	t.Helper()
	pub, err := serverKeys(sl.private)
	if err != nil {
		t.Fatal(err)
	}
	return pub
}

// TestHandshakeAndPerUserAccounting runs a real handshake as two users and
// checks that each connection reaches the tunnel named after its own user.
func TestHandshakeAndPerUserAccounting(t *testing.T) {
	users := map[string]string{"alice": "alice-secret", "bob": "bob-secret"}
	tunnel := &echoTunnel{}
	sl := startListener(t, users, tunnel)
	serverPublic := serverPublicOf(t, sl)

	for _, name := range []string{"alice", "bob"} {
		name := name
		t.Run(name, func(t *testing.T) {
			c, addr := dialClient(t, sl.bind.Addr(), serverPublic, users[name])
			defer c.Close()

			conn, err := c.stack.DialTCP(context.Background(), "tcp", netip.AddrPort{}, netip.MustParseAddrPort("1.1.1.1:80"))
			if err != nil {
				t.Fatalf("dial through the tunnel: %v", err)
			}
			defer conn.Close()
			_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
			if _, err := conn.Write([]byte("ping " + name)); err != nil {
				t.Fatalf("write: %v", err)
			}
			buf := make([]byte, len("ping "+name))
			if _, err := io.ReadFull(conn, buf); err != nil {
				t.Fatalf("read echo: %v", err)
			}

			var md *C.Metadata
			for _, seen := range tunnel.connections() {
				if seen.InUser == name {
					md = seen
					break
				}
			}
			if md == nil {
				t.Fatalf("no connection was attributed to %q (seen %v)", name, usersOf(tunnel))
			}
			if md.Type != C.WIREGUARD {
				t.Fatalf("metadata type = %v, want WireGuard", md.Type)
			}
			if md.SrcIP != addr {
				t.Fatalf("source address = %s, want the peer address %s", md.SrcIP, addr)
			}
			if md.DstIP.String() != "1.1.1.1" || md.DstPort != 80 {
				t.Fatalf("destination = %s:%d", md.DstIP, md.DstPort)
			}
		})
	}
}

func usersOf(t *echoTunnel) []string {
	var out []string
	for _, md := range t.connections() {
		out = append(out, md.InUser)
	}
	return out
}

// TestRemovedPeerIsDropped checks that the address of a removed user stops
// naming it, which is what makes its traffic unattributable (and so refused).
func TestRemovedPeerIsDropped(t *testing.T) {
	tunnel := &echoTunnel{}
	sl := startListener(t, map[string]string{"alice": "alice-secret", "bob": "bob-secret"}, tunnel)

	aliceKey, err := UserKey("alice-secret")
	if err != nil {
		t.Fatal(err)
	}
	pool, _, err := parsePool("10.66.66.0/24")
	if err != nil {
		t.Fatal(err)
	}
	aliceAddr := assignAddresses([][32]byte{aliceKey}, poolAddresses(pool))[aliceKey]
	if sl.userOf(aliceAddr) != "alice" {
		t.Fatalf("alice does not own %s before the removal", aliceAddr)
	}

	change, err := sl.ReplaceUsers([]C.InboundUser{{Name: "bob", Secret: "bob-secret"}})
	if err != nil {
		t.Fatalf("replace users: %v", err)
	}
	if len(change.Removed) != 1 || change.Removed[0] != "alice" {
		t.Fatalf("change = %+v, want alice removed", change)
	}
	if got := sl.userOf(aliceAddr); got != "" {
		t.Fatalf("the removed user still owns %s as %q", aliceAddr, got)
	}
}

// TestUserKeyIsTheUsersIdentity pins the rule the panel relies on: the same
// secret is the same peer, so two users cannot share one.
func TestUserKeyIsTheUsersIdentity(t *testing.T) {
	key, err := UserKey("secret")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := inbounduser.Validate(userKey, []C.InboundUser{
		{Name: "a", Secret: "secret"},
		{Name: "b", Secret: "secret"},
	}); err == nil {
		t.Fatal("two users with the same secret must be rejected")
	}
	if _, err := inbounduser.Validate(userKey, []C.InboundUser{{Name: "a", Secret: "secret"}}); err != nil {
		t.Fatal(err)
	}
	_ = key
}

// TestStartWithoutUsers checks a listener with no users: a fresh inbound.
func TestStartWithoutUsers(t *testing.T) {
	sl := startListener(t, nil, &echoTunnel{})
	if len(sl.Users()) != 0 {
		t.Fatalf("users = %d", len(sl.Users()))
	}
}

var _ = LC.AmneziaWGServer{}
