package wireguard

import (
	"context"
	"encoding/base64"
	"io"
	"net"
	"net/netip"
	"testing"
	"time"

	LC "github.com/metacubex/mihomo/listener/config"

	amneziav3 "github.com/metacubex/amneziawg-go/device"
	"github.com/metacubex/mipstack"
	"github.com/metacubex/wireguard-go/conn"
	"github.com/metacubex/wireguard-go/device"
	"github.com/metacubex/wireguard-go/tun"
)

// TestAmneziaWGHandshake runs a real AmneziaWG 3 handshake: the obfuscation is the part
// whose mistakes are silent (a wrong padding or a missing header protection key makes the
// handshake never converge, and neither end says why), so it must be proven on a wire.
func TestAmneziaWGHandshake(t *testing.T) {
	awg := &LC.AmneziaWGServer{
		Version:                3,
		JC:                     4,
		JMin:                   50,
		JMax:                   1000,
		S1:                     20,
		S2:                     24,
		S3:                     28,
		S4:                     32,
		H1:                     "1234567-1234667",
		H2:                     "2234567-2234667",
		H3:                     "3234567-3234667",
		H4:                     "4234567-4234667",
		HeaderProtectionKey:    func() string { k := headerKey(); return base64.StdEncoding.EncodeToString(k[:]) }(),
		ContentPaddingAddition: "20-100",
		RandomTrailers:         true,
		DisableCookies:         true,
	}
	if err := ValidateAmneziaWG(awg); err != nil {
		t.Fatalf("validate: %v", err)
	}

	tunnel := &echoTunnel{}
	serverPrivate := privateKey("node-secret")
	addr := freeUDPAddr(t)
	sl, err := New(LC.WireGuardServer{
		Enable:     true,
		Listen:     addr,
		Users:      map[string]string{"alice": "alice-secret"},
		PrivateKey: hexKey(serverPrivate),
		IPv4CIDR:   "10.66.66.0/24",
		AmneziaWG:  awg,
	}, testListenConfig{}, tunnel)
	if err != nil {
		t.Fatalf("start listener: %v", err)
	}
	defer sl.Close()

	serverPublic, err := serverKeys(serverPrivate)
	if err != nil {
		t.Fatal(err)
	}

	// The client is the v3 device with the same parameters: what AmneziaVPN and Rawline
	// put into their configs.
	private := privateKey("alice-secret")
	key, err := UserKey("alice-secret")
	if err != nil {
		t.Fatal(err)
	}
	pool, _, err := parsePool("10.66.66.0/24")
	if err != nil {
		t.Fatal(err)
	}
	clientAddr := assignAddresses([][32]byte{key}, poolAddresses(pool))[key]

	stack, err := mipstack.New(mipstack.Config{
		LocalAddresses: []netip.Prefix{netip.PrefixFrom(clientAddr, 32)},
		MTU:            defaultMTU,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := stack.Start(); err != nil {
		t.Fatal(err)
	}
	dev := &stackDevice{stack: stack, events: make(chan tun.Event, 4), mtu: defaultMTU}
	logger := &device.Logger{Verbosef: func(string, ...any) {}, Errorf: func(string, ...any) {}}
	wg := amneziav3.NewDevice(dev, conn.NewDefaultBind(), logger, 1)

	// Device-level keys come before the first public_key: like wireguard-go's UAPI, a key
	// after it belongs to the peer being configured.
	conf := "private_key=" + hexKey(private) + "\n" +
		"jc=4\njmin=50\njmax=1000\ns1=20\ns2=24\ns3=28\ns4=32\n" +
		"h1=1234567-1234667\nh2=2234567-2234667\nh3=3234567-3234667\nh4=4234567-4234667\n" +
		"header_protection_key=" + hexKey(headerKey()) + "\n" +
		"content_padding_addition=20-100\n" +
		"random_trailers=1\n" +
		"disable_cookies=1\n" +
		"public_key=" + hexKey(serverPublic) + "\n" +
		"endpoint=" + sl.bind.Addr() + "\n" +
		"allowed_ip=0.0.0.0/0\n" +
		"persistent_keepalive_interval=1\n"
	if err := wg.IpcSet(conf); err != nil {
		t.Fatalf("client ipc: %v", err)
	}
	if err := wg.Up(); err != nil {
		t.Fatalf("client up: %v", err)
	}
	defer wg.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	conn, err := stack.DialTCP(ctx, "tcp", netip.AddrPort{}, netip.MustParseAddrPort("1.1.1.1:80"))
	if err != nil {
		t.Fatalf("dial through the tunnel: %v", err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	if _, err := conn.Write([]byte("awg")); err != nil {
		t.Fatalf("write: %v", err)
	}
	buf := make([]byte, 3)
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatalf("read echo: %v", err)
	}
	if string(buf) != "awg" {
		t.Fatalf("echo = %q", buf)
	}

	var user string
	for _, md := range tunnel.connections() {
		user = md.InUser
	}
	if user != "alice" {
		t.Fatalf("the connection was attributed to %q, want alice", user)
	}
}

// headerKey returns a fixed 32-byte header protection key.
func headerKey() [32]byte {
	var key [32]byte
	for i := range key {
		key[i] = byte(i*7 + 3)
	}
	return key
}

var _ net.Conn = (*mipstack.TCPConn)(nil)
