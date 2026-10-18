package inbound_test

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/netip"
	"os"
	"strconv"
	"testing"
	"time"

	"github.com/metacubex/mihomo/adapter"
	"github.com/metacubex/mihomo/adapter/outbound"
	N "github.com/metacubex/mihomo/common/net"
	"github.com/metacubex/mihomo/component/dialer"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/listener/inbound"
	"github.com/metacubex/mihomo/transport/socks5"
	"github.com/metacubex/mihomo/tunnel"
	"github.com/metacubex/mihomo/tunnel/statistic"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const proxyClient = "203.0.113.7:51234"

var proxyV2Signature = []byte("\r\n\r\n\x00\r\nQUIT\n")

// proxyHeaderV2 returns a PROXY v2 header of the command for client, a TCP4
// or TCP6 "ip:port", to the server 192.0.2.1:443 (2001:db8::1 for TCP6).
func proxyHeaderV2(command byte, client string) []byte {
	src := netip.MustParseAddrPort(client)
	dst := netip.MustParseAddrPort("192.0.2.1:443")
	famProto := byte(0x11)
	if src.Addr().Is6() {
		dst = netip.MustParseAddrPort("[2001:db8::1]:443")
		famProto = 0x21
	}
	payload := append(src.Addr().AsSlice(), dst.Addr().AsSlice()...)
	payload = binary.BigEndian.AppendUint16(payload, src.Port())
	payload = binary.BigEndian.AppendUint16(payload, dst.Port())
	// a TLV a router may add (NOOP), skipped by the listener
	payload = append(payload, 0x04, 0x00, 0x02, 0xff, 0xff)
	header := append([]byte{}, proxyV2Signature...)
	header = append(header, 0x20|command, famProto)
	header = binary.BigEndian.AppendUint16(header, uint16(len(payload)))
	return append(header, payload...)
}

func proxyHeaderV1(client string) []byte {
	src := netip.MustParseAddrPort(client)
	port := strconv.Itoa(int(src.Port()))
	if src.Addr().Is6() {
		return []byte("PROXY TCP6 " + src.Addr().String() + " 2001:db8::1 " + port + " 443\r\n")
	}
	return []byte("PROXY TCP4 " + src.Addr().String() + " 192.0.2.1 " + port + " 443\r\n")
}

// headerDialer sends a PROXY protocol header first on every connection it
// dials, as the SNI router in front of the inbound does.
type headerDialer struct {
	C.Dialer
	header []byte
	// network and address, when set, replace what the outbound asks for
	network, address string
}

func (d *headerDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	if d.network != "" {
		network, address = d.network, d.address
	}
	var conn net.Conn
	var err error
	if network == "unix" {
		conn, err = (&net.Dialer{}).DialContext(ctx, network, address)
	} else {
		conn, err = d.Dialer.DialContext(ctx, network, address)
	}
	if err != nil {
		return nil, err
	}
	if _, err := conn.Write(d.header); err != nil {
		_ = conn.Close()
		return nil, err
	}
	return conn, nil
}

// clientTunnel returns a tunnel that reports the source address and port of
// every connection the inbound hands it.
func clientTunnel() (*TestTunnel, <-chan netip.AddrPort) {
	sources := make(chan netip.AddrPort, 16)
	tunnel := &TestTunnel{
		HandleTCPConnFn: func(conn net.Conn, metadata *C.Metadata) {
			select {
			case sources <- netip.AddrPortFrom(metadata.SrcIP, metadata.SrcPort):
			default:
			}
			_ = conn.Close()
		},
		HandleUDPPacketFn: func(packet C.UDPPacket, metadata *C.Metadata) {},
		CloseFn:           func() error { return nil },
		NewDialerFn: func() C.Dialer {
			return &TestDialer{dialer: dialer.NewDialer(), ctx: context.Background()}
		},
	}
	return tunnel, sources
}

func waitClient(t *testing.T, proxy C.ProxyAdapter, sources <-chan netip.AddrPort) netip.AddrPort {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	conn, err := proxy.DialContext(ctx, &C.Metadata{NetWork: C.TCP, DstIP: remoteAddr, DstPort: 80})
	require.NoError(t, err)
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	_, _ = conn.Write([]byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"))
	_, _ = conn.Read(make([]byte, 1))
	select {
	case src := <-sources:
		return src
	case <-time.After(10 * time.Second):
		t.Fatal("the inbound handed no connection to the tunnel")
		return netip.AddrPort{}
	}
}

func proxyBase(name string, trusted ...string) inbound.BaseOption {
	return inbound.BaseOption{NameStr: name, Listen: "127.0.0.1", Port: "0", ProxyProtocol: true, ProxyProtocolTrusted: trusted}
}

func startProxyVless(t *testing.T, tunnel C.Tunnel, option inbound.BaseOption, d C.Dialer) C.ProxyAdapter {
	t.Helper()
	in, err := inbound.NewVless(&inbound.VlessOption{
		BaseOption:    option,
		Users:         []inbound.VlessUser{{Username: "test", UUID: userUUID}},
		AllowInsecure: true,
	})
	require.NoError(t, err)
	require.NoError(t, in.Listen(tunnel))
	t.Cleanup(func() { _ = in.Close() })
	ap := netip.MustParseAddrPort(in.Address())
	outOpt := outbound.VlessOption{Name: option.NameStr, Server: ap.Addr().String(), Port: int(ap.Port()), UUID: userUUID}
	outOpt.DialerForAPI = d
	out, err := outbound.NewVless(outOpt)
	require.NoError(t, err)
	t.Cleanup(func() { _ = out.Close() })
	return out
}

// TestInboundProxyProtocol_Source checks, per protocol, that the tunnel sees
// the client of the header as the source of the connection.
func TestInboundProxyProtocol_Source(t *testing.T) {
	headers := []struct {
		name   string
		header []byte
		want   string
	}{
		{"v2-tcp4", proxyHeaderV2(1, proxyClient), proxyClient},
		{"v2-tcp6", proxyHeaderV2(1, "[2001:db8::7]:51234"), "[2001:db8::7]:51234"},
		{"v1-tcp4", proxyHeaderV1(proxyClient), proxyClient},
		{"v1-tcp6", proxyHeaderV1("[2001:db8::7]:51234"), "[2001:db8::7]:51234"},
	}
	// start starts the inbound and returns an outbound that dials it through d
	protocols := []struct {
		name  string
		start func(t *testing.T, tunnel C.Tunnel, d C.Dialer) C.ProxyAdapter
	}{
		{"vless", func(t *testing.T, tunnel C.Tunnel, d C.Dialer) C.ProxyAdapter {
			return startProxyVless(t, tunnel, proxyBase("vless_pp"), d)
		}},
		{"trojan-tls", func(t *testing.T, tunnel C.Tunnel, d C.Dialer) C.ProxyAdapter {
			in, err := inbound.NewTrojan(&inbound.TrojanOption{
				BaseOption:  proxyBase("trojan_pp"),
				Users:       []inbound.TrojanUser{{Username: "test", Password: userUUID}},
				Certificate: tlsCertificate,
				PrivateKey:  tlsPrivateKey,
			})
			require.NoError(t, err)
			require.NoError(t, in.Listen(tunnel))
			t.Cleanup(func() { _ = in.Close() })
			ap := netip.MustParseAddrPort(in.Address())
			outOpt := outbound.TrojanOption{Name: "trojan_pp", Server: ap.Addr().String(), Port: int(ap.Port()), Password: userUUID, Fingerprint: tlsFingerprint}
			outOpt.DialerForAPI = d
			out, err := outbound.NewTrojan(outOpt)
			require.NoError(t, err)
			t.Cleanup(func() { _ = out.Close() })
			return out
		}},
		{"anytls", func(t *testing.T, tunnel C.Tunnel, d C.Dialer) C.ProxyAdapter {
			in, err := inbound.NewAnyTLS(&inbound.AnyTLSOption{
				BaseOption:  proxyBase("anytls_pp"),
				Users:       map[string]string{"test": userUUID},
				Certificate: tlsCertificate,
				PrivateKey:  tlsPrivateKey,
			})
			require.NoError(t, err)
			require.NoError(t, in.Listen(tunnel))
			t.Cleanup(func() { _ = in.Close() })
			ap := netip.MustParseAddrPort(in.Address())
			outOpt := outbound.AnyTLSOption{Name: "anytls_pp", Server: ap.Addr().String(), Port: int(ap.Port()), Password: userUUID, Fingerprint: tlsFingerprint}
			outOpt.DialerForAPI = d
			out, err := outbound.NewAnyTLS(outOpt)
			require.NoError(t, err)
			t.Cleanup(func() { _ = out.Close() })
			return out
		}},
	}
	for _, p := range protocols {
		for _, h := range headers {
			p, h := p, h
			t.Run(p.name+"/"+h.name, func(t *testing.T) {
				t.Parallel()
				tunnel, sources := clientTunnel()
				out := p.start(t, tunnel, &headerDialer{Dialer: tunnel.NewDialer(), header: h.header})
				assert.Equal(t, h.want, waitClient(t, out, sources).String())
			})
		}
	}
}

// TestInboundProxyProtocol_Local checks that a v2 LOCAL header keeps the
// address of the peer.
func TestInboundProxyProtocol_Local(t *testing.T) {
	tunnel, sources := clientTunnel()
	out := startProxyVless(t, tunnel, proxyBase("vless_pp_local"),
		&headerDialer{Dialer: tunnel.NewDialer(), header: proxyHeaderV2(0, proxyClient)})
	src := waitClient(t, out, sources)
	assert.Equal(t, "127.0.0.1", src.Addr().String())
	assert.NotEqual(t, uint16(51234), src.Port())
}

// TestInboundProxyProtocol_Unix checks the header on a unix socket listener.
func TestInboundProxyProtocol_Unix(t *testing.T) {
	path := unixSocketPath(t, "pp.sock")
	tunnel, sources := clientTunnel()
	option := proxyBase("vless_pp_unix")
	option.Listen, option.Port = "unix:"+path, ""
	in, err := inbound.NewVless(&inbound.VlessOption{
		BaseOption:    option,
		Users:         []inbound.VlessUser{{Username: "test", UUID: userUUID}},
		AllowInsecure: true,
	})
	require.NoError(t, err)
	require.NoError(t, in.Listen(tunnel))
	defer in.Close()
	outOpt := outbound.VlessOption{Name: "vless_pp_unix", Server: "127.0.0.1", Port: 1, UUID: userUUID}
	outOpt.DialerForAPI = &headerDialer{Dialer: tunnel.NewDialer(), header: proxyHeaderV2(1, proxyClient), network: "unix", address: path}
	out, err := outbound.NewVless(outOpt)
	require.NoError(t, err)
	defer out.Close()
	assert.Equal(t, proxyClient, waitClient(t, out, sources).String())
}

// newProxyLimitsEnv is newLimitsEnv with the PROXY protocol on.
func newProxyLimitsEnv(t *testing.T, users ...string) *limitsEnv {
	t.Helper()
	tunnel.UpdateProxies(map[string]C.Proxy{"DIRECT": adapter.NewProxy(outbound.NewDirect())}, nil)
	tunnel.OnRunning()
	limitsInbound = "socks-proxy-protocol-" + strconv.FormatInt(time.Now().UnixNano(), 10)
	var auth inbound.AuthUsers
	for _, u := range users {
		auth = append(auth, inbound.AuthUser{Username: u, Password: u + "-pass"})
	}
	in, err := inbound.NewSocks(&inbound.SocksOption{BaseOption: proxyBase(limitsInbound), Users: auth})
	require.NoError(t, err)
	require.NoError(t, in.Listen(tunnel.Tunnel))
	t.Cleanup(func() { _ = in.Close() })
	return &limitsEnv{t: t, proxy: in.Address(), server: startSizedServer(t)}
}

// openBehindHeader connects to the sized server through the inbound as user,
// with header sent first.
func (e *limitsEnv) openBehindHeader(user string, header []byte) net.Conn {
	e.t.Helper()
	conn, err := net.DialTimeout("tcp", e.proxy, 5*time.Second)
	require.NoError(e.t, err)
	e.t.Cleanup(func() { _ = conn.Close() })
	_, err = conn.Write(header)
	require.NoError(e.t, err)
	_, err = socks5.ClientHandshake(conn, socks5.ParseAddrToSocksAddr(net.TCPAddrFromAddrPort(e.server)), socks5.CmdConnect,
		&socks5.User{Username: user, Password: user + "-pass"})
	require.NoError(e.t, err)
	return conn
}

// TestInboundProxyProtocol_UserStats checks that the device IPs of a user,
// and the limit on them, are the clients of the headers.
func TestInboundProxyProtocol_UserStats(t *testing.T) {
	e := newProxyLimitsEnv(t, "pp")
	e.limit(statistic.UserLimit{User: "pp", MaxIPs: 1})

	c1 := e.openBehindHeader("pp", proxyHeaderV2(1, "203.0.113.7:51234"))
	assert.False(t, closedByTunnel(c1))
	s := limitsStat(t, "pp")
	require.Len(t, s.IPs, 1)
	assert.Equal(t, "203.0.113.7", s.IPs[0].IP.String(), "the device IP is the client, not 127.0.0.1")

	// a second device is over the limit of one IP; the first one is not
	c2 := e.openBehindHeader("pp", proxyHeaderV2(1, "203.0.113.8:40000"))
	assert.True(t, closedByTunnel(c2), "another client IP is rejected")
	assert.Equal(t, int64(1), limitsStat(t, "pp").RejectReasons[statistic.RejectMaxIPs])
	c3 := e.openBehindHeader("pp", proxyHeaderV1("203.0.113.7:51235"))
	assert.False(t, closedByTunnel(c3), "the known client IP keeps working")
	assert.Len(t, limitsStat(t, "pp").IPs, 1)
}

// TestInboundProxyProtocol_Closes checks that the inbound closes what it
// cannot trust: a peer outside proxy-protocol-trusted, a trusted peer without
// a header and one with a broken header.
func TestInboundProxyProtocol_Closes(t *testing.T) {
	tests := []struct {
		name     string
		trusted  []string
		data     []byte
		halfShut bool // the peer shuts down its sending side after data
	}{
		{"UntrustedPeer", []string{"10.0.0.0/8"}, proxyHeaderV2(1, proxyClient), false},
		{"UntrustedPeerV6Only", []string{"::1"}, proxyHeaderV2(1, proxyClient), false},
		{"NoHeader", nil, []byte("\x16\x03\x01\x02\x00\x01\x00\x01\xfc\x03\x03 a tls client hello"), false},
		{"MalformedV1", nil, []byte("PROXY TCP4 203.0.113.7 192.0.2.1 99999 443\r\n"), false},
		{"MalformedV2", nil, append(append([]byte{}, proxyV2Signature...), 0x21, 0x12, 0, 0), false},
		{"TruncatedV2", nil, proxyHeaderV2(1, proxyClient)[:20], true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tunnel, sources := clientTunnel()
			in, err := inbound.NewSocks(&inbound.SocksOption{BaseOption: proxyBase("socks_pp_closes", tt.trusted...)})
			require.NoError(t, err)
			require.NoError(t, in.Listen(tunnel))
			defer in.Close()

			conn, err := net.Dial("tcp", in.Address())
			require.NoError(t, err)
			defer conn.Close()
			_, err = conn.Write(tt.data)
			require.NoError(t, err)
			if tt.halfShut {
				require.NoError(t, conn.(*net.TCPConn).CloseWrite())
			}
			_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
			_, err = conn.Read(make([]byte, 2))
			require.Error(t, err, "the inbound answers nothing")
			assert.False(t, errors.Is(err, os.ErrDeadlineExceeded), "the inbound closes the connection")
			select {
			case src := <-sources:
				t.Fatalf("the tunnel got a connection from %s", src)
			default:
			}
		})
	}
}

// TestInboundProxyProtocol_SilentPeer checks that a trusted peer that sends
// nothing does not hold up the connections of the others.
func TestInboundProxyProtocol_SilentPeer(t *testing.T) {
	tunnel, sources := clientTunnel()
	option := proxyBase("vless_pp_silent")
	in, err := inbound.NewVless(&inbound.VlessOption{
		BaseOption:    option,
		Users:         []inbound.VlessUser{{Username: "test", UUID: userUUID}},
		AllowInsecure: true,
	})
	require.NoError(t, err)
	require.NoError(t, in.Listen(tunnel))
	defer in.Close()

	silent, err := net.Dial("tcp", in.Address())
	require.NoError(t, err)
	defer silent.Close()

	ap := netip.MustParseAddrPort(in.Address())
	outOpt := outbound.VlessOption{Name: "vless_pp_silent", Server: ap.Addr().String(), Port: int(ap.Port()), UUID: userUUID}
	outOpt.DialerForAPI = &headerDialer{Dialer: tunnel.NewDialer(), header: proxyHeaderV2(1, proxyClient)}
	out, err := outbound.NewVless(outOpt)
	require.NoError(t, err)
	defer out.Close()
	assert.Equal(t, proxyClient, waitClient(t, out, sources).String(), "a silent peer does not block the others")
}

// TestInboundProxyProtocol_RealityFallback checks that a client that is not a
// REALITY client still reaches dest behind the header: the header is read
// before the TLS handshake and what follows it is forwarded untouched.
func TestInboundProxyProtocol_RealityFallback(t *testing.T) {
	// without the header the same setup is a plain REALITY listener
	t.Run("Control", func(t *testing.T) { testRealityFallback(t, false) })
	t.Run("ProxyProtocol", func(t *testing.T) { testRealityFallback(t, true) })
}

func testRealityFallback(t *testing.T, proxyProtocol bool) {
	cert, err := tls.X509KeyPair([]byte(tlsCertificate), []byte(tlsPrivateKey))
	require.NoError(t, err)
	dest, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS13})
	require.NoError(t, err)
	defer dest.Close()
	go func() {
		for {
			c, err := dest.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				_ = c.SetDeadline(time.Now().Add(10 * time.Second))
				if tc, ok := c.(*tls.Conn); ok && tc.Handshake() != nil {
					return
				}
				_, _ = io.WriteString(c, "dest says hello")
			}()
		}
	}()

	// the connection to dest is made through the tunnel too
	tunnel, _ := clientTunnel()
	tunnel.HandleTCPConnFn = func(conn net.Conn, metadata *C.Metadata) {
		target, err := net.Dial("tcp", metadata.RemoteAddress())
		if err != nil {
			_ = conn.Close()
			return
		}
		N.Relay(conn, target)
	}
	base := inbound.BaseOption{NameStr: "vless_pp_reality", Listen: "127.0.0.1", Port: "0", ProxyProtocol: proxyProtocol}
	in, err := inbound.NewVless(&inbound.VlessOption{
		BaseOption: base,
		Users:      []inbound.VlessUser{{Username: "test", UUID: userUUID}},
		RealityConfig: inbound.RealityConfig{
			Dest:        dest.Addr().String(),
			PrivateKey:  realityPrivateKey,
			ShortID:     []string{realityShortid},
			ServerNames: []string{"localhost"},
		},
	})
	require.NoError(t, err)
	require.NoError(t, in.Listen(tunnel))
	defer in.Close()

	conn, err := net.DialTimeout("tcp", in.Address(), 5*time.Second)
	require.NoError(t, err)
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	if proxyProtocol {
		_, err = conn.Write(proxyHeaderV2(1, proxyClient))
		require.NoError(t, err)
	}

	client := tls.Client(conn, &tls.Config{ServerName: "localhost", InsecureSkipVerify: true, MinVersion: tls.VersionTLS13})
	require.NoError(t, client.Handshake())
	peer := client.ConnectionState().PeerCertificates
	require.NotEmpty(t, peer)
	assert.Equal(t, cert.Certificate[0], peer[0].Raw, "the certificate of dest")
	got := make([]byte, len("dest says hello"))
	_, err = io.ReadFull(client, got)
	require.NoError(t, err)
	assert.Equal(t, "dest says hello", string(got))
}

func TestInboundProxyProtocol_Options(t *testing.T) {
	t.Run("TrustedWithoutProxyProtocol", func(t *testing.T) {
		_, err := inbound.NewSocks(&inbound.SocksOption{BaseOption: inbound.BaseOption{
			NameStr: "x", Listen: "127.0.0.1", Port: "0", ProxyProtocolTrusted: []string{"loopback"}}})
		assert.ErrorContains(t, err, "proxy-protocol-trusted needs proxy-protocol")
	})
	t.Run("BadTrusted", func(t *testing.T) {
		_, err := inbound.NewSocks(&inbound.SocksOption{BaseOption: proxyBase("x", "10.0.0.0/33")})
		assert.ErrorContains(t, err, "proxy-protocol-trusted")
	})
	t.Run("Shorthands", func(t *testing.T) {
		_, err := inbound.NewSocks(&inbound.SocksOption{BaseOption: proxyBase("x", "loopback", "private", "192.0.2.1", "2001:db8::/32")})
		assert.NoError(t, err)
	})
	t.Run("NotATCPStreamListener", func(t *testing.T) {
		_, err := inbound.NewTuic(&inbound.TuicOption{BaseOption: proxyBase("x")})
		assert.ErrorContains(t, err, "proxy-protocol")
		_, err = inbound.NewHysteria2(&inbound.Hysteria2Option{BaseOption: proxyBase("x")})
		assert.ErrorContains(t, err, "proxy-protocol")
	})
}
