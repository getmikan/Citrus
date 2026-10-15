package inbound_test

import (
	"context"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/metacubex/mihomo/adapter/outbound"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/listener/inbound"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// unixSocketPath returns a socket path in a fresh short directory: sun_path
// holds about a hundred bytes, which a t.TempDir() path may exceed on macOS.
func unixSocketPath(t *testing.T, name string) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "cs")
	require.NoError(t, err)
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return filepath.Join(dir, name)
}

// unixDialer dials the unix socket of the inbound under test whatever the
// address the outbound asks for, as a reverse proxy in front of it would.
type unixDialer struct {
	C.Dialer
	path string
}

func (d *unixDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	return (&net.Dialer{}).DialContext(ctx, "unix", d.path)
}

// sourceRecorder records the source address the inbound hands the tunnel.
type sourceRecorder struct {
	mu      sync.Mutex
	sources map[netip.Addr]struct{}
}

func recordSources(tunnel *TestTunnel) *sourceRecorder {
	r := &sourceRecorder{sources: map[netip.Addr]struct{}{}}
	handle := tunnel.HandleTCPConnFn
	tunnel.HandleTCPConnFn = func(conn net.Conn, metadata *C.Metadata) {
		r.mu.Lock()
		r.sources[metadata.SrcIP] = struct{}{}
		r.mu.Unlock()
		handle(conn, metadata)
	}
	return r
}

func (r *sourceRecorder) assertOnly(t *testing.T, want netip.Addr) {
	t.Helper()
	r.mu.Lock()
	defer r.mu.Unlock()
	assert.NotEmpty(t, r.sources)
	for src := range r.sources {
		assert.Equal(t, want, src)
	}
}

var loopback = netip.MustParseAddr("127.0.0.1")

// listenUnix starts in on a fresh unix socket and returns the socket path
// along with a tunnel whose dialer reaches it.
func listenUnix(t *testing.T, in C.InboundListener, path string) *TestTunnel {
	t.Helper()
	tunnel := NewHttpTestTunnel()
	t.Cleanup(func() { _ = tunnel.Close() })
	require.NoError(t, in.Listen(tunnel))
	t.Cleanup(func() {
		assert.NoError(t, in.Close())
		assert.NoFileExists(t, path, "Close leaves the socket file")
	})
	assert.Equal(t, "unix:"+path, in.Address())
	info, err := os.Lstat(path)
	require.NoError(t, err)
	require.Equal(t, os.ModeSocket, info.Mode().Type())
	return tunnel
}

func testInboundVlessUnix(t *testing.T, inboundOptions inbound.VlessOption, outboundOptions outbound.VlessOption) {
	t.Parallel()
	path := unixSocketPath(t, "vless.sock")
	inboundOptions.BaseOption = inbound.BaseOption{NameStr: "vless_unix", Listen: "unix:" + path}
	inboundOptions.Users = []inbound.VlessUser{{Username: "test", UUID: userUUID, Flow: "xtls-rprx-vision"}}
	in, err := inbound.NewVless(&inboundOptions)
	require.NoError(t, err)
	tunnel := listenUnix(t, in, path)
	sources := recordSources(tunnel)

	outboundOptions.Name = "vless_unix"
	outboundOptions.Server = "127.0.0.1"
	outboundOptions.Port = 443
	outboundOptions.UUID = userUUID
	outboundOptions.DialerForAPI = &unixDialer{Dialer: tunnel.NewDialer(), path: path}
	outboundOptions.TunnelForAPI = tunnel
	out, err := outbound.NewVless(outboundOptions)
	require.NoError(t, err)
	defer out.Close()

	tunnel.DoSequentialTest(t, out)
	sources.assertOnly(t, loopback)
}

func TestInboundUnix_Vless(t *testing.T) {
	t.Run("plain", func(t *testing.T) {
		testInboundVlessUnix(t, inbound.VlessOption{AllowInsecure: true}, outbound.VlessOption{})
	})
	t.Run("tls", func(t *testing.T) {
		testInboundVlessUnix(t,
			inbound.VlessOption{Certificate: tlsCertificate, PrivateKey: tlsPrivateKey},
			outbound.VlessOption{TLS: true, Fingerprint: tlsFingerprint, Flow: "xtls-rprx-vision"},
		)
	})
	t.Run("ws", func(t *testing.T) {
		testInboundVlessUnix(t,
			inbound.VlessOption{WsPath: "/ws", AllowInsecure: true},
			outbound.VlessOption{Network: "ws", WSOpts: outbound.WSOptions{Path: "/ws"}},
		)
	})
	t.Run("xhttp", func(t *testing.T) {
		testInboundVlessUnix(t,
			inbound.VlessOption{XHTTPConfig: inbound.XHTTPConfig{Path: "/xhttp", Mode: "auto"}, AllowInsecure: true},
			outbound.VlessOption{Network: "xhttp", XHTTPOpts: outbound.XHTTPOptions{Path: "/xhttp", Mode: "auto"}},
		)
	})
	t.Run("grpc", func(t *testing.T) {
		testInboundVlessUnix(t,
			inbound.VlessOption{GrpcServiceName: "GunService", AllowInsecure: true},
			outbound.VlessOption{Network: "grpc", GrpcOpts: outbound.GrpcOptions{GrpcServiceName: "GunService"}},
		)
	})
}

func TestInboundUnix_Trojan(t *testing.T) {
	t.Parallel()
	path := unixSocketPath(t, "trojan.sock")
	in, err := inbound.NewTrojan(&inbound.TrojanOption{
		BaseOption:  inbound.BaseOption{NameStr: "trojan_unix", Listen: "unix:" + path},
		Users:       []inbound.TrojanUser{{Username: "test", Password: userUUID}},
		Certificate: tlsCertificate,
		PrivateKey:  tlsPrivateKey,
	})
	require.NoError(t, err)
	tunnel := listenUnix(t, in, path)
	sources := recordSources(tunnel)

	out, err := outbound.NewTrojan(outbound.TrojanOption{
		BasicOption: outbound.BasicOption{DialerForAPI: &unixDialer{Dialer: tunnel.NewDialer(), path: path}, TunnelForAPI: tunnel},
		Name:        "trojan_unix",
		Server:      "127.0.0.1",
		Port:        443,
		Password:    userUUID,
		Fingerprint: tlsFingerprint,
	})
	require.NoError(t, err)
	defer out.Close()

	tunnel.DoSequentialTest(t, out)
	sources.assertOnly(t, loopback)
}

func TestInboundUnix_Mixed(t *testing.T) {
	t.Parallel()
	path := unixSocketPath(t, "mixed.sock")
	in, err := inbound.NewMixed(&inbound.MixedOption{
		BaseOption: inbound.BaseOption{NameStr: "mixed_unix", Listen: "unix:" + path},
		Users:      []inbound.AuthUser{{Username: "test", Password: userUUID}},
	})
	require.NoError(t, err)
	tunnel := listenUnix(t, in, path)
	sources := recordSources(tunnel)
	basic := outbound.BasicOption{DialerForAPI: &unixDialer{Dialer: tunnel.NewDialer(), path: path}, TunnelForAPI: tunnel}

	t.Run("http", func(t *testing.T) {
		out, err := outbound.NewHttp(outbound.HttpOption{
			BasicOption: basic, Name: "http_unix", Server: "127.0.0.1", Port: 1, UserName: "test", Password: userUUID,
		})
		require.NoError(t, err)
		defer out.Close()
		tunnel.DoSequentialTest(t, out)
	})
	t.Run("socks5", func(t *testing.T) {
		out, err := outbound.NewSocks5(outbound.Socks5Option{
			BasicOption: basic, Name: "socks5_unix", Server: "127.0.0.1", Port: 1, UserName: "test", Password: userUUID,
		})
		require.NoError(t, err)
		defer out.Close()
		tunnel.DoSequentialTest(t, out)
	})
	sources.assertOnly(t, loopback)
}

func TestInboundUnix_HTTP(t *testing.T) {
	t.Parallel()
	path := unixSocketPath(t, "http.sock")
	in, err := inbound.NewHTTP(&inbound.HTTPOption{
		BaseOption: inbound.BaseOption{NameStr: "http_unix", Listen: "unix:" + path},
		Users:      []inbound.AuthUser{{Username: "test", Password: userUUID}},
	})
	require.NoError(t, err)
	tunnel := listenUnix(t, in, path)

	out, err := outbound.NewHttp(outbound.HttpOption{
		BasicOption: outbound.BasicOption{DialerForAPI: &unixDialer{Dialer: tunnel.NewDialer(), path: path}, TunnelForAPI: tunnel},
		Name:        "http_unix", Server: "127.0.0.1", Port: 1, UserName: "test", Password: userUUID,
	})
	require.NoError(t, err)
	defer out.Close()
	tunnel.DoSequentialTest(t, out)
}

// TestInboundUnix_StaleSocket starts a listener over the socket file a crashed
// process left behind.
func TestInboundUnix_StaleSocket(t *testing.T) {
	path := unixSocketPath(t, "stale.sock")
	l, err := net.Listen("unix", path)
	require.NoError(t, err)
	l.(*net.UnixListener).SetUnlinkOnClose(false)
	require.NoError(t, l.Close())
	require.FileExists(t, path)

	in, err := inbound.NewHTTP(&inbound.HTTPOption{
		BaseOption: inbound.BaseOption{NameStr: "stale", Listen: "unix:" + path},
		Users:      []inbound.AuthUser{{Username: "test", Password: userUUID}},
	})
	require.NoError(t, err)
	tunnel := listenUnix(t, in, path)
	out, err := outbound.NewHttp(outbound.HttpOption{
		BasicOption: outbound.BasicOption{DialerForAPI: &unixDialer{Dialer: tunnel.NewDialer(), path: path}, TunnelForAPI: tunnel},
		Name:        "stale", Server: "127.0.0.1", Port: 1, UserName: "test", Password: userUUID,
	})
	require.NoError(t, err)
	defer out.Close()
	tunnel.DoSequentialTest(t, out)
}

// TestInboundUnix_InUse refuses a socket another listener serves and leaves
// it working.
func TestInboundUnix_InUse(t *testing.T) {
	path := unixSocketPath(t, "busy.sock")
	l, err := net.Listen("unix", path)
	require.NoError(t, err)
	defer l.Close()
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			_ = c.Close()
		}
	}()

	in, err := inbound.NewHTTP(&inbound.HTTPOption{BaseOption: inbound.BaseOption{NameStr: "busy", Listen: "unix:" + path}})
	require.NoError(t, err)
	err = in.Listen(NewHttpTestTunnel())
	require.ErrorContains(t, err, "already in use")
	c, err := net.Dial("unix", path)
	require.NoError(t, err)
	_ = c.Close()
}

// TestInboundUnix_RegularFile never deletes a file that is not a socket.
func TestInboundUnix_RegularFile(t *testing.T) {
	path := unixSocketPath(t, "data.txt")
	require.NoError(t, os.WriteFile(path, []byte("keep me"), 0o600))

	in, err := inbound.NewHTTP(&inbound.HTTPOption{BaseOption: inbound.BaseOption{NameStr: "file", Listen: "unix:" + path}})
	require.NoError(t, err)
	err = in.Listen(NewHttpTestTunnel())
	require.ErrorContains(t, err, "not a socket")
	data, err := os.ReadFile(path)
	require.NoError(t, err)
	require.Equal(t, "keep me", string(data))
}

// TestInboundUnix_Rejected checks the config errors of the listeners and
// options that need UDP or a host port.
func TestInboundUnix_Rejected(t *testing.T) {
	listen := "unix:" + filepath.Join(os.TempDir(), "rejected.sock")
	base := inbound.BaseOption{NameStr: "rejected", Listen: listen}
	notUnix := "cannot listen on a unix socket"
	streamsOnly := "cannot be used with a unix socket"
	for name, build := range map[string]func() (C.InboundListener, error){
		"hysteria2": func() (C.InboundListener, error) {
			return inbound.NewHysteria2(&inbound.Hysteria2Option{BaseOption: base})
		},
		"tuic": func() (C.InboundListener, error) {
			return inbound.NewTuic(&inbound.TuicOption{BaseOption: base})
		},
		"shadowquic": func() (C.InboundListener, error) {
			return inbound.NewShadowQuic(&inbound.ShadowQuicOption{BaseOption: base})
		},
		"mieru": func() (C.InboundListener, error) {
			return inbound.NewMieru(&inbound.MieruOption{BaseOption: base})
		},
		"redir": func() (C.InboundListener, error) {
			return inbound.NewRedir(&inbound.RedirOption{BaseOption: base})
		},
		"tproxy": func() (C.InboundListener, error) {
			return inbound.NewTProxy(&inbound.TProxyOption{BaseOption: base})
		},
		"socks+udp": func() (C.InboundListener, error) {
			return inbound.NewSocks(&inbound.SocksOption{BaseOption: base, UDP: true})
		},
		"mixed+udp": func() (C.InboundListener, error) {
			return inbound.NewMixed(&inbound.MixedOption{BaseOption: base, UDP: true})
		},
		"shadowsocks+udp": func() (C.InboundListener, error) {
			return inbound.NewShadowSocks(&inbound.ShadowSocksOption{BaseOption: base, Cipher: "aes-128-gcm", Password: "test", UDP: true})
		},
		"shadowsocks+kcp": func() (C.InboundListener, error) {
			return inbound.NewShadowSocks(&inbound.ShadowSocksOption{BaseOption: base, Cipher: "aes-128-gcm", Password: "test", KcpTun: inbound.KcpTun{Enable: true}})
		},
		"tunnel+udp": func() (C.InboundListener, error) {
			return inbound.NewTunnel(&inbound.TunnelOption{BaseOption: base, Network: []string{"tcp", "udp"}, Target: "127.0.0.1:80"})
		},
		"trusttunnel+udp": func() (C.InboundListener, error) {
			return inbound.NewTrustTunnel(&inbound.TrustTunnelOption{BaseOption: base, Network: []string{"tcp", "udp"}})
		},
	} {
		build := build
		t.Run(name, func(t *testing.T) {
			_, err := build()
			require.Error(t, err)
			msg := err.Error()
			assert.True(t, strings.Contains(msg, notUnix) || strings.Contains(msg, streamsOnly), msg)
		})
	}

	for name, option := range map[string]inbound.BaseOption{
		"port":         {NameStr: "rejected", Listen: listen, Port: "443"},
		"routing-mark": {NameStr: "rejected", Listen: listen, RoutingMark: 1},
		"empty path":   {NameStr: "rejected", Listen: "unix:"},
		"comma":        {NameStr: "rejected", Listen: listen + ",x"},
		"mode range":   {NameStr: "rejected", Listen: listen, UnixMode: 0o1777},
		"mode no unix": {NameStr: "rejected", Listen: "127.0.0.1", Port: "0", UnixMode: 0o660},
	} {
		option := option
		t.Run(name, func(t *testing.T) {
			_, err := inbound.NewHTTP(&inbound.HTTPOption{BaseOption: option})
			assert.Error(t, err)
		})
	}
}
