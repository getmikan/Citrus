package inbound_test

import (
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"os"
	"strconv"
	"syscall"
	"testing"
	"time"

	"github.com/metacubex/mihomo/adapter/outbound"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/listener/inbound"
	"github.com/metacubex/mihomo/transport/vless/encryption"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func xhttpH3Config(mode string, inboundALPN []string) func() (inbound.VlessOption, outbound.VlessOption) {
	return func() (inbound.VlessOption, outbound.VlessOption) {
		inboundOptions := inbound.VlessOption{
			Certificate: tlsCertificate,
			PrivateKey:  tlsPrivateKey,
			ALPN:        inboundALPN,
			XHTTPConfig: inbound.XHTTPConfig{
				Path: "/vless-xhttp",
				Host: "example.com",
				Mode: mode,
			},
		}
		outboundOptions := outbound.VlessOption{
			TLS:         true,
			Fingerprint: tlsFingerprint,
			ServerName:  "example.org",
			Network:     "xhttp",
			ALPN:        []string{"h3"},
			XHTTPOpts: outbound.XHTTPOptions{
				Path: "/vless-xhttp",
				Host: "example.com",
				Mode: mode,
			},
		}
		return inboundOptions, outboundOptions
	}
}

var xhttpModes = []string{"auto", "stream-one", "stream-up", "packet-up"}

// alpn [h3] serves XHTTP over HTTP/3 only, as Xray-core does; every mode
// works over it, with and without download-settings, ECH and mTLS.
func TestInboundVless_XHTTP_H3(t *testing.T) {
	for _, mode := range xhttpModes {
		mode := mode
		t.Run(mode, func(t *testing.T) {
			testInboundVless_XHTTP(t, xhttpH3Config(mode, []string{"h3"}), mode)
		})
	}
}

func TestInboundVless_XHTTP_H3_Encryption(t *testing.T) {
	privateKeyBase64, passwordBase64, _, err := encryption.GenX25519("")
	require.NoError(t, err)
	for _, mode := range xhttpModes {
		mode := mode
		t.Run(mode, func(t *testing.T) {
			getConfig := func() (inbound.VlessOption, outbound.VlessOption) {
				inboundOptions, outboundOptions := xhttpH3Config(mode, []string{"h3"})()
				inboundOptions.Decryption = "mlkem768x25519plus.native.600s." + privateKeyBase64
				outboundOptions.Encryption = "mlkem768x25519plus.native.0rtt." + passwordBase64
				return inboundOptions, outboundOptions
			}
			testInboundVless_XHTTP_Encryption(t, getConfig, mode)
		})
	}
}

// listenVlessXHTTP starts an xhttp inbound with alpn and returns it with its
// address.
func listenVlessXHTTP(t *testing.T, tunnel *TestTunnel, port string, alpn []string, mode string) (*inbound.Vless, netip.AddrPort) {
	t.Helper()
	inboundOptions, _ := xhttpH3Config(mode, alpn)()
	inboundOptions.BaseOption = inbound.BaseOption{NameStr: "vless_inbound", Listen: "127.0.0.1", Port: port}
	inboundOptions.Users = []inbound.VlessUser{{Username: "test", UUID: userUUID}}
	in, err := inbound.NewVless(&inboundOptions)
	require.NoError(t, err)
	// With port 0 and alpn h3 plus h2 the UDP side binds the number the
	// system gave TCP, which may sit in a range Windows reserved for UDP:
	// that bind is refused (not in use), so the inbound is started again.
	for attempt := 0; ; attempt++ {
		err = in.Listen(tunnel)
		if err == nil || port != "0" || attempt == 7 || !bindRefused(err) {
			break
		}
	}
	require.NoError(t, err)
	addrPort, err := netip.ParseAddrPort(in.Address())
	require.NoError(t, err)
	return in, addrPort
}

// bindRefused reports a bind error other than address in use, such as
// WSAEACCES for a port Windows reserved.
func bindRefused(err error) bool {
	var errno syscall.Errno
	return errors.As(err, &errno) && errno != syscall.EADDRINUSE && errno != 10048 // 10048: WSAEADDRINUSE
}

func newXHTTPOutbound(t *testing.T, tunnel *TestTunnel, addrPort netip.AddrPort, mode string, alpn []string, downloadALPN []string) *outbound.Vless {
	t.Helper()
	_, outboundOptions := xhttpH3Config(mode, nil)()
	outboundOptions.Name = "vless_outbound"
	outboundOptions.Server = addrPort.Addr().String()
	outboundOptions.Port = int(addrPort.Port())
	outboundOptions.UUID = userUUID
	outboundOptions.ALPN = alpn
	outboundOptions.DialerForAPI = tunnel.NewDialer()
	outboundOptions.TunnelForAPI = tunnel
	if downloadALPN != nil {
		outboundOptions.XHTTPOpts.DownloadSettings = &outbound.XHTTPDownloadSettings{ALPN: &downloadALPN}
	}
	out, err := outbound.NewVless(outboundOptions)
	require.NoError(t, err)
	t.Cleanup(func() { _ = out.Close() })
	return out
}

// With h3 next to h2 and http/1.1 one inbound serves TCP and UDP on the same
// port, and both share the XHTTP sessions: a client may upload over one and
// download over the other.
func TestInboundVless_XHTTP_H3AndTCP(t *testing.T) {
	t.Parallel()
	tunnel := NewHttpTestTunnel()
	defer tunnel.Close()
	in, addrPort := listenVlessXHTTP(t, tunnel, "0", []string{"h3", "h2", "http/1.1"}, "auto")
	defer in.Close()

	t.Run("h3", func(t *testing.T) {
		tunnel.DoTest(t, newXHTTPOutbound(t, tunnel, addrPort, "auto", []string{"h3"}, nil))
	})
	t.Run("h2", func(t *testing.T) {
		tunnel.DoTest(t, newXHTTPOutbound(t, tunnel, addrPort, "auto", nil, nil))
	})
	t.Run("http/1.1", func(t *testing.T) {
		tunnel.DoTest(t, newXHTTPOutbound(t, tunnel, addrPort, "auto", []string{"http/1.1"}, nil))
	})
	for _, mode := range []string{"stream-up", "packet-up"} {
		t.Run(mode+"/upload-h3-download-h2", func(t *testing.T) {
			tunnel.DoTest(t, newXHTTPOutbound(t, tunnel, addrPort, mode, []string{"h3"}, []string{"h2"}))
		})
		t.Run(mode+"/upload-h2-download-h3", func(t *testing.T) {
			tunnel.DoTest(t, newXHTTPOutbound(t, tunnel, addrPort, mode, []string{"h2"}, []string{"h3"}))
		})
	}
}

// bindProbe is the outcome of binding a port for a moment.
type bindProbe int

const (
	bindFree    bindProbe = iota // the bind succeeded: nothing listens there
	bindInUse                    // address in use: something listens there
	bindUnknown                  // another error, e.g. a port Windows reserved (WSAEACCES)
)

// probeBind binds addr on network for a moment.
func probeBind(network, addr string) bindProbe {
	var err error
	if network == "tcp" {
		var ln net.Listener
		if ln, err = net.Listen(network, addr); err == nil {
			_ = ln.Close()
		}
	} else {
		var pc net.PacketConn
		if pc, err = net.ListenPacket(network, addr); err == nil {
			_ = pc.Close()
		}
	}
	if err == nil {
		return bindFree
	}
	var errno syscall.Errno
	if errors.As(err, &errno) && (errno == syscall.EADDRINUSE || errno == 10048) { // 10048: WSAEADDRINUSE
		return bindInUse
	}
	return bindUnknown
}

// requireOtherSideFree asserts that an inbound from start leaves its port
// free on network. Other tests of the package bind random ports too and may
// hold that number on the other protocol by chance, and Windows refuses binds
// in its reserved port ranges, so a taken or refused port is retried on a
// fresh inbound; an inbound that does open the other side is in use on every
// attempt. If the system refuses every probe, nothing can be proven here.
func requireOtherSideFree(t *testing.T, network string, start func() (io.Closer, netip.AddrPort)) {
	inUse := 0
	for range 8 {
		in, addrPort := start()
		probe := probeBind(network, addrPort.String())
		_ = in.Close()
		switch probe {
		case bindFree:
			return
		case bindInUse:
			inUse++
		}
	}
	if inUse == 0 {
		t.Skipf("the system refused every %s probe bind (reserved ports); cannot check", network)
	}
	t.Fatalf("the inbound listens on %s too", network)
}

// alpn [h3] opens no TCP listener; alpn [h2] (or none) no UDP one.
func TestInboundVless_XHTTP_H3OnlyNoTCP(t *testing.T) {
	tunnel := NewHttpTestTunnel()
	defer tunnel.Close()

	requireOtherSideFree(t, "tcp", func() (io.Closer, netip.AddrPort) {
		return listenVlessXHTTP(t, tunnel, "0", []string{"h3"}, "auto")
	})
	requireOtherSideFree(t, "udp", func() (io.Closer, netip.AddrPort) {
		return listenVlessXHTTP(t, tunnel, "0", []string{"h2"}, "auto")
	})
}

// Close ends the open HTTP/3 tunnels in time and frees the UDP port, so a
// reloaded inbound binds it again.
func TestInboundVless_XHTTP_H3Close(t *testing.T) {
	t.Parallel()
	tunnel := NewHttpTestTunnel()
	defer tunnel.Close()
	in, addrPort := listenVlessXHTTP(t, tunnel, "0", []string{"h3"}, "stream-one")

	out := newXHTTPOutbound(t, tunnel, addrPort, "stream-one", []string{"h3"}, nil)
	tunnel.DoSequentialTest(t, out)
	// a tunnel that stays open over Close
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	conn, err := out.DialContext(ctx, &C.Metadata{NetWork: C.TCP, DstIP: remoteAddr, DstPort: 80})
	require.NoError(t, err)
	defer conn.Close()

	start := time.Now()
	require.NoError(t, in.Close())
	assert.Less(t, time.Since(start), 5*time.Second)

	// the client learns at once that the connection is closed, not after a
	// timeout of its own
	start = time.Now()
	_ = conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	_, err = conn.Read(make([]byte, 1))
	assert.Error(t, err)
	assert.NotErrorIs(t, err, os.ErrDeadlineExceeded)
	var netErr net.Error
	if errors.As(err, &netErr) {
		assert.False(t, netErr.Timeout(), "read timed out: %v", err)
	}
	assert.Less(t, time.Since(start), 5*time.Second)

	again, againAddrPort := listenVlessXHTTP(t, tunnel, strconv.Itoa(int(addrPort.Port())), []string{"h3"}, "stream-one")
	defer again.Close()
	assert.Equal(t, addrPort, againAddrPort)
	tunnel.DoSequentialTest(t, newXHTTPOutbound(t, tunnel, againAddrPort, "stream-one", []string{"h3"}, nil))
}

// A listen address whose UDP port is taken fails the inbound and leaves no
// TCP listener of it open.
func TestInboundVless_XHTTP_H3PortTaken(t *testing.T) {
	t.Parallel()
	var port int
	var pc net.PacketConn
	for range 20 { // a port free on TCP whose UDP side this test holds
		var err error
		pc, err = net.ListenPacket("udp", "127.0.0.1:0")
		require.NoError(t, err)
		port = pc.LocalAddr().(*net.UDPAddr).Port
		if ln, err := net.Listen("tcp", pc.LocalAddr().String()); err == nil {
			_ = ln.Close()
			break
		}
		_ = pc.Close()
		pc = nil
	}
	require.NotNil(t, pc)
	defer pc.Close()

	inboundOptions, _ := xhttpH3Config("auto", []string{"h3", "h2"})()
	inboundOptions.BaseOption = inbound.BaseOption{NameStr: "vless_inbound", Listen: "127.0.0.1", Port: strconv.Itoa(port)}
	inboundOptions.Users = []inbound.VlessUser{{Username: "test", UUID: userUUID}}
	in, err := inbound.NewVless(&inboundOptions)
	require.NoError(t, err)
	tunnel := NewHttpTestTunnel()
	defer tunnel.Close()
	require.Error(t, in.Listen(tunnel))

	ln, err := net.Listen("tcp", pc.LocalAddr().String())
	if err == nil {
		_ = ln.Close()
	}
	assert.NoError(t, err, "the TCP listener of the failed inbound is still open")
}

func TestInboundVless_XHTTP_H3InvalidConfig(t *testing.T) {
	xhttpConfig := inbound.XHTTPConfig{Path: "/vless-xhttp"}
	testCases := []struct {
		name    string
		options inbound.VlessOption
		wantErr string
	}{
		{
			name:    "H3OnlyWithWs",
			options: inbound.VlessOption{Certificate: tlsCertificate, PrivateKey: tlsPrivateKey, ALPN: []string{"h3"}, XHTTPConfig: xhttpConfig, WsPath: "/ws"},
			wantErr: "ws-path and grpc-service-name need TCP",
		},
		{
			name:    "H3OnlyWithGrpc",
			options: inbound.VlessOption{Certificate: tlsCertificate, PrivateKey: tlsPrivateKey, ALPN: []string{"h3"}, XHTTPConfig: xhttpConfig, GrpcServiceName: "grpc"},
			wantErr: "ws-path and grpc-service-name need TCP",
		},
		{
			name:    "ProxyProtocol",
			options: inbound.VlessOption{Certificate: tlsCertificate, PrivateKey: tlsPrivateKey, ALPN: []string{"h3", "h2"}, XHTTPConfig: xhttpConfig},
			wantErr: "proxy-protocol cannot be combined with alpn h3",
		},
		{
			name:    "UnknownALPN",
			options: inbound.VlessOption{Certificate: tlsCertificate, PrivateKey: tlsPrivateKey, ALPN: []string{"h3", "spdy/3"}, XHTTPConfig: xhttpConfig},
			wantErr: `unsupported alpn "spdy/3"`,
		},
		{
			name:    "NoCertificate",
			options: inbound.VlessOption{AllowInsecure: true, ALPN: []string{"h3"}, XHTTPConfig: xhttpConfig},
			wantErr: "xhttp over h3 requires certificate",
		},
		{
			name: "Reality",
			options: inbound.VlessOption{ALPN: []string{"h3"}, XHTTPConfig: xhttpConfig, RealityConfig: inbound.RealityConfig{
				Dest: net.JoinHostPort(realityDest, "443"), PrivateKey: realityPrivateKey, ShortID: []string{realityShortid}, ServerNames: []string{realityDest},
			}},
			wantErr: "xhttp over h3 cannot be combined with reality",
		},
		{
			name: "ShadowTLS",
			options: inbound.VlessOption{ALPN: []string{"h3", "h2"}, XHTTPConfig: xhttpConfig, ShadowTLS: inbound.ShadowTLS{
				Enable: true, Version: 3, Users: []inbound.ShadowTLSUser{{Name: "test", Password: "shadow-tls-password"}},
				Handshake: inbound.ShadowTLSHandshakeOptions{Dest: net.JoinHostPort(realityDest, "443")},
			}},
			wantErr: "xhttp over h3 cannot be combined with shadow-tls",
		},
		{
			name:    "UnixSocket",
			options: inbound.VlessOption{Certificate: tlsCertificate, PrivateKey: tlsPrivateKey, ALPN: []string{"h3"}, XHTTPConfig: xhttpConfig},
			wantErr: "cannot listen on a unix socket",
		},
	}
	for _, testCase := range testCases {
		testCase := testCase
		t.Run(testCase.name, func(t *testing.T) {
			options := testCase.options
			options.BaseOption = inbound.BaseOption{NameStr: "vless_inbound", Listen: "127.0.0.1", Port: "0"}
			if testCase.name == "UnixSocket" {
				options.BaseOption = inbound.BaseOption{NameStr: "vless_inbound", Listen: "unix:" + unixSocketPath(t, "vless.sock")}
			}
			if testCase.name == "ProxyProtocol" {
				options.BaseOption.ProxyProtocol = true
			}
			options.Users = []inbound.VlessUser{{Username: "test", UUID: userUUID}}
			in, err := inbound.NewVless(&options)
			if err == nil {
				tunnel := NewHttpTestTunnel()
				defer tunnel.Close()
				err = in.Listen(tunnel)
				if err == nil {
					_ = in.Close()
				}
			}
			if assert.Error(t, err) {
				assert.Contains(t, err.Error(), testCase.wantErr)
			}
		})
	}
}

// An alpn on an inbound without xhttp-config was ignored before the option
// existed; configs that carry one still start, TCP only as before.
func TestInboundVless_ALPNWithoutXHTTPIgnored(t *testing.T) {
	tunnel := NewHttpTestTunnel()
	defer tunnel.Close()
	start := func() (*inbound.Vless, netip.AddrPort) {
		inboundOptions := inbound.VlessOption{
			BaseOption:  inbound.BaseOption{NameStr: "vless_inbound", Listen: "127.0.0.1", Port: "0"},
			Users:       []inbound.VlessUser{{Username: "test", UUID: userUUID}},
			Certificate: tlsCertificate,
			PrivateKey:  tlsPrivateKey,
			ALPN:        []string{"h3", "h2"},
		}
		in, err := inbound.NewVless(&inboundOptions)
		require.NoError(t, err)
		require.NoError(t, in.Listen(tunnel))
		addrPort, err := netip.ParseAddrPort(in.Address())
		require.NoError(t, err)
		return in, addrPort
	}

	// no HTTP/3 server on the UDP side
	requireOtherSideFree(t, "udp", func() (io.Closer, netip.AddrPort) { return start() })

	in, addrPort := start()
	defer in.Close()

	outboundOptions := outbound.VlessOption{
		Name:        "vless_outbound",
		Server:      addrPort.Addr().String(),
		Port:        int(addrPort.Port()),
		UUID:        userUUID,
		TLS:         true,
		Fingerprint: tlsFingerprint,
		ServerName:  "example.org",
	}
	outboundOptions.DialerForAPI = tunnel.NewDialer()
	outboundOptions.TunnelForAPI = tunnel
	out, err := outbound.NewVless(outboundOptions)
	require.NoError(t, err)
	defer out.Close()
	tunnel.DoTest(t, out)
}
