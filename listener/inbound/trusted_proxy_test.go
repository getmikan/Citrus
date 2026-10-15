package inbound_test

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"net/http/httputil"
	"net/netip"
	"net/url"
	"testing"
	"time"

	"github.com/metacubex/mihomo/adapter/outbound"
	"github.com/metacubex/mihomo/component/authevent"
	"github.com/metacubex/mihomo/component/dialer"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/listener/inbound"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// startForwardingProxy starts a TLS reverse proxy on loopback, in front of a
// plain-text inbound as nginx or Caddy would be, that sends X-Forwarded-For
// with the value given (or none) to the inbound. h2c talks HTTP/2 to the
// inbound (gRPC, XHTTP), otherwise HTTP/1.1 (WebSocket).
func startForwardingProxy(t *testing.T, backend string, h2c bool, xff string) netip.AddrPort {
	target := &url.URL{Scheme: "http", Host: backend}
	transport := &http.Transport{
		DialContext:       (&net.Dialer{}).DialContext,
		ForceAttemptHTTP2: false,
	}
	if h2c {
		protocols := new(http.Protocols)
		protocols.SetUnencryptedHTTP2(true)
		transport.Protocols = protocols
	}
	t.Cleanup(transport.CloseIdleConnections)
	proxy := &httputil.ReverseProxy{
		Rewrite: func(r *httputil.ProxyRequest) {
			r.SetURL(target)
			r.Out.Host = r.In.Host
			if xff != "" {
				r.Out.Header.Set("X-Forwarded-For", xff)
			}
		},
		Transport:     transport,
		FlushInterval: -1,
	}

	cert, err := tls.X509KeyPair([]byte(tlsCertificate), []byte(tlsPrivateKey))
	require.NoError(t, err)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	server := &http.Server{
		Handler:   proxy,
		TLSConfig: &tls.Config{Certificates: []tls.Certificate{cert}, NextProtos: []string{"h2", "http/1.1"}},
	}
	go func() { _ = server.ServeTLS(ln, "", "") }()
	t.Cleanup(func() { _ = server.Close() })
	return netip.MustParseAddrPort(ln.Addr().String())
}

// newSourceTunnel returns a tunnel that reports the source address of every
// connection the inbound hands it.
func newSourceTunnel() (*TestTunnel, <-chan netip.Addr) {
	sources := make(chan netip.Addr, 16)
	tunnel := &TestTunnel{
		HandleTCPConnFn: func(conn net.Conn, metadata *C.Metadata) {
			select {
			case sources <- metadata.SrcIP:
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

func dialSource(t *testing.T, proxy C.ProxyAdapter, sources <-chan netip.Addr) netip.Addr {
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
		return netip.Addr{}
	}
}

var trustedProxyCases = []struct {
	name    string
	trusted []string
	xff     string
	want    string
}{
	// trusted-proxies unset: the header is never believed
	{name: "NoTrustedProxies", xff: "203.0.113.7", want: "127.0.0.1"},
	// the TCP peer (the proxy on loopback) is not a trusted proxy
	{name: "UntrustedPeer", trusted: []string{"10.0.0.0/8"}, xff: "203.0.113.7", want: "127.0.0.1"},
	{name: "TrustedPeer", trusted: []string{"loopback"}, xff: "203.0.113.7", want: "203.0.113.7"},
	// the client put 6.6.6.6 in front, a trusted hop (192.0.2.1) appended
	// itself after the proxy that saw the client: the walk from the right
	// stops at the first untrusted address
	{name: "SpoofedLeftmost", trusted: []string{"loopback", "192.0.2.0/24"}, xff: "6.6.6.6, 203.0.113.7, 192.0.2.1", want: "203.0.113.7"},
	{name: "NoHeader", trusted: []string{"loopback"}, want: "127.0.0.1"},
}

type trustedProxyTransport struct {
	name  string
	h2c   bool
	vless func(*inbound.VlessOption, *outbound.VlessOption)
	// trojan is nil for a transport trojan does not have
	trojan func(*inbound.TrojanOption, *outbound.TrojanOption)
}

var trustedProxyTransports = []trustedProxyTransport{
	{
		name: "ws",
		vless: func(in *inbound.VlessOption, out *outbound.VlessOption) {
			in.WsPath = "/ws"
			out.Network = "ws"
			out.WSOpts = outbound.WSOptions{Path: "/ws"}
		},
		trojan: func(in *inbound.TrojanOption, out *outbound.TrojanOption) {
			in.WsPath = "/ws"
			out.Network = "ws"
			out.WSOpts = outbound.WSOptions{Path: "/ws"}
		},
	},
	{
		name: "grpc",
		h2c:  true,
		vless: func(in *inbound.VlessOption, out *outbound.VlessOption) {
			in.GrpcServiceName = "GunService"
			out.Network = "grpc"
			out.GrpcOpts = outbound.GrpcOptions{GrpcServiceName: "GunService"}
		},
		trojan: func(in *inbound.TrojanOption, out *outbound.TrojanOption) {
			in.GrpcServiceName = "GunService"
			out.Network = "grpc"
			out.GrpcOpts = outbound.GrpcOptions{GrpcServiceName: "GunService"}
		},
	},
	{
		name: "xhttp",
		h2c:  true,
		vless: func(in *inbound.VlessOption, out *outbound.VlessOption) {
			in.XHTTPConfig = inbound.XHTTPConfig{Path: "/xhttp", Mode: "auto"}
			out.Network = "xhttp"
			out.XHTTPOpts = outbound.XHTTPOptions{Path: "/xhttp", Mode: "auto"}
		},
	},
}

func TestInboundVless_TrustedProxyHeader(t *testing.T) {
	for _, transport := range trustedProxyTransports {
		for _, testCase := range trustedProxyCases {
			transport, testCase := transport, testCase
			t.Run(transport.name+"/"+testCase.name, func(t *testing.T) {
				t.Parallel()
				inboundOptions := inbound.VlessOption{
					BaseOption:         inbound.BaseOption{NameStr: "vless_xff", Listen: "127.0.0.1", Port: "0"},
					Users:              []inbound.VlessUser{{Username: "test", UUID: userUUID}},
					AllowInsecure:      true,
					TrustedProxyHeader: "X-Forwarded-For",
					TrustedProxies:     testCase.trusted,
				}
				outboundOptions := outbound.VlessOption{
					Name:        "vless_xff",
					UUID:        userUUID,
					TLS:         true,
					Fingerprint: tlsFingerprint,
				}
				transport.vless(&inboundOptions, &outboundOptions)

				in, err := inbound.NewVless(&inboundOptions)
				require.NoError(t, err)
				tunnel, sources := newSourceTunnel()
				require.NoError(t, in.Listen(tunnel))
				defer in.Close()

				front := startForwardingProxy(t, in.Address(), transport.h2c, testCase.xff)
				outboundOptions.Server = front.Addr().String()
				outboundOptions.Port = int(front.Port())
				outboundOptions.DialerForAPI = tunnel.NewDialer()
				out, err := outbound.NewVless(outboundOptions)
				require.NoError(t, err)
				defer out.Close()

				assert.Equal(t, testCase.want, dialSource(t, out, sources).String())

				// the auth journal reports the same client
				events := subscribeAuthEvents(t)
				outboundOptions.UUID = "00000000-0000-4000-8000-000000000001"
				rejected, err := outbound.NewVless(outboundOptions)
				require.NoError(t, err)
				defer rejected.Close()
				dialRejected(rejected)
				e := waitAuthEvent(t, events, "vless", in.Address())
				assert.Equal(t, authevent.ReasonWrongCredentials, e.Reason)
				assertEventHost(t, testCase.want, e.Remote)
			})
		}
	}
}

func TestInboundTrojan_TrustedProxyHeader(t *testing.T) {
	for _, transport := range trustedProxyTransports {
		if transport.trojan == nil {
			continue
		}
		for _, testCase := range trustedProxyCases {
			transport, testCase := transport, testCase
			t.Run(transport.name+"/"+testCase.name, func(t *testing.T) {
				t.Parallel()
				inboundOptions := inbound.TrojanOption{
					BaseOption:         inbound.BaseOption{NameStr: "trojan_xff", Listen: "127.0.0.1", Port: "0"},
					Users:              []inbound.TrojanUser{{Username: "test", Password: userUUID}},
					AllowInsecure:      true,
					TrustedProxyHeader: "X-Forwarded-For",
					TrustedProxies:     testCase.trusted,
				}
				outboundOptions := outbound.TrojanOption{
					Name:        "trojan_xff",
					Password:    userUUID,
					Fingerprint: tlsFingerprint,
				}
				transport.trojan(&inboundOptions, &outboundOptions)

				in, err := inbound.NewTrojan(&inboundOptions)
				require.NoError(t, err)
				tunnel, sources := newSourceTunnel()
				require.NoError(t, in.Listen(tunnel))
				defer in.Close()

				front := startForwardingProxy(t, in.Address(), transport.h2c, testCase.xff)
				outboundOptions.Server = front.Addr().String()
				outboundOptions.Port = int(front.Port())
				outboundOptions.DialerForAPI = tunnel.NewDialer()
				out, err := outbound.NewTrojan(outboundOptions)
				require.NoError(t, err)
				defer out.Close()

				assert.Equal(t, testCase.want, dialSource(t, out, sources).String())

				events := subscribeAuthEvents(t)
				outboundOptions.Password = "wrong"
				rejected, err := outbound.NewTrojan(outboundOptions)
				require.NoError(t, err)
				defer rejected.Close()
				dialRejected(rejected)
				e := waitAuthEvent(t, events, "trojan", in.Address())
				assert.Equal(t, authevent.ReasonWrongCredentials, e.Reason)
				assertEventHost(t, testCase.want, e.Remote)
			})
		}
	}
}

func TestInboundVless_TrustedProxiesInvalid(t *testing.T) {
	in, err := inbound.NewVless(&inbound.VlessOption{
		BaseOption:         inbound.BaseOption{NameStr: "vless_xff_invalid", Listen: "127.0.0.1", Port: "0"},
		Users:              []inbound.VlessUser{{Username: "test", UUID: userUUID}},
		AllowInsecure:      true,
		WsPath:             "/ws",
		TrustedProxyHeader: "X-Forwarded-For",
		TrustedProxies:     []string{"10.0.0.0/33"},
	})
	require.NoError(t, err)
	tunnel, _ := newSourceTunnel()
	err = in.Listen(tunnel)
	if err == nil {
		_ = in.Close()
	}
	assert.ErrorContains(t, err, "10.0.0.0/33")
}

func assertEventHost(t *testing.T, want, remote string) {
	t.Helper()
	host, _, err := net.SplitHostPort(remote)
	if assert.NoError(t, err, remote) {
		assert.Equal(t, want, host)
	}
}
