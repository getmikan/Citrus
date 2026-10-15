package inbound_test

import (
	"context"
	"net"
	"net/http"
	"net/http/httputil"
	"net/netip"
	"net/url"
	"testing"

	"github.com/metacubex/mihomo/adapter/outbound"
	"github.com/metacubex/mihomo/listener/inbound"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// startUnixForwardingProxy starts a plain HTTP reverse proxy on loopback that
// forwards to the unix socket at path, as nginx with
// "proxy_pass http://unix:/path" would, setting X-Forwarded-For to xff.
func startUnixForwardingProxy(t *testing.T, path string, xff string) netip.AddrPort {
	transport := &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", path)
		},
	}
	t.Cleanup(transport.CloseIdleConnections)
	target := &url.URL{Scheme: "http", Host: "unix"}
	proxy := &httputil.ReverseProxy{
		Rewrite: func(r *httputil.ProxyRequest) {
			r.SetURL(target)
			r.Out.Host = r.In.Host
			r.Out.Header.Set("X-Forwarded-For", xff)
		},
		Transport:     transport,
		FlushInterval: -1,
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	server := &http.Server{Handler: proxy}
	go func() { _ = server.Serve(ln) }()
	t.Cleanup(func() { _ = server.Close() })
	return netip.MustParseAddrPort(ln.Addr().String())
}

// TestInboundUnix_TrustedProxy checks that a unix peer counts as loopback for
// trusted-proxies: the reverse proxy in front of a unix socket listener is
// believed with "trusted-proxies: [loopback]" and only then.
func TestInboundUnix_TrustedProxy(t *testing.T) {
	for _, testCase := range []struct {
		name    string
		trusted []string
		want    string
	}{
		{name: "Untrusted", want: "127.0.0.1"},
		{name: "OtherNetwork", trusted: []string{"10.0.0.0/8"}, want: "127.0.0.1"},
		{name: "Loopback", trusted: []string{"loopback"}, want: "203.0.113.7"},
	} {
		testCase := testCase
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()
			path := unixSocketPath(t, "xff.sock")
			in, err := inbound.NewVless(&inbound.VlessOption{
				BaseOption:         inbound.BaseOption{NameStr: "vless_unix_xff", Listen: "unix:" + path},
				Users:              []inbound.VlessUser{{Username: "test", UUID: userUUID}},
				WsPath:             "/ws",
				AllowInsecure:      true,
				TrustedProxyHeader: "X-Forwarded-For",
				TrustedProxies:     testCase.trusted,
			})
			require.NoError(t, err)
			tunnel, sources := newSourceTunnel()
			require.NoError(t, in.Listen(tunnel))
			defer in.Close()

			front := startUnixForwardingProxy(t, path, "203.0.113.7")
			out, err := outbound.NewVless(outbound.VlessOption{
				Name:    "vless_unix_xff",
				Server:  front.Addr().String(),
				Port:    int(front.Port()),
				UUID:    userUUID,
				Network: "ws",
				WSOpts:  outbound.WSOptions{Path: "/ws"},
			})
			require.NoError(t, err)
			defer out.Close()

			assert.Equal(t, netip.MustParseAddr(testCase.want), dialSource(t, out, sources))
		})
	}
}
