package config

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/metacubex/mihomo/adapter/outboundgroup"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// connectProxy is a minimal HTTP CONNECT proxy, the "VPN node" of the
// reserve tests.
func connectProxy(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				req, err := http.ReadRequest(bufio.NewReader(c))
				if err != nil || req.Method != http.MethodConnect {
					return
				}
				target, err := net.Dial("tcp", req.Host)
				if err != nil {
					return
				}
				defer target.Close()
				_, _ = io.WriteString(c, "HTTP/1.1 200 Connection established\r\n\r\n")
				go func() { _, _ = io.Copy(target, c) }()
				_, _ = io.Copy(c, target)
			}()
		}
	}()
	return ln.Addr().String()
}

// A fallback group with desync first and a proxy node as reserve: while
// desync works the group uses it, once its health check fails the group
// switches to the reserve.
func TestDesyncFallbackWithProxyReserve(t *testing.T) {
	web := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer web.Close()
	vpn := connectProxy(t)
	host, port, _ := net.SplitHostPort(vpn)

	proxies, _, err := parseChainConfig(t, fmt.Sprintf(`proxies:
  - {name: desync-yt, type: desync, tlsrec: "1+s"}
  - {name: desync-broken, type: desync, tlsrec: "1+s", ip-version: ipv6} # cannot reach the IPv4 test server
  - {name: vpn, type: http, server: %s, port: %s}
proxy-groups:
  - {name: yt-ok, type: fallback, proxies: [desync-yt, vpn], url: "%s", lazy: false}
  - {name: yt-broken, type: fallback, proxies: [desync-broken, vpn], url: "%s", lazy: false}
  - {name: yt-auto, type: url-test, proxies: [desync-broken, vpn], url: "%s", lazy: false}
`, host, port, web.URL, web.URL, web.URL))
	require.NoError(t, err)
	assert.Equal(t, "Desync", proxies["desync-yt"].Type().String())

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	require.Equal(t, "desync-broken", proxies["yt-broken"].Adapter().(*outboundgroup.Fallback).Now(), "untested, the first is used")
	// what the groups' health checks do; they go through each outbound
	for _, name := range []string{"desync-yt", "desync-broken", "vpn"} {
		_, _ = proxies[name].URLTest(ctx, web.URL, nil)
	}
	assert.Equal(t, "desync-yt", proxies["yt-ok"].Adapter().(*outboundgroup.Fallback).Now())
	assert.Equal(t, "vpn", proxies["yt-broken"].Adapter().(*outboundgroup.Fallback).Now())
	assert.Equal(t, "vpn", proxies["yt-auto"].Adapter().(*outboundgroup.URLTest).Now())
	assert.True(t, proxies["desync-yt"].AliveForTestUrl(web.URL))
	assert.False(t, proxies["desync-broken"].AliveForTestUrl(web.URL))
}

func TestDesyncConfigErrorsNameTheProxy(t *testing.T) {
	_, _, err := parseChainConfig(t, `proxies:
  - {name: desync-yt, type: desync, tlsrec: "1+s", tfo: true}
`)
	require.Error(t, err)
	assert.Contains(t, err.Error(), `desync "desync-yt"`)
	assert.Contains(t, err.Error(), "tfo")
}
