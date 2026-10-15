package config

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/metacubex/mihomo/adapter/outboundgroup"
	"github.com/metacubex/mihomo/component/eventbus"
	C "github.com/metacubex/mihomo/constant"
	P "github.com/metacubex/mihomo/constant/provider"
	"github.com/metacubex/mihomo/hub/metrics"
	"github.com/metacubex/mihomo/listener/inbound"
	"github.com/metacubex/mihomo/tunnel"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func parseChainConfig(t *testing.T, yaml string) (map[string]C.Proxy, map[string]P.ProxyProvider, error) {
	t.Helper()
	rawCfg, err := UnmarshalRawConfig([]byte(yaml))
	require.NoError(t, err)
	return parseProxies(rawCfg)
}

func dialerProxyOf(t *testing.T, proxies map[string]C.Proxy, name string) string {
	t.Helper()
	p, ok := proxies[name]
	require.True(t, ok, "proxy %s", name)
	return p.ProxyInfo().DialerProxy
}

const chainTestProxies = `proxies:
  - {name: entry, type: socks5, server: 127.0.0.1, port: 1081}
  - {name: mid, type: socks5, server: 127.0.0.1, port: 1082}
  - {name: exit-a, type: ss, server: 127.0.0.1, port: 1083, cipher: aes-128-gcm, password: pass}
  - {name: exit-b, type: ss, server: 127.0.0.1, port: 1084, cipher: aes-128-gcm, password: pass}
  - {name: other, type: socks5, server: 127.0.0.1, port: 1085}
`

func TestChainParseWiresHops(t *testing.T) {
	proxies, providers, err := parseChainConfig(t, chainTestProxies+`proxy-groups:
  - {name: cascade, type: chain, proxies: [entry, mid, exit-a], url: "http://127.0.0.1/", interval: 60}
`)
	require.NoError(t, err)
	assert.Equal(t, "", dialerProxyOf(t, proxies, "entry"))
	assert.Equal(t, "entry", dialerProxyOf(t, proxies, "mid"))
	assert.Equal(t, "mid", dialerProxyOf(t, proxies, "exit-a"))
	assert.Equal(t, "", dialerProxyOf(t, proxies, "exit-b"))

	chain, ok := proxies["cascade"].Adapter().(*outboundgroup.Chain)
	require.True(t, ok)
	assert.Equal(t, "Chain", proxies["cascade"].Type().String())
	assert.Equal(t, "exit-a", chain.Now())
	var hops []string
	for _, h := range chain.Hops() {
		hops = append(hops, h.Name())
	}
	assert.Equal(t, []string{"entry", "mid", "exit-a"}, hops)
	assert.Contains(t, providers, "cascade")

	st := chain.Status()
	assert.False(t, st.Checked)
	assert.Equal(t, -1, st.FailedHop)
}

func TestChainParseGroupHops(t *testing.T) {
	proxies, _, err := parseChainConfig(t, chainTestProxies+`proxy-providers:
  subs:
    type: inline
    payload:
      - {name: sub-1, type: ss, server: 127.0.0.1, port: 1090, cipher: aes-128-gcm, password: pass}
proxy-groups:
  - {name: entries, type: fallback, proxies: [entry, other], url: "http://127.0.0.1/"}
  - {name: exits, type: url-test, proxies: [exit-a, exit-b], use: [subs], url: "http://127.0.0.1/"}
  - {name: cascade, type: chain, proxies: [entries, exits]}
`)
	require.NoError(t, err)
	// a group as the first hop: the next hop goes through the group
	assert.Equal(t, "entries", dialerProxyOf(t, proxies, "exit-a"))
	assert.Equal(t, "entries", dialerProxyOf(t, proxies, "exit-b"))
	// the members of the first hop are untouched
	assert.Equal(t, "", dialerProxyOf(t, proxies, "entry"))
	assert.Equal(t, "", dialerProxyOf(t, proxies, "other"))
}

func TestChainParseGroupHopProviderIsWired(t *testing.T) {
	rawCfg, err := UnmarshalRawConfig([]byte(chainTestProxies + `proxy-providers:
  subs:
    type: inline
    payload:
      - {name: sub-1, type: ss, server: 127.0.0.1, port: 1090, cipher: aes-128-gcm, password: pass}
proxy-groups:
  - {name: exits, type: url-test, use: [subs], url: "http://127.0.0.1/"}
  - {name: cascade, type: chain, proxies: [entry, exits]}
`))
	require.NoError(t, err)
	require.NoError(t, expandChains(rawCfg))
	assert.Equal(t, "entry", rawCfg.ProxyProvider["subs"]["dialer-proxy"])
}

func TestChainParseChainAsHop(t *testing.T) {
	proxies, _, err := parseChainConfig(t, chainTestProxies+`proxy-groups:
  - {name: tail, type: chain, proxies: [mid, exit-a]}
  - {name: cascade, type: chain, proxies: [entry, tail]}
`)
	require.NoError(t, err)
	// the first hop of the inner chain goes through the hop before it
	assert.Equal(t, "entry", dialerProxyOf(t, proxies, "mid"))
	assert.Equal(t, "mid", dialerProxyOf(t, proxies, "exit-a"))
}

func TestChainParseSameWiringTwice(t *testing.T) {
	proxies, _, err := parseChainConfig(t, chainTestProxies+`proxy-groups:
  - {name: c1, type: chain, proxies: [entry, exit-a]}
  - {name: c2, type: chain, proxies: [entry, exit-a]}
`)
	require.NoError(t, err)
	assert.Equal(t, "entry", dialerProxyOf(t, proxies, "exit-a"))
}

func TestChainParseErrors(t *testing.T) {
	for name, tc := range map[string]struct {
		groups string
		extra  string
		want   string
	}{
		"one hop": {
			groups: `  - {name: cascade, type: chain, proxies: [entry]}`,
			want:   "chain [cascade]: needs at least two hops",
		},
		"unknown hop": {
			groups: `  - {name: cascade, type: chain, proxies: [entry, nope]}`,
			want:   "chain [cascade]: hop 2 [nope] not found",
		},
		"self": {
			groups: `  - {name: cascade, type: chain, proxies: [entry, cascade]}`,
			want:   "chain [cascade]: the chain is one of its own hops",
		},
		"repeated hop": {
			groups: `  - {name: cascade, type: chain, proxies: [entry, mid, entry]}`,
			want:   "chain [cascade]: hop [entry] appears twice",
		},
		"use": {
			groups: `  - {name: cascade, type: chain, proxies: [entry, mid], use: [x]}`,
			want:   "chain [cascade]: `use` is not supported",
		},
		"loop through a group": {
			// entry -> cascade (group member) and cascade -> entry (hop)
			groups: `  - {name: g, type: select, proxies: [cascade, other]}
  - {name: cascade, type: chain, proxies: [g, exit-a]}`,
			want: "chain [cascade]: loop detected: cascade -> g -> cascade",
		},
		"loop made by the wiring": {
			// exits contains the first hop: entry would go through itself
			groups: `  - {name: exits, type: fallback, proxies: [exit-a, entry]}
  - {name: cascade, type: chain, proxies: [entry, exits]}`,
			want: "loop detected: entry -> entry",
		},
		"loop through two chains": {
			groups: `  - {name: c1, type: chain, proxies: [mid, exit-a]}
  - {name: c2, type: chain, proxies: [exit-a, mid]}`,
			want: "loop detected",
		},
		"dialer-proxy conflict": {
			extra:  `  - {name: pinned, type: ss, server: 127.0.0.1, port: 1086, cipher: aes-128-gcm, password: pass, dialer-proxy: other}`,
			groups: `  - {name: cascade, type: chain, proxies: [entry, pinned]}`,
			want:   "chain [cascade]: proxy [pinned] (hop 2) already has dialer-proxy [other], the chain needs [entry]",
		},
		"two chains disagree": {
			groups: `  - {name: c1, type: chain, proxies: [entry, exit-a]}
  - {name: c2, type: chain, proxies: [mid, exit-a]}`,
			want: "chain [c2]: proxy [exit-a] (hop 2) must go through [mid], but chain [c1] already sends it through [entry]",
		},
		"builtin after the first hop": {
			groups: `  - {name: cascade, type: chain, proxies: [entry, DIRECT]}`,
			want:   "the built-in [DIRECT] can not be hop 2",
		},
		"builtin inside a group after the first hop": {
			groups: `  - {name: exits, type: select, proxies: [exit-a, DIRECT]}
  - {name: cascade, type: chain, proxies: [entry, exits]}`,
			want: "chain [cascade]: group [exits] (hop 2) contains the built-in [DIRECT], which can not go through [entry]",
		},
		"include-all group as a hop": {
			groups: `  - {name: all, type: url-test, include-all: true}
  - {name: cascade, type: chain, proxies: [entry, all]}`,
			want: "group [all] with `include-all` can not be hop 2",
		},
	} {
		t.Run(name, func(t *testing.T) {
			_, _, err := parseChainConfig(t, chainTestProxies+tc.extra+"\nproxy-groups:\n"+tc.groups+"\n")
			require.Error(t, err)
			assert.Contains(t, err.Error(), tc.want)
		})
	}
}

func TestChainParseNoChainUntouched(t *testing.T) {
	// without a chain group, dialer-proxy works as before
	proxies, _, err := parseChainConfig(t, chainTestProxies+`  - {name: pinned, type: ss, server: 127.0.0.1, port: 1086, cipher: aes-128-gcm, password: pass, dialer-proxy: other}
`)
	require.NoError(t, err)
	assert.Equal(t, "other", dialerProxyOf(t, proxies, "pinned"))
}

// hopNode is a node of a cascade in the test: an inbound whose tunnel dials
// the destination directly and records it.
type hopNode struct {
	name string
	in   hopInbound
	addr string
	mu   sync.Mutex
	seen []string
}

func (h *hopNode) record(network, dst string) {
	h.mu.Lock()
	h.seen = append(h.seen, network+" "+dst)
	h.mu.Unlock()
}

func (h *hopNode) saw(network, dst string) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	for _, s := range h.seen {
		if s == network+" "+dst {
			return true
		}
	}
	return false
}

func (h *hopNode) port() int {
	return int(netip.MustParseAddrPort(h.addr).Port())
}

func (h *hopNode) HandleTCPConn(conn net.Conn, metadata *C.Metadata) {
	defer conn.Close()
	h.record("tcp", metadata.RemoteAddress())
	out, err := net.DialTimeout("tcp", metadata.RemoteAddress(), 5*time.Second)
	if err != nil {
		return
	}
	defer out.Close()
	done := make(chan struct{}, 2)
	go func() { _, _ = io.Copy(out, conn); done <- struct{}{} }()
	go func() { _, _ = io.Copy(conn, out); done <- struct{}{} }()
	<-done
}

func (h *hopNode) HandleUDPPacket(packet C.UDPPacket, metadata *C.Metadata) {
	data := append([]byte(nil), packet.Data()...)
	packet.Drop()
	h.record("udp", metadata.RemoteAddress())
	go func() {
		pc, err := net.ListenPacket("udp", "127.0.0.1:0")
		if err != nil {
			return
		}
		defer pc.Close()
		dst := metadata.UDPAddr()
		if _, err := pc.WriteTo(data, dst); err != nil {
			return
		}
		_ = pc.SetReadDeadline(time.Now().Add(5 * time.Second))
		buf := make([]byte, 2048)
		n, from, err := pc.ReadFrom(buf)
		if err != nil {
			return
		}
		_, _ = packet.WriteBack(buf[:n], from)
	}()
}

func (h *hopNode) NatTable() C.NatTable { return nil }

type hopInbound interface {
	Close() error
	Address() string
	Listen(tunnel C.Tunnel) error
}

// newNode starts an inbound whose TCP and UDP listeners share a port, as a
// real node does.
func newNode(t *testing.T, name string, open func(port string) (hopInbound, error)) *hopNode {
	t.Helper()
	h := &hopNode{name: name}
	var err error
	for i := 0; i < 40; i++ {
		// free ports come out in runs that can fall inside a range excluded
		// for the other protocol on Windows: take the port from UDP and from
		// TCP in turn
		var addr net.Addr
		if i%2 == 0 {
			pc, err := net.ListenPacket("udp", "127.0.0.1:0")
			require.NoError(t, err)
			addr = pc.LocalAddr()
			_ = pc.Close()
		} else {
			l, err := net.Listen("tcp", "127.0.0.1:0")
			require.NoError(t, err)
			addr = l.Addr()
			_ = l.Close()
		}
		port := netip.MustParseAddrPort(addr.String()).Port()
		var in hopInbound
		if in, err = open(fmt.Sprint(port)); err != nil {
			continue
		}
		if err = in.Listen(h); err != nil {
			// the port is taken for TCP: close what was opened (a shadowsocks
			// inbound that failed has nothing to close and panics on Close),
			// then try another port
			func() {
				defer func() { _ = recover() }()
				_ = in.Close()
			}()
			continue
		}
		h.in = in
		h.addr = fmt.Sprintf("127.0.0.1:%d", port)
		t.Cleanup(func() { _ = in.Close() })
		return h
	}
	require.NoError(t, err)
	return nil
}

func newSocksNode(t *testing.T, name string) *hopNode {
	return newNode(t, name, func(port string) (hopInbound, error) {
		return inbound.NewSocks(&inbound.SocksOption{
			BaseOption: inbound.BaseOption{NameStr: name, Listen: "127.0.0.1", Port: port},
			// an empty user list: no authentication, and not the default
			// listener's LAN filter
			Users: inbound.AuthUsers{},
			UDP:   true,
		})
	})
}

func newShadowsocksNode(t *testing.T, name string) *hopNode {
	return newNode(t, name, func(port string) (hopInbound, error) {
		return inbound.NewShadowSocks(&inbound.ShadowSocksOption{
			BaseOption: inbound.BaseOption{NameStr: name, Listen: "127.0.0.1", Port: port},
			Password:   "pass",
			Cipher:     "aes-128-gcm",
			UDP:        true,
		})
	})
}

// loadChainConfig parses the configuration and installs its proxies in the
// tunnel, where dialer-proxy looks the hops up.
func loadChainConfig(t *testing.T, yaml string) (map[string]C.Proxy, map[string]P.ProxyProvider) {
	t.Helper()
	proxies, providers, err := parseChainConfig(t, yaml)
	require.NoError(t, err)
	oldProxies, oldProviders := tunnel.Proxies(), tunnel.Providers()
	tunnel.UpdateProxies(proxies, providers)
	t.Cleanup(func() { tunnel.UpdateProxies(oldProxies, oldProviders) })
	return proxies, providers
}

func newTCPEcho(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = l.Close() })
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				_, _ = io.Copy(c, c)
			}()
		}
	}()
	return l.Addr().String()
}

func newUDPEcho(t *testing.T) string {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = pc.Close() })
	go func() {
		buf := make([]byte, 2048)
		for {
			n, from, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			_, _ = pc.WriteTo(buf[:n], from)
		}
	}()
	return pc.LocalAddr().String()
}

func metadataFor(t *testing.T, network C.NetWork, addr string) *C.Metadata {
	t.Helper()
	m := &C.Metadata{NetWork: network}
	require.NoError(t, m.SetRemoteAddress(addr))
	return m
}

func chainTCPRoundTrip(t *testing.T, proxy C.Proxy, dst string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	conn, err := proxy.DialContext(ctx, metadataFor(t, C.TCP, dst))
	require.NoError(t, err)
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	_, err = conn.Write([]byte("hello chain"))
	require.NoError(t, err)
	buf := make([]byte, len("hello chain"))
	_, err = io.ReadFull(conn, buf)
	require.NoError(t, err)
	assert.Equal(t, "hello chain", string(buf))
}

func TestChainTCPTraversesHopsInOrder(t *testing.T) {
	entry := newSocksNode(t, "entry")
	exit := newShadowsocksNode(t, "exit")
	echo := newTCPEcho(t)

	proxies, _ := loadChainConfig(t, fmt.Sprintf(`proxies:
  - {name: entry, type: socks5, server: 127.0.0.1, port: %d, udp: true}
  - {name: exit, type: ss, server: 127.0.0.1, port: %d, cipher: aes-128-gcm, password: pass, udp: true}
proxy-groups:
  - {name: cascade, type: chain, proxies: [entry, exit]}
`, entry.port(), exit.port()))

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	conn, err := proxies["cascade"].DialContext(ctx, metadataFor(t, C.TCP, echo))
	require.NoError(t, err)
	// /connections: the outbound that carried the traffic, then the groups
	assert.Equal(t, C.Chain{"exit", "cascade"}, conn.Chains())
	_ = conn.Close()

	chainTCPRoundTrip(t, proxies["cascade"], echo)

	// the entry node only saw the exit node, the exit node saw the target
	assert.True(t, entry.saw("tcp", exit.addr), "entry saw %v", entry.seen)
	assert.False(t, entry.saw("tcp", echo), "entry saw %v", entry.seen)
	assert.True(t, exit.saw("tcp", echo), "exit saw %v", exit.seen)
}

func TestChainThreeHopsTCP(t *testing.T) {
	entry := newSocksNode(t, "entry")
	mid := newSocksNode(t, "mid")
	exit := newShadowsocksNode(t, "exit")
	echo := newTCPEcho(t)

	proxies, _ := loadChainConfig(t, fmt.Sprintf(`proxies:
  - {name: entry, type: socks5, server: 127.0.0.1, port: %d}
  - {name: mid, type: socks5, server: 127.0.0.1, port: %d}
  - {name: exit, type: ss, server: 127.0.0.1, port: %d, cipher: aes-128-gcm, password: pass}
proxy-groups:
  - {name: cascade, type: chain, proxies: [entry, mid, exit]}
`, entry.port(), mid.port(), exit.port()))

	chainTCPRoundTrip(t, proxies["cascade"], echo)
	assert.True(t, entry.saw("tcp", mid.addr), "entry saw %v", entry.seen)
	assert.True(t, mid.saw("tcp", exit.addr), "mid saw %v", mid.seen)
	assert.True(t, exit.saw("tcp", echo), "exit saw %v", exit.seen)
}

func TestChainUDPTraversesHopsInOrder(t *testing.T) {
	entry := newSocksNode(t, "entry")
	exit := newShadowsocksNode(t, "exit")
	echo := newUDPEcho(t)

	proxies, _ := loadChainConfig(t, fmt.Sprintf(`proxies:
  - {name: entry, type: socks5, server: 127.0.0.1, port: %d, udp: true}
  - {name: exit, type: ss, server: 127.0.0.1, port: %d, cipher: aes-128-gcm, password: pass, udp: true}
proxy-groups:
  - {name: cascade, type: chain, proxies: [entry, exit]}
`, entry.port(), exit.port()))

	cascade := proxies["cascade"]
	require.True(t, cascade.SupportUDP())

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	m := metadataFor(t, C.UDP, echo)
	pc, err := cascade.ListenPacketContext(ctx, m)
	require.NoError(t, err)
	defer pc.Close()
	assert.Equal(t, C.Chain{"exit", "cascade"}, pc.Chains())

	dst := net.UDPAddrFromAddrPort(netip.MustParseAddrPort(echo))
	buf := make([]byte, 2048)
	var got string
	// UDP may lose the first datagram while the hops set up
	for i := 0; i < 5 && got == ""; i++ {
		_, err = pc.WriteTo([]byte("udp over chain"), dst)
		require.NoError(t, err)
		_ = pc.SetReadDeadline(time.Now().Add(2 * time.Second))
		n, _, err := pc.ReadFrom(buf)
		if err == nil {
			got = string(buf[:n])
		}
	}
	assert.Equal(t, "udp over chain", got)
	assert.True(t, entry.saw("udp", exit.addr), "entry saw %v", entry.seen)
	assert.True(t, exit.saw("udp", echo), "exit saw %v", exit.seen)
}

func newHealthTarget(t *testing.T) string {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(srv.Close)
	return srv.URL + "/generate_204"
}

func TestChainHealthCheckFindsFailedHop(t *testing.T) {
	entry := newSocksNode(t, "entry")
	mid := newSocksNode(t, "mid")
	exit := newShadowsocksNode(t, "exit")
	target := newHealthTarget(t)

	proxies, providers := loadChainConfig(t, fmt.Sprintf(`proxies:
  - {name: entry, type: socks5, server: 127.0.0.1, port: %d}
  - {name: mid, type: socks5, server: 127.0.0.1, port: %d}
  - {name: exit, type: ss, server: 127.0.0.1, port: %d, cipher: aes-128-gcm, password: pass}
proxy-groups:
  - {name: cascade, type: chain, proxies: [entry, mid, exit], url: "%s", timeout: 3000}
`, entry.port(), mid.port(), exit.port(), target))
	chain := proxies["cascade"].Adapter().(*outboundgroup.Chain)

	sub := eventbus.Subscribe(eventbus.All, 16)
	defer sub.Close()

	// all hops up
	healthCheck(providers["cascade"])
	st := chain.Status()
	require.True(t, st.Checked)
	assert.True(t, st.Alive)
	assert.Equal(t, -1, st.FailedHop)
	for _, h := range st.Hops {
		require.NotNil(t, h.Alive)
		assert.True(t, *h.Alive)
	}

	// the middle hop goes down
	require.NoError(t, mid.in.Close())
	healthCheck(providers["cascade"])
	st = chain.Status()
	assert.False(t, st.Alive)
	assert.Equal(t, 1, st.FailedHop)
	require.NotNil(t, st.Hops[0].Alive)
	assert.True(t, *st.Hops[0].Alive)
	require.NotNil(t, st.Hops[1].Alive)
	assert.False(t, *st.Hops[1].Alive)
	assert.Nil(t, st.Hops[2].Alive)
	assert.Contains(t, st.Error, "hop 2 [mid] failed, the hops before it are alive")

	// /proxies shows it
	js, err := proxies["cascade"].MarshalJSON()
	require.NoError(t, err)
	assert.Contains(t, string(js), `"failedHop":"mid"`)
	assert.Contains(t, string(js), `"failedHopPosition":2`)
	assert.Contains(t, string(js), `"chainAlive":false`)

	// /metrics shows it
	var buf bytes.Buffer
	require.NoError(t, metrics.Write(&buf, metrics.Options{Enable: true}))
	assert.Contains(t, buf.String(), `citrus_chain_alive{chain="cascade"} 0`)
	assert.Contains(t, buf.String(), `citrus_chain_hop_alive{chain="cascade",hop="entry",position="1"} 1`)
	assert.Contains(t, buf.String(), `citrus_chain_hop_alive{chain="cascade",hop="mid",position="2"} 0`)
	assert.NotContains(t, buf.String(), `hop="exit"`)

	// the event of the change
	e := waitEvent(t, sub, eventbus.TypeChainHealth)
	d := e.Data.(eventbus.ChainHealth)
	assert.Equal(t, "cascade", d.Chain)
	assert.False(t, d.Alive)
	assert.Equal(t, "mid", d.FailedHop)
	assert.Equal(t, 2, d.Position)

	// the delay test of the group reports the hop too
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	delays, err := chain.URLTest(ctx, target, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "hop 2 [mid] failed, the hops before it are alive")
	assert.Contains(t, delays, "entry")
}

func TestChainHealthCheckFirstAndLastHop(t *testing.T) {
	entry := newSocksNode(t, "entry")
	exit := newShadowsocksNode(t, "exit")
	target := newHealthTarget(t)

	proxies, providers := loadChainConfig(t, fmt.Sprintf(`proxies:
  - {name: entry, type: socks5, server: 127.0.0.1, port: %d}
  - {name: exit, type: ss, server: 127.0.0.1, port: %d, cipher: aes-128-gcm, password: pass}
proxy-groups:
  - {name: cascade, type: chain, proxies: [entry, exit], url: "%s", timeout: 3000}
`, entry.port(), exit.port(), target))
	chain := proxies["cascade"].Adapter().(*outboundgroup.Chain)

	// the exit goes down: the entry still works
	require.NoError(t, exit.in.Close())
	healthCheck(providers["cascade"])
	st := chain.Status()
	assert.False(t, st.Alive)
	assert.Equal(t, 1, st.FailedHop)
	assert.True(t, *st.Hops[0].Alive)

	// the entry goes down too: the first hop is reported
	require.NoError(t, entry.in.Close())
	healthCheck(providers["cascade"])
	st = chain.Status()
	assert.False(t, st.Alive)
	assert.Equal(t, 0, st.FailedHop)
	assert.False(t, *st.Hops[0].Alive)
	assert.Nil(t, st.Hops[1].Alive)
	assert.Contains(t, st.Error, "hop 1 [entry] failed")
}

func TestChainFailoverAcrossExits(t *testing.T) {
	entry := newSocksNode(t, "entry")
	exitA := newShadowsocksNode(t, "exit-a")
	exitB := newShadowsocksNode(t, "exit-b")
	echo := newTCPEcho(t)
	target := newHealthTarget(t)

	proxies, providers := loadChainConfig(t, fmt.Sprintf(`proxies:
  - {name: entry, type: socks5, server: 127.0.0.1, port: %d}
  - {name: exit-a, type: ss, server: 127.0.0.1, port: %d, cipher: aes-128-gcm, password: pass}
  - {name: exit-b, type: ss, server: 127.0.0.1, port: %d, cipher: aes-128-gcm, password: pass}
proxy-groups:
  - {name: exits, type: fallback, proxies: [exit-a, exit-b], url: "%s", timeout: 3000}
  - {name: cascade, type: chain, proxies: [entry, exits], url: "%s", timeout: 3000}
`, entry.port(), exitA.port(), exitB.port(), target, target))

	// both exits up: the first one carries the traffic, through the entry
	healthCheck(providers["exits"])
	chainTCPRoundTrip(t, proxies["cascade"], echo)
	assert.True(t, exitA.saw("tcp", echo))
	assert.False(t, exitB.saw("tcp", echo))
	assert.True(t, entry.saw("tcp", exitA.addr))
	// the health check of the exits group went through the entry as well
	assert.True(t, entry.saw("tcp", exitB.addr), "entry saw %v", entry.seen)

	// exit-a goes down: the group fails over to exit-b, still through the entry
	require.NoError(t, exitA.in.Close())
	healthCheck(providers["exits"])
	assert.Equal(t, "exit-b", proxies["exits"].Adapter().(outboundgroup.ProxyGroup).Now())
	chainTCPRoundTrip(t, proxies["cascade"], echo)
	assert.True(t, exitB.saw("tcp", echo), "exit-b saw %v", exitB.seen)

	healthCheck(providers["cascade"])
	st := proxies["cascade"].Adapter().(*outboundgroup.Chain).Status()
	assert.True(t, st.Alive)
}

func waitEvent(t *testing.T, sub *eventbus.Subscription, typ string) eventbus.Event {
	t.Helper()
	timeout := time.After(5 * time.Second)
	for {
		select {
		case e := <-sub.C():
			if e.Type == typ {
				return e
			}
		case <-timeout:
			require.FailNow(t, "no "+typ+" event")
		}
	}
}

// healthCheck runs a health check of the provider; a check right after
// another one is skipped (it is shared for a second), so it waits that out.
func healthCheck(pd P.ProxyProvider) {
	time.Sleep(1100 * time.Millisecond)
	pd.HealthCheck()
}
