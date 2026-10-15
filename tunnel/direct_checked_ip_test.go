package tunnel_test

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/metacubex/mihomo/adapter"
	"github.com/metacubex/mihomo/adapter/outbound"
	"github.com/metacubex/mihomo/component/resolver"
	C "github.com/metacubex/mihomo/constant"
	RC "github.com/metacubex/mihomo/rules/common"
	"github.com/metacubex/mihomo/tunnel"

	D "github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// sequenceResolver answers successive lookups with the next address of its
// list (the last one repeats), like a rebinding DNS server with a zero TTL.
// IP literals are returned as is and not counted, as dns.Resolver does.
type sequenceResolver struct {
	mu    sync.Mutex
	ips   []netip.Addr
	calls int
}

func (r *sequenceResolver) lookup(host string) []netip.Addr {
	if ip, err := netip.ParseAddr(host); err == nil {
		return []netip.Addr{ip}
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	i := r.calls
	if i >= len(r.ips) {
		i = len(r.ips) - 1
	}
	r.calls++
	return []netip.Addr{r.ips[i]}
}

func (r *sequenceResolver) Calls() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.calls
}

func (r *sequenceResolver) LookupIP(_ context.Context, host string) ([]netip.Addr, error) {
	return r.lookup(host), nil
}

func (r *sequenceResolver) LookupIPv4(_ context.Context, host string) ([]netip.Addr, error) {
	return r.lookup(host), nil
}

func (r *sequenceResolver) LookupIPv6(context.Context, string) ([]netip.Addr, error) {
	return nil, resolver.ErrIPv6Disabled
}

func (r *sequenceResolver) ResolveECH(context.Context, string) ([]byte, error) {
	return nil, errors.New("not supported")
}

func (r *sequenceResolver) ExchangeContext(context.Context, *D.Msg) (*D.Msg, error) {
	return nil, errors.New("not supported")
}

func (r *sequenceResolver) Invalid() bool    { return true }
func (r *sequenceResolver) ClearCache()      {}
func (r *sequenceResolver) ResetConnection() {}

var _ resolver.Resolver = (*sequenceResolver)(nil)

func setupTunnel(t *testing.T, rules []C.Rule, defaultResolver, directResolver resolver.Resolver) {
	t.Helper()
	oldDefault, oldDirect, oldV6 := resolver.DefaultResolver, resolver.DirectHostResolver, resolver.DisableIPv6
	resolver.DefaultResolver = defaultResolver
	resolver.DirectHostResolver = directResolver
	resolver.DisableIPv6 = true
	t.Cleanup(func() {
		resolver.DefaultResolver, resolver.DirectHostResolver, resolver.DisableIPv6 = oldDefault, oldDirect, oldV6
		tunnel.UpdateRules(nil, nil, nil)
		tunnel.UpdateProxies(map[string]C.Proxy{}, nil)
		tunnel.OnSuspend()
	})

	tunnel.UpdateProxies(map[string]C.Proxy{
		"DIRECT": adapter.NewProxy(outbound.NewDirect()),
		"REJECT": adapter.NewProxy(outbound.NewReject()),
	}, nil)
	tunnel.UpdateRules(rules, nil, nil)
	tunnel.SetMode(tunnel.Rule)
	tunnel.OnRunning()
}

// runConn hands one TCP connection for host:port to the tunnel and reports
// whether the listener received it.
func runConn(t *testing.T, ln net.Listener, host string) bool {
	t.Helper()
	port := ln.Addr().(*net.TCPAddr).Port

	accepted := make(chan struct{}, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		accepted <- struct{}{}
		_ = c.Close()
	}()

	client, server := net.Pipe()
	defer client.Close()
	metadata := &C.Metadata{
		NetWork: C.TCP,
		Type:    C.SOCKS5,
		SrcIP:   netip.MustParseAddr("192.0.2.1"),
		SrcPort: 40000,
		Host:    host,
		DstPort: uint16(port),
	}
	done := make(chan struct{})
	go func() {
		tunnel.Tunnel.HandleTCPConn(server, metadata)
		close(done)
	}()

	var ok bool
	select {
	case <-accepted:
		ok = true
	case <-time.After(3 * time.Second):
	}
	_ = client.Close()
	_ = ln.Close()
	<-done
	return ok
}

func listen(t *testing.T) net.Listener {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	return ln
}

// The IP rule checks the first answer (a "public" address, 127.0.0.1 here as
// it is outside 10/8); a second lookup would return 10.0.0.1. DIRECT must
// dial the checked address and must not resolve the host again.
func TestDirectDialsCheckedIP(t *testing.T) {
	rebinding := &sequenceResolver{ips: []netip.Addr{
		netip.MustParseAddr("127.0.0.1"),
		netip.MustParseAddr("10.0.0.1"),
	}}
	reject, err := RC.NewIPCIDR("10.0.0.0/8", "REJECT")
	require.NoError(t, err)
	setupTunnel(t, []C.Rule{reject, RC.NewMatch("DIRECT")}, rebinding, rebinding)

	assert.True(t, runConn(t, listen(t), "rebind.example"), "DIRECT must reach the checked address")
	assert.Equal(t, 1, rebinding.Calls(), "the host must be resolved once, for the rule check only")
}

// Same, with direct-nameserver configured: DIRECT must still not ask it,
// since its answer was never checked against the IP rules.
func TestDirectDialsCheckedIPWithDirectNameserver(t *testing.T) {
	main := &sequenceResolver{ips: []netip.Addr{netip.MustParseAddr("127.0.0.1")}}
	direct := &sequenceResolver{ips: []netip.Addr{netip.MustParseAddr("10.0.0.1")}}
	reject, err := RC.NewIPCIDR("10.0.0.0/8", "REJECT")
	require.NoError(t, err)
	setupTunnel(t, []C.Rule{reject, RC.NewMatch("DIRECT")}, main, direct)

	assert.True(t, runConn(t, listen(t), "rebind.example"))
	assert.Equal(t, 1, main.Calls())
	assert.Equal(t, 0, direct.Calls())
}

// With only domain rules no IP was checked, so DIRECT keeps resolving the host
// through direct-nameserver.
func TestDirectUsesDirectNameserverWithoutIPRules(t *testing.T) {
	main := &sequenceResolver{ips: []netip.Addr{netip.MustParseAddr("10.0.0.1")}}
	direct := &sequenceResolver{ips: []netip.Addr{netip.MustParseAddr("127.0.0.1")}}
	setupTunnel(t, []C.Rule{
		RC.NewDomainSuffix("blocked.example", "REJECT"),
		RC.NewMatch("DIRECT"),
	}, main, direct)

	assert.True(t, runConn(t, listen(t), "allowed.example"))
	assert.Equal(t, 0, main.Calls())
	assert.GreaterOrEqual(t, direct.Calls(), 1)
}

// IP-CIDR with no-resolve does not resolve, so nothing is pinned and DIRECT
// resolves through direct-nameserver as before.
func TestDirectNoResolveIPRuleKeepsDirectNameserver(t *testing.T) {
	main := &sequenceResolver{ips: []netip.Addr{netip.MustParseAddr("10.0.0.1")}}
	direct := &sequenceResolver{ips: []netip.Addr{netip.MustParseAddr("127.0.0.1")}}
	reject, err := RC.NewIPCIDR("10.0.0.0/8", "REJECT", RC.WithIPCIDRNoResolve(true))
	require.NoError(t, err)
	setupTunnel(t, []C.Rule{reject, RC.NewMatch("DIRECT")}, main, direct)

	assert.True(t, runConn(t, listen(t), "allowed.example"))
	assert.Equal(t, 0, main.Calls())
	assert.GreaterOrEqual(t, direct.Calls(), 1)
}
