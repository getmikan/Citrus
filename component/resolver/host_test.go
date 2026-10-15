package resolver

import (
	"context"
	"errors"
	"net/netip"
	"testing"
	"time"

	"github.com/metacubex/mihomo/component/trie"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newTestHosts(t *testing.T, entries map[string][]string) Hosts {
	t.Helper()
	tree := trie.New[HostValue]()
	for domain, value := range entries {
		hv, err := NewHostValue(value)
		require.NoError(t, err)
		require.NoError(t, tree.Insert(domain, hv))
	}
	tree.Optimize()
	return NewHosts(tree)
}

// search fails the test instead of hanging when Hosts.Search doesn't return.
func search(t *testing.T, h Hosts, domain string, isDomain bool) (*HostValue, bool) {
	t.Helper()
	type result struct {
		value *HostValue
		ok    bool
	}
	done := make(chan result, 1)
	go func() {
		value, ok := h.Search(domain, isDomain)
		done <- result{value, ok}
	}()
	select {
	case r := <-done:
		return r.value, r.ok
	case <-time.After(5 * time.Second):
		t.Fatalf("Search(%q, %v) did not return", domain, isDomain)
		return nil, false
	}
}

func TestHostsSearchIPs(t *testing.T) {
	h := newTestHosts(t, map[string][]string{"a.com": {"1.1.1.1", "::1"}})

	value, ok := search(t, h, "a.com", false)
	require.True(t, ok)
	assert.Equal(t, []netip.Addr{netip.MustParseAddr("1.1.1.1"), netip.MustParseAddr("::1")}, value.IPs)

	value, ok = search(t, h, "a.com", true)
	assert.False(t, ok)
	assert.False(t, value.IsDomain)
}

func TestHostsSearchChain(t *testing.T) {
	h := newTestHosts(t, map[string][]string{
		"a.com": {"b.com"},
		"b.com": {"c.com"},
		"c.com": {"3.3.3.3"},
		"x.com": {"y.com"},
		"y.com": {"z.com"},
	})

	value, ok := search(t, h, "a.com", false)
	require.True(t, ok)
	assert.Equal(t, []netip.Addr{netip.MustParseAddr("3.3.3.3")}, value.IPs)

	// a chain without IPs ends at its last domain
	value, ok = search(t, h, "x.com", false)
	assert.False(t, ok)
	require.NotNil(t, value)
	assert.Equal(t, "z.com", value.Domain)

	// a CNAME lookup takes the first hop only
	value, ok = search(t, h, "a.com", true)
	require.True(t, ok)
	assert.Equal(t, "b.com", value.Domain)
}

func TestHostsSearchSelfWildcard(t *testing.T) {
	h := newTestHosts(t, map[string][]string{
		"+.example.com": {"example.com"},
		"+.example.org": {"foo.example.org"},
	})

	for domain, target := range map[string]string{
		"example.com":     "example.com",
		"www.example.com": "example.com",
		"bar.example.org": "foo.example.org",
		"foo.example.org": "foo.example.org",
	} {
		value, ok := search(t, h, domain, false)
		assert.False(t, ok, domain)
		if assert.NotNil(t, value, domain) {
			assert.Equal(t, target, value.Domain, domain)
		}
	}
}

func TestHostsSearchCycle(t *testing.T) {
	h := newTestHosts(t, map[string][]string{
		"a.com":      {"b.com"},
		"b.com":      {"a.com"},
		"+.loop.io":  {"x.loop.net"},
		"+.loop.net": {"y.loop.io"},
	})

	for _, domain := range []string{"a.com", "b.com", "www.loop.io", "www.loop.net"} {
		value, ok := search(t, h, domain, false)
		assert.False(t, ok, domain)
		assert.Nil(t, value, domain)
	}
}

// fakeResolver answers from a fixed map and reports Invalid() so the Lookup*
// functions use it instead of the system resolver.
type fakeResolver map[string][]netip.Addr

func (f fakeResolver) lookup(host string, keep func(netip.Addr) bool) ([]netip.Addr, error) {
	ips, ok := f[host]
	if !ok {
		return nil, errors.New("no such host: " + host)
	}
	var out []netip.Addr
	for _, ip := range ips {
		if keep(ip) {
			out = append(out, ip)
		}
	}
	return out, nil
}

func (f fakeResolver) LookupIP(_ context.Context, host string) ([]netip.Addr, error) {
	return f.lookup(host, func(netip.Addr) bool { return true })
}

func (f fakeResolver) LookupIPv4(_ context.Context, host string) ([]netip.Addr, error) {
	return f.lookup(host, netip.Addr.Is4)
}

func (f fakeResolver) LookupIPv6(_ context.Context, host string) ([]netip.Addr, error) {
	return f.lookup(host, netip.Addr.Is6)
}

func (f fakeResolver) ResolveECH(context.Context, string) ([]byte, error) { return nil, nil }

func (f fakeResolver) ExchangeContext(context.Context, *dns.Msg) (*dns.Msg, error) {
	return nil, nil
}

func (f fakeResolver) Invalid() bool    { return true }
func (f fakeResolver) ClearCache()      {}
func (f fakeResolver) ResetConnection() {}

func withDefaultHosts(t *testing.T, entries map[string][]string) {
	t.Helper()
	orig, origDisableIPv6 := DefaultHosts, DisableIPv6
	t.Cleanup(func() { DefaultHosts, DisableIPv6 = orig, origDisableIPv6 })
	DefaultHosts = newTestHosts(t, entries)
	DisableIPv6 = false
}

func TestLookupFollowsHostsDomainMapping(t *testing.T) {
	withDefaultHosts(t, map[string][]string{
		"a.com":         {"b.com"},
		"ip.com":        {"9.9.9.9"},
		"+.example.com": {"example.com"},
		"loop1.com":     {"loop2.com"},
		"loop2.com":     {"loop1.com"},
	})
	r := fakeResolver{
		"a.com":       {netip.MustParseAddr("2.2.2.2"), netip.MustParseAddr("2::2")},
		"b.com":       {netip.MustParseAddr("1.1.1.1"), netip.MustParseAddr("1::1")},
		"example.com": {netip.MustParseAddr("5.5.5.5")},
		"loop1.com":   {netip.MustParseAddr("7.7.7.7")},
	}
	ctx := context.Background()

	ips, err := LookupIPv4WithResolver(ctx, "a.com", r)
	require.NoError(t, err)
	assert.Equal(t, []netip.Addr{netip.MustParseAddr("1.1.1.1")}, ips)

	ips, err = LookupIPv6WithResolver(ctx, "a.com", r)
	require.NoError(t, err)
	assert.Equal(t, []netip.Addr{netip.MustParseAddr("1::1")}, ips)

	ips, err = LookupIPWithResolver(ctx, "a.com", r)
	require.NoError(t, err)
	assert.Equal(t, []netip.Addr{netip.MustParseAddr("1.1.1.1"), netip.MustParseAddr("1::1")}, ips)

	// plain IP hosts are unchanged
	ips, err = LookupIPv4WithResolver(ctx, "ip.com", r)
	require.NoError(t, err)
	assert.Equal(t, []netip.Addr{netip.MustParseAddr("9.9.9.9")}, ips)

	ips, err = LookupIPv4WithResolver(ctx, "www.example.com", r)
	require.NoError(t, err)
	assert.Equal(t, []netip.Addr{netip.MustParseAddr("5.5.5.5")}, ips)

	// a cycle counts as no mapping: the name itself is resolved
	ips, err = LookupIPv4WithResolver(ctx, "loop1.com", r)
	require.NoError(t, err)
	assert.Equal(t, []netip.Addr{netip.MustParseAddr("7.7.7.7")}, ips)
}
