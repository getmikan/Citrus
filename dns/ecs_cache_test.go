package dns

import (
	"context"
	"net/netip"
	"testing"

	D "github.com/miekg/dns"
)

// ecsUpstream answers with an address chosen by the query's client subnet,
// like a CDN's authoritative server would.
type ecsUpstream struct{}

func (ecsUpstream) ExchangeContext(ctx context.Context, m *D.Msg) (*D.Msg, error) {
	ip := netip.MustParseAddr("198.51.100.1") // no ECS
	if opt := m.IsEdns0(); opt != nil {
		for _, o := range opt.Option {
			if s, ok := o.(*D.EDNS0_SUBNET); ok {
				addr, _ := netip.AddrFromSlice(s.Address)
				ip = netip.AddrFrom4([4]byte{198, 51, 100, addr.Unmap().As4()[0]})
			}
		}
	}
	return answerA(m, ip, 300), nil
}

func (ecsUpstream) Address() string  { return "ecs" }
func (ecsUpstream) ResetConnection() {}

func queryWithECS(subnet string) *D.Msg {
	m := new(D.Msg)
	m.SetQuestion("cdn.example.", D.TypeA)
	if subnet != "" {
		setEdns0Subnet(m, netip.MustParsePrefix(subnet), false)
	}
	return m
}

func TestCacheKeyIncludesClientSubnet(t *testing.T) {
	plain := cacheKey(queryWithECS(""))
	a := cacheKey(queryWithECS("10.0.0.0/24"))
	b := cacheKey(queryWithECS("20.0.0.0/24"))
	if plain == a || a == b {
		t.Fatalf("keys collide: %q %q %q", plain, a, b)
	}
	if a != cacheKey(queryWithECS("10.0.0.0/24")) {
		t.Fatal("same subnet gives different keys")
	}
	if plain != queryWithECS("").Question[0].String() {
		t.Fatal("queries without ECS changed key")
	}
}

func TestResolverCacheSeparatesClientSubnets(t *testing.T) {
	r := &Resolver{main: []dnsClient{ecsUpstream{}}, cache: Config{}.newCache()}
	ctx := context.Background()

	want := map[string]string{
		"10.0.0.0/24": "198.51.100.10",
		"20.0.0.0/24": "198.51.100.20",
		"":            "198.51.100.1",
	}
	// Twice: the second round is served from the cache.
	for round := 0; round < 2; round++ {
		for subnet, ip := range want {
			msg, err := r.ExchangeContext(ctx, queryWithECS(subnet))
			if err != nil {
				t.Fatal(err)
			}
			if got := answerIP(t, msg).String(); got != ip {
				t.Fatalf("round %d, subnet %q: got %s, want %s", round, subnet, got, ip)
			}
		}
	}
}
