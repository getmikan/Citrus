package outbound

import (
	"context"
	"errors"
	"net/netip"
	"testing"

	"github.com/metacubex/mihomo/component/resolver"
	C "github.com/metacubex/mihomo/constant"

	D "github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type fixedResolver struct {
	ip    netip.Addr
	calls int
}

func (r *fixedResolver) LookupIP(context.Context, string) ([]netip.Addr, error) {
	r.calls++
	return []netip.Addr{r.ip}, nil
}

func (r *fixedResolver) LookupIPv4(ctx context.Context, host string) ([]netip.Addr, error) {
	return r.LookupIP(ctx, host)
}

func (r *fixedResolver) LookupIPv6(context.Context, string) ([]netip.Addr, error) {
	return nil, resolver.ErrIPv6Disabled
}

func (r *fixedResolver) ResolveECH(context.Context, string) ([]byte, error) {
	return nil, errors.New("not supported")
}

func (r *fixedResolver) ExchangeContext(context.Context, *D.Msg) (*D.Msg, error) {
	return nil, errors.New("not supported")
}

func (r *fixedResolver) Invalid() bool    { return true }
func (r *fixedResolver) ClearCache()      {}
func (r *fixedResolver) ResetConnection() {}

func TestDirectAddress(t *testing.T) {
	m := &C.Metadata{Host: "example.com", DstIP: netip.MustParseAddr("203.0.113.7"), DstPort: 443}
	assert.Equal(t, "example.com:443", directAddress(m), "an unchecked address resolves the host")

	m.DstIPChecked = true
	assert.Equal(t, "203.0.113.7:443", directAddress(m), "a checked address is dialled as is")

	m6 := &C.Metadata{Host: "example.com", DstIP: netip.MustParseAddr("2001:db8::1"), DstPort: 443, DstIPChecked: true}
	assert.Equal(t, "[2001:db8::1]:443", directAddress(m6))
}

func TestDirectResolveUDPKeepsCheckedIP(t *testing.T) {
	main := &fixedResolver{ip: netip.MustParseAddr("203.0.113.7")}
	direct := &fixedResolver{ip: netip.MustParseAddr("10.0.0.1")}
	oldDefault, oldDirect, oldV6 := resolver.DefaultResolver, resolver.DirectHostResolver, resolver.DisableIPv6
	resolver.DefaultResolver, resolver.DirectHostResolver, resolver.DisableIPv6 = main, direct, true
	t.Cleanup(func() {
		resolver.DefaultResolver, resolver.DirectHostResolver, resolver.DisableIPv6 = oldDefault, oldDirect, oldV6
	})

	d := NewDirect()

	checked := &C.Metadata{NetWork: C.UDP, Host: "example.com", DstIP: netip.MustParseAddr("203.0.113.7"), DstPort: 53, DstIPChecked: true}
	require.NoError(t, d.ResolveUDP(context.Background(), checked))
	assert.Equal(t, netip.MustParseAddr("203.0.113.7"), checked.DstIP)
	assert.Equal(t, 0, direct.calls)

	// Not checked by an IP rule: direct-nameserver still decides.
	unchecked := &C.Metadata{NetWork: C.UDP, Host: "example.com", DstPort: 53}
	require.NoError(t, d.ResolveUDP(context.Background(), unchecked))
	assert.Equal(t, netip.MustParseAddr("10.0.0.1"), unchecked.DstIP)
	assert.Equal(t, 1, direct.calls)
}
