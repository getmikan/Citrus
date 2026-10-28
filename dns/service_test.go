package dns

import (
	"context"
	"net"
	"testing"

	icontext "github.com/metacubex/mihomo/context"

	D "github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// upstreamOptService answers like an upstream on a cache miss: with its own
// OPT carrying a large UDP size and an ECS option.
func upstreamOptService(rcode int) *Service {
	return &Service{handler: func(ctx *icontext.DNSContext, m *D.Msg) (*D.Msg, error) {
		r := new(D.Msg)
		r.SetRcode(m, rcode)
		r.Answer = append(r.Answer, &D.A{
			Hdr: D.RR_Header{Name: m.Question[0].Name, Rrtype: D.TypeA, Class: D.ClassINET, Ttl: 60},
			A:   net.IPv4(192, 0, 2, 1),
		})
		r.SetEdns0(4096, false)
		opt := r.IsEdns0()
		opt.Option = append(opt.Option, &D.EDNS0_SUBNET{
			Code: D.EDNS0SUBNET, Family: 1, SourceNetmask: 24, Address: net.IPv4(198, 51, 100, 0),
		})
		return r, nil
	}}
}

func TestServeMsgDropsUpstreamOptWithoutRequestOpt(t *testing.T) {
	m := new(D.Msg)
	m.SetQuestion("example.com.", D.TypeA)

	r, err := upstreamOptService(D.RcodeSuccess).ServeMsg(context.Background(), m)
	require.NoError(t, err)
	assert.Nil(t, r.IsEdns0())
	assert.Len(t, r.Answer, 1)

	_, err = r.Pack()
	assert.NoError(t, err)
}

func TestServeMsgReplacesUpstreamOpt(t *testing.T) {
	m := new(D.Msg)
	m.SetQuestion("example.com.", D.TypeA)
	m.SetEdns0(1400, true)

	r, err := upstreamOptService(D.RcodeSuccess).ServeMsg(context.Background(), m)
	require.NoError(t, err)

	opts := 0
	for _, rr := range r.Extra {
		if rr.Header().Rrtype == D.TypeOPT {
			opts++
		}
	}
	require.Equal(t, 1, opts)
	opt := r.IsEdns0()
	assert.Equal(t, uint16(1232), opt.UDPSize())
	assert.True(t, opt.Do())
	assert.Empty(t, opt.Option, "upstream options must not be forwarded")
}

func TestServeMsgExtendedRcodeWithoutRequestOpt(t *testing.T) {
	m := new(D.Msg)
	m.SetQuestion("example.com.", D.TypeA)

	r, err := upstreamOptService(D.RcodeBadCookie).ServeMsg(context.Background(), m)
	require.NoError(t, err)
	assert.Nil(t, r.IsEdns0())
	assert.Equal(t, D.RcodeServerFailure, r.Rcode)

	_, err = r.Pack()
	assert.NoError(t, err)
}
