package dns

import (
	"context"
	"net/netip"
	"testing"

	"github.com/metacubex/mihomo/component/fakeip"
	icontext "github.com/metacubex/mihomo/context"

	D "github.com/miekg/dns"
	"github.com/stretchr/testify/require"
)

func TestWithFakeIPSkipsEscapedNames(t *testing.T) {
	// a query for "a.cn\x98." as it arrives on the wire, ID 1, RD
	wire := []byte{
		0x00, 0x01, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		1, 'a', 3, 'c', 'n', 0x98, 0,
		0x00, 0x01, 0x00, 0x01,
	}
	raw := new(D.Msg)
	require.NoError(t, raw.Unpack(wire))
	require.Equal(t, `a.cn\152.`, raw.Question[0].Name)

	for _, tt := range []struct {
		name   string
		msg    *D.Msg
		forged bool
	}{
		{name: "raw non-ASCII byte", msg: raw},
		{name: "dot inside a label", msg: question(`a\.b.example.`, D.TypeA)},
		{name: "space inside a label, AAAA", msg: question(`a\ b.example.`, D.TypeAAAA)},
		{name: "HTTPS for an escaped name", msg: question(`a\152.example.`, D.TypeHTTPS)},
		{name: "plain name", msg: question("www.example.", D.TypeA), forged: true},
		{name: "underscore is not escaped", msg: question("_dmarc.example.", D.TypeA), forged: true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			pool, err := fakeip.New(fakeip.Options{IPNet: netip.MustParsePrefix("198.18.0.1/16"), Size: 10})
			require.NoError(t, err)
			pool6, err := fakeip.New(fakeip.Options{IPNet: netip.MustParsePrefix("fc00::/18"), Size: 10})
			require.NoError(t, err)

			passed := false
			next := func(_ *icontext.DNSContext, r *D.Msg) (*D.Msg, error) {
				passed = true
				msg := new(D.Msg)
				msg.SetRcode(r, D.RcodeNameError)
				return msg, nil
			}
			ctx := icontext.NewDNSContext(context.Background())
			msg, err := withFakeIP(&fakeip.Skipper{}, pool, pool6, 1)(next)(ctx, tt.msg)
			require.NoError(t, err)

			if tt.forged {
				require.False(t, passed)
				require.Len(t, msg.Answer, 1)
				require.Equal(t, icontext.DNSTypeFakeIP, ctx.Type())
				return
			}
			require.True(t, passed, "an escaped name goes to the regular resolution")
			require.Equal(t, D.RcodeNameError, msg.Rcode)
			require.Empty(t, msg.Answer)
			require.NotEqual(t, icontext.DNSTypeFakeIP, ctx.Type())
			for _, p := range []*fakeip.Pool{pool, pool6} {
				// the first address the pool hands out is still free
				first := p.Lookup("probe.example")
				ref, err := fakeip.New(fakeip.Options{IPNet: p.IPNet(), Size: 10})
				require.NoError(t, err)
				require.Equal(t, ref.Lookup("probe.example"), first, "no fake IP was allocated")
			}
		})
	}
}

func question(name string, qtype uint16) *D.Msg {
	msg := new(D.Msg)
	msg.SetQuestion(name, qtype)
	return msg
}
