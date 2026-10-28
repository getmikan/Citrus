package dns

import (
	"context"
	"errors"

	"github.com/metacubex/mihomo/component/resolver"
	icontext "github.com/metacubex/mihomo/context"
	D "github.com/miekg/dns"
	"github.com/samber/lo"
)

type Service struct {
	handler handler
}

// ServeMsg implement [resolver.Service] ResolveMsg
func (s *Service) ServeMsg(ctx context.Context, msg *D.Msg) (*D.Msg, error) {
	if len(msg.Question) == 0 {
		return nil, errors.New("at least one question is required")
	}

	// read the request OPT before the handler runs: OPT is per-hop, so only
	// what this client sent decides whether the reply carries one.
	reqOpt := msg.IsEdns0()
	wantOpt, do := reqOpt != nil, reqOpt != nil && reqOpt.Do()

	r, err := s.handler(icontext.NewDNSContext(ctx), msg)
	if err != nil {
		return r, err
	}

	// echo back EDNS0: if the client asked with an OPT, reply with our own OPT.
	// OPT is a per-hop pseudo-record (RFC 6891), so we generate it here instead of
	// caching/forwarding the upstream one, and send none to a client that sent
	// none (RFC 6891 section 7). Doing it at this convergence point covers
	// both the listening DNS server (ServeDNS) and the TUN hijack relay path.
	// 1232 is the fragmentation-safe UDP payload size recommended by
	// https://dnsflagday.net/2020/ : the IPv6 minimum MTU (1280) minus
	// the IPv6 and UDP header sizes (40 + 8).
	if r != nil {
		if r.IsEdns0() != nil {
			r.Extra = lo.Filter(r.Extra, func(rr D.RR, index int) bool {
				return rr.Header().Rrtype != D.TypeOPT
			})
		}
		if wantOpt {
			r.SetEdns0(1232, do)
		} else if r.Rcode > 0xF {
			// an extended RCODE needs an OPT to be encoded at all
			r.Rcode = D.RcodeServerFailure
		}
	}

	return r, nil
}

var _ resolver.Service = (*Service)(nil)

func NewService(resolver resolver.Resolver, mapper *ResolverEnhancer) *Service {
	return &Service{handler: newHandler(resolver, mapper)}
}
