package http

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/metacubex/mihomo/component/resolver"

	"github.com/metacubex/http"
)

// maxRedirects matches the net/http default.
const maxRedirects = 10

// redirectLookup resolves a redirect target's host name. A variable so tests
// can replace it.
var redirectLookup = func(ctx context.Context, host string) ([]netip.Addr, error) {
	return resolver.LookupIP(ctx, host)
}

var cgnatPrefix = netip.MustParsePrefix("100.64.0.0/10")

// isNonPublicAddr reports addresses that belong to this host or its local
// networks rather than the internet: loopback, private, link-local (cloud
// metadata included), CGNAT, multicast and unspecified.
func isNonPublicAddr(addr netip.Addr) bool {
	addr = addr.Unmap()
	return !addr.IsValid() ||
		addr.IsLoopback() ||
		addr.IsPrivate() ||
		addr.IsLinkLocalUnicast() ||
		addr.IsLinkLocalMulticast() ||
		addr.IsInterfaceLocalMulticast() ||
		addr.IsMulticast() ||
		addr.IsUnspecified() ||
		(addr.Is4() && addr.As4()[0] == 0) ||
		cgnatPrefix.Contains(addr)
}

func resolveRedirectHost(ctx context.Context, lookup func(context.Context, string) ([]netip.Addr, error), host string) ([]netip.Addr, error) {
	host = strings.TrimSuffix(strings.ToLower(host), ".")
	if host == "localhost" || strings.HasSuffix(host, ".localhost") {
		return []netip.Addr{netip.MustParseAddr("127.0.0.1")}, nil
	}
	if addr, err := netip.ParseAddr(host); err == nil {
		return []netip.Addr{addr.Unmap()}, nil
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	addrs, err := lookup(ctx, host)
	if err != nil || len(addrs) == 0 {
		if err == nil {
			err = errors.New("no addresses")
		}
		return nil, err
	}
	for i := range addrs {
		addrs[i] = addrs[i].Unmap()
	}
	return addrs, nil
}

type redirectPolicy struct {
	lookup func(context.Context, string) ([]netip.Addr, error)
	mu     sync.RWMutex
	pinned map[string][]netip.Addr

	// originDone is closed once privateOrigin is known.
	originDone    chan struct{}
	privateOrigin bool
}

// newRedirectPolicy starts classifying the origin as the request starts, not
// when a redirect arrives, so a later DNS answer cannot manufacture the
// private-origin exemption. The lookup runs in the background: most requests
// never redirect, and one whose origin resolves only through a proxy must not
// wait on (or be failed by) a local lookup.
func newRedirectPolicy(ctx context.Context, originHost string) *redirectPolicy {
	p := &redirectPolicy{
		lookup:     redirectLookup,
		pinned:     make(map[string][]netip.Addr),
		originDone: make(chan struct{}),
	}
	go func() {
		defer close(p.originDone)
		p.privateOrigin = isPrivateOrigin(ctx, p.lookup, originHost)
	}()
	return p
}

// isPrivateOrigin reports whether every address of host is non-public. An
// origin that does not resolve locally, or resolves to a mix, gets no
// exemption: its redirects are checked like any public origin's.
func isPrivateOrigin(ctx context.Context, lookup func(context.Context, string) ([]netip.Addr, error), host string) bool {
	addrs, err := resolveRedirectHost(ctx, lookup, host)
	if err != nil {
		return false
	}
	for _, addr := range addrs {
		if !isNonPublicAddr(addr) {
			return false
		}
	}
	return true
}

func normalizeRedirectHost(host string) string {
	return strings.TrimSuffix(strings.ToLower(host), ".")
}

func (p *redirectPolicy) pin(host string, addrs []netip.Addr) {
	p.mu.Lock()
	p.pinned[normalizeRedirectHost(host)] = append([]netip.Addr(nil), addrs...)
	p.mu.Unlock()
}

func (p *redirectPolicy) approved(host string) ([]netip.Addr, bool) {
	p.mu.RLock()
	addrs, ok := p.pinned[normalizeRedirectHost(host)]
	p.mu.RUnlock()
	return append([]netip.Addr(nil), addrs...), ok
}

// approvedFor returns the validated addresses of address's host that suit
// network. pinned is false when the host is not a validated redirect target.
func (p *redirectPolicy) approvedFor(network, address string) (addrs []netip.Addr, pinned bool, err error) {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return nil, false, nil
	}
	approved, ok := p.approved(host)
	if !ok {
		return nil, false, nil
	}
	for _, ip := range approved {
		if (network == "tcp4" && !ip.Is4()) || (network == "tcp6" && !ip.Is6()) {
			continue
		}
		addrs = append(addrs, ip)
	}
	if len(addrs) == 0 {
		return nil, true, errors.New("redirect target has no validated address for " + network)
	}
	return addrs, true, nil
}

// checkRedirect keeps a remote resource (provider, rule set, GEO database,
// dashboard) from redirecting Citrus to loopback, link-local or private
// addresses. A resource whose configured URL is itself on such an address
// (a provider served from the LAN, say) may still redirect anywhere.
func (p *redirectPolicy) checkRedirect(req *http.Request, via []*http.Request) error {
	if len(via) >= maxRedirects {
		return fmt.Errorf("stopped after %d redirects", maxRedirects)
	}
	select {
	case <-p.originDone:
	case <-req.Context().Done():
		return req.Context().Err()
	}
	if p.privateOrigin {
		// The origin's private identity was captured before the first request;
		// later DNS answers cannot manufacture this exemption.
		return nil
	}

	target := req.URL.Hostname()
	addrs, err := resolveRedirectHost(req.Context(), p.lookup, target)
	if err != nil {
		return fmt.Errorf("cannot validate redirect target %s: %w", req.URL.Host, err)
	}
	for _, addr := range addrs {
		if isNonPublicAddr(addr) {
			return errors.New("refusing redirect from " + via[0].URL.Host + " to non-public address " + req.URL.Host)
		}
	}
	if len(addrs) == 0 {
		return errors.New("refusing redirect target with no validated addresses: " + req.URL.Host)
	}
	p.pin(target, addrs)
	return nil
}

func checkRedirect(req *http.Request, via []*http.Request) error {
	return newRedirectPolicy(req.Context(), via[0].URL.Hostname()).checkRedirect(req, via)
}
