package http

import (
	"context"
	"errors"
	"fmt"
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

func resolveRedirectHost(ctx context.Context, host string) ([]netip.Addr, error) {
	host = strings.TrimSuffix(strings.ToLower(host), ".")
	if host == "localhost" || strings.HasSuffix(host, ".localhost") {
		return []netip.Addr{netip.MustParseAddr("127.0.0.1")}, nil
	}
	if addr, err := netip.ParseAddr(host); err == nil {
		return []netip.Addr{addr.Unmap()}, nil
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	addrs, err := redirectLookup(ctx, host)
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
	mu            sync.RWMutex
	pinned        map[string][]netip.Addr
	privateOrigin bool
	originErr     error
}

func newRedirectPolicy(ctx context.Context, originHost string) *redirectPolicy {
	p := &redirectPolicy{pinned: make(map[string][]netip.Addr)}
	addrs, err := resolveRedirectHost(ctx, originHost)
	if err != nil {
		p.originErr = err
		return p
	}
	private, public := false, false
	for _, addr := range addrs {
		if isNonPublicAddr(addr) {
			private = true
		} else {
			public = true
		}
	}
	if private && public {
		p.originErr = errors.New("origin resolves to both public and non-public addresses")
		return p
	}
	p.privateOrigin = private
	return p
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

// checkRedirect keeps a remote resource (provider, rule set, GEO database,
// dashboard) from redirecting Citrus to loopback, link-local or private
// addresses. A resource whose configured URL is itself on such an address
// (a provider served from the LAN, say) may still redirect anywhere.
func (p *redirectPolicy) checkRedirect(req *http.Request, via []*http.Request) error {
	if len(via) >= maxRedirects {
		return fmt.Errorf("stopped after %d redirects", maxRedirects)
	}
	if p.originErr != nil {
		return fmt.Errorf("cannot validate redirect origin %s: %w", via[0].URL.Host, p.originErr)
	}
	if p.privateOrigin {
		// The origin's private identity was captured before the first request;
		// later DNS answers cannot manufacture this exemption.
		return nil
	}

	target := req.URL.Hostname()
	addrs, err := resolveRedirectHost(req.Context(), target)
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
