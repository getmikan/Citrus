package http

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"strings"
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

// isNonPublicHost reports whether host (an IP literal or a name) points to a
// non-public address. Names are resolved; a name that does not resolve here
// is treated as public, because the request itself will then go wherever the
// dialer (possibly a remote proxy) resolves it.
func isNonPublicHost(ctx context.Context, host string) bool {
	host = strings.TrimSuffix(strings.ToLower(host), ".")
	if host == "localhost" || strings.HasSuffix(host, ".localhost") {
		return true
	}
	if addr, err := netip.ParseAddr(host); err == nil {
		return isNonPublicAddr(addr)
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	addrs, err := redirectLookup(ctx, host)
	if err != nil {
		return false
	}
	for _, addr := range addrs {
		if isNonPublicAddr(addr) {
			return true
		}
	}
	return false
}

// checkRedirect keeps a remote resource (provider, rule set, GEO database,
// dashboard) from redirecting Citrus to loopback, link-local or private
// addresses. A resource whose configured URL is itself on such an address
// (a provider served from the LAN, say) may still redirect anywhere.
func checkRedirect(req *http.Request, via []*http.Request) error {
	if len(via) >= maxRedirects {
		return fmt.Errorf("stopped after %d redirects", maxRedirects)
	}
	target := req.URL.Hostname()
	if !isNonPublicHost(req.Context(), target) {
		return nil
	}
	if isNonPublicHost(req.Context(), via[0].URL.Hostname()) {
		return nil
	}
	return errors.New("refusing redirect from " + via[0].URL.Host + " to non-public address " + req.URL.Host)
}
