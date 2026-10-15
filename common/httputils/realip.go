package httputils

import (
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"

	"github.com/metacubex/http"
)

// RealIP finds the address of the client behind a reverse proxy (nginx,
// Caddy, a CDN) in the header the proxy sets, such as X-Forwarded-For,
// X-Real-IP or CF-Connecting-IP.
//
// The header is believed only when the TCP peer of the request is one of the
// Trusted proxies: anybody who reaches the listener directly can send it with
// any address in it. In a list header (X-Forwarded-For) every proxy appends
// the address it got the request from, so the list is read from the right and
// the client is the first address that is not a trusted proxy, as nginx does
// with real_ip_recursive on. A client that puts a forged address at the left
// of the list gets it skipped.
type RealIP struct {
	// Header names the header to read the client address from. Empty turns
	// the lookup off.
	Header string
	// Trusted holds the proxies whose header is believed.
	Trusted []netip.Prefix
	// TrustAny believes the leftmost address of the header from any peer when
	// Trusted is empty. It keeps the behaviour of configs written before
	// trusted-proxies existed and must not be set for a new option.
	TrustAny bool
}

// NewRealIP builds a RealIP from the header name and the trusted-proxies
// list of a listener config.
func NewRealIP(header string, trustedProxies []string, trustAny bool) (RealIP, error) {
	trusted, err := ParseTrustedProxies(trustedProxies)
	if err != nil {
		return RealIP{}, err
	}
	return RealIP{Header: strings.TrimSpace(header), Trusted: trusted, TrustAny: trustAny}, nil
}

// Enabled reports whether the header can ever be believed.
func (r RealIP) Enabled() bool {
	return r.Header != "" && (len(r.Trusted) > 0 || r.TrustAny)
}

// ClientAddrPort returns the client address the request was forwarded for,
// or the zero AddrPort when there is none to believe and the TCP peer of the
// request is the client. The port is zero when the header has none.
func (r RealIP) ClientAddrPort(req *http.Request) netip.AddrPort {
	if r.Header == "" {
		return netip.AddrPort{}
	}
	if len(r.Trusted) == 0 {
		if !r.TrustAny {
			return netip.AddrPort{}
		}
		value := req.Header.Get(r.Header)
		if i := strings.IndexByte(value, ','); i >= 0 {
			value = value[:i]
		}
		ap, _ := parseForwardedAddr(value)
		return ap
	}

	peer, ok := parsePeerAddr(req.RemoteAddr)
	if !ok || !r.isTrusted(peer) {
		return netip.AddrPort{}
	}

	values := req.Header.Values(r.Header)
	var last netip.AddrPort
	for i := len(values) - 1; i >= 0; i-- {
		parts := strings.Split(values[i], ",")
		for j := len(parts) - 1; j >= 0; j-- {
			ap, ok := parseForwardedAddr(parts[j])
			if !ok {
				// a hop the proxies did not write: stop at the last
				// address a trusted proxy vouched for
				return last
			}
			if !r.isTrusted(ap.Addr()) {
				return ap
			}
			last = ap
		}
	}
	// every address is a trusted proxy: the leftmost one sent the request
	return last
}

// ClientNetAddr turns an address from ClientAddrPort into a net.Addr, taking
// the port of the TCP peer when the header had none, as WithSrcAddrPort does
// for the connection metadata.
func ClientNetAddr(ap netip.AddrPort, peer net.Addr) net.Addr {
	if ap.Port() == 0 {
		if tcpAddr, ok := peer.(*net.TCPAddr); ok {
			ap = netip.AddrPortFrom(ap.Addr(), uint16(tcpAddr.Port))
		}
	}
	return net.TCPAddrFromAddrPort(ap)
}

func (r RealIP) isTrusted(addr netip.Addr) bool {
	addr = addr.Unmap()
	for _, prefix := range r.Trusted {
		if prefix.Contains(addr) {
			return true
		}
	}
	return false
}

var trustedProxyShorthands = map[string][]netip.Prefix{
	"loopback": {
		netip.MustParsePrefix("127.0.0.0/8"),
		netip.MustParsePrefix("::1/128"),
	},
	"private": {
		netip.MustParsePrefix("10.0.0.0/8"),
		netip.MustParsePrefix("172.16.0.0/12"),
		netip.MustParsePrefix("192.168.0.0/16"),
		netip.MustParsePrefix("fc00::/7"),
	},
}

// ParseTrustedProxies parses a trusted-proxies list: CIDRs, single addresses
// and the shorthands "loopback" (127.0.0.0/8, ::1) and "private" (10.0.0.0/8,
// 172.16.0.0/12, 192.168.0.0/16, fc00::/7).
func ParseTrustedProxies(list []string) ([]netip.Prefix, error) {
	var prefixes []netip.Prefix
	for _, item := range list {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		if shorthand, ok := trustedProxyShorthands[strings.ToLower(item)]; ok {
			prefixes = append(prefixes, shorthand...)
			continue
		}
		if strings.Contains(item, "/") {
			prefix, err := netip.ParsePrefix(item)
			if err != nil {
				return nil, fmt.Errorf("invalid trusted proxy %q: %w", item, err)
			}
			if prefix.Addr().Is4In6() {
				bits := prefix.Bits() - 96
				if bits < 0 {
					return nil, fmt.Errorf("invalid trusted proxy %q: an IPv4-mapped prefix shorter than /96", item)
				}
				prefix = netip.PrefixFrom(prefix.Addr().Unmap(), bits)
			}
			prefixes = append(prefixes, prefix.Masked())
			continue
		}
		addr, err := netip.ParseAddr(item)
		if err != nil {
			return nil, fmt.Errorf("invalid trusted proxy %q: %w", item, err)
		}
		addr = addr.Unmap()
		prefixes = append(prefixes, netip.PrefixFrom(addr, addr.BitLen()))
	}
	return prefixes, nil
}

func parsePeerAddr(remoteAddr string) (netip.Addr, bool) {
	if ap, err := netip.ParseAddrPort(remoteAddr); err == nil {
		return ap.Addr().Unmap(), true
	}
	host := remoteAddr
	if h, _, err := net.SplitHostPort(remoteAddr); err == nil {
		host = h
	}
	addr, err := netip.ParseAddr(host)
	if err != nil {
		return netip.Addr{}, false
	}
	return addr.Unmap(), true
}

// parseForwardedAddr parses one hop of a forwarding header: an address,
// optionally with a port ("1.2.3.4:5678", "[2001:db8::1]:5678").
func parseForwardedAddr(value string) (netip.AddrPort, bool) {
	value = strings.TrimSpace(value)
	if value == "" {
		return netip.AddrPort{}, false
	}
	var port uint16
	if h, p, err := net.SplitHostPort(value); err == nil {
		value = h
		if p, err := strconv.ParseUint(p, 10, 16); err == nil {
			port = uint16(p)
		}
	}
	addr, err := netip.ParseAddr(value)
	if err != nil || addr.Zone() != "" {
		return netip.AddrPort{}, false
	}
	return netip.AddrPortFrom(addr.Unmap(), port), true
}
