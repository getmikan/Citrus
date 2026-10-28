// Package egress is the egress guard: the connections that authenticated
// users of the server inbounds (vless, trojan, shadowsocks, tuic, ...) send
// to DIRECT must not reach the server's own network. It refuses the
// loopback, private, link-local, CGNAT, ULA, multicast, unspecified and
// reserved ranges, the cloud metadata services and the addresses of this
// host, for IP literals and for the addresses a domain resolved to, TCP and
// UDP, whatever the rules say: DIRECT checks the guard right before it
// connects or sends.
package egress

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"sync/atomic"

	"github.com/metacubex/mihomo/component/iface"
	"github.com/metacubex/mihomo/component/publicaddr"
	C "github.com/metacubex/mihomo/constant"
)

// ErrBlocked is matched by every error of the guard (errors.Is).
var ErrBlocked = errors.New("egress guard")

// BlockedError is the refusal of one destination address.
type BlockedError struct {
	Addr    netip.Addr
	Target  string // the destination when it is not an IP (Addr is invalid)
	Reason  string
	Inbound string
}

func (e *BlockedError) Error() string {
	target := e.Target
	if e.Addr.IsValid() {
		target = e.Addr.String()
	}
	return fmt.Sprintf("egress guard blocked %s: %s, not reachable from inbound %s (allow it with egress-guard.allow-ips, or egress-guard: false on the listener)", target, e.Reason, e.Inbound)
}

func (e *BlockedError) Is(target error) bool {
	return target == ErrBlocked
}

// Options is the egress-guard section of the config.
type Options struct {
	// Enable guards the server inbounds that have no egress-guard of their
	// own. A listener with egress-guard: true is guarded either way.
	Enable bool
	// AllowIPs are exempt from the guard.
	AllowIPs []netip.Prefix
	// AllowAddrPorts exempt one port of an address, e.g. a website on this
	// host's public address, while its other ports stay blocked.
	AllowAddrPorts []netip.AddrPort
}

var current atomic.Pointer[Options]

func init() {
	current.Store(&Options{Enable: true})
}

// SetOptions publishes a new config. Every check reads the published one, so
// it applies at once to the UDP sessions already open as well.
func SetOptions(o Options) {
	o.AllowIPs = slices.Clone(o.AllowIPs)
	for i, prefix := range o.AllowIPs {
		o.AllowIPs[i] = prefix.Masked()
	}
	o.AllowAddrPorts = slices.Clone(o.AllowAddrPorts)
	for i, ap := range o.AllowAddrPorts {
		o.AllowAddrPorts[i] = netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port())
	}
	current.Store(&o)
}

// CurrentOptions returns the published config.
func CurrentOptions() Options {
	o := *current.Load()
	o.AllowIPs = slices.Clone(o.AllowIPs)
	o.AllowAddrPorts = slices.Clone(o.AllowAddrPorts)
	return o
}

// isLocalIP reports whether addr is assigned to an interface of this host;
// a variable for the tests.
var isLocalIP = func(addr netip.Addr) bool {
	local, err := iface.IsLocalIp(addr)
	return err == nil && local
}

// IsServerInbound reports whether connections of the inbound type come from
// the authenticated users of a server protocol, which the guard covers by
// default. The local client inbounds (http, socks, mixed, redir, tproxy, tun,
// tunnel) and the core's own connections (inner) are not covered.
func IsServerInbound(t C.Type) bool {
	switch t {
	case C.SHADOWSOCKS, C.SNELL, C.VLESS, C.TROJAN, C.TUIC, C.HYSTERIA2,
		C.ANYTLS, C.MIERU, C.SUDOKU, C.TRUSTTUNNEL, C.SHADOWQUIC:
		return true
	}
	return false
}

// Guard checks the destinations of one connection or UDP session against the
// published config.
type Guard struct {
	on      bool // the listener's egress-guard: true, guarded whatever enable says
	inbound string
}

// For returns the guard of the connection described by metadata, or nil when
// the connection is never guarded. A server inbound gets a guard while
// egress-guard.enable is false too: a reload that turns it on reaches the UDP
// sessions already open.
func For(metadata *C.Metadata) *Guard {
	switch metadata.EgressGuard {
	case C.EgressGuardOff:
		return nil
	case C.EgressGuardOn:
	default:
		if !IsServerInbound(metadata.Type) {
			return nil
		}
	}
	inbound := metadata.InName
	if inbound == "" {
		inbound = metadata.Type.String()
	}
	if metadata.InUser != "" {
		inbound += " (user " + metadata.InUser + ")"
	}
	return &Guard{on: metadata.EgressGuard == C.EgressGuardOn, inbound: inbound}
}

// options returns the published config, or nil when it leaves g unguarded.
func (g *Guard) options() *Options {
	o := current.Load()
	if !g.on && !o.Enable {
		return nil
	}
	return o
}

// CheckAddrPort returns a *BlockedError when ap must not be reached. It
// implements dialer.AddrFilter.
func (g *Guard) CheckAddrPort(ap netip.AddrPort) error {
	o := g.options()
	if o == nil {
		return nil
	}
	addr := ap.Addr().Unmap()
	if !addr.IsValid() {
		// a socket sends to the unspecified address, this host, in its place
		return &BlockedError{Target: "an invalid address", Reason: "not an IP address", Inbound: g.inbound}
	}
	for _, prefix := range o.AllowIPs {
		if prefix.Contains(addr) {
			return nil
		}
	}
	for _, allowed := range o.AllowAddrPorts {
		if allowed.Addr() == addr && allowed.Port() == ap.Port() {
			return nil
		}
	}
	if !publicaddr.IsPublicIP(addr) {
		return &BlockedError{Addr: addr, Reason: "private, loopback, link-local, reserved or cloud metadata address", Inbound: g.inbound}
	}
	if isLocalIP(addr) {
		return &BlockedError{Addr: addr, Reason: "address of this host", Inbound: g.inbound}
	}
	return nil
}

// checkNetAddr is CheckAddrPort for the address of a UDP datagram. An address
// that is not an IP and port (a domain, a nil address) cannot be checked and
// is refused.
func (g *Guard) checkNetAddr(addr net.Addr) error {
	var ap netip.AddrPort
	switch addr := addr.(type) {
	case *net.UDPAddr:
		if addr != nil {
			ap = addr.AddrPort()
		}
	case nil:
	default:
		parsed, err := netip.ParseAddrPort(addr.String())
		if err != nil {
			if g.options() == nil {
				return nil
			}
			return &BlockedError{Target: addr.String(), Reason: "not an IP address", Inbound: g.inbound}
		}
		ap = parsed
	}
	return g.CheckAddrPort(ap)
}
