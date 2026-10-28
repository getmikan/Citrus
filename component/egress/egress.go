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
	Reason  string
	Inbound string
}

func (e *BlockedError) Error() string {
	return fmt.Sprintf("egress guard blocked %s: %s, not reachable from inbound %s (allow it with egress-guard.allow-ips, or egress-guard: false on the listener)", e.Addr, e.Reason, e.Inbound)
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
}

var current atomic.Pointer[Options]

func init() {
	current.Store(&Options{Enable: true})
}

// SetOptions publishes a new config; the connections dialed afterwards use it.
func SetOptions(o Options) {
	o.AllowIPs = slices.Clone(o.AllowIPs)
	for i, prefix := range o.AllowIPs {
		o.AllowIPs[i] = prefix.Masked()
	}
	current.Store(&o)
}

// CurrentOptions returns the published config.
func CurrentOptions() Options {
	o := *current.Load()
	o.AllowIPs = slices.Clone(o.AllowIPs)
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

// Guard checks the destinations of one connection or UDP session.
type Guard struct {
	allow   []netip.Prefix
	inbound string
}

// For returns the guard of the connection described by metadata, or nil when
// the connection is not guarded.
func For(metadata *C.Metadata) *Guard {
	o := current.Load()
	switch metadata.EgressGuard {
	case C.EgressGuardOff:
		return nil
	case C.EgressGuardOn:
	default:
		if !o.Enable || !IsServerInbound(metadata.Type) {
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
	return &Guard{allow: o.AllowIPs, inbound: inbound}
}

// CheckAddr returns a *BlockedError when addr must not be reached. It
// implements dialer.AddrFilter.
func (g *Guard) CheckAddr(addr netip.Addr) error {
	addr = addr.Unmap()
	if !addr.IsValid() {
		return nil // nothing to connect to, the dial fails on its own
	}
	for _, prefix := range g.allow {
		if prefix.Contains(addr) {
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

// checkNetAddr is CheckAddr for the address of a UDP datagram. An address that
// is not an IP (which a UDP socket cannot send to anyway) is let through.
func (g *Guard) checkNetAddr(addr net.Addr) error {
	var ap netip.AddrPort
	switch addr := addr.(type) {
	case *net.UDPAddr:
		if addr == nil {
			return nil
		}
		ap = addr.AddrPort()
	default:
		if addr == nil {
			return nil
		}
		parsed, err := netip.ParseAddrPort(addr.String())
		if err != nil {
			return nil
		}
		ap = parsed
	}
	return g.CheckAddr(ap.Addr())
}
