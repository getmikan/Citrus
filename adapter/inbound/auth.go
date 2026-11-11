package inbound

import (
	"net"
	"net/netip"

	C "github.com/metacubex/mihomo/constant"
)

func SetSkipAuthPrefixes(prefixes []netip.Prefix) {
	policy := loadAccessPolicy()
	SetAccessPolicy(prefixes, policy.allowed, policy.denied)
}

func SkipAuthPrefixes() []netip.Prefix {
	return clonePrefixes(loadAccessPolicy().skipAuth)
}

func SkipAuthRemoteAddr(addr net.Addr) bool {
	_, skip := EvaluateRemoteAddr(addr)
	return skip
}

func SkipAuthRemoteAddress(addr string) bool {
	m := C.Metadata{}
	if err := m.SetRemoteAddress(addr); err != nil {
		return false
	}
	return skipAuth(m.AddrPort().Addr())
}

func skipAuth(addr netip.Addr) bool {
	return prefixesContains(loadAccessPolicy().skipAuth, addr)
}
