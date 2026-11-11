package inbound

import (
	"net"
	"net/netip"
)

func SetAllowedIPs(prefixes []netip.Prefix) {
	policy := loadAccessPolicy()
	SetAccessPolicy(policy.skipAuth, prefixes, policy.denied)
}

func SetDisAllowedIPs(prefixes []netip.Prefix) {
	policy := loadAccessPolicy()
	SetAccessPolicy(policy.skipAuth, policy.allowed, prefixes)
}

func AllowedIPs() []netip.Prefix {
	return clonePrefixes(loadAccessPolicy().allowed)
}

func DisAllowedIPs() []netip.Prefix {
	return clonePrefixes(loadAccessPolicy().denied)
}

func IsRemoteAddrDisAllowed(addr net.Addr) bool {
	allowed, _ := EvaluateRemoteAddr(addr)
	return allowed
}

func isAllowed(addr netip.Addr) bool {
	return prefixesContains(loadAccessPolicy().allowed, addr)
}

func isDisAllowed(addr netip.Addr) bool {
	return prefixesContains(loadAccessPolicy().denied, addr)
}
