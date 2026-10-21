package inbound

import (
	"net"
	"net/netip"
	"sync/atomic"

	C "github.com/metacubex/mihomo/constant"
)

type accessPolicy struct {
	skipAuth []netip.Prefix
	allowed  []netip.Prefix
	denied   []netip.Prefix
}

var currentAccessPolicy atomic.Pointer[accessPolicy]

func clonePrefixes(prefixes []netip.Prefix) []netip.Prefix {
	return append([]netip.Prefix(nil), prefixes...)
}

func loadAccessPolicy() *accessPolicy {
	if policy := currentAccessPolicy.Load(); policy != nil {
		return policy
	}
	return &accessPolicy{}
}

// SetAccessPolicy publishes all related admission and authentication-bypass
// rules as one immutable generation.
func SetAccessPolicy(skipAuth, allowed, denied []netip.Prefix) {
	currentAccessPolicy.Store(&accessPolicy{
		skipAuth: clonePrefixes(skipAuth),
		allowed:  clonePrefixes(allowed),
		denied:   clonePrefixes(denied),
	})
}

// EvaluateRemoteAddr loads exactly one policy generation for both decisions.
func EvaluateRemoteAddr(addr net.Addr) (allowed, skipAuth bool) {
	m := C.Metadata{}
	if err := m.SetRemoteAddr(addr); err != nil {
		return false, false
	}
	ip := m.AddrPort().Addr()
	if !ip.IsValid() {
		return false, false
	}
	policy := loadAccessPolicy()
	return prefixesContains(policy.allowed, ip) && !prefixesContains(policy.denied, ip), prefixesContains(policy.skipAuth, ip)
}
