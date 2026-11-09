package iface

import (
	"net"
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// hostAddrs returns an IPv4 and an IPv6 address of an interface of this host
// that is up, invalid where there is none.
func hostAddrs(t *testing.T) (v4, v6 netip.Addr) {
	t.Helper()
	ifaces, err := Interfaces()
	require.NoError(t, err)
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 {
			continue
		}
		for _, prefix := range iface.Addresses {
			addr := prefix.Addr()
			switch {
			case addr.Is4() && !v4.IsValid():
				v4 = addr
			case addr.Is6() && !v6.IsValid():
				v6 = addr
			}
		}
	}
	return v4, v6
}

// An address of this host is found in every spelling of it: with an IPv6
// zone, which names an interface and leaves the address the same, and in the
// IPv4-mapped form of an IPv4 address.
func TestIsLocalIpZoneAndMapped(t *testing.T) {
	v4, v6 := hostAddrs(t)
	if !v4.IsValid() && !v6.IsValid() {
		t.Skip("no address on the interfaces of this host")
	}
	if v6.IsValid() {
		local, err := IsLocalIp(v6)
		require.NoError(t, err)
		require.True(t, local, v6.String())
		for _, zone := range []string{"x", "1", "eth0"} {
			local, err = IsLocalIp(v6.WithZone(zone))
			require.NoError(t, err)
			assert.True(t, local, "%s%%%s", v6, zone)
		}
	}
	if v4.IsValid() {
		local, err := IsLocalIp(netip.AddrFrom16(v4.As16()))
		require.NoError(t, err)
		assert.True(t, local, "::ffff:%s", v4)
	}

	local, err := IsLocalIp(netip.MustParseAddr("2001:db8::1%x"))
	require.NoError(t, err)
	assert.False(t, local, "an address that is not on this host")
}
