package config

import (
	"net/netip"
	"testing"

	"github.com/metacubex/mihomo/component/egress"
	C "github.com/metacubex/mihomo/constant"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseEgressGuard(t *testing.T) {
	raw, err := UnmarshalRawConfig([]byte("mode: direct\n"))
	require.NoError(t, err)
	o, err := parseEgressGuard(raw)
	require.NoError(t, err)
	assert.Equal(t, &egress.Options{Enable: true}, o, "on by default")

	// a section without enable keeps the default
	raw, err = UnmarshalRawConfig([]byte("egress-guard:\n  allow-ips: [10.8.0.0/24, 192.168.1.10, 'fd00::1', 10.9.1.1/16]\n"))
	require.NoError(t, err)
	o, err = parseEgressGuard(raw)
	require.NoError(t, err)
	assert.Equal(t, &egress.Options{Enable: true, AllowIPs: []netip.Prefix{
		netip.MustParsePrefix("10.8.0.0/24"),
		netip.MustParsePrefix("192.168.1.10/32"),
		netip.MustParsePrefix("fd00::1/128"),
		netip.MustParsePrefix("10.9.0.0/16"),
	}}, o)

	raw, err = UnmarshalRawConfig([]byte("egress-guard:\n  enable: false\n"))
	require.NoError(t, err)
	o, err = parseEgressGuard(raw)
	require.NoError(t, err)
	assert.False(t, o.Enable)

	for _, bad := range []string{"lan", "'::ffff:10.0.0.0/95'", "'1.2.3.4:http'"} {
		raw, err = UnmarshalRawConfig([]byte("egress-guard:\n  allow-ips: [" + bad + "]\n"))
		require.NoError(t, err)
		_, err = parseEgressGuard(raw)
		assert.ErrorContains(t, err, "egress-guard.allow-ips", bad)
	}
}

// The guard compares unmapped destinations, so an IPv4-mapped CIDR or
// address is stored as the IPv4 one; an address:port exempts that port only.
func TestParseEgressGuardMappedAndPorts(t *testing.T) {
	raw, err := UnmarshalRawConfig([]byte("egress-guard:\n  allow-ips: ['::ffff:192.168.1.0/120', '::ffff:10.0.0.1', '203.0.113.10:443', '[2001:db8::1]:80', '[::ffff:10.0.0.2]:5432']\n"))
	require.NoError(t, err)
	o, err := parseEgressGuard(raw)
	require.NoError(t, err)
	assert.Equal(t, []netip.Prefix{
		netip.MustParsePrefix("192.168.1.0/24"),
		netip.MustParsePrefix("10.0.0.1/32"),
	}, o.AllowIPs)
	assert.Equal(t, []netip.AddrPort{
		netip.MustParseAddrPort("203.0.113.10:443"),
		netip.MustParseAddrPort("[2001:db8::1]:80"),
		netip.MustParseAddrPort("10.0.0.2:5432"),
	}, o.AllowAddrPorts)

	// and the mapped CIDR matches the destinations it names
	old := egress.CurrentOptions()
	egress.SetOptions(*o)
	t.Cleanup(func() { egress.SetOptions(old) })
	g := egress.For(&C.Metadata{Type: C.VLESS})
	assert.NoError(t, g.CheckAddrPort(netip.MustParseAddrPort("192.168.1.5:3306")))
	assert.NoError(t, g.CheckAddrPort(netip.MustParseAddrPort("[::ffff:192.168.1.5]:3306")))
	assert.ErrorIs(t, g.CheckAddrPort(netip.MustParseAddrPort("192.168.2.5:3306")), egress.ErrBlocked)
}
