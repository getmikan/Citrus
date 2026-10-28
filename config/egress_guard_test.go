package config

import (
	"net/netip"
	"testing"

	"github.com/metacubex/mihomo/component/egress"

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

	raw, err = UnmarshalRawConfig([]byte("egress-guard:\n  allow-ips: [lan]\n"))
	require.NoError(t, err)
	_, err = parseEgressGuard(raw)
	assert.ErrorContains(t, err, "egress-guard.allow-ips")
}
