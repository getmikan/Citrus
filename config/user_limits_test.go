package config

import (
	"testing"

	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/tunnel/statistic"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseUserLimits(t *testing.T) {
	raw, err := UnmarshalRawConfig([]byte(`
user-limits:
  - {inbound: vless-in, user: alice, speed-up: 10M, speed-down: 80Mbps, max-conns: 64, max-ips: 3, quota: 100G, expire-at: 1767225600}
  - inbound: vless-in
    user: "*"
    max-conns: 16
    quota: 512MiB
    expire-at: 2026-01-01T00:00:00Z
  - {inbound: vless-in, user: bob, speed-down: 1000000}
`))
	require.NoError(t, err)
	limits, err := parseUserLimits(raw.UserLimits, map[string]C.InboundListener{})
	require.NoError(t, err)
	require.Len(t, limits, 3)
	assert.Equal(t, statistic.UserLimit{
		Inbound: "vless-in", User: "alice",
		SpeedUp: 10_000_000, SpeedDown: 10_000_000,
		MaxConns: 64, MaxIPs: 3, Quota: 100_000_000_000, ExpireAt: 1767225600,
	}, limits[0])
	assert.Equal(t, statistic.UserLimit{
		Inbound: "vless-in", User: "*", MaxConns: 16, Quota: 512 << 20, ExpireAt: 1767225600,
	}, limits[1])
	assert.Equal(t, int64(1_000_000), limits[2].SpeedDown)

	for _, yaml := range []string{
		"user-limits:\n  - {inbound: a, user: b, quota: 10Mbps}\n",
		"user-limits:\n  - {inbound: a, user: b, max-conn: 1}\n",
		"user-limits:\n  - {inbound: a, user: b}\n  - {inbound: a, user: b}\n",
		"user-limits:\n  - {user: b}\n",
	} {
		raw, err := UnmarshalRawConfig([]byte(yaml))
		require.NoError(t, err)
		_, err = parseUserLimits(raw.UserLimits, nil)
		assert.Error(t, err, yaml)
	}

	raw, err = UnmarshalRawConfig([]byte("mode: rule\n"))
	require.NoError(t, err)
	limits, err = parseUserLimits(raw.UserLimits, nil)
	require.NoError(t, err)
	assert.Empty(t, limits)
}
