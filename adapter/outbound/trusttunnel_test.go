package outbound

import (
	"testing"
	"time"

	"github.com/metacubex/mihomo/common/structure"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func decodeTrustTunnelOption(t *testing.T, mapping map[string]any) TrustTunnelOption {
	t.Helper()
	decoder := structure.NewDecoder(structure.Option{TagName: "proxy", WeaklyTypedInput: true, KeyReplacer: structure.DefaultKeyReplacer})
	option := TrustTunnelOption{}
	require.NoError(t, decoder.Decode(mapping, &option))
	return option
}

func TestTrustTunnelSessionTimers(t *testing.T) {
	base := func() map[string]any {
		return map[string]any{"name": "tt", "type": "trusttunnel", "server": "127.0.0.1", "port": 443}
	}

	option := decodeTrustTunnelOption(t, base())
	pingInterval, pingTimeout, handshakeTimeout, err := option.sessionTimers()
	require.NoError(t, err)
	assert.Zero(t, pingInterval, "unset ping-interval leaves the transport default")
	assert.Zero(t, pingTimeout)
	assert.Zero(t, handshakeTimeout)

	mapping := base()
	mapping["ping-interval"] = 30
	mapping["ping-timeout"] = 5
	mapping["handshake-timeout"] = 3
	option = decodeTrustTunnelOption(t, mapping)
	pingInterval, pingTimeout, handshakeTimeout, err = option.sessionTimers()
	require.NoError(t, err)
	assert.Equal(t, 30*time.Second, pingInterval)
	assert.Equal(t, 5*time.Second, pingTimeout)
	assert.Equal(t, 3*time.Second, handshakeTimeout)

	mapping = base()
	mapping["ping-interval"] = -1
	option = decodeTrustTunnelOption(t, mapping)
	pingInterval, _, _, err = option.sessionTimers()
	require.NoError(t, err)
	assert.Negative(t, pingInterval, "ping-interval -1 turns pings off")

	for key, value := range map[string]int{"ping-interval": -2, "ping-timeout": -1, "handshake-timeout": -1} {
		mapping = base()
		mapping[key] = value
		option = decodeTrustTunnelOption(t, mapping)
		_, _, _, err = option.sessionTimers()
		assert.ErrorContains(t, err, key)
		_, err = NewTrustTunnel(option)
		assert.ErrorContains(t, err, key)
	}
}

func TestTrustTunnelAcceptsSessionTimers(t *testing.T) {
	mapping := map[string]any{
		"name": "tt", "type": "trusttunnel", "server": "127.0.0.1", "port": 443,
		"ping-interval": 20, "ping-timeout": 10, "handshake-timeout": 4,
	}
	proxy, err := NewTrustTunnel(decodeTrustTunnelOption(t, mapping))
	require.NoError(t, err)
	require.NoError(t, proxy.Close())
}
