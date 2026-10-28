package provider

import (
	"errors"
	"testing"

	"github.com/metacubex/mihomo/adapter"
	C "github.com/metacubex/mihomo/constant"
	"github.com/stretchr/testify/require"
)

// One entry without a host-key or server identity policy is skipped, not
// fatal for the whole subscription.
func TestProviderSkipsEntriesWithoutIdentityPolicy(t *testing.T) {
	parse, err := NewProxiesParser("test", nil, "", "", "", "", overrideSchema{}, "")
	require.NoError(t, err)

	proxies, err := parse([]byte(`proxies:
  - {name: ok, type: socks5, server: 127.0.0.1, port: 1080}
  - {name: ssh, type: ssh, server: 192.0.2.1, port: 22, username: u, password: p}
  - {name: vpn, type: openvpn, server: 192.0.2.1, port: 1194, ca: x}
`))
	require.NoError(t, err)
	require.Len(t, proxies, 1)
	require.Equal(t, "ok", proxies[0].Name())
}

// Top-level proxies keep the hard error.
func TestIdentityPolicyErrorsStayFatalOutsideProviders(t *testing.T) {
	_, err := adapter.ParseProxy(map[string]any{"name": "ssh", "type": "ssh", "server": "192.0.2.1", "port": 22, "username": "u", "password": "p"})
	require.True(t, errors.Is(err, C.ErrProviderSkip), "got %v", err)
}
