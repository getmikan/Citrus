package provider

import (
	"testing"

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
