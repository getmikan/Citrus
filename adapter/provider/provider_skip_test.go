package provider

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
)

// One entry without a host-key or server identity policy is skipped, not
// fatal for the whole subscription.
func TestProviderSkipsEntriesWithoutIdentityPolicy(t *testing.T) {
	parse, err := NewProxiesParser("test", nil, "", "", "", "", overrideSchema{}, "", true)
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

// xdrive local is refused only in documents fetched from a subscription URL;
// file and inline providers are written by the user.
func TestProviderXDriveLocalOnlyFromUserDocuments(t *testing.T) {
	doc := []byte(fmt.Sprintf(`proxies:
  - {name: ok, type: socks5, server: 127.0.0.1, port: 1080}
  - name: drive
    type: vless
    server: 127.0.0.1
    port: 443
    uuid: 27848739-7e62-4138-9fd3-098a63964b6b
    encryption: mlkem768x25519plus.native.0rtt.XKbaq1BuzJKKKPxZbwgRpn-gYQbnhrYketgezASCL1I
    network: xdrive
    xdrive-opts: {service: local, remote-folder: %q}
`, t.TempDir()))
	for _, remote := range []bool{false, true} {
		t.Run(fmt.Sprint(remote), func(t *testing.T) {
			parse, err := NewProxiesParser("test", nil, "", "", "", "", overrideSchema{}, "", remote)
			require.NoError(t, err)
			proxies, err := parse(doc)
			require.NoError(t, err)
			defer func() {
				for _, proxy := range proxies {
					_ = proxy.Close()
				}
			}()
			if remote {
				require.Len(t, proxies, 1)
			} else {
				require.Len(t, proxies, 2)
				require.Equal(t, "drive", proxies[1].Name())
			}
		})
	}
}
