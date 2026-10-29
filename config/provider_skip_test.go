package config

import (
	"errors"
	"fmt"
	"testing"

	C "github.com/metacubex/mihomo/constant"

	"github.com/stretchr/testify/require"
)

// Errors that providers skip with a warning stay fatal for proxies written in
// the top-level config.
func TestParseProxiesProviderSkipErrorsStayFatal(t *testing.T) {
	rawCfg, err := UnmarshalRawConfig([]byte(`proxies:
  - {name: ssh, type: ssh, server: 192.0.2.1, port: 22, username: u, password: p}
`))
	require.NoError(t, err)
	_, _, err = parseProxies(rawCfg)
	require.Error(t, err)
	require.True(t, errors.Is(err, C.ErrProviderSkip), "want ErrProviderSkip, got %v", err)
}

// An inline provider is written by the user, so it keeps xdrive local.
func TestParseProxiesInlineProviderKeepsXDriveLocal(t *testing.T) {
	rawCfg, err := UnmarshalRawConfig([]byte(fmt.Sprintf(`proxy-providers:
  inline:
    type: inline
    payload:
      - name: drive
        type: vless
        server: 127.0.0.1
        port: 443
        uuid: 27848739-7e62-4138-9fd3-098a63964b6b
        encryption: mlkem768x25519plus.native.0rtt.XKbaq1BuzJKKKPxZbwgRpn-gYQbnhrYketgezASCL1I
        network: xdrive
        xdrive-opts: {service: local, remote-folder: %q}
`, t.TempDir())))
	require.NoError(t, err)
	_, providers, err := parseProxies(rawCfg)
	require.NoError(t, err)
	pd := providers["inline"]
	require.NotNil(t, pd)
	require.NoError(t, pd.Initial())
	proxies := pd.Proxies()
	require.Len(t, proxies, 1)
	defer proxies[0].Close()
	require.Equal(t, "drive", proxies[0].Name())
}
