package config

import (
	"errors"
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
