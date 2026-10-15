package config

import (
	"errors"
	"testing"

	C "github.com/metacubex/mihomo/constant"

	"github.com/stretchr/testify/require"
)

func TestParseRawConfigVMessRemoved(t *testing.T) {
	for name, cfg := range map[string]string{
		"vmess-config": "vmess-config: vmess://127.0.0.1:10000?uuid=b831381d-6324-4d53-ad4f-8cda48b30811\n",
		"listener": `listeners:
  - name: vmess-in
    type: vmess
    port: 10000
    users:
      - uuid: b831381d-6324-4d53-ad4f-8cda48b30811
`,
		"proxy": `proxies:
  - name: vmess-out
    type: vmess
    server: 127.0.0.1
    port: 443
    uuid: b831381d-6324-4d53-ad4f-8cda48b30811
    cipher: auto
`,
	} {
		t.Run(name, func(t *testing.T) {
			rawCfg, err := UnmarshalRawConfig([]byte(cfg))
			require.NoError(t, err)
			switch name {
			case "vmess-config":
				_, err = parseGeneral(rawCfg)
			case "listener":
				_, err = parseListeners(rawCfg)
			case "proxy":
				_, _, err = parseProxies(rawCfg)
			}
			require.Error(t, err)
			require.True(t, errors.Is(err, C.ErrRemovedProtocol), "want ErrRemovedProtocol, got %v", err)
			require.Contains(t, err.Error(), "VMess was removed from Citrus, use VLESS")
		})
	}
}
