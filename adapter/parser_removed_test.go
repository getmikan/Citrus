package adapter

import (
	"errors"
	"testing"

	C "github.com/metacubex/mihomo/constant"
)

func TestParseProxyRemovedProtocols(t *testing.T) {
	cases := map[string]map[string]any{
		"ssr":      {"name": "a", "type": "ssr", "server": "127.0.0.1", "port": 443},
		"hysteria": {"name": "b", "type": "hysteria", "server": "127.0.0.1", "port": 443},
		"tuic v4":  {"name": "c", "type": "tuic", "server": "127.0.0.1", "port": 443, "token": "t"},
		"stream cipher": {"name": "d", "type": "ss", "server": "127.0.0.1", "port": 443,
			"cipher": "rc4-md5", "password": "p"},
		"v2ray-plugin": {"name": "e", "type": "ss", "server": "127.0.0.1", "port": 443,
			"cipher": "aes-128-gcm", "password": "p", "plugin": "v2ray-plugin"},
		"vmess": {"name": "g", "type": "vmess", "server": "127.0.0.1", "port": 443,
			"uuid": "b831381d-6324-4d53-ad4f-8cda48b30811", "cipher": "auto"},
		"mkcp": {"name": "h", "type": "vless", "server": "127.0.0.1", "port": 443,
			"uuid": "b831381d-6324-4d53-ad4f-8cda48b30811", "network": "mkcp"},
		"kcp": {"name": "i", "type": "vless", "server": "127.0.0.1", "port": 443,
			"uuid": "b831381d-6324-4d53-ad4f-8cda48b30811", "network": "kcp"},
		"mekya": {"name": "j", "type": "trojan", "server": "127.0.0.1", "port": 443,
			"password": "p", "network": "mekya"},
		"tlsmirror": {"name": "k", "type": "vless", "server": "127.0.0.1", "port": 443,
			"uuid": "b831381d-6324-4d53-ad4f-8cda48b30811", "tlsmirror-opts": map[string]any{"primary-key": "x"}},
	}
	for name, mapping := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := ParseProxy(mapping)
			if !errors.Is(err, C.ErrRemovedProtocol) {
				t.Fatalf("want ErrRemovedProtocol, got %v", err)
			}
		})
	}

	_, err := ParseProxy(cases["vmess"])
	if err == nil || err.Error() != "VMess was removed from Citrus, use VLESS" {
		t.Fatalf("unclear VMess error: %v", err)
	}

	_, err = ParseProxy(map[string]any{"name": "f", "type": "nope", "server": "127.0.0.1", "port": 443})
	if err == nil || errors.Is(err, C.ErrRemovedProtocol) {
		t.Fatalf("unknown type must not be treated as removed: %v", err)
	}
}
