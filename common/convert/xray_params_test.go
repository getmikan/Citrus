package convert_test

import (
	"encoding/base64"
	"net/url"
	"testing"

	"github.com/metacubex/mihomo/adapter"
	. "github.com/metacubex/mihomo/common/convert"
	_ "github.com/metacubex/mihomo/config" // dns.ParseNameServer for ech-opts query-server

	"github.com/metacubex/mldsa"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	testPin1 = "65b3acd7db555768304a16abb6f4366c1a0c0bb5cec81429617f0150d7d66726"
	testPin2 = "ab:CD:ef:01:23:45:67:89:ab:cd:ef:01:23:45:67:89:ab:cd:ef:01:23:45:67:89:ab:cd:ef:01:23:45:67:89"
	// a base64 ECHConfigList, '+' and '/' included
	testECHConfig = "AEX+DQBBpQAgACB/+0mHWZ1jCOT4Ou7Ux3sp6R2HO5TeqE6xh5gBJ0VBXwAEAAEAAQASY2xvdWRmbGFyZS1lY2guY29tAAA="
)

func TestConvertsV2RayXrayTLSParams(t *testing.T) {
	for _, scheme := range []string{"vless", "trojan"} {
		t.Run(scheme, func(t *testing.T) {
			uri := scheme + "://b831381d-6324-4d53-ad4f-8cda48b30811@example.com:443?security=tls&type=tcp&sni=cdn.example.com&fp=hellofirefox_148" +
				"&pcs=" + url.QueryEscape(testPin1+","+testPin2) +
				"&vcn=" + url.QueryEscape("example.com,example.org") +
				"&ech=" + url.QueryEscape(testECHConfig)
			proxies, err := ConvertsV2Ray([]byte(uri))
			require.NoError(t, err)
			require.Len(t, proxies, 1)
			assert.Equal(t, "hellofirefox_148", proxies[0]["client-fingerprint"])
			assert.Equal(t, testPin1+","+testPin2, proxies[0]["fingerprint"])
			assert.Equal(t, "example.com,example.org", proxies[0]["name-cert-verify"])
			assert.Equal(t, map[string]any{"enable": true, "config": testECHConfig}, proxies[0]["ech-opts"])
			_, err = adapter.ParseProxy(proxies[0])
			assert.NoError(t, err)
		})
	}
}

func TestConvertsV2RayXrayECHParam(t *testing.T) {
	for _, tt := range []struct {
		name, ech string
		want      map[string]any
	}{
		{"base64", url.QueryEscape(testECHConfig), map[string]any{"enable": true, "config": testECHConfig}},
		{"base64 with unescaped plus", testECHConfig, map[string]any{"enable": true, "config": testECHConfig}},
		{"doh", url.QueryEscape("https://1.1.1.1/dns-query"), map[string]any{"enable": true, "query-server": "https://1.1.1.1/dns-query"}},
		{"domain and doh", url.QueryEscape("ech.example.com+https://1.1.1.1/dns-query"), map[string]any{"enable": true, "query-server-name": "ech.example.com", "query-server": "https://1.1.1.1/dns-query"}},
		{"domain and doh with unescaped plus", "ech.example.com+https://1.1.1.1/dns-query", map[string]any{"enable": true, "query-server-name": "ech.example.com", "query-server": "https://1.1.1.1/dns-query"}},
		{"udp", url.QueryEscape("udp://8.8.8.8"), map[string]any{"enable": true, "query-server": "udp://8.8.8.8"}},
		{"domain and udp with port", url.QueryEscape("ech.example.com+udp://8.8.8.8:53"), map[string]any{"enable": true, "query-server-name": "ech.example.com", "query-server": "udp://8.8.8.8:53"}},
		{"h2c", url.QueryEscape("h2c://dns.google/dns-query"), map[string]any{"enable": true, "query-server": "https://dns.google/dns-query"}},
		{"domain and h2c", url.QueryEscape("ech.example.com+h2c://dns.google/dns-query"), map[string]any{"enable": true, "query-server-name": "ech.example.com", "query-server": "https://dns.google/dns-query"}},
		{"empty domain and doh", url.QueryEscape("+https://1.1.1.1/dns-query"), map[string]any{"enable": true, "query-server": "https://1.1.1.1/dns-query"}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			uri := "vless://b831381d-6324-4d53-ad4f-8cda48b30811@example.com:443?security=tls&type=tcp&ech=" + tt.ech
			proxies, err := ConvertsV2Ray([]byte(uri))
			require.NoError(t, err)
			require.Len(t, proxies, 1)
			assert.Equal(t, tt.want, proxies[0]["ech-opts"])
			_, err = adapter.ParseProxy(proxies[0])
			assert.NoError(t, err)
		})
	}
}

func TestConvertsV2RayXrayRealityParams(t *testing.T) {
	key, err := mldsa.GenerateKey(mldsa.MLDSA65())
	require.NoError(t, err)
	pqv := base64.RawURLEncoding.EncodeToString(key.PublicKey().Bytes())
	for _, scheme := range []string{"vless"} {
		t.Run(scheme, func(t *testing.T) {
			uri := scheme + "://b831381d-6324-4d53-ad4f-8cda48b30811@example.com:443?security=reality&type=tcp&sni=www.example.com&fp=hellosafari_26_3" +
				"&pbk=ppQ9FwLrLIa0AOrp1WvcyiaQ37vg2WSy_CD4bIdiTUw&sid=6ba85179&spx=%2Fpath%3Fq%3D1&pqv=" + pqv
			proxies, err := ConvertsV2Ray([]byte(uri))
			require.NoError(t, err)
			require.Len(t, proxies, 1)
			assert.Equal(t, map[string]any{
				"public-key":     "ppQ9FwLrLIa0AOrp1WvcyiaQ37vg2WSy_CD4bIdiTUw",
				"short-id":       "6ba85179",
				"mldsa65-verify": pqv,
			}, proxies[0]["reality-opts"])
			_, err = adapter.ParseProxy(proxies[0])
			assert.NoError(t, err)
		})
	}
}
