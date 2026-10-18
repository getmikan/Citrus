package main

import (
	"fmt"
	"testing"
	"time"

	"github.com/metacubex/mihomo/adapter/outbound"
	C "github.com/metacubex/mihomo/constant"
	"github.com/moby/moby/api/types/container"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TODO: fix udp test
func TestMihomo_VlessTLS(t *testing.T) {
	cfg := &container.Config{
		Image:        ImageV2fly,
		ExposedPorts: defaultExposedPorts,
	}
	hostCfg := &container.HostConfig{
		PortBindings: defaultPortBindings,
		Binds: []string{
			fmt.Sprintf("%s:/etc/v2ray/config.json", C.Path.Resolve("vless-tls.json")),
			fmt.Sprintf("%s:/etc/ssl/v2ray/fullchain.pem", C.Path.Resolve("example.org.pem")),
			fmt.Sprintf("%s:/etc/ssl/v2ray/privkey.pem", C.Path.Resolve("example.org-key.pem")),
		},
	}

	id, err := startContainer(cfg, hostCfg, "vless-tls")
	if err != nil {
		assert.FailNow(t, err.Error())
	}
	defer cleanContainer(id)

	proxy, err := outbound.NewVless(outbound.VlessOption{
		Name:           "vless",
		Server:         localIP.String(),
		Port:           10002,
		UUID:           "b831381d-6324-4d53-ad4f-8cda48b30811",
		TLS:            true,
		SkipCertVerify: true,
		ServerName:     "example.org",
		UDP:            true,
	})
	if err != nil {
		assert.FailNow(t, err.Error())
	}

	time.Sleep(waitTime)
	testSuit(t, proxy)
}

// TODO: fix udp test
func TestMihomo_VlessXTLS(t *testing.T) {
	cfg := &container.Config{
		Image:        ImageXray,
		ExposedPorts: defaultExposedPorts,
	}
	hostCfg := &container.HostConfig{
		PortBindings: defaultPortBindings,
		Binds: []string{
			fmt.Sprintf("%s:/etc/xray/config.json", C.Path.Resolve("vless-xtls.json")),
			fmt.Sprintf("%s:/etc/ssl/v2ray/fullchain.pem", C.Path.Resolve("example.org.pem")),
			fmt.Sprintf("%s:/etc/ssl/v2ray/privkey.pem", C.Path.Resolve("example.org-key.pem")),
		},
	}

	id, err := startContainer(cfg, hostCfg, "vless-xtls")
	if err != nil {
		assert.FailNow(t, err.Error())
	}
	defer cleanContainer(id)

	proxy, err := outbound.NewVless(outbound.VlessOption{
		Name:           "vless",
		Server:         localIP.String(),
		Port:           10002,
		UUID:           "b831381d-6324-4d53-ad4f-8cda48b30811",
		TLS:            true,
		SkipCertVerify: true,
		ServerName:     "example.org",
		UDP:            true,
		Flow:           "xtls-rprx-direct",
	})
	if err != nil {
		assert.FailNow(t, err.Error())
	}

	time.Sleep(waitTime)
	testSuit(t, proxy)
}

// TODO: fix udp test
func TestMihomo_VlessWS(t *testing.T) {
	cfg := &container.Config{
		Image:        ImageV2fly,
		ExposedPorts: defaultExposedPorts,
	}
	hostCfg := &container.HostConfig{
		PortBindings: defaultPortBindings,
		Binds: []string{
			fmt.Sprintf("%s:/etc/v2ray/config.json", C.Path.Resolve("vless-ws.json")),
			fmt.Sprintf("%s:/etc/ssl/v2ray/fullchain.pem", C.Path.Resolve("example.org.pem")),
			fmt.Sprintf("%s:/etc/ssl/v2ray/privkey.pem", C.Path.Resolve("example.org-key.pem")),
		},
	}

	id, err := startContainer(cfg, hostCfg, "vless-ws")
	if err != nil {
		assert.FailNow(t, err.Error())
	}
	defer cleanContainer(id)

	proxy, err := outbound.NewVless(outbound.VlessOption{
		Name:           "vless",
		Server:         localIP.String(),
		Port:           10002,
		UUID:           "b831381d-6324-4d53-ad4f-8cda48b30811",
		TLS:            true,
		SkipCertVerify: true,
		ServerName:     "example.org",
		Network:        "ws",
		UDP:            true,
	})
	if err != nil {
		assert.FailNow(t, err.Error())
	}

	time.Sleep(waitTime)
	testSuit(t, proxy)
}

// The HTTP/2, HTTP-obfs and WebSocket early-data transports used to be
// covered only by the VMess tests.

func TestMihomo_VlessHTTP2(t *testing.T) {
	cfg := &container.Config{
		Image:        ImageV2fly,
		ExposedPorts: defaultExposedPorts,
	}
	hostCfg := &container.HostConfig{
		PortBindings: defaultPortBindings,
		Binds: []string{
			fmt.Sprintf("%s:/etc/v2ray/config.json", C.Path.Resolve("vless-http2.json")),
			fmt.Sprintf("%s:/etc/ssl/v2ray/fullchain.pem", C.Path.Resolve("example.org.pem")),
			fmt.Sprintf("%s:/etc/ssl/v2ray/privkey.pem", C.Path.Resolve("example.org-key.pem")),
		},
	}

	id, err := startContainer(cfg, hostCfg, "vless-http2")
	require.NoError(t, err)
	t.Cleanup(func() {
		cleanContainer(id)
	})

	proxy, err := outbound.NewVless(outbound.VlessOption{
		Name:           "vless",
		Server:         localIP.String(),
		Port:           10002,
		UUID:           "b831381d-6324-4d53-ad4f-8cda48b30811",
		Network:        "h2",
		TLS:            true,
		SkipCertVerify: true,
		ServerName:     "example.org",
		UDP:            true,
		HTTP2Opts: outbound.HTTP2Options{
			Host: []string{"example.org"},
			Path: "/test",
		},
	})
	require.NoError(t, err)

	time.Sleep(waitTime)
	testSuit(t, proxy)
}

func TestMihomo_VlessHTTP(t *testing.T) {
	cfg := &container.Config{
		Image:        ImageV2fly,
		ExposedPorts: defaultExposedPorts,
	}
	hostCfg := &container.HostConfig{
		PortBindings: defaultPortBindings,
		Binds: []string{
			fmt.Sprintf("%s:/etc/v2ray/config.json", C.Path.Resolve("vless-http.json")),
		},
	}

	id, err := startContainer(cfg, hostCfg, "vless-http")
	require.NoError(t, err)
	t.Cleanup(func() {
		cleanContainer(id)
	})

	proxy, err := outbound.NewVless(outbound.VlessOption{
		Name:    "vless",
		Server:  localIP.String(),
		Port:    10002,
		UUID:    "b831381d-6324-4d53-ad4f-8cda48b30811",
		Network: "http",
		UDP:     true,
		HTTPOpts: outbound.HTTPOptions{
			Method: "GET",
			Path:   []string{"/"},
			Headers: map[string][]string{
				"Host": {"www.amazon.com"},
				"User-Agent": {
					"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/84.0.4147.105 Safari/537.36 Edg/84.0.522.49",
				},
				"Accept-Encoding": {
					"gzip, deflate",
				},
				"Connection": {
					"keep-alive",
				},
				"Pragma": {"no-cache"},
			},
		},
	})
	require.NoError(t, err)

	time.Sleep(waitTime)
	testSuit(t, proxy)
}

func TestMihomo_VlessWebsocket0RTT(t *testing.T) {
	cfg := &container.Config{
		Image:        ImageV2fly,
		ExposedPorts: defaultExposedPorts,
	}
	hostCfg := &container.HostConfig{
		PortBindings: defaultPortBindings,
		Binds: []string{
			fmt.Sprintf("%s:/etc/v2ray/config.json", C.Path.Resolve("vless-ws-0rtt.json")),
		},
	}

	id, err := startContainer(cfg, hostCfg, "vless-ws-0rtt")
	require.NoError(t, err)
	t.Cleanup(func() {
		cleanContainer(id)
	})

	proxy, err := outbound.NewVless(outbound.VlessOption{
		Name:       "vless",
		Server:     localIP.String(),
		Port:       10002,
		UUID:       "b831381d-6324-4d53-ad4f-8cda48b30811",
		Network:    "ws",
		UDP:        true,
		ServerName: "example.org",
		WSOpts: outbound.WSOptions{
			MaxEarlyData:        2048,
			EarlyDataHeaderName: "Sec-WebSocket-Protocol",
		},
	})
	require.NoError(t, err)

	time.Sleep(waitTime)
	testSuit(t, proxy)
}

func TestMihomo_VlessWebsocketXray0RTT(t *testing.T) {
	cfg := &container.Config{
		Image:        ImageXray,
		ExposedPorts: defaultExposedPorts,
	}
	hostCfg := &container.HostConfig{
		PortBindings: defaultPortBindings,
		Binds: []string{
			fmt.Sprintf("%s:/etc/xray/config.json", C.Path.Resolve("vless-ws-0rtt.json")),
		},
	}

	id, err := startContainer(cfg, hostCfg, "vless-xray-ws-0rtt")
	require.NoError(t, err)
	t.Cleanup(func() {
		cleanContainer(id)
	})

	proxy, err := outbound.NewVless(outbound.VlessOption{
		Name:       "vless",
		Server:     localIP.String(),
		Port:       10002,
		UUID:       "b831381d-6324-4d53-ad4f-8cda48b30811",
		Network:    "ws",
		UDP:        true,
		ServerName: "example.org",
		WSOpts: outbound.WSOptions{
			Path: "/?ed=2048",
		},
	})
	require.NoError(t, err)

	time.Sleep(waitTime)
	testSuit(t, proxy)
}
