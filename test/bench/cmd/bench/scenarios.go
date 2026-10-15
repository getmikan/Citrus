package main

import "strings"

type obj = map[string]any

// scenario is one inbound protocol: the server listener and the matching
// client proxy (a Citrus outbound, run in the driver process).
type scenario struct {
	name string
	udp  bool // listener on UDP (QUIC)
	// streamsPerConn > 0: the client is a multiplexing transport; spread the
	// streams over proxy instances, this many per instance (one QUIC
	// connection each). 0: one proxy instance for everything.
	streamsPerConn int
	listener       func(m *material, port int, dest string) obj
	proxy          func(m *material, port int) obj
	note           string
}

const inboundName = "bench-in"

func base(typ string, port int) obj {
	return obj{"name": inboundName, "type": typ, "listen": serverHost, "port": port}
}

func merge(a obj, b obj) obj {
	for k, v := range b {
		a[k] = v
	}
	return a
}

func realityConfig(m *material, dest string) obj {
	return obj{
		"dest": dest, "private-key": m.realityPriv,
		"short-id": []string{m.shortID}, "server-names": []string{benchSNI},
	}
}

func realityClient(m *material, port int) obj {
	return obj{
		"type": "vless", "server": serverHost, "port": port, "uuid": m.uuid, "udp": false,
		"tls": true, "servername": benchSNI, "client-fingerprint": "chrome",
		"reality-opts": obj{"public-key": m.realityPub, "short-id": m.shortID},
	}
}

func xhttpScenario(mode string) scenario {
	return scenario{
		name: "vless-xhttp-" + mode,
		listener: func(m *material, port int, dest string) obj {
			return merge(base("vless", port), obj{
				"users":          []obj{{"username": "u1", "uuid": m.uuid}},
				"reality-config": realityConfig(m, dest),
				"xhttp-config":   obj{"path": "/xh", "mode": "auto"},
			})
		},
		proxy: func(m *material, port int) obj {
			return merge(realityClient(m, port), obj{
				"network": "xhttp", "alpn": []string{"h2"},
				"xhttp-opts": obj{"path": "/xh", "mode": mode},
			})
		},
		note: "REALITY + h2, client default xmux (streams share h2 connections)",
	}
}

var scenarios = []scenario{
	{
		name: "vless-reality-vision",
		listener: func(m *material, port int, dest string) obj {
			return merge(base("vless", port), obj{
				"users":          []obj{{"username": "u1", "uuid": m.uuid, "flow": "xtls-rprx-vision"}},
				"reality-config": realityConfig(m, dest),
			})
		},
		proxy: func(m *material, port int) obj {
			return merge(realityClient(m, port), obj{"flow": "xtls-rprx-vision", "network": "tcp"})
		},
	},
	xhttpScenario("stream-one"),
	xhttpScenario("packet-up"),
	{
		name: "trojan-tls",
		listener: func(m *material, port int, dest string) obj {
			return merge(base("trojan", port), obj{
				"users":       []obj{{"username": "u1", "password": m.password}},
				"certificate": m.certPEM, "private-key": m.keyPEM,
			})
		},
		proxy: func(m *material, port int) obj {
			return obj{
				"type": "trojan", "server": serverHost, "port": port, "password": m.password,
				"sni": benchSNI, "skip-cert-verify": true, "udp": false,
			}
		},
	},
	{
		name:           "hysteria2",
		udp:            true,
		streamsPerConn: 64,
		listener: func(m *material, port int, dest string) obj {
			return merge(base("hysteria2", port), obj{
				"users":       obj{"u1": m.password},
				"certificate": m.certPEM, "private-key": m.keyPEM,
			})
		},
		proxy: func(m *material, port int) obj {
			return obj{
				"type": "hysteria2", "server": serverHost, "port": port, "password": m.password,
				"sni": benchSNI, "skip-cert-verify": true,
			}
		},
		note: "QUIC: one connection per 64 streams; per-conn figures are per stream",
	},
	{
		name: "ss2022",
		listener: func(m *material, port int, dest string) obj {
			return merge(base("shadowsocks", port), obj{
				"cipher": "2022-blake3-aes-128-gcm", "password": m.ssServerPSK,
				"users": []obj{{"name": "u1", "password": m.ssUserPSK}},
			})
		},
		proxy: func(m *material, port int) obj {
			return obj{
				"type": "ss", "server": serverHost, "port": port, "cipher": "2022-blake3-aes-128-gcm",
				"password": m.ssServerPSK + ":" + m.ssUserPSK, "udp": false,
			}
		},
		note: "2022-blake3-aes-128-gcm, multi-user (EIH)",
	},
	{
		name:           "tuic-v5",
		udp:            true,
		streamsPerConn: 64,
		listener: func(m *material, port int, dest string) obj {
			return merge(base("tuic", port), obj{
				"users":       obj{m.uuid: m.password},
				"certificate": m.certPEM, "private-key": m.keyPEM,
			})
		},
		proxy: func(m *material, port int) obj {
			return obj{
				"type": "tuic", "server": serverHost, "port": port, "uuid": m.uuid, "password": m.password,
				"sni": benchSNI, "skip-cert-verify": true, "alpn": []string{"h3"}, "udp-relay-mode": "native",
			}
		},
		note: "QUIC: one connection per 64 streams; per-conn figures are per stream",
	},
}

func findScenario(name string) *scenario {
	for i := range scenarios {
		if scenarios[i].name == name {
			return &scenarios[i]
		}
	}
	return nil
}

func scenarioNames() string {
	var n []string
	for _, s := range scenarios {
		n = append(n, s.name)
	}
	return strings.Join(n, ",")
}

// variant is a server-side setting of the user accounting (#42) and the user
// limits (#44).
type variant struct {
	name  string
	stats bool
	limit bool
}

var variants = []variant{
	{"stats-off", false, false},
	{"stats-on", true, false},
	{"stats-on+limit", true, true},
}

func serverConfig(s *scenario, m *material, port int, dest string, v variant) obj {
	cfg := obj{
		"mode":       "rule",
		"log-level":  "warning",
		"ipv6":       false,
		"user-stats": v.stats,
		"profile":    obj{"store-selected": false, "store-fake-ip": false},
		"listeners":  []obj{s.listener(m, port, dest)},
		"rules":      []string{"MATCH,DIRECT"},
	}
	if v.limit {
		// Limits that never bind: the cost of enforcing them, not of throttling.
		cfg["user-limits"] = []obj{{
			"inbound": inboundName, "user": "*",
			"speed-up": "100G", "speed-down": "100G",
			"max-conns": 1000000, "max-ips": 1000, "quota": "1000T",
		}}
	}
	return cfg
}
