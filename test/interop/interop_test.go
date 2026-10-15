//go:build interop

package interop

import (
	"testing"
)

// --- 1. Citrus client -> Xray server: vless + vision + REALITY (ML-DSA-65) ---

func TestCitrusClientXrayServerReality(t *testing.T) {
	needXray(t)
	keys, pq, wrong, id := genX25519(t), genMLDSA65(t), genMLDSA65(t), genUUID(t)

	sport := freePort(t)
	startXray(t, "xray-server", obj{
		"log": xrayLog(),
		"inbounds": []obj{{
			"listen": "127.0.0.1", "port": sport, "protocol": "vless",
			"settings": obj{"clients": []obj{{"id": id, "flow": "xtls-rprx-vision"}}, "decryption": "none"},
			"streamSettings": obj{"network": "raw", "security": "reality", "realitySettings": obj{
				"target": targetAddr, "serverNames": []string{realitySNI},
				"privateKey": keys.priv, "shortIds": []string{shortID}, "mldsa65Seed": pq.seed,
			}},
		}},
		"outbounds": []obj{xrayFreedom()},
	}, sport)

	client := func(fp, verify string) obj {
		return obj{
			"type": "vless", "server": "127.0.0.1", "port": sport, "uuid": id, "udp": false,
			"flow": "xtls-rprx-vision", "network": "tcp", "tls": true,
			"servername": realitySNI, "client-fingerprint": fp,
			"reality-opts": obj{"public-key": keys.pub, "short-id": shortID, "mldsa65-verify": verify},
		}
	}
	for _, fp := range []string{"chrome", "firefox", "safari", "ios"} {
		t.Run(fp, func(t *testing.T) {
			mp := freePort(t)
			startCitrus(t, "citrus-client", citrusClient(mp, client(fp, pq.verify)), mp)
			checkTraffic(t, mp)
		})
	}
	t.Run("wrong-mldsa65-verify", func(t *testing.T) {
		mp := freePort(t)
		startCitrus(t, "citrus-client", citrusClient(mp, client("chrome", wrong.verify)), mp)
		checkBlocked(t, mp)
	})
}

// --- 2. Xray client -> Citrus server: REALITY with mldsa65-seed + X25519MLKEM768 rule ---

func TestXrayClientCitrusServerReality(t *testing.T) {
	needXray(t)
	keys, pq, wrong, id := genX25519(t), genMLDSA65(t), genMLDSA65(t), genUUID(t)

	sport := freePort(t)
	startCitrus(t, "citrus-server", citrusServer(obj{
		"name": "vless-reality-pq", "type": "vless", "listen": "127.0.0.1", "port": sport,
		"users": []obj{{"username": "u", "uuid": id, "flow": "xtls-rprx-vision"}},
		"reality-config": obj{
			"dest": targetAddr, "private-key": keys.priv, "short-id": []string{shortID},
			"server-names": []string{realitySNI}, "mldsa65-seed": pq.seed,
			"require-x25519mlkem768": true,
		},
	}), sport)

	client := func(port int, fp, verify string) obj {
		return obj{
			"log":      xrayLog(),
			"inbounds": []obj{xraySocksIn(port)},
			"outbounds": []obj{{
				"protocol": "vless",
				"settings": obj{"vnext": []obj{{"address": "127.0.0.1", "port": sport,
					"users": []obj{{"id": id, "encryption": "none", "flow": "xtls-rprx-vision"}}}}},
				"streamSettings": obj{"network": "raw", "security": "reality", "realitySettings": obj{
					"fingerprint": fp, "serverName": realitySNI, "password": keys.pub,
					"shortId": shortID, "mldsa65Verify": verify,
				}},
			}},
		}
	}
	for _, fp := range []string{"chrome", "firefox"} {
		t.Run(fp, func(t *testing.T) {
			cp := freePort(t)
			startXray(t, "xray-client", client(cp, fp, pq.verify), cp)
			checkTraffic(t, cp)
		})
	}
	t.Run("wrong-mldsa65-verify", func(t *testing.T) {
		cp := freePort(t)
		startXray(t, "xray-client", client(cp, "chrome", wrong.verify), cp)
		checkBlocked(t, cp)
	})
}

// --- 3. XHTTP over REALITY (h2), both directions ---

func TestCitrusClientXrayServerXHTTP(t *testing.T) {
	needXray(t)
	keys, id := genX25519(t), genUUID(t)

	sport := freePort(t)
	startXray(t, "xray-server", obj{
		"log": xrayLog(),
		"inbounds": []obj{{
			"listen": "127.0.0.1", "port": sport, "protocol": "vless",
			"settings": obj{"clients": []obj{{"id": id}}, "decryption": "none"},
			"streamSettings": obj{
				"network":       "xhttp",
				"xhttpSettings": obj{"path": "/xh", "mode": "auto"},
				"security":      "reality",
				"realitySettings": obj{
					"target": targetAddr, "serverNames": []string{realitySNI},
					"privateKey": keys.priv, "shortIds": []string{shortID},
				},
			},
		}},
		"outbounds": []obj{xrayFreedom()},
	}, sport)

	cases := []struct {
		name string
		opts obj
	}{
		{"packet-up", obj{"path": "/xh", "mode": "packet-up"}},
		{"stream-one", obj{"path": "/xh", "mode": "stream-one"}},
		{"stream-up", obj{"path": "/xh", "mode": "stream-up"}},
		{"packet-up-path-query", obj{"path": "/xh?ed=2048", "mode": "packet-up"}},
		{"packet-up-no-padding", obj{"path": "/xh", "mode": "packet-up", "x-padding-bytes": "0-0"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			mp := freePort(t)
			startCitrus(t, "citrus-client", citrusClient(mp, obj{
				"type": "vless", "server": "127.0.0.1", "port": sport, "uuid": id, "udp": false,
				"network": "xhttp", "tls": true, "alpn": []string{"h2"},
				"servername": realitySNI, "client-fingerprint": "chrome",
				"reality-opts": obj{"public-key": keys.pub, "short-id": shortID},
				"xhttp-opts":   c.opts,
			}), mp)
			checkTraffic(t, mp)
		})
	}
}

func TestXrayClientCitrusServerXHTTP(t *testing.T) {
	needXray(t)
	keys, id := genX25519(t), genUUID(t)

	sport := freePort(t)
	startCitrus(t, "citrus-server", citrusServer(obj{
		"name": "vless-xhttp", "type": "vless", "listen": "127.0.0.1", "port": sport,
		"users": []obj{{"username": "u", "uuid": id}},
		"reality-config": obj{
			"dest": targetAddr, "private-key": keys.priv, "short-id": []string{shortID},
			"server-names": []string{realitySNI},
		},
		"xhttp-config": obj{"path": "/xh", "mode": "packet-up"},
	}), sport)

	t.Run("packet-up-GET-header", func(t *testing.T) {
		cp := freePort(t)
		startXray(t, "xray-client", obj{
			"log":      xrayLog(),
			"inbounds": []obj{xraySocksIn(cp)},
			"outbounds": []obj{{
				"protocol": "vless",
				"settings": obj{"vnext": []obj{{"address": "127.0.0.1", "port": sport,
					"users": []obj{{"id": id, "encryption": "none"}}}}},
				"streamSettings": obj{
					"network": "xhttp",
					"xhttpSettings": obj{
						"path": "/xh", "mode": "packet-up",
						"uplinkHTTPMethod": "GET", "uplinkDataPlacement": "header",
					},
					"security": "reality",
					"realitySettings": obj{
						"fingerprint": "chrome", "serverName": realitySNI,
						"password": keys.pub, "shortId": shortID,
					},
				},
			}},
		}, cp)
		checkTraffic(t, cp)
	})
}

// --- 4. ECH (vless over TLS) with keys from `xray tls ech`, both directions ---
//
// The certificate is self-signed for interop.test and pinned by the clients. A
// config list the server has no key for makes the server reject ECH; the client
// then checks the outer certificate against the public name with the system
// roots, which fails, so the wrong-ech-config cases prove ECH was accepted in
// the good ones.

func TestXrayClientCitrusServerECH(t *testing.T) {
	needXray(t)
	ech, other, id := genECH(t, echPublic), genECH(t, echPublic), genUUID(t)

	sport := freePort(t)
	startCitrus(t, "citrus-server", citrusServer(obj{
		"name": "vless-tls-ech", "type": "vless", "listen": "127.0.0.1", "port": sport,
		"users":       []obj{{"username": "u", "uuid": id}},
		"certificate": string(tlsCertPEM), "private-key": string(tlsKeyPEM),
		"ech-key": ech.serverKeys,
	}), sport)

	client := func(port int, configList string) obj {
		return obj{
			"log":      xrayLog(),
			"inbounds": []obj{xraySocksIn(port)},
			"outbounds": []obj{{
				"protocol": "vless",
				"settings": obj{"vnext": []obj{{"address": "127.0.0.1", "port": sport,
					"users": []obj{{"id": id, "encryption": "none"}}}}},
				"streamSettings": obj{"network": "raw", "security": "tls", "tlsSettings": obj{
					"serverName": realitySNI, "pinnedPeerCertSha256": tlsCertSHA256,
					"echConfigList": configList,
				}},
			}},
		}
	}
	t.Run("ech", func(t *testing.T) {
		cp := freePort(t)
		startXray(t, "xray-client", client(cp, ech.configList), cp)
		checkTraffic(t, cp)
	})
	t.Run("wrong-ech-config", func(t *testing.T) {
		cp := freePort(t)
		startXray(t, "xray-client", client(cp, other.configList), cp)
		checkBlocked(t, cp)
	})
}

func TestCitrusClientXrayServerECH(t *testing.T) {
	needXray(t)
	ech, other, id := genECH(t, echPublic), genECH(t, echPublic), genUUID(t)

	dir := caseDir(t, "xray-server")
	certFile, keyFile := writeFile(t, dir, "cert.pem", tlsCertPEM), writeFile(t, dir, "key.pem", tlsKeyPEM)
	sport := freePort(t)
	startXray(t, "xray-server", obj{
		"log": xrayLog(),
		"inbounds": []obj{{
			"listen": "127.0.0.1", "port": sport, "protocol": "vless",
			"settings": obj{"clients": []obj{{"id": id}}, "decryption": "none"},
			"streamSettings": obj{"network": "raw", "security": "tls", "tlsSettings": obj{
				"certificates":  []obj{{"certificateFile": certFile, "keyFile": keyFile}},
				"echServerKeys": ech.serverKeys,
			}},
		}},
		"outbounds": []obj{xrayFreedom()},
	}, sport)

	client := func(configList string) obj {
		return obj{
			"type": "vless", "server": "127.0.0.1", "port": sport, "uuid": id, "udp": false,
			"network": "tcp", "tls": true, "servername": realitySNI, "fingerprint": tlsCertSHA256,
			"ech-opts": obj{"enable": true, "config": configList},
		}
	}
	t.Run("ech", func(t *testing.T) {
		mp := freePort(t)
		startCitrus(t, "citrus-client", citrusClient(mp, client(ech.configList)), mp)
		checkTraffic(t, mp)
	})
	t.Run("wrong-ech-config", func(t *testing.T) {
		mp := freePort(t)
		startCitrus(t, "citrus-client", citrusClient(mp, client(other.configList)), mp)
		checkBlocked(t, mp)
	})
}

// --- 5. gRPC (gun) over REALITY, both directions ---

func TestCitrusClientXrayServerGRPC(t *testing.T) {
	needXray(t)
	keys, id := genX25519(t), genUUID(t)

	sport := freePort(t)
	startXray(t, "xray-server", obj{
		"log": xrayLog(),
		"inbounds": []obj{{
			"listen": "127.0.0.1", "port": sport, "protocol": "vless",
			"settings": obj{"clients": []obj{{"id": id}}, "decryption": "none"},
			"streamSettings": obj{
				"network":      "grpc",
				"grpcSettings": obj{"serviceName": "gs"},
				"security":     "reality",
				"realitySettings": obj{
					"target": targetAddr, "serverNames": []string{realitySNI},
					"privateKey": keys.priv, "shortIds": []string{shortID},
				},
			},
		}},
		"outbounds": []obj{xrayFreedom()},
	}, sport)

	mp := freePort(t)
	startCitrus(t, "citrus-client", citrusClient(mp, obj{
		"type": "vless", "server": "127.0.0.1", "port": sport, "uuid": id, "udp": false,
		"network": "grpc", "tls": true,
		"servername": realitySNI, "client-fingerprint": "chrome",
		"reality-opts": obj{"public-key": keys.pub, "short-id": shortID},
		"grpc-opts":    obj{"grpc-service-name": "gs"},
	}), mp)
	checkTraffic(t, mp)
}

func TestXrayClientCitrusServerGRPC(t *testing.T) {
	needXray(t)
	keys, id := genX25519(t), genUUID(t)

	sport := freePort(t)
	startCitrus(t, "citrus-server", citrusServer(obj{
		"name": "vless-grpc", "type": "vless", "listen": "127.0.0.1", "port": sport,
		"users": []obj{{"username": "u", "uuid": id}},
		"reality-config": obj{
			"dest": targetAddr, "private-key": keys.priv, "short-id": []string{shortID},
			"server-names": []string{realitySNI},
		},
		"grpc-service-name": "gs",
	}), sport)

	cp := freePort(t)
	startXray(t, "xray-client", obj{
		"log":      xrayLog(),
		"inbounds": []obj{xraySocksIn(cp)},
		"outbounds": []obj{{
			"protocol": "vless",
			"settings": obj{"vnext": []obj{{"address": "127.0.0.1", "port": sport,
				"users": []obj{{"id": id, "encryption": "none"}}}}},
			"streamSettings": obj{
				"network":      "grpc",
				"grpcSettings": obj{"serviceName": "gs"},
				"security":     "reality",
				"realitySettings": obj{
					"fingerprint": "chrome", "serverName": realitySNI,
					"password": keys.pub, "shortId": shortID,
				},
			},
		}},
	}, cp)
	checkTraffic(t, cp)
}
