package convert

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"net/url"
	"strconv"
	"strings"

	"github.com/metacubex/mihomo/log"
	ssCore "github.com/metacubex/mihomo/transport/shadowsocks/core"
)

// ConvertsV2Ray convert V2Ray subscribe proxies data to mihomo proxies config
func ConvertsV2Ray(buf []byte) ([]map[string]any, error) {
	data := DecodeBase64(buf)

	rawLines := bytes.Split(data, []byte("\n"))

	proxies := make([]map[string]any, 0, len(rawLines))
	names := make(map[string]int, 200)

	for _, raw := range rawLines {
		line := strings.TrimRight(string(raw), " \r")
		if line == "" {
			continue
		}

		scheme, _, found := strings.Cut(line, "://")
		if !found {
			continue
		}

		scheme = strings.ToLower(scheme)
		switch scheme {
		case "hysteria2", "hy2", "hysteria2+realm", "hy2+realm":
			realmMode := strings.HasSuffix(scheme, "+realm")
			hopLine, ports := splitHysteria2Ports(line)
			urlHysteria2, err := url.Parse(hopLine)
			if err != nil {
				continue
			}

			query := urlHysteria2.Query()
			name := uniqueName(names, urlHysteria2.Fragment)
			hysteria2 := make(map[string]any, 20)

			hysteria2["name"] = name
			hysteria2["type"] = "hysteria2"
			hysteria2["server"] = urlHysteria2.Hostname()
			if port := urlHysteria2.Port(); port != "" {
				hysteria2["port"] = port
			} else {
				hysteria2["port"] = "443"
			}
			if ports != "" {
				hysteria2["ports"] = ports
			}
			hysteria2["obfs"] = query.Get("obfs")
			hysteria2["obfs-password"] = query.Get("obfs-password")
			hysteria2["sni"] = query.Get("sni")
			hysteria2["skip-cert-verify"], _ = strconv.ParseBool(query.Get("insecure"))
			if alpn := query.Get("alpn"); alpn != "" {
				hysteria2["alpn"] = strings.Split(alpn, ",")
			}
			hysteria2["fingerprint"] = query.Get("pinSHA256")
			hysteria2["down"] = query.Get("down")
			hysteria2["up"] = query.Get("up")
			if realmMode {
				token, _ := url.PathUnescape(urlHysteria2.User.String())
				realmID, _ := url.PathUnescape(strings.TrimPrefix(urlHysteria2.EscapedPath(), "/"))
				hysteria2["realm-opts"] = buildRealmOpts("https://"+urlHysteria2.Host, token, realmID, query["stun"])
				if auth := query.Get("auth"); auth != "" {
					hysteria2["password"] = auth
				}
			} else if auth := urlHysteria2.User.String(); auth != "" {
				hysteria2["password"] = auth
			}

			proxies = append(proxies, hysteria2)

		case "tuic":
			// A temporary unofficial TUIC share link standard
			// Modified from https://github.com/daeuniverse/dae/discussions/182
			// Changes:
			//   1. Remove `allow_insecure` field
			// Only TUIC v5 (uuid:password) is supported; v4 token-only links are skipped.
			urlTUIC, err := url.Parse(line)
			if err != nil {
				continue
			}
			password, v5 := urlTUIC.User.Password()
			if !v5 {
				continue
			}
			query := urlTUIC.Query()

			tuic := make(map[string]any, 20)
			tuic["name"] = uniqueName(names, urlTUIC.Fragment)
			tuic["type"] = scheme
			tuic["server"] = urlTUIC.Hostname()
			tuic["port"] = urlTUIC.Port()
			tuic["udp"] = true
			tuic["uuid"] = urlTUIC.User.Username()
			tuic["password"] = password
			if cc := query.Get("congestion_control"); cc != "" {
				tuic["congestion-controller"] = cc
			}
			if alpn := query.Get("alpn"); alpn != "" {
				tuic["alpn"] = strings.Split(alpn, ",")
			}
			if sni := query.Get("sni"); sni != "" {
				tuic["sni"] = sni
			}
			if query.Get("disable_sni") == "1" {
				tuic["disable-sni"] = true
			}
			if udpRelayMode := query.Get("udp_relay_mode"); udpRelayMode != "" {
				tuic["udp-relay-mode"] = udpRelayMode
			}

			proxies = append(proxies, tuic)

		case "trojan":
			urlTrojan, err := url.Parse(line)
			if err != nil {
				continue
			}

			query := urlTrojan.Query()

			name := uniqueName(names, urlTrojan.Fragment)
			trojan := make(map[string]any, 20)

			trojan["name"] = name
			trojan["type"] = scheme
			trojan["server"] = urlTrojan.Hostname()
			trojan["port"] = urlTrojan.Port()
			trojan["password"] = urlTrojan.User.Username()
			trojan["udp"] = true
			trojan["skip-cert-verify"], _ = strconv.ParseBool(query.Get("allowInsecure"))

			if sni := query.Get("sni"); sni != "" {
				trojan["sni"] = sni
			}
			if alpn := query.Get("alpn"); alpn != "" {
				trojan["alpn"] = strings.Split(alpn, ",")
			}

			network := strings.ToLower(query.Get("type"))
			if network != "" {
				trojan["network"] = network
			}

			switch network {
			case "ws":
				headers := make(map[string]any)
				wsOpts := make(map[string]any)

				headers["User-Agent"] = RandUserAgent()

				wsOpts["path"] = query.Get("path")
				wsOpts["headers"] = headers

				trojan["ws-opts"] = wsOpts

			case "grpc":
				grpcOpts := make(map[string]any)
				grpcOpts["grpc-service-name"] = query.Get("serviceName")
				trojan["grpc-opts"] = grpcOpts
			}

			if fingerprint := query.Get("fp"); fingerprint == "" {
				trojan["client-fingerprint"] = "chrome"
			} else {
				trojan["client-fingerprint"] = fingerprint
			}

			handleTLSShareLinkQuery(query, trojan)

			proxies = append(proxies, trojan)

		case "vless":
			urlVLess, err := url.Parse(line)
			if err != nil {
				continue
			}
			if decodedHost, err := tryDecodeBase64([]byte(urlVLess.Host)); err == nil {
				urlVLess.Host = string(decodedHost)
			}
			query := urlVLess.Query()
			vless := make(map[string]any, 20)
			err = handleVShareLink(names, urlVLess, scheme, vless)
			if err != nil {
				// Only the server and the name: the link's user part and
				// query carry the UUID, keys and passwords.
				log.Warnln("skip vless link to %s (%s): %s", urlVLess.Host, urlVLess.Fragment, err.Error())
				continue
			}
			if flow := query.Get("flow"); flow != "" {
				vless["flow"] = strings.ToLower(flow)
			}
			if encryption := query.Get("encryption"); encryption != "" {
				vless["encryption"] = encryption
			}
			proxies = append(proxies, vless)

		case "vmess":
			continue // VMess is no longer supported

		case "ss":
			urlSS, err := url.Parse(line)
			if err != nil {
				continue
			}

			name := uniqueName(names, urlSS.Fragment)
			port := urlSS.Port()

			if port == "" {
				dcBuf, err := encRaw.DecodeString(urlSS.Host)
				if err != nil {
					continue
				}

				urlSS, err = url.Parse("ss://" + string(dcBuf))
				if err != nil {
					continue
				}
			}

			var (
				cipherRaw = urlSS.User.Username()
				cipher    string
				password  string
			)
			cipher = cipherRaw
			if password, found = urlSS.User.Password(); !found {
				dcBuf, err := base64.RawURLEncoding.DecodeString(cipherRaw)
				if err != nil {
					dcBuf, _ = enc.DecodeString(cipherRaw)
				}
				cipher, password, found = strings.Cut(string(dcBuf), ":")
				if !found {
					continue
				}
				err = VerifyMethod(cipher, password)
				if err != nil {
					dcBuf, _ = encRaw.DecodeString(cipherRaw)
					cipher, password, found = strings.Cut(string(dcBuf), ":")
				}
			}

			if ssCore.IsStreamCipher(cipher) {
				continue // legacy stream ciphers are no longer supported
			}

			ss := make(map[string]any, 10)

			ss["name"] = name
			ss["type"] = scheme
			ss["server"] = urlSS.Hostname()
			ss["port"] = urlSS.Port()
			ss["cipher"] = cipher
			ss["password"] = password
			query := urlSS.Query()
			ss["udp"] = true
			if query.Get("udp-over-tcp") == "true" || query.Get("uot") == "1" {
				ss["udp-over-tcp"] = true
			}
			plugin := query.Get("plugin")
			if strings.Contains(plugin, ";") {
				pluginInfo, _ := url.ParseQuery("pluginName=" + strings.ReplaceAll(plugin, ";", "&"))
				pluginName := pluginInfo.Get("pluginName")
				if strings.Contains(pluginName, "obfs") {
					ss["plugin"] = "obfs"
					ss["plugin-opts"] = map[string]any{
						"mode": pluginInfo.Get("obfs"),
						"host": pluginInfo.Get("obfs-host"),
					}
				} else if strings.Contains(pluginName, "v2ray-plugin") {
					continue // v2ray-plugin is no longer supported
				}
			}

			proxies = append(proxies, ss)

		case "socks", "socks5", "socks5h", "http", "https":
			link, err := url.Parse(line)
			if err != nil {
				continue
			}
			server := link.Hostname()
			if server == "" {
				continue
			}
			portStr := link.Port()
			if portStr == "" {
				continue
			}
			remarks := link.Fragment
			if remarks == "" {
				remarks = fmt.Sprintf("%s:%s", server, portStr)
			}
			name := uniqueName(names, remarks)
			encodeStr := link.User.String()
			var username, password string
			if encodeStr != "" {
				decodeStr := string(DecodeBase64([]byte(encodeStr)))
				splitStr := strings.Split(decodeStr, ":")

				// todo: should use url.QueryUnescape ?
				username = splitStr[0]
				if len(splitStr) == 2 {
					password = splitStr[1]
				}
			}
			socks := make(map[string]any, 10)
			socks["name"] = name
			socks["type"] = func() string {
				switch scheme {
				case "socks", "socks5", "socks5h":
					return "socks5"
				case "http", "https":
					return "http"
				}
				return scheme
			}()
			socks["server"] = server
			socks["port"] = portStr
			socks["username"] = username
			socks["password"] = password
			// verify the certificate unless the link explicitly asks not to
			if linkAllowsInsecure(link.Query()) {
				socks["skip-cert-verify"] = true
			}
			if scheme == "https" {
				socks["tls"] = true
			}

			proxies = append(proxies, socks)

		case "anytls":
			// https://github.com/anytls/anytls-go/blob/main/docs/uri_scheme.md
			link, err := url.Parse(line)
			if err != nil {
				continue
			}
			username := link.User.Username()
			password, exist := link.User.Password()
			if !exist {
				password = username
			}
			query := link.Query()
			server := link.Hostname()
			if server == "" {
				continue
			}
			portStr := link.Port()
			if portStr == "" {
				continue
			}
			insecure, sni := query.Get("insecure"), query.Get("sni")
			insecureBool := insecure == "1"
			fingerprint := query.Get("hpkp")

			remarks := link.Fragment
			if remarks == "" {
				remarks = fmt.Sprintf("%s:%s", server, portStr)
			}
			name := uniqueName(names, remarks)
			anytls := make(map[string]any, 10)
			anytls["name"] = name
			anytls["type"] = "anytls"
			anytls["server"] = server
			anytls["port"] = portStr
			anytls["username"] = username
			anytls["password"] = password
			anytls["sni"] = sni
			anytls["fingerprint"] = fingerprint
			anytls["skip-cert-verify"] = insecureBool
			anytls["udp"] = true

			proxies = append(proxies, anytls)

		case "mierus":
			urlMieru, err := url.Parse(line)
			if err != nil {
				continue
			}

			query := urlMieru.Query()

			server := urlMieru.Hostname()
			if server == "" {
				continue
			}
			username := urlMieru.User.Username()
			password, _ := urlMieru.User.Password()

			baseName := urlMieru.Fragment
			if baseName == "" {
				baseName = query.Get("profile")
			}
			if baseName == "" {
				baseName = server
			}

			multiplexing := query.Get("multiplexing")
			handshakeMode := query.Get("handshake-mode")
			trafficPattern := query.Get("traffic-pattern")

			portList := query["port"]
			protocolList := query["protocol"]
			if len(portList) == 0 || len(portList) != len(protocolList) {
				continue
			}

			for i, port := range portList {
				protocol := protocolList[i]
				name := uniqueName(names, fmt.Sprintf("%s:%s/%s", baseName, port, protocol))

				mieru := make(map[string]any, 15)
				mieru["name"] = name
				mieru["type"] = "mieru"
				mieru["server"] = server
				mieru["transport"] = protocol
				mieru["udp"] = true
				mieru["username"] = username
				mieru["password"] = password

				if strings.Contains(port, "-") {
					mieru["port-range"] = port
				} else {
					portNum, err := strconv.Atoi(port)
					if err != nil {
						continue
					}
					mieru["port"] = portNum
				}

				if multiplexing != "" {
					mieru["multiplexing"] = multiplexing
				}
				if handshakeMode != "" {
					mieru["handshake-mode"] = handshakeMode
				}
				if trafficPattern != "" {
					mieru["traffic-pattern"] = trafficPattern
				}

				proxies = append(proxies, mieru)
			}
		}
	}

	if len(proxies) == 0 {
		return nil, fmt.Errorf("convert v2ray subscribe error: format invalid")
	}

	return proxies, nil
}

func uniqueName(names map[string]int, name string) string {
	if index, ok := names[name]; ok {
		index++
		names[name] = index
		name = fmt.Sprintf("%s-%02d", name, index)
	} else {
		index = 0
		names[name] = index
	}
	return name
}
