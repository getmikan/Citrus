//go:build interop

package interop

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

// Exercise the on-storage protocol against Xray, including encrypted headers,
// Mux.Cool stream reuse, concurrent TCP streams, large transfers and XUDP.
func TestXDriveInterop(t *testing.T) {
	needXray(t)
	for _, backend := range []string{"local", "template"} {
		for _, rtt := range []string{"0rtt", "1rtt"} {
			for _, direction := range []string{"citrus-client", "xray-client"} {
				t.Run(backend+"/"+rtt+"/"+direction, func(t *testing.T) {
					keys, id := genX25519Go(t), genUUIDGo(t)
					enc := "mlkem768x25519plus.native." + rtt + "." + keys.pub
					dec := "mlkem768x25519plus.native.600s." + keys.priv
					citrusOpts, xrayOpts := xdriveStorage(t, backend)
					sport, ready, clientPort := freePort(t), freePort(t), freePort(t)
					if direction == "citrus-client" {
						startXray(t, "xray-server", obj{"log": xrayLog(), "inbounds": []obj{
							xraySocksIn(ready),
							{"listen": "127.0.0.1", "port": sport, "protocol": "vless", "settings": obj{"clients": []obj{{"id": id}}, "decryption": dec}, "streamSettings": obj{"network": "xdrive", "xdriveSettings": xrayOpts}},
						}, "outbounds": []obj{xrayFreedom()}}, ready)
						startCitrus(t, "citrus-client", citrusClient(clientPort, obj{"type": "vless", "server": "127.0.0.1", "port": sport, "uuid": id, "udp": true, "network": "xdrive", "encryption": enc, "xdrive-opts": citrusOpts}), clientPort)
					} else {
						cfg := citrusServer(obj{"name": "xdrive", "type": "vless", "listen": "127.0.0.1", "port": sport, "users": []obj{{"username": "u", "uuid": id}}, "decryption": dec, "xdrive-config": citrusOpts})
						cfg["mixed-port"] = ready
						startCitrus(t, "citrus-server", cfg, ready)
						socks := xraySocksIn(clientPort)
						socks["settings"] = obj{"udp": true}
						startXray(t, "xray-client", obj{"log": xrayLog(), "inbounds": []obj{socks}, "outbounds": []obj{{
							"protocol": "vless", "settings": obj{"vnext": []obj{{"address": "127.0.0.1", "port": sport, "users": []obj{{"id": id, "encryption": enc}}}}},
							"streamSettings": obj{"network": "xdrive", "xdriveSettings": xrayOpts}, "mux": obj{"enabled": true, "concurrency": 8, "xudpConcurrency": 8, "xudpProxyUDP443": "allow"},
						}}}, clientPort)
					}
					checkTraffic(t, clientPort)
					checkUDP(t, clientPort)
					for i := 0; i < 16; i++ {
						t.Run(fmt.Sprintf("concurrent-%02d", i), func(t *testing.T) { t.Parallel(); checkTraffic(t, clientPort) })
					}
				})
			}
		}
	}
}

func xdriveStorage(t *testing.T, backend string) (obj, obj) {
	t.Helper()
	folder := t.TempDir()
	c := obj{"service": backend, "remote-folder": folder, "segment-bytes": 65536, "flush-interval-ms": 5, "poll-interval-ms": 5, "max-poll-interval-ms": 20}
	x := obj{"service": backend, "remoteFolder": folder, "segmentBytes": 65536, "flushIntervalMs": 5, "pollIntervalMs": 5, "maxPollIntervalMs": 20}
	if backend == "template" {
		var mu sync.Mutex
		objects := make(map[string][]byte)
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			name := strings.TrimPrefix(r.URL.Path, "/objects/")
			switch r.Method {
			case "PUT":
				b, err := io.ReadAll(r.Body)
				if err != nil {
					http.Error(w, err.Error(), 400)
					return
				}
				mu.Lock()
				objects[name] = b
				mu.Unlock()
				w.WriteHeader(201)
			case "GET":
				mu.Lock()
				b, ok := objects[name]
				mu.Unlock()
				if !ok {
					w.WriteHeader(404)
					return
				}
				w.Write(b)
			case "DELETE":
				mu.Lock()
				for key := range objects {
					if key == name || strings.HasPrefix(key, name+"~") {
						delete(objects, key)
					}
				}
				mu.Unlock()
				w.WriteHeader(204)
			case "PROPFIND":
				mu.Lock()
				defer mu.Unlock()
				for key := range objects {
					fmt.Fprintf(w, "<key>%s</key>\n", key)
				}
			default:
				w.WriteHeader(405)
			}
		}))
		t.Cleanup(server.Close)
		tmpl := obj{"flatten": true, "put": obj{"method": "PUT", "url": server.URL + "/objects/{name}"}, "get": obj{"method": "GET", "url": server.URL + "/objects/{name}"}, "delete": obj{"method": "DELETE", "url": server.URL + "/objects/{name}"}, "list": obj{"method": "PROPFIND", "url": server.URL + "/objects/", "namesRegex": "<key>([^<]+)</key>"}}
		c["template"], x["template"] = tmpl, tmpl
	}
	return c, x
}
