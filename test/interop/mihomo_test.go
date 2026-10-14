//go:build interop

package interop

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// Upstream mihomo client -> Citrus server: the clients the panel's users run
// (Mikan, ClashFest, Clash Verge and the like) embed an upstream mihomo release,
// so every inbound Citrus serves is checked against a release binary of it.
//
// Not tested, because Citrus has removed them on the server side: VMess, SSR,
// Hysteria v1, TUIC v4, Shadowsocks stream ciphers, v2ray-plugin and mKCP.

func needMihomo(t *testing.T) {
	t.Helper()
	if mihomoBin == "" {
		t.Skip("MIHOMO_BIN is not set")
	}
}

const ctlSecret = "interop-secret"

// mihomoCase is one row of the matrix: a Citrus listener and the upstream
// mihomo proxy that should reach it.
type mihomoCase struct {
	name   string
	server obj  // Citrus listener (name, listen and port are filled in)
	client obj  // upstream mihomo proxy (name, server and port are filled in)
	udp    bool // also check UDP through the tunnel
	// user, when set, must have the traffic in /traffic/users; decoy, another
	// user of the same inbound, must not
	user, decoy string
	// blocked: the client is expected to be refused (a negative control)
	blocked bool
}

func TestMihomoClientCitrusServer(t *testing.T) {
	needMihomo(t)
	reality, mldsaSeed := genX25519Go(t), randB64URL(t, 32)
	idA, idB := genUUIDGo(t), genUUIDGo(t)
	ss128 := func() string { return randB64(t, 16) }
	ssI, ssA, ssB, ssSingle := ss128(), ss128(), ss128(), ss128()
	pwA, pwB := token(), token()
	tls := obj{"certificate": string(tlsCertPEM), "private-key": string(tlsKeyPEM)}
	clientTLS := obj{"fingerprint": tlsCertSHA256}

	vlessUsers := func(flow string) []obj {
		return []obj{
			{"username": "alice", "uuid": idA, "flow": flow},
			{"username": "bob", "uuid": idB, "flow": flow},
		}
	}
	realityServer := func(extra obj) obj {
		rc := obj{
			"dest": targetAddr, "private-key": reality.priv, "short-id": []string{shortID},
			"server-names": []string{realitySNI},
		}
		return obj{"type": "vless", "users": vlessUsers("xtls-rprx-vision"), "reality-config": merge(rc, extra)}
	}
	realityClient := func(extra obj) obj {
		ro := obj{"public-key": reality.pub, "short-id": shortID}
		return obj{
			"type": "vless", "uuid": idA, "flow": "xtls-rprx-vision", "network": "tcp", "udp": true,
			"tls": true, "servername": realitySNI, "client-fingerprint": "chrome",
			"reality-opts": merge(ro, extra),
		}
	}
	vlessTLSClient := func(network string, extra obj) obj {
		return merge(obj{
			"type": "vless", "uuid": idA, "network": network, "udp": true,
			"tls": true, "servername": realitySNI,
		}, clientTLS, extra)
	}

	cases := []mihomoCase{
		// --- VLESS + REALITY + vision ---
		{name: "vless-reality-vision", server: realityServer(nil), client: realityClient(nil),
			udp: true, user: "alice", decoy: "bob"},
		{name: "vless-reality-vision-client-mlkem", server: realityServer(nil),
			client: realityClient(obj{"support-x25519mlkem768": true}), udp: true},
		// classic X25519 client against a server that signs with ML-DSA-65
		{name: "vless-reality-vision-pq-server", server: realityServer(obj{"mldsa65-seed": mldsaSeed}),
			client: realityClient(nil), udp: true},
		{name: "vless-reality-vision-pq-server-client-mlkem", server: realityServer(obj{"mldsa65-seed": mldsaSeed}),
			client: realityClient(obj{"support-x25519mlkem768": true}), udp: true},
		// a server that requires X25519MLKEM768 lets in only the client that offers it
		{name: "vless-reality-require-mlkem-client-mlkem",
			server: realityServer(obj{"mldsa65-seed": mldsaSeed, "require-x25519mlkem768": true}),
			client: realityClient(obj{"support-x25519mlkem768": true})},
		{name: "vless-reality-require-mlkem-client-classic",
			server: realityServer(obj{"require-x25519mlkem768": true}),
			client: realityClient(nil), blocked: true},

		// --- VLESS over TLS transports ---
		{name: "vless-xhttp-stream-one-tls",
			server: merge(obj{"type": "vless", "users": vlessUsers(""), "xhttp-config": obj{"path": "/xh", "mode": "auto"}}, tls),
			client: vlessTLSClient("xhttp", obj{"alpn": []string{"h2"}, "xhttp-opts": obj{"path": "/xh", "mode": "stream-one"}}),
			udp:    true},
		{name: "vless-xhttp-packet-up-tls",
			server: merge(obj{"type": "vless", "users": vlessUsers(""), "xhttp-config": obj{"path": "/xh", "mode": "auto"}}, tls),
			client: vlessTLSClient("xhttp", obj{"alpn": []string{"h2"}, "xhttp-opts": obj{"path": "/xh", "mode": "packet-up"}}),
			udp:    true},
		{name: "vless-xhttp-packet-up-tls-http1",
			server: merge(obj{"type": "vless", "users": vlessUsers(""), "xhttp-config": obj{"path": "/xh", "mode": "auto"}}, tls),
			client: vlessTLSClient("xhttp", obj{"alpn": []string{"http/1.1"}, "xhttp-opts": obj{"path": "/xh", "mode": "packet-up"}}),
			udp:    true},
		{name: "vless-ws-tls",
			server: merge(obj{"type": "vless", "users": vlessUsers(""), "ws-path": "/ws"}, tls),
			client: vlessTLSClient("ws", obj{"ws-opts": obj{"path": "/ws"}}), udp: true},
		{name: "vless-grpc-tls",
			server: merge(obj{"type": "vless", "users": vlessUsers(""), "grpc-service-name": "gs"}, tls),
			client: vlessTLSClient("grpc", obj{"grpc-opts": obj{"grpc-service-name": "gs"}}), udp: true},
		{name: "vless-vision-tls",
			server: merge(obj{"type": "vless", "users": vlessUsers("xtls-rprx-vision")}, tls),
			client: vlessTLSClient("tcp", obj{"flow": "xtls-rprx-vision", "client-fingerprint": "chrome"}), udp: true},

		// --- Trojan ---
		{name: "trojan-tls",
			server: merge(obj{"type": "trojan", "users": []obj{{"username": "alice", "password": pwA}, {"username": "bob", "password": pwB}}}, tls),
			client: merge(obj{"type": "trojan", "password": pwA, "sni": realitySNI, "udp": true}, clientTLS),
			udp:    true, user: "alice", decoy: "bob"},

		// --- Shadowsocks 2022 ---
		{name: "ss2022-single-user",
			server: obj{"type": "shadowsocks", "cipher": "2022-blake3-aes-128-gcm", "password": ssSingle, "udp": true},
			client: obj{"type": "ss", "cipher": "2022-blake3-aes-128-gcm", "password": ssSingle, "udp": true},
			udp:    true},
		{name: "ss2022-multi-user-eih",
			server: obj{"type": "shadowsocks", "cipher": "2022-blake3-aes-128-gcm", "password": ssI, "udp": true,
				"users": []obj{{"name": "alice", "password": ssA}, {"name": "bob", "password": ssB}}},
			client: obj{"type": "ss", "cipher": "2022-blake3-aes-128-gcm", "password": ssI + ":" + ssA, "udp": true},
			udp:    true, user: "alice", decoy: "bob"},

		// --- QUIC ---
		{name: "hysteria2",
			server: merge(obj{"type": "hysteria2", "users": obj{"alice": pwA, "bob": pwB}}, tls),
			client: merge(obj{"type": "hysteria2", "password": pwA, "sni": realitySNI, "udp": true}, clientTLS),
			udp:    true, user: "alice", decoy: "bob"},
		{name: "tuic-v5",
			server: merge(obj{"type": "tuic", "users": obj{idA: pwA, idB: pwB}, "alpn": []string{"h3"}}, tls),
			client: merge(obj{"type": "tuic", "uuid": idA, "password": pwA, "sni": realitySNI, "alpn": []string{"h3"}, "udp": true}, clientTLS),
			udp:    true},

		// --- AnyTLS ---
		{name: "anytls",
			server: merge(obj{"type": "anytls", "users": obj{"alice": pwA, "bob": pwB}}, tls),
			client: merge(obj{"type": "anytls", "password": pwA, "sni": realitySNI, "udp": true}, clientTLS),
			udp:    true},

		// --- TrustTunnel ---
		{name: "trusttunnel-h2",
			server: merge(obj{"type": "trusttunnel", "users": []obj{{"username": "alice", "password": pwA}}}, tls),
			client: merge(obj{"type": "trusttunnel", "username": "alice", "password": pwA, "sni": realitySNI, "udp": true}, clientTLS),
			udp:    true},
		{name: "trusttunnel-quic",
			server: merge(obj{"type": "trusttunnel", "users": []obj{{"username": "alice", "password": pwA}}, "network": []string{"udp"}}, tls),
			client: merge(obj{"type": "trusttunnel", "username": "alice", "password": pwA, "sni": realitySNI, "udp": true, "quic": true}, clientTLS),
			udp:    true},

		// --- Snell (the client defaults to v1, the server to v4: set both) ---
		{name: "snell-v3",
			server: obj{"type": "snell", "psk": pwA, "version": 3, "udp": true},
			client: obj{"type": "snell", "psk": pwA, "version": 3, "udp": true}, udp: true},
		{name: "snell-v4",
			server: obj{"type": "snell", "psk": pwA, "version": 4, "udp": true},
			client: obj{"type": "snell", "psk": pwA, "version": 4, "udp": true}, udp: true},
		{name: "snell-v5",
			server: obj{"type": "snell", "psk": pwA, "version": 5, "udp": true},
			client: obj{"type": "snell", "psk": pwA, "version": 5, "udp": true}, udp: true},

		// --- Mieru ---
		{name: "mieru-tcp",
			server: obj{"type": "mieru", "transport": "TCP", "users": obj{"alice": pwA}},
			client: obj{"type": "mieru", "transport": "TCP", "username": "alice", "password": pwA, "udp": true},
			udp:    true},
		{name: "mieru-udp",
			server: obj{"type": "mieru", "transport": "UDP", "users": obj{"alice": pwA}},
			client: obj{"type": "mieru", "transport": "UDP", "username": "alice", "password": pwA, "udp": true},
			udp:    true},

		// --- Sudoku ---
		{name: "sudoku",
			server: obj{"type": "sudoku", "key": pwA},
			client: obj{"type": "sudoku", "key": pwA, "udp": true}, udp: true},

		// --- plain proxies with auth ---
		{name: "http-auth",
			server: obj{"type": "http", "users": []obj{{"username": "alice", "password": pwA}}},
			client: obj{"type": "http", "username": "alice", "password": pwA}},
		{name: "socks5-auth",
			server: obj{"type": "socks", "udp": true, "users": []obj{{"username": "alice", "password": pwA}}},
			client: obj{"type": "socks5", "username": "alice", "password": pwA, "udp": true}, udp: true},
		{name: "mixed-auth-as-http",
			server: obj{"type": "mixed", "udp": true, "users": []obj{{"username": "alice", "password": pwA}}},
			client: obj{"type": "http", "username": "alice", "password": pwA}},
		{name: "mixed-auth-as-socks5",
			server: obj{"type": "mixed", "udp": true, "users": []obj{{"username": "alice", "password": pwA}}},
			client: obj{"type": "socks5", "username": "alice", "password": pwA, "udp": true}, udp: true},
		{name: "socks5-wrong-password",
			server: obj{"type": "socks", "users": []obj{{"username": "alice", "password": pwA}}},
			client: obj{"type": "socks5", "username": "alice", "password": pwB}, blocked: true},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) { runMihomoCase(t, c) })
	}
}

func runMihomoCase(t *testing.T, c mihomoCase) {
	sport, ctl := freePort(t), freePort(t)
	listener := merge(obj{"name": "in", "listen": "127.0.0.1", "port": sport}, c.server)
	srv := citrusServer(listener)
	srv["external-controller"] = fmt.Sprintf("127.0.0.1:%d", ctl)
	srv["secret"] = ctlSecret
	// the listener may be UDP only: wait for the controller, startCitrus then
	// waits until the listeners are up
	srvLog := startCitrus(t, "citrus-server", srv, ctl)

	mp := freePort(t)
	proxy := merge(obj{"server": "127.0.0.1", "port": sport}, c.client)
	startMihomo(t, citrusClient(mp, proxy), mp)

	// the server's own log proves the traffic went through its inbound
	udpSeen := "--> " + udpEchoAddr
	if c.blocked {
		checkBlocked(t, mp)
		if logHas(srvLog, "--> "+echoAddr) {
			t.Fatalf("the server relayed traffic of a client it should refuse")
		}
		return
	}
	checkTraffic(t, mp)
	if !logHas(srvLog, "--> "+echoAddr) {
		t.Fatalf("the server never relayed the TCP traffic: it went around the tunnel")
	}
	if c.udp {
		checkUDP(t, mp)
		waitLog(t, srvLog, udpSeen)
		if !logHas(srvLog, "[UDP] ") {
			t.Fatalf("the server never relayed the UDP traffic as UDP")
		}
	}
	if c.user != "" {
		checkUserStats(t, ctl, "in", c.user, c.decoy)
	}
}

// startMihomo writes cfg and runs the upstream mihomo binary; waits for port.
func startMihomo(t *testing.T, cfg obj, port int) {
	t.Helper()
	dir := caseDir(t, "mihomo-client")
	p := filepath.Join(dir, "config.yaml")
	writeJSON(t, p, cfg)
	logPath := start(t, "mihomo-client", mihomoBin, "-d", dir, "-f", p)
	waitPort(t, port)
	waitLog(t, logPath, "Start initial compatible provider")
	time.Sleep(300 * time.Millisecond)
}

func logHas(path, s string) bool {
	b, err := os.ReadFile(path)
	return err == nil && strings.Contains(string(b), s)
}

func merge(maps ...obj) obj {
	out := obj{}
	for _, m := range maps {
		for k, v := range m {
			out[k] = v
		}
	}
	return out
}

// --- keys, without xray ------------------------------------------------------

func genX25519Go(t *testing.T) x25519Keys {
	t.Helper()
	k, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	enc := base64.RawURLEncoding
	return x25519Keys{priv: enc.EncodeToString(k.Bytes()), pub: enc.EncodeToString(k.PublicKey().Bytes())}
}

func genUUIDGo(t *testing.T) string {
	b := make([]byte, 16)
	rand.Read(b)
	b[6] = b[6]&0x0f | 0x40
	b[8] = b[8]&0x3f | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:])
}

func randB64(t *testing.T, n int) string {
	b := make([]byte, n)
	rand.Read(b)
	return base64.StdEncoding.EncodeToString(b)
}

func randB64URL(t *testing.T, n int) string {
	b := make([]byte, n)
	rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

// --- UDP through a SOCKS5 UDP ASSOCIATE ---------------------------------------

// checkUDP sends datagrams of a few sizes to the UDP echo server through the
// socks5 port of the client and expects each one back. A datagram may be lost
// (the tunnel is set up by the first one), so each is retried.
func checkUDP(t *testing.T, port int) {
	t.Helper()
	ctrl, relay := socksUDPAssociate(t, port)
	defer ctrl.Close()
	uc, err := net.DialUDP("udp", nil, relay)
	if err != nil {
		t.Fatal(err)
	}
	defer uc.Close()

	dst, err := net.ResolveUDPAddr("udp", udpEchoAddr)
	if err != nil {
		t.Fatal(err)
	}
	hdr := []byte{0, 0, 0, 1}
	hdr = append(hdr, dst.IP.To4()...)
	hdr = binary.BigEndian.AppendUint16(hdr, uint16(dst.Port))

	buf := make([]byte, 64*1024)
	for _, size := range []int{16, 512, 1200} {
		payload := make([]byte, size)
		rand.Read(payload)
		pkt := append(append([]byte{}, hdr...), payload...)
		ok := false
		for attempt := 0; attempt < 8 && !ok; attempt++ {
			if _, err := uc.Write(pkt); err != nil {
				t.Fatalf("UDP write: %v", err)
			}
			deadline := time.Now().Add(1500 * time.Millisecond)
			for !ok {
				uc.SetReadDeadline(deadline)
				n, err := uc.Read(buf)
				if err != nil {
					break
				}
				if body, err := socksUDPBody(buf[:n]); err == nil && bytes.Equal(body, payload) {
					ok = true
				}
			}
		}
		if !ok {
			t.Fatalf("UDP echo of %d bytes: no reply through the tunnel", size)
		}
	}
}

func socksUDPAssociate(t *testing.T, port int) (net.Conn, *net.UDPAddr) {
	t.Helper()
	c, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	c.SetDeadline(time.Now().Add(10 * time.Second))
	fatal := func(format string, args ...any) {
		c.Close()
		t.Fatalf(format, args...)
	}
	if _, err := c.Write([]byte{5, 1, 0}); err != nil {
		fatal("socks greeting: %v", err)
	}
	r := make([]byte, 2)
	if _, err := io.ReadFull(c, r); err != nil || r[1] != 0 {
		fatal("socks greeting reply %v: %v", r, err)
	}
	if _, err := c.Write([]byte{5, 3, 0, 1, 0, 0, 0, 0, 0, 0}); err != nil {
		fatal("socks UDP ASSOCIATE: %v", err)
	}
	head := make([]byte, 4)
	if _, err := io.ReadFull(c, head); err != nil || head[1] != 0 {
		fatal("socks UDP ASSOCIATE reply %v: %v", head, err)
	}
	var ip net.IP
	switch head[3] {
	case 1:
		ip = make(net.IP, 4)
	case 4:
		ip = make(net.IP, 16)
	default:
		fatal("socks UDP ASSOCIATE reply address type %d", head[3])
	}
	if _, err := io.ReadFull(c, ip); err != nil {
		fatal("socks UDP ASSOCIATE reply: %v", err)
	}
	pb := make([]byte, 2)
	if _, err := io.ReadFull(c, pb); err != nil {
		fatal("socks UDP ASSOCIATE reply: %v", err)
	}
	c.SetDeadline(time.Time{})
	if ip.IsUnspecified() {
		ip = net.IPv4(127, 0, 0, 1)
	}
	return c, &net.UDPAddr{IP: ip, Port: int(binary.BigEndian.Uint16(pb))}
}

func socksUDPBody(p []byte) ([]byte, error) {
	if len(p) < 4 {
		return nil, io.ErrUnexpectedEOF
	}
	n := 4
	switch p[3] {
	case 1:
		n += 4
	case 4:
		n += 16
	case 3:
		if len(p) < 5 {
			return nil, io.ErrUnexpectedEOF
		}
		n += 1 + int(p[4])
	default:
		return nil, fmt.Errorf("address type %d", p[3])
	}
	n += 2
	if len(p) < n {
		return nil, io.ErrUnexpectedEOF
	}
	return p[n:], nil
}

// --- per-user statistics on the server ----------------------------------------

type userStat struct {
	Inbound string `json:"inbound"`
	User    string `json:"user"`
	Up      int64  `json:"up"`
	Down    int64  `json:"down"`
	Conns   int64  `json:"conns"`
}

// checkUserStats expects user of inbound to have at least the 256 KiB POST of
// checkTraffic as upload, some download, and decoy (when set) nothing.
func checkUserStats(t *testing.T, ctl int, inbound, user, decoy string) {
	t.Helper()
	const minUp = 256 * 1024
	var last []userStat
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		last = fetchUserStats(t, ctl)
		var got *userStat
		for i := range last {
			s := &last[i]
			if s.Inbound != inbound {
				continue
			}
			if s.User == decoy && decoy != "" && (s.Up > 0 || s.Down > 0 || s.Conns > 0) {
				t.Fatalf("traffic counted for %q, the user that sent nothing: %+v", decoy, *s)
			}
			if s.User == user {
				got = s
			}
		}
		if got != nil && got.Up >= minUp && got.Down > 0 {
			t.Logf("stats for %s/%s: up %d, down %d, conns %d", inbound, user, got.Up, got.Down, got.Conns)
			return
		}
		time.Sleep(250 * time.Millisecond)
	}
	b, _ := json.Marshal(last)
	t.Fatalf("no traffic counted for %s/%s (want up >= %d): %s", inbound, user, minUp, b)
}

func fetchUserStats(t *testing.T, ctl int) []userStat {
	t.Helper()
	req, _ := http.NewRequest(http.MethodGet, "http://127.0.0.1:"+strconv.Itoa(ctl)+"/traffic/users", nil)
	req.Header.Set("Authorization", "Bearer "+ctlSecret)
	resp, err := (&http.Client{Timeout: 5 * time.Second}).Do(req)
	if err != nil {
		t.Fatalf("GET /traffic/users: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /traffic/users: %d %s", resp.StatusCode, body)
	}
	var stats []userStat
	if err := json.Unmarshal(body, &stats); err != nil {
		t.Fatalf("GET /traffic/users: %v: %s", err, body)
	}
	return stats
}
