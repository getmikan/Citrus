//go:build interop

package interop

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"sync"
	"testing"
	"time"
)

// sing-box against Citrus. A large share of the apps people connect with are
// built on sing-box (SFA/SFI, Hiddify, NekoBox, sing-box for Desktop), so every
// inbound those apps can reach is checked with a sing-box release as the
// client, and two of the protocols the other way round, with sing-box as the
// server.
//
// Not tested: VMess, which Citrus has removed on the server side.

func needSingbox(t *testing.T) {
	t.Helper()
	if singboxBin == "" {
		t.Skip("SINGBOX_BIN is not set")
	}
}

// startSingbox writes cfg and runs sing-box. It returns once sing-box reports
// that every inbound and outbound has started, with the path of its log.
func startSingbox(t *testing.T, role string, cfg obj) string {
	t.Helper()
	dir := caseDir(t, role)
	p := filepath.Join(dir, "config.json")
	writeJSON(t, p, cfg)
	// a config the release does not accept fails here with the reason, rather
	// than as a process that never reports it started
	if out, err := exec.Command(singboxBin, "check", "-c", p, "-D", dir).CombinedOutput(); err != nil {
		t.Fatalf("sing-box check %s: %v\n%s", role, err, out)
	}
	logPath := start(t, role, singboxBin, "run", "-c", p, "-D", dir)
	waitLog(t, logPath, "sing-box started")
	return logPath
}

// singboxClient is a sing-box config with a socks/http mixed port on mixedPort
// and every connection sent to out.
func singboxClient(mixedPort int, out obj) obj {
	out["tag"] = "out"
	return obj{
		"log":       obj{"level": "debug", "timestamp": true},
		"inbounds":  []obj{{"type": "mixed", "tag": "in", "listen": "127.0.0.1", "listen_port": mixedPort}},
		"outbounds": []obj{out},
		"route":     obj{"final": "out"},
	}
}

func singboxServer(in obj) obj {
	in["tag"] = "in"
	return obj{
		"log":       obj{"level": "debug", "timestamp": true},
		"inbounds":  []obj{in},
		"outbounds": []obj{{"type": "direct", "tag": "direct"}},
		"route":     obj{"final": "direct"},
	}
}

func runSingboxCase(t *testing.T, c serverCase) {
	runServerCase(t, c, func(t *testing.T, sport, mp int) {
		out := merge(obj{"server": "127.0.0.1", "server_port": sport}, c.client)
		startSingbox(t, "singbox-client", singboxClient(mp, out))
		waitPort(t, mp)
	})
}

// --- sing-box client -> Citrus server ----------------------------------------

func TestSingboxClientCitrusServer(t *testing.T) {
	needSingbox(t)
	reality, wrongReality := genX25519Go(t), genX25519Go(t)
	idA, idB := genUUIDGo(t), genUUIDGo(t)
	ss128 := func() string { return randB64(t, 16) }
	ssI, ssA, ssB, ssSingle := ss128(), ss128(), ss128(), ss128()
	pwA, pwB := token(), token()
	tls := obj{"certificate": string(tlsCertPEM), "private-key": string(tlsKeyPEM)}
	// sing-box pins by the whole chain it is given: the self-signed leaf
	clientTLS := func(extra obj) obj {
		return merge(obj{"enabled": true, "server_name": realitySNI, "certificate": string(tlsCertPEM)}, extra)
	}
	chrome := obj{"utls": obj{"enabled": true, "fingerprint": "chrome"}}

	vlessUsers := func(flow string) []obj {
		return []obj{
			{"username": "alice", "uuid": idA, "flow": flow},
			{"username": "bob", "uuid": idB, "flow": flow},
		}
	}
	realityServer := obj{"type": "vless", "users": vlessUsers("xtls-rprx-vision"), "reality-config": obj{
		"dest": targetAddr, "private-key": reality.priv, "short-id": []string{shortID},
		"server-names": []string{realitySNI},
	}}
	realityClient := func(pub string) obj {
		return obj{
			"type": "vless", "uuid": idA, "flow": "xtls-rprx-vision",
			"tls": merge(obj{"enabled": true, "server_name": realitySNI,
				"reality": obj{"enabled": true, "public_key": pub, "short_id": shortID}}, chrome),
		}
	}

	cases := []serverCase{
		// --- VLESS ---
		{name: "vless-reality-vision", server: realityServer, client: realityClient(reality.pub),
			udp: true, user: "alice", decoy: "bob"},
		{name: "vless-reality-wrong-public-key", server: realityServer, client: realityClient(wrongReality.pub),
			blocked: true},
		{name: "vless-tcp-tls",
			server: merge(obj{"type": "vless", "users": vlessUsers("")}, tls),
			client: obj{"type": "vless", "uuid": idA, "tls": clientTLS(nil)},
			udp:    true, user: "alice", decoy: "bob"},
		{name: "vless-vision-tls",
			server: merge(obj{"type": "vless", "users": vlessUsers("xtls-rprx-vision")}, tls),
			client: obj{"type": "vless", "uuid": idA, "flow": "xtls-rprx-vision", "tls": clientTLS(chrome)},
			udp:    true},

		// --- Trojan ---
		{name: "trojan-tls",
			server: merge(obj{"type": "trojan", "users": []obj{{"username": "alice", "password": pwA}, {"username": "bob", "password": pwB}}}, tls),
			client: obj{"type": "trojan", "password": pwA, "tls": clientTLS(nil)},
			udp:    true, user: "alice", decoy: "bob"},

		// --- Shadowsocks 2022 ---
		{name: "ss2022-single-user",
			server: obj{"type": "shadowsocks", "cipher": "2022-blake3-aes-128-gcm", "password": ssSingle, "udp": true},
			client: obj{"type": "shadowsocks", "method": "2022-blake3-aes-128-gcm", "password": ssSingle},
			udp:    true},
		{name: "ss2022-multi-user-eih",
			server: obj{"type": "shadowsocks", "cipher": "2022-blake3-aes-128-gcm", "password": ssI, "udp": true,
				"users": []obj{{"name": "alice", "password": ssA}, {"name": "bob", "password": ssB}}},
			client: obj{"type": "shadowsocks", "method": "2022-blake3-aes-128-gcm", "password": ssI + ":" + ssA},
			udp:    true, user: "alice", decoy: "bob"},

		// --- QUIC ---
		{name: "hysteria2",
			server: merge(obj{"type": "hysteria2", "users": obj{"alice": pwA, "bob": pwB}}, tls),
			client: obj{"type": "hysteria2", "password": pwA, "tls": clientTLS(obj{"alpn": []string{"h3"}})},
			udp:    true, user: "alice", decoy: "bob"},
		{name: "hysteria2-wrong-password",
			server:  merge(obj{"type": "hysteria2", "users": obj{"alice": pwA}}, tls),
			client:  obj{"type": "hysteria2", "password": pwB, "tls": clientTLS(obj{"alpn": []string{"h3"}})},
			blocked: true},
		{name: "tuic-v5",
			server: merge(obj{"type": "tuic", "users": obj{idA: pwA, idB: pwB}, "alpn": []string{"h3"}}, tls),
			client: obj{"type": "tuic", "uuid": idA, "password": pwA, "tls": clientTLS(obj{"alpn": []string{"h3"}})},
			udp:    true},

		// --- AnyTLS ---
		{name: "anytls",
			server: merge(obj{"type": "anytls", "users": obj{"alice": pwA, "bob": pwB}}, tls),
			client: obj{"type": "anytls", "password": pwA, "tls": clientTLS(nil)},
			udp:    true, user: "alice", decoy: "bob"},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) { runSingboxCase(t, c) })
	}
}

// --- TUIC: many streams on one QUIC connection -------------------------------

// The Citrus TUIC server grants 2048 bidirectional streams per QUIC connection
// (listener/tuic.ServerMaxIncomingStreams), one per TCP relay. The sing-box
// client keeps every relay on a single connection and opens its streams
// without waiting for the server's MAX_STREAMS credit, so past 2048 concurrent
// relays its new connections fail instead of queueing: sing-box 1.14.4 logs
// "open connection ... using outbound/tuic[out]: too many open streams" for
// exactly the relays above 2048 (see the roadmap, "The TUIC stream limit"). Below the limit everything has to work; the case past
// it documents the known break and runs only when INTEROP_TUIC_OVER_LIMIT is
// set, so that it can be reproduced and turned on once the limit is settled.
const tuicStreamLimit = 2048

func TestSingboxClientCitrusServerTUICStreams(t *testing.T) {
	needSingbox(t)
	t.Run("under-limit", func(t *testing.T) { runTUICStreams(t, tuicStreamLimit/2) })
	t.Run("over-limit", func(t *testing.T) {
		if os.Getenv("INTEROP_TUIC_OVER_LIMIT") == "" {
			t.Skipf("known issue: a sing-box TUIC client fails past %d concurrent streams; "+
				"set INTEROP_TUIC_OVER_LIMIT=1 to run", tuicStreamLimit)
		}
		runTUICStreams(t, tuicStreamLimit+64)
	})
}

// runTUICStreams holds n TCP relays open at once through a sing-box TUIC
// client and a Citrus TUIC server, then checks that each of them still carries
// data both ways.
func runTUICStreams(t *testing.T, n int) {
	id, pw := genUUIDGo(t), token()
	sport, ctl := freePort(t), freePort(t)
	srv := citrusServer(obj{
		"name": "in", "type": "tuic", "listen": "127.0.0.1", "port": sport,
		"users": obj{id: pw}, "alpn": []string{"h3"},
		"certificate": string(tlsCertPEM), "private-key": string(tlsKeyPEM),
	})
	// TUIC listens on UDP only: wait for the controller instead
	srv["external-controller"] = fmt.Sprintf("127.0.0.1:%d", ctl)
	srv["secret"] = ctlSecret
	startCitrus(t, "citrus-server", srv, ctl)

	mp := freePort(t)
	startSingbox(t, "singbox-client", singboxClient(mp, obj{
		"type": "tuic", "server": "127.0.0.1", "server_port": sport, "uuid": id, "password": pw,
		"tls": obj{"enabled": true, "server_name": realitySNI, "certificate": string(tlsCertPEM),
			"alpn": []string{"h3"}},
	}))
	waitPort(t, mp)

	conns := make([]net.Conn, n)
	t.Cleanup(func() {
		for _, c := range conns {
			if c != nil {
				resetClose(c)
			}
		}
	})
	// registered after conns: its cleanup runs first and resets the server
	// ends, so that Citrus' dials do not linger in TIME_WAIT either
	echo := startTCPEcho(t)

	// open them all, 32 at a time, each one proven end to end, so that every
	// one holds a stream on the server
	var (
		wg       sync.WaitGroup
		mu       sync.Mutex
		failed   int
		firstErr error
	)
	sem := make(chan struct{}, 32)
	for i := range n {
		wg.Add(1)
		sem <- struct{}{}
		go func() {
			defer wg.Done()
			defer func() { <-sem }()
			c, err := socksConnect(mp, echo)
			if err == nil {
				conns[i] = c
				err = echoRound(c, i, 0)
			}
			if err != nil {
				mu.Lock()
				failed++
				if firstErr == nil {
					firstErr = fmt.Errorf("relay %d: %w", i, err)
				}
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if failed > 0 {
		t.Fatalf("%d of %d concurrent relays failed to open; first: %v", failed, n, firstErr)
	}

	// all n are open now: every one must still work
	for i, c := range conns {
		if err := echoRound(c, i, 1); err != nil {
			t.Fatalf("relay %d of %d with all open: %v", i, n, err)
		}
	}
	t.Logf("%d concurrent relays over one TUIC connection", n)
}

// echoRound writes a line naming relay i and round r and expects it back.
func echoRound(c net.Conn, i, r int) error {
	c.SetDeadline(time.Now().Add(20 * time.Second))
	defer c.SetDeadline(time.Time{})
	msg := []byte("relay " + strconv.Itoa(i) + " round " + strconv.Itoa(r) + "\n")
	if _, err := c.Write(msg); err != nil {
		return err
	}
	got := make([]byte, len(msg))
	if _, err := io.ReadFull(c, got); err != nil {
		return err
	}
	if !bytes.Equal(got, msg) {
		return fmt.Errorf("echo: got %q, want %q", got, msg)
	}
	return nil
}

// resetClose closes c with a reset rather than a FIN: the thousands of sockets
// of a stream test would otherwise sit in TIME_WAIT and use up the ephemeral
// ports of the cases that follow (Windows has 16384 of them).
func resetClose(c net.Conn) {
	if tc, ok := c.(*net.TCPConn); ok {
		tc.SetLinger(0)
	}
	c.Close()
}

// startTCPEcho runs a raw TCP echo server for the test and returns its
// address. When the test ends it resets every connection it accepted.
func startTCPEcho(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var (
		wg       sync.WaitGroup
		mu       sync.Mutex
		accepted []net.Conn
		closed   bool
	)
	t.Cleanup(func() {
		ln.Close()
		mu.Lock()
		closed = true
		for _, c := range accepted {
			resetClose(c)
		}
		mu.Unlock()
		wg.Wait()
	})
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			mu.Lock()
			if closed { // accepted while the cleanup ran
				mu.Unlock()
				resetClose(c)
				return
			}
			accepted = append(accepted, c)
			mu.Unlock()
			wg.Add(1)
			go func() {
				defer wg.Done()
				io.Copy(c, c)
			}()
		}
	}()
	return ln.Addr().String()
}

// socksConnect opens a SOCKS5 CONNECT to the IPv4 address addr through the
// proxy on port.
func socksConnect(port int, addr string) (net.Conn, error) {
	dst, err := net.ResolveTCPAddr("tcp", addr)
	if err != nil {
		return nil, err
	}
	c, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), 5*time.Second)
	if err != nil {
		return nil, err
	}
	fail := func(err error) (net.Conn, error) {
		c.Close()
		return nil, err
	}
	c.SetDeadline(time.Now().Add(20 * time.Second))
	if _, err := c.Write([]byte{5, 1, 0}); err != nil {
		return fail(err)
	}
	r := make([]byte, 2)
	if _, err := io.ReadFull(c, r); err != nil {
		return fail(err)
	}
	if r[1] != 0 {
		return fail(fmt.Errorf("socks greeting reply %v", r))
	}
	req := append([]byte{5, 1, 0, 1}, dst.IP.To4()...)
	req = binary.BigEndian.AppendUint16(req, uint16(dst.Port))
	if _, err := c.Write(req); err != nil {
		return fail(err)
	}
	// VER REP RSV ATYP=1 BND.ADDR(4) BND.PORT(2); a domain or IPv6 reply is
	// longer, which no proxy here sends for an IPv4 request
	head := make([]byte, 10)
	if _, err := io.ReadFull(c, head); err != nil {
		return fail(err)
	}
	if head[1] != 0 {
		return fail(fmt.Errorf("socks CONNECT reply code %d", head[1]))
	}
	if head[3] != 1 {
		return fail(errors.New("socks CONNECT reply with a non-IPv4 bound address"))
	}
	c.SetDeadline(time.Time{})
	return c, nil
}

// --- Citrus client -> sing-box server ----------------------------------------

func TestCitrusClientSingboxServer(t *testing.T) {
	needSingbox(t)
	reality, id, pw := genX25519Go(t), genUUIDGo(t), token()
	targetHost, targetPortStr, err := net.SplitHostPort(targetAddr)
	if err != nil {
		t.Fatal(err)
	}
	targetPort, _ := strconv.Atoi(targetPortStr)

	cases := []struct {
		name   string
		server obj // sing-box inbound (listen and listen_port are filled in)
		client obj // Citrus proxy (server and port are filled in)
		tcp    bool
	}{
		{name: "vless-reality-vision", tcp: true,
			server: obj{"type": "vless", "users": []obj{{"name": "u", "uuid": id, "flow": "xtls-rprx-vision"}},
				"tls": obj{"enabled": true, "server_name": realitySNI, "reality": obj{
					"enabled":     true,
					"handshake":   obj{"server": targetHost, "server_port": targetPort},
					"private_key": reality.priv,
					"short_id":    []string{shortID},
				}}},
			client: obj{"type": "vless", "uuid": id, "flow": "xtls-rprx-vision", "network": "tcp", "udp": true,
				"tls": true, "servername": realitySNI, "client-fingerprint": "chrome",
				"reality-opts": obj{"public-key": reality.pub, "short-id": shortID}}},
		{name: "hysteria2",
			server: obj{"type": "hysteria2", "users": []obj{{"name": "u", "password": pw}},
				"tls": obj{"enabled": true, "alpn": []string{"h3"},
					"certificate": string(tlsCertPEM), "key": string(tlsKeyPEM)}},
			client: obj{"type": "hysteria2", "password": pw, "sni": realitySNI,
				"fingerprint": tlsCertSHA256, "udp": true}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			sport := freePort(t)
			sbLog := startSingbox(t, "singbox-server",
				singboxServer(merge(obj{"listen": "127.0.0.1", "listen_port": sport}, c.server)))
			if c.tcp {
				waitPort(t, sport)
			}
			mp := freePort(t)
			startCitrus(t, "citrus-client",
				citrusClient(mp, merge(obj{"server": "127.0.0.1", "port": sport}, c.client)), mp)
			checkTraffic(t, mp)
			if !logHas(sbLog, echoAddr) {
				t.Fatalf("the sing-box server never relayed the TCP traffic: it went around the tunnel")
			}
			checkUDP(t, mp)
			waitLog(t, sbLog, udpEchoAddr)
		})
	}
}
