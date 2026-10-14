package http

import (
	"bufio"
	"encoding/base64"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/metacubex/mihomo/component/auth"
	C "github.com/metacubex/mihomo/constant"
	authStore "github.com/metacubex/mihomo/listener/auth"

	"github.com/metacubex/http"
	"github.com/stretchr/testify/require"
)

// originTunnel answers every forwarded request with "ok" and records the
// inbound user of each connection it is handed.
type originTunnel struct {
	mu    sync.Mutex
	users []string
}

func (o *originTunnel) HandleTCPConn(conn net.Conn, metadata *C.Metadata) {
	o.mu.Lock()
	o.users = append(o.users, metadata.InUser)
	o.mu.Unlock()
	defer conn.Close()
	br := bufio.NewReader(conn)
	for {
		req, err := http.ReadRequest(br)
		if err != nil {
			return
		}
		_, _ = io.Copy(io.Discard, req.Body)
		if _, err := io.WriteString(conn, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"); err != nil {
			return
		}
	}
}

func (o *originTunnel) HandleUDPPacket(packet C.UDPPacket, metadata *C.Metadata) {}

func (o *originTunnel) NatTable() C.NatTable { return nil }

func (o *originTunnel) seen() []string {
	o.mu.Lock()
	defer o.mu.Unlock()
	return append([]string(nil), o.users...)
}

func testStore() auth.AuthStore {
	return authStore.NewAuthStore(auth.NewAuthenticator([]auth.AuthUser{
		{User: "alice", Pass: "alice-pw"},
		{User: "bob", Pass: "bob-pw"},
	}))
}

func serveProxy(t *testing.T, store auth.AuthStore, tunnel C.Tunnel) (net.Conn, *bufio.Reader, <-chan struct{}) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = ln.Close() })
	done := make(chan struct{})
	go func() {
		defer close(done)
		c, err := ln.Accept()
		if err != nil {
			return
		}
		HandleConn(c, tunnel, store)
	}()
	client, err := net.Dial("tcp", ln.Addr().String())
	require.NoError(t, err)
	t.Cleanup(func() {
		_ = client.Close()
		<-done // the handler is gone before the next test changes globals
	})
	_ = client.SetDeadline(time.Now().Add(10 * time.Second))
	return client, bufio.NewReader(client), done
}

func basic(user, pass string) string {
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(user+":"+pass))
}

func roundTrip(t *testing.T, client net.Conn, br *bufio.Reader, method, credential string) *http.Response {
	t.Helper()
	target := "http://example.com/"
	if method == http.MethodConnect {
		target = "example.com:443"
	}
	req := method + " " + target + " HTTP/1.1\r\nHost: example.com\r\nProxy-Connection: keep-alive\r\n"
	if credential != "" {
		req += "Proxy-Authorization: " + credential + "\r\n"
	}
	_, err := io.WriteString(client, req+"\r\n")
	require.NoError(t, err)
	resp, err := http.ReadResponse(br, &http.Request{Method: method})
	require.NoError(t, err)
	if method != http.MethodConnect {
		_, _ = io.Copy(io.Discard, resp.Body)
	}
	return resp
}

func requireClosed(t *testing.T, br *bufio.Reader, done <-chan struct{}) {
	t.Helper()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("the connection was kept open")
	}
	_, err := br.ReadByte()
	require.Error(t, err)
}

// A request on a keep-alive connection is not forwarded on the strength of an
// earlier request: without credentials it is asked for them.
func TestHTTPKeepAliveRequestWithoutCredentials(t *testing.T) {
	for _, method := range []string{http.MethodGet, http.MethodConnect} {
		t.Run(method, func(t *testing.T) {
			origin := &originTunnel{}
			client, br, _ := serveProxy(t, testStore(), origin)

			require.Equal(t, http.StatusOK, roundTrip(t, client, br, http.MethodGet, basic("alice", "alice-pw")).StatusCode)
			resp := roundTrip(t, client, br, method, "")
			require.Equal(t, http.StatusProxyAuthRequired, resp.StatusCode)
			require.Equal(t, []string{"alice"}, origin.seen(), "the request without credentials reached the tunnel")
		})
	}
}

// A request with wrong credentials is refused, the connection is closed, and
// the user it named never reaches the tunnel.
func TestHTTPKeepAliveRequestWithWrongCredentials(t *testing.T) {
	for _, method := range []string{http.MethodGet, http.MethodConnect} {
		t.Run(method, func(t *testing.T) {
			origin := &originTunnel{}
			client, br, done := serveProxy(t, testStore(), origin)

			require.Equal(t, http.StatusOK, roundTrip(t, client, br, http.MethodGet, basic("alice", "alice-pw")).StatusCode)
			resp := roundTrip(t, client, br, method, basic("bob", "wrong"))
			require.Equal(t, http.StatusForbidden, resp.StatusCode)
			requireClosed(t, br, done)
			require.Equal(t, []string{"alice"}, origin.seen())
		})
	}
}

// Each request is forwarded as the user it authenticated as.
func TestHTTPKeepAliveUserPerRequest(t *testing.T) {
	origin := &originTunnel{}
	client, br, _ := serveProxy(t, testStore(), origin)

	require.Equal(t, http.StatusOK, roundTrip(t, client, br, http.MethodGet, basic("alice", "alice-pw")).StatusCode)
	require.Equal(t, http.StatusOK, roundTrip(t, client, br, http.MethodGet, basic("bob", "bob-pw")).StatusCode)
	require.Equal(t, []string{"alice", "bob"}, origin.seen())
}

// A browser asks without credentials first, then again with them, on the same
// connection.
func TestHTTPRetryAfterProxyAuthRequired(t *testing.T) {
	origin := &originTunnel{}
	client, br, _ := serveProxy(t, testStore(), origin)

	require.Equal(t, http.StatusProxyAuthRequired, roundTrip(t, client, br, http.MethodGet, "").StatusCode)
	require.Equal(t, http.StatusOK, roundTrip(t, client, br, http.MethodGet, basic("alice", "alice-pw")).StatusCode)
	require.Equal(t, []string{"alice"}, origin.seen())
}

// Without authentication a Proxy-Authorization header names no user.
func TestHTTPUnverifiedUserIgnored(t *testing.T) {
	origin := &originTunnel{}
	client, br, _ := serveProxy(t, authStore.Nil, origin)

	require.Equal(t, http.StatusOK, roundTrip(t, client, br, http.MethodGet, basic("alice", "anything")).StatusCode)
	require.Equal(t, []string{""}, origin.seen())
}

// A header larger than MaxHeaderBytes is refused before it is parsed whole.
func TestHTTPHeaderTooLarge(t *testing.T) {
	origin := &originTunnel{}
	client, br, done := serveProxy(t, testStore(), origin)

	go func() {
		_, _ = io.WriteString(client, "GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\nX-Pad: "+
			strings.Repeat("a", 2*MaxHeaderBytes)+"\r\n\r\n")
	}()
	resp, err := http.ReadResponse(br, nil)
	require.NoError(t, err)
	require.Equal(t, http.StatusRequestHeaderFieldsTooLarge, resp.StatusCode)
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("the connection was kept open")
	}
	require.Empty(t, origin.seen())
}

// A header just under the limit still goes through.
func TestHTTPLargeHeaderUnderLimit(t *testing.T) {
	origin := &originTunnel{}
	client, br, _ := serveProxy(t, authStore.Nil, origin)

	_, err := io.WriteString(client, "GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\nProxy-Connection: keep-alive\r\nX-Pad: "+
		strings.Repeat("a", MaxHeaderBytes-1024)+"\r\n\r\n")
	require.NoError(t, err)
	resp, err := http.ReadResponse(br, nil)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	_, _ = io.Copy(io.Discard, resp.Body)
	// and the limit is armed again for the next request
	require.Equal(t, http.StatusOK, roundTrip(t, client, br, http.MethodGet, "").StatusCode)
}

func useGlobalAuth(t *testing.T, a auth.Authenticator) {
	t.Helper()
	authStore.Default.SetAuthenticator(a)
	t.Cleanup(func() { authStore.Default.SetAuthenticator(nil) })
}

func aliceWith(pass string) auth.Authenticator {
	return auth.NewAuthenticator([]auth.AuthUser{{User: "alice", Pass: pass}, {User: "bob", Pass: "bob-pw"}})
}

// A reload of the global authentication closes the keep-alive connections of
// a re-keyed user and keeps the others.
func TestHTTPGlobalAuthRotation(t *testing.T) {
	useGlobalAuth(t, aliceWith("alice-pw"))
	origin := &originTunnel{}
	alice, aliceBr, aliceDone := serveProxy(t, authStore.Default, origin)
	bob, bobBr, _ := serveProxy(t, authStore.Default, origin)
	require.Equal(t, http.StatusOK, roundTrip(t, alice, aliceBr, http.MethodGet, basic("alice", "alice-pw")).StatusCode)
	require.Equal(t, http.StatusOK, roundTrip(t, bob, bobBr, http.MethodGet, basic("bob", "bob-pw")).StatusCode)

	authStore.Default.SetAuthenticator(aliceWith("alice-new"))
	requireClosed(t, aliceBr, aliceDone)
	require.Equal(t, http.StatusOK, roundTrip(t, bob, bobBr, http.MethodGet, basic("bob", "bob-pw")).StatusCode)
}

// Turning the global authentication on closes the connections that were let
// in without it.
func TestHTTPGlobalAuthTurnedOn(t *testing.T) {
	useGlobalAuth(t, nil)
	origin := &originTunnel{}
	client, br, done := serveProxy(t, authStore.Default, origin)
	require.Equal(t, http.StatusOK, roundTrip(t, client, br, http.MethodGet, "").StatusCode)

	authStore.Default.SetAuthenticator(aliceWith("alice-pw"))
	requireClosed(t, br, done)
}
