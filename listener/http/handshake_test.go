package http

import (
	"bufio"
	"io"
	"net"
	"testing"
	"time"

	C "github.com/metacubex/mihomo/constant"
	authStore "github.com/metacubex/mihomo/listener/auth"

	"github.com/metacubex/http"
	"github.com/stretchr/testify/require"
)

func shortHandshakeTimeout(t *testing.T, d time.Duration) {
	old := authStore.HandshakeTimeout
	authStore.HandshakeTimeout = d
	t.Cleanup(func() { authStore.HandshakeTimeout = old })
}

// echoAfterIdleTunnel idles past the handshake timeout, then echoes 5 bytes.
type echoAfterIdleTunnel struct{ idle time.Duration }

func (tt echoAfterIdleTunnel) HandleTCPConn(conn net.Conn, metadata *C.Metadata) {
	defer conn.Close()
	time.Sleep(tt.idle)
	b := make([]byte, 5)
	if _, err := io.ReadFull(conn, b); err != nil {
		return
	}
	_, _ = conn.Write(b)
}

func (tt echoAfterIdleTunnel) HandleUDPPacket(packet C.UDPPacket, metadata *C.Metadata) {}

func (tt echoAfterIdleTunnel) NatTable() C.NatTable { return nil }

func serveHTTPOnce(t *testing.T, tunnel C.Tunnel) (net.Conn, <-chan struct{}) {
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
		HandleConn(c, tunnel, authStore.Nil)
	}()
	client, err := net.Dial("tcp", ln.Addr().String())
	require.NoError(t, err)
	t.Cleanup(func() { _ = client.Close() })
	return client, done
}

func TestHTTPSilentClientTimesOut(t *testing.T) {
	shortHandshakeTimeout(t, 100*time.Millisecond)
	for _, partial := range []string{"", "CONNECT example.com:443 HTTP/1.1\r\n"} {
		client, done := serveHTTPOnce(t, echoAfterIdleTunnel{})
		if partial != "" {
			_, err := io.WriteString(client, partial) // an unfinished header, then nothing
			require.NoError(t, err)
		}
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Fatal("a client that sends no complete request is never dropped")
		}
	}
}

func TestHTTPConnectOutlivesHandshakeTimeout(t *testing.T) {
	shortHandshakeTimeout(t, 100*time.Millisecond)
	client, _ := serveHTTPOnce(t, echoAfterIdleTunnel{idle: 400 * time.Millisecond})

	_, err := io.WriteString(client, "CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n")
	require.NoError(t, err)
	br := bufio.NewReader(client)
	resp, err := http.ReadResponse(br, &http.Request{Method: http.MethodConnect})
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode)

	time.Sleep(300 * time.Millisecond) // idle well past the handshake timeout
	_, err = client.Write([]byte("hello"))
	require.NoError(t, err)
	_ = client.SetReadDeadline(time.Now().Add(5 * time.Second))
	b := make([]byte, 5)
	_, err = io.ReadFull(br, b)
	require.NoError(t, err)
	require.Equal(t, "hello", string(b))
}
