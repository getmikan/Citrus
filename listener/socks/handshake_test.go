package socks

import (
	"io"
	"net"
	"testing"
	"time"

	C "github.com/metacubex/mihomo/constant"
	authStore "github.com/metacubex/mihomo/listener/auth"
	"github.com/metacubex/mihomo/transport/socks5"

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

// serveSocksOnce accepts one TCP connection and hands it to handleSocks.
func serveSocksOnce(t *testing.T, tunnel C.Tunnel) (net.Conn, <-chan struct{}) {
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
		handleSocks(c, tunnel, authStore.Nil)
	}()
	client, err := net.Dial("tcp", ln.Addr().String())
	require.NoError(t, err)
	t.Cleanup(func() { _ = client.Close() })
	return client, done
}

func TestSocksSilentClientTimesOut(t *testing.T) {
	shortHandshakeTimeout(t, 100*time.Millisecond)
	for _, greeting := range [][]byte{nil, {socks5.Version}} {
		client, done := serveSocksOnce(t, echoAfterIdleTunnel{})
		if greeting != nil {
			_, err := client.Write(greeting) // a partial greeting, then nothing
			require.NoError(t, err)
		}
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Fatal("a client that sends no complete request is never dropped")
		}
	}
}

func TestSocksTunnelOutlivesHandshakeTimeout(t *testing.T) {
	shortHandshakeTimeout(t, 100*time.Millisecond)
	client, _ := serveSocksOnce(t, echoAfterIdleTunnel{idle: 400 * time.Millisecond})

	_, err := socks5.ClientHandshake(client, socks5.ParseAddr("example.com:80"), socks5.CmdConnect, nil)
	require.NoError(t, err)

	time.Sleep(300 * time.Millisecond) // idle well past the handshake timeout
	_, err = client.Write([]byte("hello"))
	require.NoError(t, err)
	_ = client.SetReadDeadline(time.Now().Add(5 * time.Second))
	b := make([]byte, 5)
	_, err = io.ReadFull(client, b)
	require.NoError(t, err)
	require.Equal(t, "hello", string(b))
}
