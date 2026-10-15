package shadowsocks

import (
	"errors"
	"io"
	"net"
	"os"
	"testing"
	"time"

	"github.com/metacubex/mihomo/adapter/inbound"
	C "github.com/metacubex/mihomo/constant"
	authStore "github.com/metacubex/mihomo/listener/auth"
	LC "github.com/metacubex/mihomo/listener/config"
	"github.com/metacubex/mihomo/transport/shadowsocks/core"
	"github.com/metacubex/mihomo/transport/socks5"
)

// testHandshakeTimeout replaces the handshake deadline for the whole
// package, before any listener goroutine starts (a per-test change would race
// with the goroutines of the previous test).
const testHandshakeTimeout = 300 * time.Millisecond

func TestMain(m *testing.M) {
	authStore.HandshakeTimeout = testHandshakeTimeout
	os.Exit(m.Run())
}

// echoAfterIdleTunnel idles past the handshake timeout, then echoes 5 bytes.
type echoAfterIdleTunnel struct {
	idle time.Duration
}

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

func serve(t *testing.T, idle time.Duration) net.Conn {
	t.Helper()
	l, err := New(LC.ShadowsocksServer{Listen: "127.0.0.1:0", Cipher: "aes-128-gcm", Password: "password"},
		inbound.NewListenConfig(), echoAfterIdleTunnel{idle: idle}, inbound.WithInName("test"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.Close() })
	client, err := net.Dial("tcp", l.AddrList()[0].String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })
	return client
}

func TestShadowsocksHandshakeTimeoutSilentClient(t *testing.T) {
	client := serve(t, 0)
	_ = client.SetReadDeadline(time.Now().Add(5 * time.Second))
	_, err := client.Read(make([]byte, 1))
	if errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatal("server kept the unauthenticated conn open")
	}
	if err == nil {
		t.Fatal("server sent data to an unauthenticated client")
	}
}

func TestShadowsocksHandshakeDeadlineClearedAfterRequest(t *testing.T) {
	timeout := testHandshakeTimeout
	client := serve(t, 4*timeout)
	cipher, err := core.PickCipher("aes-128-gcm", nil, "password")
	if err != nil {
		t.Fatal(err)
	}
	conn := cipher.StreamConn(client)
	if _, err := conn.Write(socks5.ParseAddr("1.2.3.4:80")); err != nil {
		t.Fatal(err)
	}
	time.Sleep(4 * timeout)
	if _, err := conn.Write([]byte("hello")); err != nil {
		t.Fatal(err)
	}
	_ = client.SetReadDeadline(time.Now().Add(5 * time.Second))
	resp := make([]byte, 5)
	if _, err := io.ReadFull(conn, resp); err != nil {
		t.Fatalf("authenticated idle session was cut: %v", err)
	}
	if string(resp) != "hello" {
		t.Fatalf("unexpected response %q", resp)
	}
}
