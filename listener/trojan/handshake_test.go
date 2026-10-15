package trojan

import (
	"bytes"
	"errors"
	"io"
	"net"
	"os"
	"testing"
	"time"

	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/listener/inbounduser"
	"github.com/metacubex/mihomo/listener/sing"
	"github.com/metacubex/mihomo/transport/socks5"
	"github.com/metacubex/mihomo/transport/trojan"
)

const testPassword = "password"

// shortHandshakeTimeout shortens handshakeTimeout for one test.
func shortHandshakeTimeout(t *testing.T, d time.Duration) {
	old := handshakeTimeout.Load()
	handshakeTimeout.Store(d)
	t.Cleanup(func() { handshakeTimeout.Store(old) })
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

func serveTrojanOnce(t *testing.T, idle time.Duration) net.Conn {
	t.Helper()
	h, err := sing.NewListenerHandler(sing.ListenerConfig{
		Tunnel: echoAfterIdleTunnel{idle: idle},
		Type:   C.TROJAN,
	})
	if err != nil {
		t.Fatal(err)
	}
	l := &Listener{
		users:   testUsers(),
		handler: h,
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		l.serveConn(c, nil, nil)
	}()
	client, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })
	return client
}

func trojanRequestHeader() []byte {
	var b bytes.Buffer
	key := trojan.Key(testPassword)
	b.Write(key[:])
	b.WriteString("\r\n")
	b.WriteByte(trojan.CommandTCP)
	b.Write(socks5.ParseAddr("1.2.3.4:80"))
	b.WriteString("\r\n")
	return b.Bytes()
}

func expectClosedWithin(t *testing.T, client net.Conn, limit time.Duration) {
	t.Helper()
	_ = client.SetReadDeadline(time.Now().Add(limit))
	_, err := client.Read(make([]byte, 1))
	if errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("server kept the unauthenticated conn open for %v", limit)
	}
	if err == nil {
		t.Fatal("server sent data to an unauthenticated client")
	}
}

func TestTrojanHandshakeTimeoutSilentClient(t *testing.T) {
	shortHandshakeTimeout(t, 200*time.Millisecond)
	client := serveTrojanOnce(t, 0)
	expectClosedWithin(t, client, 5*time.Second)
}

func TestTrojanHandshakeTimeoutAfterKey(t *testing.T) {
	shortHandshakeTimeout(t, 200*time.Millisecond)
	client := serveTrojanOnce(t, 0)
	// a valid key, then nothing: the deadline still covers the rest of the header
	header := trojanRequestHeader()
	if _, err := client.Write(header[:trojan.KeyLength+2]); err != nil {
		t.Fatal(err)
	}
	expectClosedWithin(t, client, 5*time.Second)
}

func TestTrojanHandshakeDeadlineClearedAfterHeader(t *testing.T) {
	timeout := 200 * time.Millisecond
	shortHandshakeTimeout(t, timeout)
	client := serveTrojanOnce(t, 4*timeout)
	if _, err := client.Write(trojanRequestHeader()); err != nil {
		t.Fatal(err)
	}
	time.Sleep(4 * timeout)
	if _, err := client.Write([]byte("hello")); err != nil {
		t.Fatal(err)
	}
	_ = client.SetReadDeadline(time.Now().Add(5 * time.Second))
	resp := make([]byte, 5)
	if _, err := io.ReadFull(client, resp); err != nil {
		t.Fatalf("authenticated idle session was cut: %v", err)
	}
	if string(resp) != "hello" {
		t.Fatalf("unexpected response %q", resp)
	}
}

func testUsers() *inbounduser.Set[[trojan.KeyLength]byte] {
	users, _ := inbounduser.New(userKey, []C.InboundUser{{Name: "test", Secret: testPassword}})
	return users
}
