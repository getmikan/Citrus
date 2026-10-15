package sing_vless

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"os"
	"testing"
	"time"

	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/transport/vless"

	"github.com/gofrs/uuid/v5"
	"github.com/metacubex/sing-vmess"
	M "github.com/metacubex/sing/common/metadata"
	N "github.com/metacubex/sing/common/network"
)

const testUUID = "b831381d-6324-4d53-ad4f-8cda48b30811"

// shortHandshakeTimeout shortens handshakeTimeout for one test.
func shortHandshakeTimeout(t *testing.T, d time.Duration) {
	old := handshakeTimeout.Load()
	handshakeTimeout.Store(d)
	t.Cleanup(func() { handshakeTimeout.Store(old) })
}

type echoAfterIdleHandler struct {
	idle time.Duration
}

// NewConnection idles past the handshake timeout, then echoes what it reads.
func (h echoAfterIdleHandler) NewConnection(ctx context.Context, conn net.Conn, metadata M.Metadata) error {
	defer conn.Close()
	time.Sleep(h.idle)
	b := make([]byte, 5)
	if _, err := io.ReadFull(conn, b); err != nil {
		return err
	}
	_, err := conn.Write(b)
	return err
}

func (h echoAfterIdleHandler) NewPacketConnection(ctx context.Context, conn N.PacketConn, metadata M.Metadata) error {
	return conn.Close()
}

func (h echoAfterIdleHandler) NewError(ctx context.Context, err error) {}

// serveVlessOnce accepts one TCP connection and serves it with l.serveConn.
func serveVlessOnce(t *testing.T, l *Listener) net.Conn {
	t.Helper()
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

func newTestVlessListener(idle time.Duration) *Listener {
	service := NewService(echoAfterIdleHandler{idle: idle}, []C.InboundUser{{Name: "test", Secret: testUUID}})
	return &Listener{service: service}
}

func vlessRequestHeader(t *testing.T) []byte {
	t.Helper()
	var b bytes.Buffer
	b.WriteByte(vless.Version)
	id := uuid.FromStringOrNil(testUUID)
	b.Write(id[:])
	b.WriteByte(0) // no addons
	b.WriteByte(vless.CommandTCP)
	if err := vmess.AddressSerializer.WriteAddrPort(&b, M.ParseSocksaddrHostPort("1.2.3.4", 80)); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

// expectClosedWithin asserts the server closes client within limit.
func expectClosedWithin(t *testing.T, client net.Conn, limit time.Duration) {
	t.Helper()
	start := time.Now()
	_ = client.SetReadDeadline(time.Now().Add(limit))
	_, err := client.Read(make([]byte, 1))
	if errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("server kept the unauthenticated conn open for %v", limit)
	}
	if err == nil {
		t.Fatal("server sent data to an unauthenticated client")
	}
	t.Logf("closed after %v: %v", time.Since(start), err)
}

func TestVlessHandshakeTimeoutSilentClient(t *testing.T) {
	shortHandshakeTimeout(t, 200*time.Millisecond)
	client := serveVlessOnce(t, newTestVlessListener(0))
	expectClosedWithin(t, client, 5*time.Second)
}

func TestVlessHandshakeTimeoutTricklingClient(t *testing.T) {
	shortHandshakeTimeout(t, 300*time.Millisecond)
	client := serveVlessOnce(t, newTestVlessListener(0))
	header := vlessRequestHeader(t)
	go func() {
		// one byte every 50ms: each read makes progress, the header never ends in time
		for _, c := range header[:len(header)-1] {
			if _, err := client.Write([]byte{c}); err != nil {
				return
			}
			time.Sleep(50 * time.Millisecond)
		}
	}()
	expectClosedWithin(t, client, 5*time.Second)
}

func TestVlessHandshakeDeadlineClearedAfterAuth(t *testing.T) {
	timeout := 200 * time.Millisecond
	shortHandshakeTimeout(t, timeout)
	client := serveVlessOnce(t, newTestVlessListener(4*timeout))
	if _, err := client.Write(vlessRequestHeader(t)); err != nil {
		t.Fatal(err)
	}
	// idle well past the handshake timeout on both sides
	time.Sleep(4 * timeout)
	if _, err := client.Write([]byte("hello")); err != nil {
		t.Fatal(err)
	}
	_ = client.SetReadDeadline(time.Now().Add(5 * time.Second))
	resp := make([]byte, 2+5)
	if _, err := io.ReadFull(client, resp); err != nil {
		t.Fatalf("authenticated idle session was cut: %v", err)
	}
	if !bytes.Equal(resp, []byte{vless.Version, 0, 'h', 'e', 'l', 'l', 'o'}) {
		t.Fatalf("unexpected response %q", resp)
	}
}
