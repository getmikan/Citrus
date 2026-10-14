package snell

import (
	"errors"
	"io"
	"net"
	"os"
	"testing"
	"time"

	C "github.com/metacubex/mihomo/constant"
	authStore "github.com/metacubex/mihomo/listener/auth"
	LC "github.com/metacubex/mihomo/listener/config"
	"github.com/metacubex/mihomo/transport/snell"
)

const testPSK = "psk"

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

func serveSnellOnce(t *testing.T, version int, obfsMode string, idle time.Duration) net.Conn {
	t.Helper()
	l := &Listener{config: LC.SnellServer{Psk: testPSK, Version: version, ObfsMode: obfsMode}}
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
		l.HandleConn(c, echoAfterIdleTunnel{idle: idle})
	}()
	client, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })
	return client
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

func TestSnellHandshakeTimeoutSilentClient(t *testing.T) {
	for _, obfsMode := range []string{"", "http", "tls"} {
		t.Run("obfs="+obfsMode, func(t *testing.T) {
			client := serveSnellOnce(t, snell.Version4, obfsMode, 0)
			expectClosedWithin(t, client, 5*time.Second)
		})
	}
}

func TestSnellHandshakeTimeoutTrickle(t *testing.T) {
	client := serveSnellOnce(t, snell.Version3, "", 0)
	// a byte now and then never completes the header: the deadline is
	// absolute, so trickling does not extend it
	done := make(chan struct{})
	defer close(done)
	go func() {
		for {
			select {
			case <-done:
				return
			case <-time.After(200 * time.Millisecond):
				if _, err := client.Write([]byte{0}); err != nil {
					return
				}
			}
		}
	}()
	expectClosedWithin(t, client, 5*time.Second)
}

func TestSnellHandshakeDeadlineClearedAfterRequest(t *testing.T) {
	for _, version := range []int{snell.Version1, snell.Version3, snell.Version4, snell.Version5} {
		t.Run(string(rune('0'+version)), func(t *testing.T) {
			timeout := testHandshakeTimeout
			client := serveSnellOnce(t, version, "", 4*timeout)
			stream := snell.StreamConn(client, []byte(testPSK), version)
			if err := snell.WriteHeader(stream, "1.2.3.4", 80, version); err != nil {
				t.Fatal(err)
			}
			time.Sleep(4 * timeout)
			if _, err := stream.Write([]byte("hello")); err != nil {
				t.Fatal(err)
			}
			_ = client.SetReadDeadline(time.Now().Add(5 * time.Second))
			resp := make([]byte, 5)
			if _, err := io.ReadFull(stream, resp); err != nil {
				t.Fatalf("authenticated idle session was cut: %v", err)
			}
			if string(resp) != "hello" {
				t.Fatalf("unexpected response %q", resp)
			}
		})
	}
}
