package trusttunnel

import (
	"context"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/metacubex/mihomo/transport/v2ray"
)

// silentFirstDialer sends the first dial to a listener that accepts TCP and
// never answers the TLS handshake, and every later dial to the real server.
type silentFirstDialer struct {
	silent string
	dials  atomic.Int64
}

func (d *silentFirstDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	if d.dials.Add(1) == 1 {
		address = d.silent
	}
	var dialer net.Dialer
	return dialer.DialContext(ctx, network, address)
}

func (d *silentFirstDialer) ListenPacket(ctx context.Context, network, address string, rAddrPort netip.AddrPort) (net.PacketConn, error) {
	var config net.ListenConfig
	return config.ListenPacket(ctx, network, address)
}

// startSilentListener accepts connections and holds them open without
// reading or writing, like a server that took TCP and stalled.
func startSilentListener(t *testing.T) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	var conns []net.Conn
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			mu.Lock()
			conns = append(conns, conn)
			mu.Unlock()
		}
	}()
	t.Cleanup(func() {
		_ = listener.Close()
		mu.Lock()
		defer mu.Unlock()
		for _, conn := range conns {
			_ = conn.Close()
		}
	})
	return listener.Addr().String()
}

// With one connection per client, every stream of a cold client waits for
// the one dial. A server that accepts TCP and never finishes TLS must fail
// that dial within the timeout and leave the slot free for a fresh one.
func TestClientDialTimesOutOnSilentServer(t *testing.T) {
	server := startConnectServer(t)
	dialer := &silentFirstDialer{silent: startSilentListener(t)}
	client, err := NewPoolClient(context.Background(), ClientOptions{
		Dialer:           dialer,
		Server:           server.Listener.Addr().String(),
		Username:         "user",
		Password:         "password",
		TLSConfig:        &v2ray.TLSConfig{Host: "example.com", SkipCertVerify: true},
		MaxConnections:   1,
		HandshakeTimeout: 300 * time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	start := time.Now()
	conn, err := client.Dial(ctx, "example.org:443")
	cancel()
	if err == nil {
		_ = conn.Close()
		t.Fatal("dial through a silent server succeeded")
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Fatalf("dial through a silent server failed after %v, want about the 300ms timeout", elapsed)
	}

	ctx, cancel = context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err = client.Dial(ctx, "example.org:443")
	if err != nil {
		t.Fatalf("dial after the timeout: %v (dials=%d)", err, dialer.dials.Load())
	}
	_ = conn.Close()
	if got := dialer.dials.Load(); got != 2 {
		t.Fatalf("dials = %d, want 2: the silent one and a fresh one", got)
	}
}
