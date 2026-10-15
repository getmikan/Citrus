package trusttunnel

import (
	"context"
	"io"
	"log"
	"net"
	stdhttp "net/http"
	"net/http/httptest"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/metacubex/mihomo/transport/v2ray"
)

type countingDialer struct {
	dials atomic.Int64
}

func (d *countingDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	d.dials.Add(1)
	var dialer net.Dialer
	return dialer.DialContext(ctx, network, address)
}

func (d *countingDialer) ListenPacket(ctx context.Context, network, address string, rAddrPort netip.AddrPort) (net.PacketConn, error) {
	var config net.ListenConfig
	return config.ListenPacket(ctx, network, address)
}

// startConnectServer answers every CONNECT with 200 and keeps the stream open
// until the client closes it.
func startConnectServer(t *testing.T) *httptest.Server {
	t.Helper()
	server := httptest.NewUnstartedServer(stdhttp.HandlerFunc(func(writer stdhttp.ResponseWriter, request *stdhttp.Request) {
		if request.Method != stdhttp.MethodConnect {
			writer.WriteHeader(stdhttp.StatusMethodNotAllowed)
			return
		}
		writer.WriteHeader(stdhttp.StatusOK)
		writer.(stdhttp.Flusher).Flush()
		_, _ = io.Copy(io.Discard, request.Body)
	}))
	server.EnableHTTP2 = true
	server.Config.ErrorLog = log.New(io.Discard, "", 0)
	server.StartTLS()
	t.Cleanup(server.Close)
	return server
}

func newCountingClient(t *testing.T, server *httptest.Server, maxConnections int) (*PoolClient, *countingDialer) {
	t.Helper()
	dialer := &countingDialer{}
	client, err := NewPoolClient(context.Background(), ClientOptions{
		Dialer:         dialer,
		Server:         server.Listener.Addr().String(),
		Username:       "user",
		Password:       "password",
		TLSConfig:      &v2ray.TLSConfig{Host: "example.com", SkipCertVerify: true},
		MaxConnections: maxConnections,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })
	return client, dialer
}

func dialConcurrently(t *testing.T, client *PoolClient, n int) []net.Conn {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	conns := make([]net.Conn, n)
	errs := make([]error, n)
	var wg sync.WaitGroup
	for i := range conns {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			conns[i], errs[i] = client.Dial(ctx, "example.org:443")
		}(i)
	}
	wg.Wait()
	for i, err := range errs {
		if err != nil {
			t.Fatalf("dial %d: %v", i, err)
		}
	}
	t.Cleanup(func() {
		for _, conn := range conns {
			_ = conn.Close()
		}
	})
	return conns
}

// One client must mean one TLS connection: concurrent streams on a cold
// client wait for the first HTTP/2 session instead of each dialing their own.
func TestClientConcurrentDialsShareConnection(t *testing.T) {
	server := startConnectServer(t)
	client, dialer := newCountingClient(t, server, 1)
	dialConcurrently(t, client, 20)
	if got := dialer.dials.Load(); got != 1 {
		t.Fatalf("20 concurrent streams with max-connections 1 opened %d connections, want 1", got)
	}
}

// After the server drops the connection the client must dial again rather
// than wait forever for a slot held by the dead connection.
func TestClientRedialsAfterConnectionLoss(t *testing.T) {
	server := startConnectServer(t)
	client, dialer := newCountingClient(t, server, 1)
	dialConcurrently(t, client, 5)
	server.CloseClientConnections()

	deadline := time.Now().Add(5 * time.Second)
	for {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		conn, err := client.Dial(ctx, "example.org:443")
		cancel()
		if err == nil {
			_ = conn.Close()
			if dialer.dials.Load() >= 2 {
				return
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("no new connection after loss: dials=%d, last error: %v", dialer.dials.Load(), err)
		}
		time.Sleep(50 * time.Millisecond)
	}
}
