package trusttunnel

import (
	"context"
	"io"
	"log"
	"net"
	stdhttp "net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/metacubex/mihomo/transport/v2ray"
)

// freezeProxy forwards TCP to target. freeze stops the connections open at
// that moment from moving data without closing them, like a path that went
// silent; connections made afterwards pass normally.
type freezeProxy struct {
	listener net.Listener
	target   string

	mu    sync.Mutex
	cond  *sync.Cond
	pairs []*freezePair
}

type freezePair struct {
	frozen bool
	conns  [2]net.Conn
}

func startFreezeProxy(t *testing.T, target string) *freezeProxy {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	p := &freezeProxy{listener: listener, target: target}
	p.cond = sync.NewCond(&p.mu)
	go p.serve()
	t.Cleanup(p.close)
	return p
}

func (p *freezeProxy) serve() {
	for {
		client, err := p.listener.Accept()
		if err != nil {
			return
		}
		server, err := net.Dial("tcp", p.target)
		if err != nil {
			_ = client.Close()
			continue
		}
		pair := &freezePair{conns: [2]net.Conn{client, server}}
		p.mu.Lock()
		p.pairs = append(p.pairs, pair)
		p.mu.Unlock()
		go p.pipe(pair, server, client)
		go p.pipe(pair, client, server)
	}
}

func (p *freezeProxy) pipe(pair *freezePair, dst, src net.Conn) {
	buf := make([]byte, 32*1024)
	for {
		n, err := src.Read(buf)
		p.mu.Lock()
		for pair.frozen {
			p.cond.Wait()
		}
		p.mu.Unlock()
		if n > 0 {
			if _, werr := dst.Write(buf[:n]); werr != nil {
				return
			}
		}
		if err != nil {
			_ = dst.Close()
			return
		}
	}
}

func (p *freezeProxy) setFrozen(frozen bool) {
	p.mu.Lock()
	for _, pair := range p.pairs {
		pair.frozen = frozen
	}
	p.mu.Unlock()
	p.cond.Broadcast()
}

func (p *freezeProxy) close() {
	_ = p.listener.Close()
	p.setFrozen(false)
	p.mu.Lock()
	for _, pair := range p.pairs {
		_ = pair.conns[0].Close()
		_ = pair.conns[1].Close()
	}
	p.mu.Unlock()
}

// startEchoServer answers CONNECT with 200 and echoes the stream back.
func startEchoServer(t *testing.T) *httptest.Server {
	t.Helper()
	server := httptest.NewUnstartedServer(stdhttp.HandlerFunc(func(writer stdhttp.ResponseWriter, request *stdhttp.Request) {
		if request.Method != stdhttp.MethodConnect {
			writer.WriteHeader(stdhttp.StatusMethodNotAllowed)
			return
		}
		writer.WriteHeader(stdhttp.StatusOK)
		flusher := writer.(stdhttp.Flusher)
		flusher.Flush()
		buf := make([]byte, 32*1024)
		for {
			n, err := request.Body.Read(buf)
			if n > 0 {
				if _, werr := writer.Write(buf[:n]); werr != nil {
					return
				}
				flusher.Flush()
			}
			if err != nil {
				return
			}
		}
	}))
	server.EnableHTTP2 = true
	server.Config.ErrorLog = log.New(io.Discard, "", 0)
	server.StartTLS()
	t.Cleanup(server.Close)
	return server
}

func newProxiedClient(t *testing.T, address string, pingInterval, pingTimeout time.Duration) (*PoolClient, *countingDialer) {
	t.Helper()
	dialer := &countingDialer{}
	client, err := NewPoolClient(context.Background(), ClientOptions{
		Dialer:         dialer,
		Server:         address,
		Username:       "user",
		Password:       "password",
		TLSConfig:      &v2ray.TLSConfig{Host: "example.com", SkipCertVerify: true},
		MaxConnections: 1,
		PingInterval:   pingInterval,
		PingTimeout:    pingTimeout,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })
	return client, dialer
}

func echoOnce(t *testing.T, conn net.Conn, message string) {
	t.Helper()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	defer func() { _ = conn.SetDeadline(time.Time{}) }()
	if _, err := conn.Write([]byte(message)); err != nil {
		t.Fatalf("write: %v", err)
	}
	buf := make([]byte, len(message))
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(buf) != message {
		t.Fatalf("echo %q, want %q", buf, message)
	}
}

// A session that stops answering is closed by the ping, its stream fails and
// the next stream gets a new connection.
func TestClientClosesSilentSession(t *testing.T) {
	server := startEchoServer(t)
	proxy := startFreezeProxy(t, server.Listener.Addr().String())
	client, dialer := newProxiedClient(t, proxy.listener.Addr().String(), 200*time.Millisecond, 300*time.Millisecond)

	conn, err := client.Dial(context.Background(), "example.org:443")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	echoOnce(t, conn, "before")

	proxy.setFrozen(true)
	frozenAt := time.Now()
	failed := make(chan error, 1)
	go func() {
		_, err := conn.Read(make([]byte, 1))
		failed <- err
	}()
	select {
	case err := <-failed:
		if err == nil {
			t.Fatal("read on a dead session returned no error")
		}
		// ping interval + ping timeout is 0.5s; allow for slow CI runners.
		if elapsed := time.Since(frozenAt); elapsed > 2*time.Second {
			t.Fatalf("dead session closed after %v, want about 0.5s", elapsed)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("dead session was not closed")
	}

	next, err := client.Dial(context.Background(), "example.org:443")
	if err != nil {
		t.Fatal(err)
	}
	defer next.Close()
	echoOnce(t, next, "after")
	if got := dialer.dials.Load(); got != 2 {
		t.Fatalf("got %d connections, want a second one after the dead session", got)
	}
}

// A pause shorter than the ping timeout must not cost the session.
func TestClientKeepsSessionThroughShortPause(t *testing.T) {
	server := startEchoServer(t)
	proxy := startFreezeProxy(t, server.Listener.Addr().String())
	client, dialer := newProxiedClient(t, proxy.listener.Addr().String(), 200*time.Millisecond, 2*time.Second)

	conn, err := client.Dial(context.Background(), "example.org:443")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	echoOnce(t, conn, "before")

	proxy.setFrozen(true)
	time.Sleep(700 * time.Millisecond) // a ping goes out and waits
	proxy.setFrozen(false)
	time.Sleep(300 * time.Millisecond)

	echoOnce(t, conn, "after")
	if got := dialer.dials.Load(); got != 1 {
		t.Fatalf("got %d connections, want the session kept", got)
	}
}
