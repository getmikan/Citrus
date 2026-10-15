package route

import (
	"bufio"
	"fmt"
	"io"
	stdnet "net"
	stdhttp "net/http"
	"strings"
	"testing"
	"time"

	"github.com/metacubex/mihomo/config"

	"github.com/metacubex/http"
	"github.com/metacubex/http/httptest"
)

func TestIsLoopbackAddr(t *testing.T) {
	for addr, want := range map[string]bool{
		"127.0.0.1:9090":   true,
		"127.0.0.53:9090":  true,
		"[::1]:9090":       true,
		"localhost:9090":   true,
		"LOCALHOST:9090":   true,
		"0.0.0.0:9090":     false,
		":9090":            false,
		"[::]:9090":        false,
		"192.168.1.1:9090": false,
		"example.com:9090": false,
		"127.0.0.1":        false, // not host:port
	} {
		if got := isLoopbackAddr(addr); got != want {
			t.Errorf("isLoopbackAddr(%q) = %v, want %v", addr, got, want)
		}
	}
}

func TestConfigValidate(t *testing.T) {
	for _, tc := range []struct {
		name string
		cfg  Config
		ok   bool
	}{
		{"no controller", Config{}, true},
		{"loopback without secret", Config{Addr: "127.0.0.1:9090", TLSAddr: "[::1]:9443"}, true},
		{"unix and pipe without secret", Config{UnixAddr: "c.sock", PipeAddr: `\\.\pipe\c`}, true},
		{"all interfaces without secret", Config{Addr: "0.0.0.0:9090"}, false},
		{"port only without secret", Config{Addr: ":9090"}, false},
		{"all interfaces with secret", Config{Addr: "0.0.0.0:9090", Secret: testSecret}, true},
		{"all interfaces, allow-insecure", Config{Addr: "0.0.0.0:9090", AllowInsecure: true}, true},
		{"tls without secret", Config{TLSAddr: "0.0.0.0:9443"}, false},
		{"tls verify-if-given without secret", Config{TLSAddr: "0.0.0.0:9443", ClientAuthType: "verify-if-given", ClientAuthCert: "ca.crt"}, false},
		{"tls require-and-verify without secret", Config{TLSAddr: "0.0.0.0:9443", ClientAuthType: "require-and-verify", ClientAuthCert: "ca.crt"}, true},
		{"tls client-auth-cert without secret", Config{TLSAddr: "0.0.0.0:9443", ClientAuthCert: "ca.crt"}, true},
	} {
		err := tc.cfg.Validate()
		if (err == nil) != tc.ok {
			t.Errorf("%s: Validate() = %v, want ok=%v", tc.name, err, tc.ok)
		}
	}
}

func guardStatus(h http.Handler, host, origin, token string) int {
	req := httptest.NewRequest(http.MethodGet, "/version", nil)
	req.Host = host
	if origin != "" {
		req.Header.Set("Origin", origin)
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec.Code
}

func TestBrowserGuard(t *testing.T) {
	wildcard := Cors{AllowOrigins: []string{"*"}, AllowPrivateNetwork: true}
	h := newNetworkHandler(&Config{Cors: wildcard})
	for _, tc := range []struct {
		host, origin string
		want         int
	}{
		{"127.0.0.1:9090", "", http.StatusOK},
		{"localhost:9090", "", http.StatusOK},
		{"[::1]:9090", "", http.StatusOK},
		{"rebind.example.com:9090", "", http.StatusForbidden},
		{"127.0.0.1:9090", "https://evil.example.com", http.StatusForbidden},
		{"127.0.0.1:9090", "null", http.StatusForbidden},
		{"127.0.0.1:9090", "http://127.0.0.1:9090", http.StatusOK},
		{"localhost:9090", "http://LOCALHOST:9090", http.StatusOK},
		{"127.0.0.1:9090", "http://127.0.0.1:8080", http.StatusForbidden},
	} {
		if got := guardStatus(h, tc.host, tc.origin, ""); got != tc.want {
			t.Errorf("host %q origin %q: got %d, want %d", tc.host, tc.origin, got, tc.want)
		}
	}

	listed := Cors{AllowOrigins: []string{"*", "https://board.example.com"}}
	h = newNetworkHandler(&Config{Cors: listed})
	if got := guardStatus(h, "127.0.0.1:9090", "https://board.example.com", ""); got != http.StatusOK {
		t.Errorf("listed origin: got %d, want 200", got)
	}

	// A secret replaces the guard: the bearer token is the protection.
	h = newNetworkHandler(&Config{Secret: testSecret, Cors: wildcard})
	if got := guardStatus(h, "node.example.com:9090", "https://evil.example.com", testSecret); got != http.StatusOK {
		t.Errorf("with secret: got %d, want 200", got)
	}
	// So does the explicit opt-out.
	h = newNetworkHandler(&Config{AllowInsecure: true, Cors: wildcard})
	if got := guardStatus(h, "node.example.com:9090", "https://evil.example.com", ""); got != http.StatusOK {
		t.Errorf("allow-insecure: got %d, want 200", got)
	}
	// The local transports are not reachable by a browser and keep no guard.
	h = newHandler(&Config{Cors: wildcard})
	if got := guardStatus(h, "unix", "https://evil.example.com", ""); got != http.StatusOK {
		t.Errorf("local handler: got %d, want 200", got)
	}
}

func TestConnectionsIntervalRejectedBeforeUpgrade(t *testing.T) {
	for _, interval := range []string{"0", "-5", "abc", "99999999999999999999", "3600001"} {
		req := httptest.NewRequest(http.MethodGet, "/connections?interval="+interval, nil)
		req.Header.Set("Upgrade", "websocket")
		req.Header.Set("Connection", "Upgrade")
		req.Header.Set("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==")
		req.Header.Set("Sec-WebSocket-Version", "13")
		rec := httptest.NewRecorder()
		getConnections(rec, req)
		if rec.Code != http.StatusBadRequest {
			t.Errorf("interval %q: got %d, want 400", interval, rec.Code)
		}
	}
}

func TestControllerServerTimeouts(t *testing.T) {
	s := newServer(http.NotFoundHandler())
	if s.ReadHeaderTimeout <= 0 || s.IdleTimeout <= 0 || s.MaxHeaderBytes <= 0 {
		t.Fatalf("server limits not set: %+v", s)
	}
}

func freeLoopbackAddr(t *testing.T) string {
	t.Helper()
	l, err := stdnet.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := l.Addr().String()
	_ = l.Close()
	return addr
}

func tokenStatus(t *testing.T, addr, token string) int {
	t.Helper()
	client := &stdhttp.Client{Timeout: 5 * time.Second, Transport: &stdhttp.Transport{DisableKeepAlives: true}}
	req, _ := stdhttp.NewRequest(stdhttp.MethodGet, "http://"+addr+"/version", nil)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("GET /version: %v", err)
	}
	_ = resp.Body.Close()
	return resp.StatusCode
}

func openLogsStream(t *testing.T, addr, token string) stdnet.Conn {
	t.Helper()
	conn, err := stdnet.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = fmt.Fprintf(conn, "GET /logs HTTP/1.1\r\nHost: %s\r\nAuthorization: Bearer %s\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n", addr, token)
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	status, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil || !strings.Contains(status, "101") {
		t.Fatalf("websocket upgrade: %q, %v", status, err)
	}
	return conn
}

func TestReCreateServerAppliesSecretRotation(t *testing.T) {
	addr := freeLoopbackAddr(t)
	t.Cleanup(func() {
		ReCreateServer(&Config{})
		serverMu.Lock()
		applied = nil
		serverMu.Unlock()
	})

	ReCreateServer(&Config{Addr: addr, Secret: "old"})
	if code := tokenStatus(t, addr, "old"); code != http.StatusOK {
		t.Fatalf("old secret before rotation: got %d", code)
	}
	stream := openLogsStream(t, addr, "old")
	defer stream.Close()

	// The same configuration again (a reload that keeps the controller as it
	// is) leaves the listener and its streams alone.
	ReCreateServer(&Config{Addr: addr, Secret: "old"})
	_ = stream.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
	if _, err := stream.Read(make([]byte, 1)); err == nil || !isTimeout(err) {
		t.Fatalf("stream after an unchanged reload: %v, want a read timeout", err)
	}

	ReCreateServer(&Config{Addr: addr, Secret: "new"})
	if code := tokenStatus(t, addr, "old"); code != http.StatusUnauthorized {
		t.Errorf("old secret after rotation: got %d, want 401", code)
	}
	if code := tokenStatus(t, addr, "new"); code != http.StatusOK {
		t.Errorf("new secret after rotation: got %d, want 200", code)
	}
	_ = stream.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := io.ReadAll(stream); err != nil && isTimeout(err) {
		t.Errorf("log stream of the old secret still open after rotation")
	}
}

func isTimeout(err error) bool {
	var ne stdnet.Error
	if e, ok := err.(stdnet.Error); ok {
		ne = e
	}
	return ne != nil && ne.Timeout()
}

func TestReCreateServerRefusesInsecure(t *testing.T) {
	t.Cleanup(func() {
		ReCreateServer(&Config{})
		serverMu.Lock()
		applied = nil
		serverMu.Unlock()
	})
	ReCreateServer(&Config{Addr: "0.0.0.0:0"})
	serverMu.Lock()
	started := httpServer != nil
	serverMu.Unlock()
	if started {
		t.Fatal("controller on all interfaces without a secret was started")
	}
}

func TestUpdateConfigsRefusedController(t *testing.T) {
	prev := loadControllerReloader()
	t.Cleanup(func() { SetControllerReloader(prev) })
	called := false
	SetControllerReloader(func(cfg *config.Config) (func(), error) {
		called = true
		return nil, fmt.Errorf("refused")
	})

	body := `{"payload": "mixed-port: 0\nrules:\n  - MATCH,DIRECT\n"}`
	req := httptest.NewRequest(http.MethodPut, "/configs", strings.NewReader(body))
	rec := httptest.NewRecorder()
	updateConfigs(rec, req)
	if !called {
		t.Fatal("controller reloader not consulted")
	}
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "refused") {
		t.Fatalf("got %d %q, want 400 with the reason", rec.Code, rec.Body.String())
	}
}
