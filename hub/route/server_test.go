package route

import (
	"context"
	stdnet "net"
	stdhttp "net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/metacubex/http"
	"github.com/metacubex/http/httptest"
)

const testSecret = "test-secret"

func serveRouter(t *testing.T, h http.Handler, method, path, token string) int {
	t.Helper()
	req := httptest.NewRequest(method, path, nil)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec.Code
}

func TestRouterDebugRequiresSecret(t *testing.T) {
	h := router(true, testSecret, "", Cors{})
	for _, tc := range []struct {
		method, path string
	}{
		{http.MethodGet, "/debug/pprof/"},
		{http.MethodGet, "/debug/pprof/cmdline"},
		{http.MethodPut, "/debug/gc"},
	} {
		if code := serveRouter(t, h, tc.method, tc.path, ""); code != http.StatusUnauthorized {
			t.Errorf("%s %s without token: got %d, want %d", tc.method, tc.path, code, http.StatusUnauthorized)
		}
		if code := serveRouter(t, h, tc.method, tc.path, "wrong"); code != http.StatusUnauthorized {
			t.Errorf("%s %s with wrong token: got %d, want %d", tc.method, tc.path, code, http.StatusUnauthorized)
		}
		if code := serveRouter(t, h, tc.method, tc.path, testSecret); code != http.StatusOK {
			t.Errorf("%s %s with token: got %d, want %d", tc.method, tc.path, code, http.StatusOK)
		}
	}
}

func TestRouterDebugWithoutSecret(t *testing.T) {
	h := router(true, "", "", Cors{})
	if code := serveRouter(t, h, http.MethodGet, "/debug/pprof/", ""); code != http.StatusOK {
		t.Errorf("GET /debug/pprof/ without secret: got %d, want %d", code, http.StatusOK)
	}
	h = router(false, "", "", Cors{})
	if code := serveRouter(t, h, http.MethodGet, "/debug/pprof/", ""); code != http.StatusNotFound {
		t.Errorf("GET /debug/pprof/ without debug: got %d, want %d", code, http.StatusNotFound)
	}
}

func TestNewHandlerUsesSecret(t *testing.T) {
	h := newHandler(&Config{Secret: testSecret})
	if code := serveRouter(t, h, http.MethodGet, "/", ""); code != http.StatusUnauthorized {
		t.Errorf("GET / without token: got %d, want %d", code, http.StatusUnauthorized)
	}
	if code := serveRouter(t, h, http.MethodGet, "/", testSecret); code != http.StatusOK {
		t.Errorf("GET / with token: got %d, want %d", code, http.StatusOK)
	}
	h = newHandler(&Config{})
	if code := serveRouter(t, h, http.MethodGet, "/", ""); code != http.StatusOK {
		t.Errorf("GET / without secret: got %d, want %d", code, http.StatusOK)
	}
}

func TestParseUnixSocketMode(t *testing.T) {
	for in, want := range map[string]os.FileMode{
		"600":   0o600,
		"0600":  0o600,
		"0660":  0o660,
		"0o666": 0o666,
		"777":   0o777,
	} {
		got, err := parseUnixSocketMode(in)
		if err != nil || got != want {
			t.Errorf("parseUnixSocketMode(%q) = %#o, %v; want %#o", in, got, err, want)
		}
	}
	for _, in := range []string{"", "abc", "0888", "1777", "-1"} {
		if _, err := parseUnixSocketMode(in); err == nil {
			t.Errorf("parseUnixSocketMode(%q) expected error", in)
		}
	}

	t.Setenv(UnixSocketModeEnv, "")
	if got := unixSocketMode(); got != 0o600 {
		t.Errorf("default mode = %#o, want 0600", got)
	}
	t.Setenv(UnixSocketModeEnv, "0660")
	if got := unixSocketMode(); got != 0o660 {
		t.Errorf("mode with %s=0660 = %#o, want 0660", UnixSocketModeEnv, got)
	}
	t.Setenv(UnixSocketModeEnv, "bogus")
	if got := unixSocketMode(); got != 0o600 {
		t.Errorf("mode with invalid env = %#o, want 0600", got)
	}
}

// shortTempDir keeps socket paths below the sun_path limit.
func shortTempDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "ct")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return dir
}

// getStatus performs GET / against a controller reachable through dial.
func getStatus(t *testing.T, dial func(ctx context.Context) (stdnet.Conn, error), token string) int {
	t.Helper()
	client := &stdhttp.Client{
		Timeout: 5 * time.Second,
		Transport: &stdhttp.Transport{
			DialContext: func(ctx context.Context, _, _ string) (stdnet.Conn, error) {
				return dial(ctx)
			},
			DisableKeepAlives: true,
		},
	}
	req, err := stdhttp.NewRequest(stdhttp.MethodGet, "http://localhost/", nil)
	if err != nil {
		t.Fatal(err)
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("GET /: %v", err)
	}
	_ = resp.Body.Close()
	return resp.StatusCode
}

func TestUnixSocketEnforcesSecret(t *testing.T) {
	addr := filepath.Join(shortTempDir(t), "c.sock")
	l, err := listenUnix(addr)
	if err != nil {
		t.Skipf("unix socket not supported: %v", err)
	}
	server := &http.Server{Handler: newHandler(&Config{Secret: testSecret})}
	go func() { _ = server.Serve(l) }()
	defer server.Close()

	dial := func(ctx context.Context) (stdnet.Conn, error) {
		var d stdnet.Dialer
		return d.DialContext(ctx, "unix", addr)
	}
	if code := getStatus(t, dial, ""); code != http.StatusUnauthorized {
		t.Errorf("unix GET / without token: got %d, want %d", code, http.StatusUnauthorized)
	}
	if code := getStatus(t, dial, testSecret); code != http.StatusOK {
		t.Errorf("unix GET / with token: got %d, want %d", code, http.StatusOK)
	}
}
