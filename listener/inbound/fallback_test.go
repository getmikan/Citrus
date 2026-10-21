package inbound_test

import (
	"io"
	"net/http"
	"os"
	"path/filepath"
	"testing"

	"github.com/metacubex/mihomo/adapter/outbound"
	"github.com/metacubex/mihomo/listener/inbound"
	"github.com/stretchr/testify/assert"
)

// fallbackFile is an HTML page for fallback-page.
func fallbackFile(t *testing.T) string {
	t.Helper()
	file := filepath.Join(t.TempDir(), "page.html")
	if err := os.WriteFile(file, []byte("<html>maintenance</html>"), 0o600); err != nil {
		t.Fatal(err)
	}
	return file
}

// listenVless starts a VLESS inbound on loopback and returns its address.
func listenVless(t *testing.T, opt inbound.VlessOption) string {
	t.Helper()
	opt.BaseOption = inbound.BaseOption{NameStr: "vless_fallback", Listen: "127.0.0.1", Port: "0"}
	opt.Users = []inbound.VlessUser{{Username: "test", UUID: userUUID}}
	in, err := inbound.NewVless(&opt)
	if err != nil {
		t.Fatal(err)
	}
	tunnel := NewHttpTestTunnel()
	t.Cleanup(func() { tunnel.Close() })
	if err := in.Listen(tunnel); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { in.Close() })
	return in.Address()
}

// get asks addr for path with Host host ("" the address) and returns the status and body.
func get(t *testing.T, addr, host, path string) (int, string) {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, "http://"+addr+path, nil)
	if err != nil {
		t.Fatal(err)
	}
	if host != "" {
		req.Host = host
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(body)
}

// fallback-page on an HTTP transport: a request that is not the inbound's own gets the page
// at "/" and a plain 404 elsewhere, XHTTP's for another name too, while the protocol goes on
// over the transport; a VLESS inbound with no HTTP transport takes no page and stays VLESS.
func TestInboundFallbackPage(t *testing.T) {
	file := fallbackFile(t)
	t.Run("websocket", func(t *testing.T) {
		addr := listenVless(t, inbound.VlessOption{WsPath: "/ws", AllowInsecure: true, FallbackPage: file})
		if code, body := get(t, addr, "", "/"); code != http.StatusOK || body != "<html>maintenance</html>" {
			t.Fatalf("/: %d %q", code, body)
		}
		if code, _ := get(t, addr, "", "/admin"); code != http.StatusNotFound {
			t.Fatalf("another path: %d", code)
		}
		if code, body := get(t, addr, "", "/ws"); code == http.StatusOK || body == "<html>maintenance</html>" {
			t.Fatalf("the inbound's own path is not the page: %d %q", code, body)
		}
	})
	t.Run("xhttp", func(t *testing.T) {
		addr := listenVless(t, inbound.VlessOption{AllowInsecure: true, FallbackPage: file,
			XHTTPConfig: inbound.XHTTPConfig{Path: "/x", Host: "example.com", Mode: "auto"}})
		if code, body := get(t, addr, "", "/"); code != http.StatusOK || body != "<html>maintenance</html>" {
			t.Fatalf("/: %d %q", code, body)
		}
		// Another name is no request of the inbound: the site of one page has nothing at /x.
		if code, _ := get(t, addr, "other.example.org", "/x"); code != http.StatusNotFound {
			t.Fatalf("another name under the path: %d", code)
		}
	})
	t.Run("a missing page fails the listener", func(t *testing.T) {
		opt := inbound.VlessOption{WsPath: "/ws", AllowInsecure: true, FallbackPage: filepath.Join(t.TempDir(), "none.html")}
		opt.BaseOption = inbound.BaseOption{NameStr: "vless_fallback", Listen: "127.0.0.1", Port: "0"}
		opt.Users = []inbound.VlessUser{{Username: "test", UUID: userUUID}}
		in, err := inbound.NewVless(&opt)
		if err != nil {
			t.Fatal(err)
		}
		tunnel := NewHttpTestTunnel()
		defer tunnel.Close()
		if err := in.Listen(tunnel); err == nil {
			in.Close()
			t.Fatal("a page that cannot be read starts no listener")
		}
	})
	t.Run("the protocol over websocket", func(t *testing.T) {
		testInboundVless(t, inbound.VlessOption{WsPath: "/ws", AllowInsecure: true, FallbackPage: file},
			outbound.VlessOption{Network: "ws", WSOpts: outbound.WSOptions{Path: "/ws"}})
	})
	t.Run("plain vless takes no page", func(t *testing.T) {
		testInboundVless(t, inbound.VlessOption{AllowInsecure: true, FallbackPage: file}, outbound.VlessOption{})
	})
	assert.FileExists(t, file)
}
