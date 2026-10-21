package inbound_test

import (
	"io"
	"net/http"
	"os"
	"path/filepath"
	"testing"

	"github.com/metacubex/mihomo/adapter/outbound"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/listener/inbound"
)

const fallbackHTML = "<html>maintenance</html>"

// fallbackFile is an HTML page for fallback-page in a home directory of its own, where the
// safe-path check lets the listener read it.
func fallbackFile(t *testing.T) string {
	t.Helper()
	home := t.TempDir()
	old := C.Path.HomeDir()
	C.SetHomeDir(home)
	t.Cleanup(func() { C.SetHomeDir(old) })
	file := filepath.Join(home, "page.html")
	if err := os.WriteFile(file, []byte(fallbackHTML), 0o600); err != nil {
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

// get asks addr for path with Host host ("" the address) and returns the response and body.
func get(t *testing.T, addr, host, path string) (*http.Response, string) {
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
	return resp, string(body)
}

// fallback-page on an HTTP transport: a request that is not the inbound's own gets the page
// at "/" and a plain 404 elsewhere, while the protocol goes on over the transport. A
// WebSocket path of "/" takes the page into its own handler, XHTTP's page carries none of
// XHTTP's headers, Trojan's WebSocket has it too, a VLESS inbound with no HTTP transport
// takes no page, and a page that cannot be read, or lies outside the safe paths, starts no
// listener.
func TestInboundFallbackPage(t *testing.T) {
	file := fallbackFile(t)
	// isPage asks addr for "/" and wants the page.
	isPage := func(t *testing.T, addr string) *http.Response {
		t.Helper()
		resp, body := get(t, addr, "", "/")
		if resp.StatusCode != http.StatusOK || body != fallbackHTML {
			t.Fatalf("the page: %d %q", resp.StatusCode, body)
		}
		return resp
	}
	t.Run("websocket", func(t *testing.T) {
		addr := listenVless(t, inbound.VlessOption{WsPath: "/ws", AllowInsecure: true, FallbackPage: file})
		isPage(t, addr)
		if resp, _ := get(t, addr, "", "/admin"); resp.StatusCode != http.StatusNotFound {
			t.Fatalf("another path: %d", resp.StatusCode)
		}
		// A browser opening the inbound's own path is no WebSocket client either.
		if resp, _ := get(t, addr, "", "/ws"); resp.StatusCode != http.StatusNotFound {
			t.Fatalf("the path without an upgrade: %d", resp.StatusCode)
		}
	})
	t.Run("websocket at /", func(t *testing.T) {
		addr := listenVless(t, inbound.VlessOption{WsPath: "/", AllowInsecure: true, FallbackPage: file})
		isPage(t, addr)
	})
	t.Run("xhttp", func(t *testing.T) {
		addr := listenVless(t, inbound.VlessOption{AllowInsecure: true, FallbackPage: file,
			XHTTPConfig: inbound.XHTTPConfig{Path: "/x", Host: "example.com", Mode: "auto"}})
		isPage(t, addr)
		if resp, _ := get(t, addr, "other.example.org", "/x"); resp.StatusCode != http.StatusNotFound {
			t.Fatalf("another name under the path: %d", resp.StatusCode)
		}
	})
	t.Run("xhttp at /", func(t *testing.T) {
		addr := listenVless(t, inbound.VlessOption{AllowInsecure: true, FallbackPage: file, XHTTPConfig: inbound.XHTTPConfig{Path: "/", Mode: "auto"}})
		resp := isPage(t, addr)
		if resp.Header.Get("X-Padding") != "" {
			t.Fatal("the page carries XHTTP's padding header")
		}
	})
	t.Run("trojan websocket", func(t *testing.T) {
		opt := inbound.TrojanOption{WsPath: "/ws", AllowInsecure: true, FallbackPage: file,
			BaseOption: inbound.BaseOption{NameStr: "trojan_fallback", Listen: "127.0.0.1", Port: "0"},
			Users:      []inbound.TrojanUser{{Username: "test", Password: userUUID}}}
		in, err := inbound.NewTrojan(&opt)
		if err != nil {
			t.Fatal(err)
		}
		tunnel := NewHttpTestTunnel()
		defer tunnel.Close()
		if err := in.Listen(tunnel); err != nil {
			t.Fatal(err)
		}
		defer in.Close()
		isPage(t, in.Address())
	})
	refused := func(t *testing.T, page string) {
		t.Helper()
		opt := inbound.VlessOption{WsPath: "/ws", AllowInsecure: true, FallbackPage: page}
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
			t.Fatalf("%s starts a listener", page)
		}
	}
	t.Run("a missing page fails the listener", func(t *testing.T) {
		refused(t, filepath.Join(filepath.Dir(file), "none.html"))
	})
	t.Run("a page outside the safe paths fails the listener", func(t *testing.T) {
		outside := filepath.Join(t.TempDir(), "page.html")
		if err := os.WriteFile(outside, []byte(fallbackHTML), 0o600); err != nil {
			t.Fatal(err)
		}
		refused(t, outside)
	})
	t.Run("the protocol over websocket", func(t *testing.T) {
		testInboundVless(t, inbound.VlessOption{WsPath: "/ws", AllowInsecure: true, FallbackPage: file},
			outbound.VlessOption{Network: "ws", WSOpts: outbound.WSOptions{Path: "/ws"}})
	})
	t.Run("the protocol over websocket at /", func(t *testing.T) {
		testInboundVless(t, inbound.VlessOption{WsPath: "/", AllowInsecure: true, FallbackPage: file},
			outbound.VlessOption{Network: "ws", WSOpts: outbound.WSOptions{Path: "/"}})
	})
	t.Run("plain vless takes no page", func(t *testing.T) {
		testInboundVless(t, inbound.VlessOption{AllowInsecure: true, FallbackPage: file}, outbound.VlessOption{})
	})
}
