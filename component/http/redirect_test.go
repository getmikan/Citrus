package http

import (
	"context"
	"errors"
	"net/netip"
	"testing"

	"github.com/metacubex/http"
)

func TestIsNonPublicAddr(t *testing.T) {
	for _, s := range []string{"127.0.0.1", "10.1.2.3", "172.16.0.1", "192.168.1.1", "169.254.169.254", "100.100.100.200", "0.0.0.0", "0.1.2.3", "224.0.0.1", "::1", "::", "fe80::1", "fd00::1", "::ffff:127.0.0.1", "::ffff:169.254.169.254"} {
		if !isNonPublicAddr(netip.MustParseAddr(s)) {
			t.Errorf("%s should be non-public", s)
		}
	}
	for _, s := range []string{"1.1.1.1", "93.184.216.34", "2606:4700::1111", "::ffff:8.8.8.8"} {
		if isNonPublicAddr(netip.MustParseAddr(s)) {
			t.Errorf("%s should be public", s)
		}
	}
}

func TestCheckRedirect(t *testing.T) {
	old := redirectLookup
	defer func() { redirectLookup = old }()
	redirectLookup = func(_ context.Context, host string) ([]netip.Addr, error) {
		switch host {
		case "public.example", "cdn.example":
			return []netip.Addr{netip.MustParseAddr("93.184.216.34")}, nil
		case "rebind.example":
			return []netip.Addr{netip.MustParseAddr("93.184.216.34"), netip.MustParseAddr("127.0.0.1")}, nil
		case "nas.lan":
			return []netip.Addr{netip.MustParseAddr("192.168.1.10")}, nil
		}
		return nil, errors.New("no such host")
	}

	req := func(url string) *http.Request {
		r, err := http.NewRequest(http.MethodGet, url, nil)
		if err != nil {
			t.Fatal(err)
		}
		return r
	}
	tests := []struct {
		from, to string
		allowed  bool
	}{
		{"https://public.example/sub", "https://cdn.example/sub", true},
		{"https://public.example/sub", "https://unknown.example/sub", false},
		{"https://public.example/sub", "http://127.0.0.1:9090/configs", false},
		{"https://public.example/sub", "http://[::1]/", false},
		{"https://public.example/sub", "http://169.254.169.254/latest/meta-data/", false},
		{"https://public.example/sub", "http://localhost:8080/", false},
		{"https://public.example/sub", "http://nas.lan/", false},
		{"https://public.example/sub", "http://rebind.example/", false},
		{"https://public.example/sub", "http://[::ffff:10.0.0.1]/", false},
		// Configured on the LAN: redirects stay unrestricted.
		{"http://nas.lan/sub", "http://192.168.1.11/sub", true},
		{"http://192.168.1.10/sub", "http://127.0.0.1/sub", true},
		{"http://localhost:8000/sub", "http://127.0.0.1:8001/sub", true},
	}
	for _, tt := range tests {
		err := checkRedirect(req(tt.to), []*http.Request{req(tt.from)})
		if (err == nil) != tt.allowed {
			t.Errorf("%s -> %s: allowed=%v, err=%v", tt.from, tt.to, tt.allowed, err)
		}
	}

	via := make([]*http.Request, maxRedirects)
	for i := range via {
		via[i] = req("https://public.example/")
	}
	if err := checkRedirect(req("https://cdn.example/"), via); err == nil {
		t.Error("redirect chain is not capped")
	}
}

func TestRedirectPolicyPinsValidatedAddresses(t *testing.T) {
	old := redirectLookup
	defer func() { redirectLookup = old }()
	redirectLookup = func(_ context.Context, host string) ([]netip.Addr, error) {
		switch host {
		case "public.example":
			return []netip.Addr{netip.MustParseAddr("93.184.216.34")}, nil
		case "cdn.example":
			return []netip.Addr{netip.MustParseAddr("203.0.113.10"), netip.MustParseAddr("2001:db8::10")}, nil
		default:
			return nil, errors.New("no such host")
		}
	}
	p := newRedirectPolicy(context.Background(), "public.example")
	from, _ := http.NewRequest(http.MethodGet, "https://public.example/", nil)
	to, _ := http.NewRequest(http.MethodGet, "https://cdn.example/file", nil)
	if err := p.checkRedirect(to, []*http.Request{from}); err != nil {
		t.Fatal(err)
	}
	got, ok := p.approved("CDN.EXAMPLE.")
	if !ok || len(got) != 2 || got[0] != netip.MustParseAddr("203.0.113.10") {
		t.Fatalf("approved addresses = %v, %v", got, ok)
	}
}

func TestRedirectPolicyOriginRebindCannotGainPrivateExemption(t *testing.T) {
	old := redirectLookup
	defer func() { redirectLookup = old }()
	originPrivate := false
	redirectLookup = func(_ context.Context, host string) ([]netip.Addr, error) {
		if host == "public.example" {
			if originPrivate {
				return []netip.Addr{netip.MustParseAddr("127.0.0.1")}, nil
			}
			return []netip.Addr{netip.MustParseAddr("93.184.216.34")}, nil
		}
		return nil, errors.New("no such host")
	}
	p := newRedirectPolicy(context.Background(), "public.example")
	originPrivate = true
	from, _ := http.NewRequest(http.MethodGet, "https://public.example/", nil)
	to, _ := http.NewRequest(http.MethodGet, "http://127.0.0.1/admin", nil)
	if err := p.checkRedirect(to, []*http.Request{from}); err == nil {
		t.Fatal("origin DNS rebind gained the private-origin redirect exemption")
	}
}
