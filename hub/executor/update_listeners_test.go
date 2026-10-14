package executor

import (
	"net"
	"net/netip"
	"testing"

	"github.com/metacubex/mihomo/adapter/inbound"
	"github.com/metacubex/mihomo/config"
	"github.com/metacubex/mihomo/listener"
	"github.com/metacubex/mihomo/tunnel"
)

func freePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

// A reload without force keeps the ports of the built-in listeners but takes
// the access policy of the new configuration.
func TestUpdateListenersWithoutForceAppliesAccessPolicy(t *testing.T) {
	t.Cleanup(func() {
		inbound.SetSkipAuthPrefixes(nil)
		inbound.SetAllowedIPs(nil)
		inbound.SetDisAllowedIPs(nil)
		listener.SetAllowLan(false)
		listener.SetBindAddress("*")
		listener.ReCreateMixed(0, tunnel.Tunnel)
	})

	port := freePort(t)
	updateListeners(&config.General{Inbound: config.Inbound{
		MixedPort:        port,
		BindAddress:      "*",
		SkipAuthPrefixes: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")},
	}}, nil, true)
	if got := listener.GetPorts().MixedPort; got != port {
		t.Fatalf("mixed port after a forced reload = %d, want %d", got, port)
	}

	deny := []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0")}
	updateListeners(&config.General{Inbound: config.Inbound{
		MixedPort:        freePort(t),
		AllowLan:         true,
		BindAddress:      "127.0.0.1",
		LanDisAllowedIPs: deny,
	}}, nil, false)

	if got := listener.GetPorts().MixedPort; got != port {
		t.Errorf("mixed port after a reload without force = %d, want the running %d", got, port)
	}
	if got := inbound.SkipAuthPrefixes(); len(got) != 0 {
		t.Errorf("skip-auth-prefixes after a reload without force = %v, want none", got)
	}
	if got := inbound.DisAllowedIPs(); len(got) != 1 || got[0] != deny[0] {
		t.Errorf("lan-disallowed-ips after a reload without force = %v, want %v", got, deny)
	}
	if !listener.AllowLan() || listener.BindAddress() != "127.0.0.1" {
		t.Errorf("allow-lan/bind-address not applied: %v %q", listener.AllowLan(), listener.BindAddress())
	}
}
