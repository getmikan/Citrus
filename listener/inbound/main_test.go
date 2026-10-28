package inbound_test

import (
	"net/netip"
	"os"
	"testing"

	"github.com/metacubex/mihomo/component/egress"
)

// The tests send the users of the server inbounds to targets on the loopback,
// which the egress guard refuses by default. It stays on, with the loopback
// allowed, so the guarded DIRECT path is still the one under test.
func TestMain(m *testing.M) {
	egress.SetOptions(egress.Options{Enable: true, AllowIPs: []netip.Prefix{
		netip.MustParsePrefix("127.0.0.0/8"),
		netip.MustParsePrefix("::1/128"),
	}})
	os.Exit(m.Run())
}
