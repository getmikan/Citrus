package sing_tun

import (
	"net"
	"testing"

	"github.com/metacubex/mihomo/common/utils"
	C "github.com/metacubex/mihomo/constant"
	P "github.com/metacubex/mihomo/constant/provider"
	LC "github.com/metacubex/mihomo/listener/config"
)

// fakeTunnel satisfies both tunnel interfaces New asserts; none of its methods
// are reached on the error paths tested here.
type fakeTunnel struct{}

func (fakeTunnel) HandleTCPConn(net.Conn, *C.Metadata)                 {}
func (fakeTunnel) HandleUDPPacket(C.UDPPacket, *C.Metadata)            {}
func (fakeTunnel) NatTable() C.NatTable                                { return nil }
func (fakeTunnel) Providers() map[string]P.ProxyProvider               { return nil }
func (fakeTunnel) RuleProviders() map[string]P.RuleProvider            { return nil }
func (fakeTunnel) RuleUpdateCallback() *utils.Callback[P.RuleProvider] { return nil }

// auto-redirect without auto-route must be reported as a config error before
// anything is started, not panic in the deferred cleanup with a nil Listener.
func TestNewAutoRedirectRequiresAutoRoute(t *testing.T) {
	if !supportRedirect {
		t.Skip("auto-redirect is not supported on this platform")
	}
	l, err := New(LC.Tun{Enable: true, AutoRedirect: true, AutoRoute: false}, fakeTunnel{})
	if err == nil {
		t.Fatal("expected an error for auto-redirect without auto-route")
	}
	if l != nil {
		t.Fatal("expected a nil listener on error")
	}
}
