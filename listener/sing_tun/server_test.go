package sing_tun

import (
	"testing"

	LC "github.com/metacubex/mihomo/listener/config"
)

// auto-redirect without auto-route must be reported as a config error before
// anything is started, not panic in the deferred cleanup with a nil Listener.
func TestNewAutoRedirectRequiresAutoRoute(t *testing.T) {
	if !supportRedirect {
		t.Skip("auto-redirect is not supported on this platform")
	}
	l, err := New(LC.Tun{Enable: true, AutoRedirect: true, AutoRoute: false}, nil)
	if err == nil {
		t.Fatal("expected an error for auto-redirect without auto-route")
	}
	if l != nil {
		t.Fatal("expected a nil listener on error")
	}
}
