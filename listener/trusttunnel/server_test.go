package trusttunnel

import (
	"strings"
	"testing"

	LC "github.com/metacubex/mihomo/listener/config"
)

func TestInvalidFallbackBeforeListening(t *testing.T) {
	for _, fallback := range []string{"http://127.0.0.1:8080", "127.0.0.1", ":8080", "host:0"} {
		_, err := New(LC.TrustTunnelServer{Fallback: fallback}, nil, nil)
		if err == nil || !strings.Contains(err.Error(), "fallback") {
			t.Errorf("%q: expected configuration error, got %v", fallback, err)
		}
	}
}
