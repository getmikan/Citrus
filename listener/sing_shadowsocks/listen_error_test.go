package sing_shadowsocks

import (
	"testing"

	"github.com/metacubex/mihomo/adapter/inbound"
	LC "github.com/metacubex/mihomo/listener/config"
	"github.com/metacubex/mihomo/listener/internal/porttest"

	"github.com/stretchr/testify/require"
)

// When a later address is busy, New must not leave the earlier ones bound
// and served with the rejected configuration.
func TestNewLaterAddressFailsFreesEarlier(t *testing.T) {
	for _, tc := range []struct{ name, cipher, network string }{
		{"aead-tcp", "aes-128-gcm", "tcp"},
		{"aead-udp", "aes-128-gcm", "udp"},
		// sing has no "dummy": listener/shadowsocks serves it
		{"embedded-tcp", "dummy", "tcp"},
		{"embedded-udp", "dummy", "udp"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			first := porttest.FreeAddr(t)
			_, err := New(LC.ShadowsocksServer{
				Enable:   true,
				Listen:   first + "," + porttest.BusyAddr(t, tc.network),
				Password: "password",
				Cipher:   tc.cipher,
				Udp:      true,
			}, inbound.NewListenConfig(), nil)
			require.Error(t, err)
			porttest.RequireFree(t, "tcp", first)
			porttest.RequireFree(t, "udp", first)
		})
	}
}
