package sing_hysteria2

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
	first := porttest.FreeAddr(t)
	_, err := New(LC.Hysteria2Server{
		Enable: true,
		Listen: first + "," + porttest.BusyAddr(t, "udp"),
		Users:  map[string]string{"user": "password"},
	}, inbound.NewListenConfig(), nil)
	require.Error(t, err)
	porttest.RequireFree(t, "udp", first)
}
