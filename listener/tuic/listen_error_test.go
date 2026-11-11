package tuic

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
	_, err := New(LC.TuicServer{
		Enable: true,
		Listen: first + "," + porttest.BusyAddr(t, "udp"),
		Users:  map[string]string{"00000000-0000-0000-0000-000000000000": "password"},
	}, inbound.NewListenConfig(), nil)
	require.Error(t, err)
	porttest.RequireFree(t, "udp", first)
}
