package trojan

import (
	"testing"

	"github.com/metacubex/mihomo/adapter/inbound"
	LC "github.com/metacubex/mihomo/listener/config"
	"github.com/metacubex/mihomo/listener/internal/porttest"

	"github.com/stretchr/testify/require"
)

func TestNewInsecureRejectedFreesPort(t *testing.T) {
	addr := porttest.FreeAddr(t)
	_, err := New(LC.TrojanServer{Enable: true, Listen: addr}, inbound.NewListenConfig(), nil)
	require.ErrorContains(t, err, "disallow using Trojan")
	porttest.RequireFree(t, "tcp", addr)
}

func TestNewLaterAddressFailsFreesEarlier(t *testing.T) {
	first := porttest.FreeAddr(t)
	_, err := New(LC.TrojanServer{
		Enable:        true,
		Listen:        first + "," + porttest.BusyAddr(t, "tcp"),
		AllowInsecure: true,
	}, inbound.NewListenConfig(), nil)
	require.Error(t, err)
	porttest.RequireFree(t, "tcp", first)
}
