package trojan

import (
	"net"
	"testing"

	"github.com/metacubex/mihomo/adapter/inbound"
	LC "github.com/metacubex/mihomo/listener/config"

	"github.com/stretchr/testify/require"
)

func freeAddr(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	addr := l.Addr().String()
	require.NoError(t, l.Close())
	return addr
}

// requireFree checks that addr can be listened on again: a failed New must
// not keep the port bound.
func requireFree(t *testing.T, addr string) {
	t.Helper()
	l, err := net.Listen("tcp", addr)
	require.NoError(t, err, "the failed listener keeps the port")
	_ = l.Close()
}

func TestNewInsecureRejectedFreesPort(t *testing.T) {
	addr := freeAddr(t)
	_, err := New(LC.TrojanServer{Enable: true, Listen: addr}, inbound.NewListenConfig(), nil)
	require.ErrorContains(t, err, "disallow using Trojan")
	requireFree(t, addr)
}

func TestNewLaterAddressFailsFreesEarlier(t *testing.T) {
	first := freeAddr(t)
	busy, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer busy.Close()

	_, err = New(LC.TrojanServer{
		Enable:        true,
		Listen:        first + "," + busy.Addr().String(),
		AllowInsecure: true,
	}, inbound.NewListenConfig(), nil)
	require.Error(t, err)
	requireFree(t, first)
}
