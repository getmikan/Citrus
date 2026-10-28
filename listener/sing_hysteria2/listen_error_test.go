package sing_hysteria2

import (
	"net"
	"testing"

	"github.com/metacubex/mihomo/adapter/inbound"
	LC "github.com/metacubex/mihomo/listener/config"

	"github.com/stretchr/testify/require"
)

// When a later address is busy, New must not leave the earlier ones bound
// and served with the rejected configuration.
func TestNewLaterAddressFailsFreesEarlier(t *testing.T) {
	l, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)
	first := l.LocalAddr().String()
	require.NoError(t, l.Close())
	busy, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)
	defer busy.Close()

	_, err = New(LC.Hysteria2Server{
		Enable: true,
		Listen: first + "," + busy.LocalAddr().String(),
		Users:  map[string]string{"user": "password"},
	}, inbound.NewListenConfig(), nil)
	require.Error(t, err)

	l, err = net.ListenPacket("udp", first)
	require.NoError(t, err, "the failed listener keeps the port")
	_ = l.Close()
}
