package hysteria2_realm

import (
	"testing"
	"time"

	"github.com/metacubex/mihomo/adapter/inbound"
	LC "github.com/metacubex/mihomo/listener/config"
	"github.com/metacubex/mihomo/listener/internal/porttest"

	"github.com/stretchr/testify/require"
)

// Without IdleTimeout an idle keep-alive connection is kept forever: the
// server has no ReadTimeout, since /events is long-lived.
func TestRealmServerIdleTimeout(t *testing.T) {
	l, _ := startRealmListener(t, LC.Hysteria2RealmServer{})
	require.NotEmpty(t, l.servers)
	for _, srv := range l.servers {
		require.Equal(t, 30*time.Second, srv.IdleTimeout)
	}
}

func TestNewLaterAddressFailsFreesEarlier(t *testing.T) {
	first := porttest.FreeAddr(t)
	_, err := New(LC.Hysteria2RealmServer{
		Listen:           first + "," + porttest.BusyAddr(t, "tcp"),
		Token:            "realm-token",
		AllowInsecure:    true,
		RealmNamePattern: DefaultRealmNamePattern,
	}, inbound.NewListenConfig(), nil)
	require.Error(t, err)
	porttest.RequireFree(t, "tcp", first)
}
