package socks

import (
	"errors"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/metacubex/mihomo/adapter/inbound"
	"github.com/metacubex/mihomo/component/auth"
	authStore "github.com/metacubex/mihomo/listener/auth"
	"github.com/metacubex/mihomo/transport/socks5"

	"github.com/stretchr/testify/require"
)

func requireServerClosed(t *testing.T, conn net.Conn) {
	t.Helper()
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	_, err := conn.Read(make([]byte, 1))
	require.Error(t, err)
	var ne net.Error
	require.False(t, errors.As(err, &ne) && ne.Timeout(), "the session was kept open")
}

func requireOpen(t *testing.T, conn net.Conn) {
	t.Helper()
	_ = conn.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
	_, err := conn.Read(make([]byte, 1))
	var ne net.Error
	require.True(t, errors.As(err, &ne) && ne.Timeout(), "the session was closed: %v", err)
}

// A reload of the global authentication closes the sessions of a re-keyed
// user, and those let in before authentication was turned on.
func TestSocksGlobalAuthRotation(t *testing.T) {
	// the listeners of the global authentication check the LAN allow list
	allowed := inbound.AllowedIPs()
	inbound.SetAllowedIPs([]netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")})
	authStore.Default.SetAuthenticator(nil)
	t.Cleanup(func() {
		authStore.Default.SetAuthenticator(nil)
		inbound.SetAllowedIPs(allowed)
	})
	tcp, _, _ := newSocksPair(t, authStore.Default)

	open := associate(t, tcp.Address(), nil)
	defer open.Close()
	authStore.Default.SetAuthenticator(auth.NewAuthenticator([]auth.AuthUser{{User: "u", Pass: "p"}, {User: "v", Pass: "q"}}))
	requireServerClosed(t, open)

	u := associate(t, tcp.Address(), &socks5.User{Username: "u", Password: "p"})
	defer u.Close()
	v := associate(t, tcp.Address(), &socks5.User{Username: "v", Password: "q"})
	defer v.Close()
	authStore.Default.SetAuthenticator(auth.NewAuthenticator([]auth.AuthUser{{User: "u", Pass: "p2"}, {User: "v", Pass: "q"}}))
	requireServerClosed(t, u)
	requireOpen(t, v)
}
