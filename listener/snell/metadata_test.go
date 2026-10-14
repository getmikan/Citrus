package snell

import (
	"net"
	"testing"

	"github.com/metacubex/mihomo/adapter/inbound"
	C "github.com/metacubex/mihomo/constant"

	"github.com/stretchr/testify/require"
)

type addrConn struct{ net.Conn }

func (addrConn) RemoteAddr() net.Addr { return &net.TCPAddr{IP: net.IPv4(10, 0, 0, 2), Port: 40000} }
func (addrConn) LocalAddr() net.Addr  { return &net.TCPAddr{IP: net.IPv4(10, 0, 0, 1), Port: 8388} }

// The Snell client ID never replaces the user an outer layer (ShadowTLS,
// JLS) verified; without one it still names the user.
func TestMetadataClientIDKeepsVerifiedUser(t *testing.T) {
	l := &Listener{}
	base := []inbound.Addition{inbound.WithInName("snell-in")}

	verified := append(append([]inbound.Addition(nil), base...), inbound.WithInUser("alice"))
	m := l.metadata(C.TCP, "1.2.3.4", 443, addrConn{}, "mallory", verified...)
	require.Equal(t, "alice", m.InUser)
	require.Equal(t, "snell-in", m.InName)

	m = l.metadata(C.UDP, "1.2.3.4", 53, addrConn{}, "", verified...)
	require.Equal(t, "alice", m.InUser)

	m = l.metadata(C.TCP, "1.2.3.4", 443, addrConn{}, "client-7", base...)
	require.Equal(t, "client-7", m.InUser)
}
