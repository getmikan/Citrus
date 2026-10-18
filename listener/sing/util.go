package sing

import (
	"context"
	"net"

	"github.com/metacubex/mihomo/adapter/inbound"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/transport/socks5"
)

// HandleSocket like inbound.NewSocket combine with Tunnel.HandleTCPConn but also handel specialFqdn
func (h *ListenerHandler) HandleSocket(target socks5.Addr, conn net.Conn, _additions ...inbound.Addition) {
	conn, metadata := h.newSocket(target, conn, _additions)
	if metadata != nil {
		h.Tunnel.HandleTCPConn(conn, metadata)
	}
}

// newSocket returns the conn and metadata of HandleSocket, or a nil metadata
// when the target is a special FQDN, which it handles itself. A function of
// its own, so that its frame is not on the stack under the relay (see
// tunnel.dialTCPConn).
//
//go:noinline
func (h *ListenerHandler) newSocket(target socks5.Addr, conn net.Conn, _additions []inbound.Addition) (net.Conn, *C.Metadata) {
	conn, metadata := inbound.NewSocket(target, conn, h.Type, h.Additions...)
	if h.IsSpecialFqdn(metadata.Host) {
		err := h.ParseSpecialFqdn(
			WithAdditions(context.Background(), _additions...),
			conn,
			ConvertMetadata(metadata),
		)
		if err != nil {
			_ = conn.Close()
		}
		return conn, nil
	}
	inbound.ApplyAdditions(metadata, _additions...)
	return conn, metadata
}
