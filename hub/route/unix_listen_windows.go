package route

import (
	"context"
	"net"

	"github.com/metacubex/mihomo/adapter/inbound"
)

// listenUnix listens on an AF_UNIX socket at addr.
// Windows ignores the unix permission bits: access to the socket file is
// governed by the ACL inherited from its parent directory.
func listenUnix(addr string) (net.Listener, error) {
	lc := inbound.NewListenConfig()
	lc.SetRouteMark(0) // don't set route mark for unix socket
	return lc.Listen(context.Background(), "unix", addr)
}
