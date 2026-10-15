package inbound

import (
	"context"
	"io/fs"
	"net"
)

// listenUnixSocket binds an AF_UNIX socket at path (Windows 10 1803 and
// later). Windows ignores the unix permission bits: access to the socket file
// is governed by the ACL it inherits from its directory, so mode is unused.
func listenUnixSocket(ctx context.Context, path string, _ fs.FileMode) (net.Listener, error) {
	return bindUnix(ctx, path)
}
