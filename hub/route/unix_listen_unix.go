//go:build !windows

package route

import (
	"context"
	"net"
	"os"
	"path/filepath"

	"github.com/metacubex/mihomo/adapter/inbound"
	"github.com/metacubex/mihomo/log"
)

// listenUnix listens on a unix socket at addr whose permissions are unixSocketMode().
//
// The socket is bound inside a fresh 0700 directory next to addr, gets its final
// permissions there and is then renamed into place, so other users can never
// reach it with looser permissions than the configured ones.
func listenUnix(addr string) (net.Listener, error) {
	mode := unixSocketMode()

	l, err := listenUnixPrivate(addr, mode)
	if err == nil {
		return l, nil
	}
	// e.g. the temporary path exceeds the sun_path limit: bind in place and tighten at once.
	log.Warnln("External controller unix private listen failed, binding in place: %s", err)

	lc := inbound.NewListenConfig()
	lc.SetRouteMark(0) // don't set route mark for unix socket
	l, err = lc.Listen(context.Background(), "unix", addr)
	if err != nil {
		return nil, err
	}
	if err = os.Chmod(addr, mode); err != nil {
		_ = l.Close()
		return nil, err
	}
	return l, nil
}

func listenUnixPrivate(addr string, mode os.FileMode) (net.Listener, error) {
	tmpDir, err := os.MkdirTemp(filepath.Dir(addr), ".cs")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(tmpDir)
	tmpAddr := filepath.Join(tmpDir, "s")

	lc := inbound.NewListenConfig()
	lc.SetRouteMark(0) // don't set route mark for unix socket
	l, err := lc.Listen(context.Background(), "unix", tmpAddr)
	if err != nil {
		return nil, err
	}
	if err = os.Chmod(tmpAddr, mode); err != nil {
		_ = l.Close()
		return nil, err
	}
	if err = os.Rename(tmpAddr, addr); err != nil {
		_ = l.Close()
		return nil, err
	}
	info, err := os.Lstat(addr)
	if err != nil {
		_ = l.Close()
		return nil, err
	}
	if ul, ok := l.(*net.UnixListener); ok {
		ul.SetUnlinkOnClose(false) // its bound path is gone; renamedUnixListener removes addr instead
	}
	return &renamedUnixListener{
		Listener: l,
		addr:     &net.UnixAddr{Name: addr, Net: "unix"},
		info:     info,
	}, nil
}

// renamedUnixListener reports and cleans up the final socket path of a
// listener that was bound at a temporary path.
type renamedUnixListener struct {
	net.Listener
	addr *net.UnixAddr
	info os.FileInfo
}

func (l *renamedUnixListener) Addr() net.Addr {
	return l.addr
}

func (l *renamedUnixListener) Close() error {
	err := l.Listener.Close()
	// remove the socket file only if it is still ours
	if info, statErr := os.Lstat(l.addr.Name); statErr == nil && os.SameFile(info, l.info) {
		_ = os.Remove(l.addr.Name)
	}
	return err
}
